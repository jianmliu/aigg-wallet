package agentwallet

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// ErrAllowanceExceeded is returned when a spend would exceed the remaining
// Permit2 allowance recorded on the authorization.
var ErrAllowanceExceeded = errors.New("agentwallet: spend exceeds remaining allowance")

// Crediter optionally credits a consumer-side ledger after a confirmed
// transferFrom. Idempotent on transferTxHash. Returns the credited amount,
// the new balance, and whether this was an idempotent replay.
type Crediter interface {
	CreditAfterSpend(ctx context.Context, owner, token, atoms, transferTxHash string) (creditedAtoms, balanceAfterAtoms string, replayed bool, err error)
}

// SpendResult reports the outcome of a Spend.
type SpendResult struct {
	PermitTxHash      string // empty if the on-chain allowance already covered it
	TransferTxHash    string
	AmountAtoms       string
	Agent             string
	Owner             string
	Token             string
	Seller            string
	GasFundedTxHash   string // set if the agent EOA was auto-topped-up this spend
	CreditedAtoms     string
	BalanceAfterAtoms string
	CreditReplayed    bool
	CreditError       string // set if crediting failed AFTER a successful transfer
}

// Spender orchestrates a Permit2 spend for the agent EOA the Signer controls.
type Spender struct {
	Store           AuthorizationStore
	RPC             BaseRPC
	Signer          Signer
	SellerAddressFn func(ctx context.Context) (string, error)
	GasFunder       GasFunder // optional
	Crediter        Crediter  // optional
	Permit2Addr     string    // default CanonicalPermit2Address
	ReceiptTimeout  time.Duration
	PollInterval    time.Duration
}

func (s *Spender) timeout() time.Duration {
	if s.ReceiptTimeout > 0 {
		return s.ReceiptTimeout
	}
	return 30 * time.Second
}
func (s *Spender) poll() time.Duration {
	if s.PollInterval > 0 {
		return s.PollInterval
	}
	return 2 * time.Second
}
func (s *Spender) permit2() string {
	if s.Permit2Addr != "" {
		return s.Permit2Addr
	}
	return CanonicalPermit2Address
}

// Spend submits Permit2.permit (if needed) + transferFrom for amountAtoms
// against the agent's active authorization. now is the current unix time.
func (s *Spender) Spend(ctx context.Context, amountAtoms *big.Int, now int64) (*SpendResult, error) {
	if s == nil || s.Store == nil || s.RPC == nil || s.Signer == nil || s.SellerAddressFn == nil {
		return nil, fmt.Errorf("agentwallet spender: not configured")
	}
	if amountAtoms == nil || amountAtoms.Sign() <= 0 {
		return nil, fmt.Errorf("agentwallet spend: amount must be > 0")
	}
	agentAddr, err := s.Signer.Address(ctx)
	if err != nil {
		return nil, fmt.Errorf("agentwallet spend: agent address: %w", err)
	}
	row, err := s.Store.ActiveForAgent(ctx, agentAddr, now)
	if err != nil {
		return nil, err // ErrNoAuthorization / ErrAuthorizationMissingSignature
	}
	allowance, ok := new(big.Int).SetString(row.AmountAtoms, 10)
	if !ok {
		return nil, fmt.Errorf("agentwallet spend: malformed allowance %q", row.AmountAtoms)
	}
	remaining := new(big.Int).Sub(allowance, row.spent())
	if new(big.Int).Sub(remaining, amountAtoms).Sign() < 0 {
		return nil, fmt.Errorf("%w: requested %s, remaining %s", ErrAllowanceExceeded, amountAtoms, remaining)
	}
	seller, err := s.SellerAddressFn(ctx)
	if err != nil {
		return nil, fmt.Errorf("agentwallet spend: seller: %w", err)
	}
	if !common.IsHexAddress(seller) {
		return nil, fmt.Errorf("agentwallet spend: seller %q malformed", seller)
	}
	chainID, err := s.RPC.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("agentwallet spend: chain id: %w", err)
	}

	result := &SpendResult{
		AmountAtoms: amountAtoms.String(), Agent: agentAddr,
		Owner: row.Owner, Token: row.Token, Seller: seller,
	}

	// gas auto-fund (optional, before broadcasting)
	if s.GasFunder != nil {
		fund, err := s.GasFunder.EnsureGas(ctx, agentAddr, chainID)
		if err != nil {
			return nil, fmt.Errorf("agentwallet spend: ensure gas: %w", err)
		}
		if fund != nil && fund.Funded {
			result.GasFundedTxHash = fund.TxHash
		}
	}

	// skip permit() if the on-chain allowance already covers this spend
	skipPermit := s.allowanceCovers(ctx, row.Owner, row.Token, agentAddr, amountAtoms, now)

	if !skipPermit {
		ptx, err := s.sendPermit(ctx, chainID, row)
		if err != nil {
			return nil, fmt.Errorf("agentwallet spend: permit: %w", err)
		}
		result.PermitTxHash = ptx.Hash().Hex()
		rc, err := WaitForReceipt(ctx, s.RPC, ptx.Hash(), s.timeout(), s.poll())
		if err != nil {
			return nil, fmt.Errorf("agentwallet spend: permit receipt: %w", err)
		}
		if rc.Status != 1 {
			return nil, fmt.Errorf("agentwallet spend: permit reverted (%s)", ptx.Hash().Hex())
		}
	}

	ttx, err := s.sendTransferFrom(ctx, chainID, row.Owner, seller, row.Token, amountAtoms)
	if err != nil {
		return nil, fmt.Errorf("agentwallet spend: transferFrom: %w", err)
	}
	result.TransferTxHash = ttx.Hash().Hex()
	rc, err := WaitForReceipt(ctx, s.RPC, ttx.Hash(), s.timeout(), s.poll())
	if err != nil {
		return nil, fmt.Errorf("agentwallet spend: transfer receipt: %w", err)
	}
	if rc.Status != 1 {
		return nil, fmt.Errorf("agentwallet spend: transferFrom reverted (%s)", ttx.Hash().Hex())
	}

	if err := s.Store.BumpSpent(ctx, row.Owner, agentAddr, row.Token, row.Nonce, amountAtoms.String()); err != nil {
		return nil, fmt.Errorf("agentwallet spend: bump spent: %w", err)
	}

	if s.Crediter != nil {
		ca, ba, replayed, cerr := s.Crediter.CreditAfterSpend(ctx, row.Owner, row.Token, amountAtoms.String(), result.TransferTxHash)
		if cerr != nil {
			result.CreditError = cerr.Error()
		} else {
			result.CreditedAtoms, result.BalanceAfterAtoms, result.CreditReplayed = ca, ba, replayed
		}
	}
	return result, nil
}

func (s *Spender) sendPermit(ctx context.Context, chainID *big.Int, row *Authorization) (*types.Transaction, error) {
	sig, err := decodeSigOnchain(row.SignatureHex)
	if err != nil {
		return nil, fmt.Errorf("decode cached sig: %w", err)
	}
	amount, ok := new(big.Int).SetString(row.AmountAtoms, 10)
	if !ok {
		return nil, fmt.Errorf("malformed amount %q", row.AmountAtoms)
	}
	calldata, err := EncodePermitCall(PermitSingleCallArgs{
		Owner: row.Owner, Token: row.Token, Spender: row.Agent,
		Amount: amount, Expiration: uint64(row.Expiration), Nonce: uint64(row.Nonce),
		SigDeadline: big.NewInt(row.Expiration), Signature: sig,
	})
	if err != nil {
		return nil, err
	}
	return s.buildSignSend(ctx, chainID, common.HexToAddress(s.permit2()), calldata)
}

func (s *Spender) sendTransferFrom(ctx context.Context, chainID *big.Int, owner, seller, token string, amount *big.Int) (*types.Transaction, error) {
	calldata, err := EncodeTransferFromCall(TransferFromCallArgs{From: owner, To: seller, Amount: amount, Token: token})
	if err != nil {
		return nil, err
	}
	return s.buildSignSend(ctx, chainID, common.HexToAddress(s.permit2()), calldata)
}

func (s *Spender) buildSignSend(ctx context.Context, chainID *big.Int, to common.Address, calldata []byte) (*types.Transaction, error) {
	addrStr, err := s.Signer.Address(ctx)
	if err != nil {
		return nil, fmt.Errorf("agent address: %w", err)
	}
	from := common.HexToAddress(addrStr)
	nonce, err := s.RPC.PendingNonceAt(ctx, from)
	if err != nil {
		return nil, fmt.Errorf("pending nonce: %w", err)
	}
	tip, tipErr := s.RPC.SuggestGasTipCap(ctx)
	if tipErr != nil || tip == nil || tip.Sign() <= 0 {
		tip = big.NewInt(1_000_000)
	}
	gasPrice, gpErr := s.RPC.SuggestGasPrice(ctx)
	if gpErr != nil || gasPrice == nil || gasPrice.Sign() <= 0 {
		return nil, fmt.Errorf("gas price: %w", gpErr)
	}
	maxFee := new(big.Int).Mul(gasPrice, big.NewInt(2))
	if maxFee.Cmp(tip) < 0 {
		maxFee = new(big.Int).Set(tip)
	}
	gasLimit, err := s.RPC.EstimateGas(ctx, ethereum.CallMsg{From: from, To: &to, Data: calldata, GasFeeCap: maxFee, GasTipCap: tip})
	if err != nil {
		return nil, fmt.Errorf("estimate gas: %w", err)
	}
	gasLimit = (gasLimit * 120) / 100
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID: chainID, Nonce: nonce, GasTipCap: tip, GasFeeCap: maxFee,
		Gas: gasLimit, To: &to, Value: big.NewInt(0), Data: calldata,
	})
	signed, err := s.Signer.SignTx(ctx, tx, chainID)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	if err := s.RPC.SendTransaction(ctx, signed); err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}
	return signed, nil
}

// allowanceCovers eth_calls Permit2.allowance(owner,token,spender) → (amount,
// expiration, nonce); returns true if amount >= need and expiration > now.
// Non-fatal: any error → false (do the permit anyway).
func (s *Spender) allowanceCovers(ctx context.Context, owner, token, spender string, need *big.Int, now int64) bool {
	if !common.IsHexAddress(owner) || !common.IsHexAddress(token) || !common.IsHexAddress(spender) {
		return false
	}
	data := append(funcSelector("allowance(address,address,address)"),
		append(append(
			common.LeftPadBytes(common.HexToAddress(owner).Bytes(), 32),
			common.LeftPadBytes(common.HexToAddress(token).Bytes(), 32)...),
			common.LeftPadBytes(common.HexToAddress(spender).Bytes(), 32)...)...)
	to := common.HexToAddress(s.permit2())
	out, err := s.RPC.CallContract(ctx, ethereum.CallMsg{To: &to, Data: data}, nil)
	if err != nil || len(out) < 96 {
		return false
	}
	amount := new(big.Int).SetBytes(out[0:32])
	expiration := new(big.Int).SetBytes(out[32:64]).Int64()
	return expiration > now && amount.Cmp(need) >= 0
}

// decodeSigOnchain returns the 65 raw bytes with v in {27,28} (Permit2 wants
// the Ethereum convention).
func decodeSigOnchain(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	if len(s) != 130 {
		return nil, fmt.Errorf("expected 65-byte signature, got %d hex", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 65)
	copy(out, b)
	if out[64] < 27 {
		out[64] += 27
	}
	return out, nil
}
