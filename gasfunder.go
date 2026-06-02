package agentwallet

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// GasFunder tops up an agent EOA's native ETH so it can pay gas. The Spender
// calls EnsureGas before broadcasting. Optional (Spender skips when nil).
type GasFunder interface {
	EnsureGas(ctx context.Context, agentAddress string, chainID *big.Int) (*GasFundResult, error)
}

// GasFundResult reports what EnsureGas did.
type GasFundResult struct {
	Funded     bool
	TxHash     string
	FundedWei  string
	BalanceWei string // agent balance observed before the decision
}

// RealGasFunder is a hot-wallet-backed funder. The funder key MUST be
// dedicated (not shared with a minter/treasury/other signer) or external txs
// desync its account nonce.
type RealGasFunder struct {
	rpc            BaseRPC
	privateKey     *ecdsa.PrivateKey
	address        common.Address
	minBalanceWei  *big.Int
	topUpWei       *big.Int
	receiptTimeout time.Duration
	pollInterval   time.Duration
	mu             sync.Mutex // serialize funding so concurrent top-ups don't race the funder nonce
}

// NewGasFunder builds a funder from a hex key. minBalanceWei/topUpWei nil →
// defaults (trigger 0.0002 ETH, top up 0.001 ETH).
func NewGasFunder(rpc BaseRPC, hexKey string, minBalanceWei, topUpWei *big.Int) (*RealGasFunder, error) {
	if rpc == nil {
		return nil, fmt.Errorf("agentwallet gasfunder: nil rpc")
	}
	k := strings.TrimPrefix(strings.TrimSpace(hexKey), "0x")
	if k == "" {
		return nil, fmt.Errorf("agentwallet gasfunder: empty private key")
	}
	priv, err := ethcrypto.HexToECDSA(k)
	if err != nil {
		return nil, fmt.Errorf("agentwallet gasfunder: bad private key: %w", err)
	}
	if minBalanceWei == nil || minBalanceWei.Sign() <= 0 {
		minBalanceWei = big.NewInt(200_000_000_000_000) // 0.0002 ETH
	}
	if topUpWei == nil || topUpWei.Sign() <= 0 {
		topUpWei = big.NewInt(1_000_000_000_000_000) // 0.001 ETH
	}
	return &RealGasFunder{
		rpc: rpc, privateKey: priv,
		address:        ethcrypto.PubkeyToAddress(priv.PublicKey),
		minBalanceWei:  minBalanceWei,
		topUpWei:       topUpWei,
		receiptTimeout: 60 * time.Second,
		pollInterval:   2 * time.Second,
	}, nil
}

// FunderAddress returns the funder hot-wallet address (for monitoring).
func (f *RealGasFunder) FunderAddress() string { return f.address.Hex() }

// EnsureGas implements GasFunder.
func (f *RealGasFunder) EnsureGas(ctx context.Context, agentAddress string, chainID *big.Int) (*GasFundResult, error) {
	if f == nil {
		return &GasFundResult{}, nil
	}
	if !common.IsHexAddress(agentAddress) {
		return nil, fmt.Errorf("agentwallet gasfunder: bad agent address %q", agentAddress)
	}
	if chainID == nil || chainID.Sign() <= 0 {
		return nil, fmt.Errorf("agentwallet gasfunder: chainID required")
	}
	agent := common.HexToAddress(agentAddress)
	bal, err := f.rpc.BalanceAt(ctx, agent)
	if err != nil {
		return nil, fmt.Errorf("agentwallet gasfunder: read agent balance: %w", err)
	}
	res := &GasFundResult{BalanceWei: bal.String()}
	if bal.Cmp(f.minBalanceWei) >= 0 {
		return res, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if bal2, err := f.rpc.BalanceAt(ctx, agent); err == nil && bal2.Cmp(f.minBalanceWei) >= 0 {
		res.BalanceWei = bal2.String()
		return res, nil
	}
	funderBal, err := f.rpc.BalanceAt(ctx, f.address)
	if err != nil {
		return nil, fmt.Errorf("agentwallet gasfunder: read funder balance: %w", err)
	}
	if funderBal.Cmp(f.topUpWei) <= 0 {
		return nil, fmt.Errorf("agentwallet gasfunder: funder %s underfunded (%s wei)", f.address.Hex(), funderBal.String())
	}
	tx, err := f.buildAndSend(ctx, agent, chainID)
	if err != nil {
		return nil, fmt.Errorf("agentwallet gasfunder: send: %w", err)
	}
	receipt, err := WaitForReceipt(ctx, f.rpc, tx.Hash(), f.receiptTimeout, f.pollInterval)
	if err != nil {
		return nil, fmt.Errorf("agentwallet gasfunder: funding receipt: %w", err)
	}
	if receipt.Status != 1 {
		return nil, fmt.Errorf("agentwallet gasfunder: funding tx reverted (%s)", tx.Hash().Hex())
	}
	res.Funded = true
	res.TxHash = tx.Hash().Hex()
	res.FundedWei = f.topUpWei.String()
	return res, nil
}

func (f *RealGasFunder) buildAndSend(ctx context.Context, to common.Address, chainID *big.Int) (*types.Transaction, error) {
	nonce, err := f.rpc.PendingNonceAt(ctx, f.address)
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	tip, tipErr := f.rpc.SuggestGasTipCap(ctx)
	if tipErr != nil || tip == nil || tip.Sign() <= 0 {
		tip = big.NewInt(1_000_000)
	}
	gasPrice, gpErr := f.rpc.SuggestGasPrice(ctx)
	if gpErr != nil || gasPrice == nil || gasPrice.Sign() <= 0 {
		return nil, fmt.Errorf("gas price: %w", gpErr)
	}
	maxFee := new(big.Int).Mul(gasPrice, big.NewInt(2)) // EIP-1559: clears base fee; never tip*2
	if maxFee.Cmp(tip) < 0 {
		maxFee = new(big.Int).Set(tip)
	}
	gasLimit := uint64(21000)
	if est, err := f.rpc.EstimateGas(ctx, ethereum.CallMsg{From: f.address, To: &to, Value: f.topUpWei}); err == nil && est > 0 {
		gasLimit = est
	}
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID: chainID, Nonce: nonce, GasTipCap: tip, GasFeeCap: maxFee,
		Gas: gasLimit, To: &to, Value: new(big.Int).Set(f.topUpWei),
	})
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), f.privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	if err := f.rpc.SendTransaction(ctx, signed); err != nil {
		return nil, fmt.Errorf("broadcast: %w", err)
	}
	return signed, nil
}

var _ GasFunder = (*RealGasFunder)(nil)
