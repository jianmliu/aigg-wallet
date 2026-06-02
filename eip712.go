package agentwallet

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// SignedPayload bundles the 65-byte signature (0x-hex) and the EIP-712 digest
// it commits to (0x-hex). Digest is exposed for cross-checking against
// independent hashers in integration tests.
type SignedPayload struct {
	Signature string
	Digest    string
}

// Permit2TransferParams is a Uniswap Permit2 PermitSingle. Atom fields are
// decimal strings to carry amounts >= 2^63 safely.
type Permit2TransferParams struct {
	Token       string // ERC-20 token
	Spender     string // authorized to call Permit2.transferFrom (the agent EOA)
	Amount      string // allowance, atoms (uint160)
	Nonce       uint64 // Permit2 AllowanceTransfer sequential nonce (uint48)
	Deadline    int64  // unix ts (uint48 expiration + sigDeadline)
	ChainID     int64
	Permit2Addr string // canonical Permit2 (EIP-712 verifyingContract)
}

// EIP2612PermitParams is an ERC-2612 permit() message.
type EIP2612PermitParams struct {
	Token    string
	Owner    string
	Spender  string
	Value    string // atoms (uint256)
	Nonce    uint64 // token.nonces(owner)
	Deadline int64
	ChainID  int64
}

// EIP3009TransferParams is an EIP-3009 transferWithAuthorization message.
type EIP3009TransferParams struct {
	Token       string
	From        string
	To          string
	Value       string // atoms (uint256)
	ValidAfter  int64
	ValidBefore int64
	Nonce       string // bytes32, 0x-prefixed 64-hex
	ChainID     int64
}

const (
	permit2AmountMaxBits     = 160
	permit2NonceMaxBits      = 48
	permit2ExpirationMaxBits = 48
)

// BuildPermit2TypedData builds the EIP-712 TypedData for a Permit2
// PermitSingle. The Permit2 domain intentionally omits `version`.
func BuildPermit2TypedData(p Permit2TransferParams) (*apitypes.TypedData, error) {
	amount, err := decimalToBigInt(p.Amount)
	if err != nil {
		return nil, fmt.Errorf("permit2: amount: %w", err)
	}
	if amount.BitLen() > permit2AmountMaxBits {
		return nil, fmt.Errorf("permit2: amount %s overflows uint160", p.Amount)
	}
	if bitsForU64(p.Nonce) > permit2NonceMaxBits {
		return nil, fmt.Errorf("permit2: nonce %d overflows uint48", p.Nonce)
	}
	if bitsForU64(uint64(p.Deadline)) > permit2ExpirationMaxBits {
		return nil, fmt.Errorf("permit2: deadline %d overflows uint48", p.Deadline)
	}
	if !looksLikeAddress(p.Token) || !looksLikeAddress(p.Spender) || !looksLikeAddress(p.Permit2Addr) {
		return nil, fmt.Errorf("permit2: invalid address (token/spender/permit2addr)")
	}
	return &apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": []apitypes.Type{
				{Name: "name", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"PermitDetails": []apitypes.Type{
				{Name: "token", Type: "address"},
				{Name: "amount", Type: "uint160"},
				{Name: "expiration", Type: "uint48"},
				{Name: "nonce", Type: "uint48"},
			},
			"PermitSingle": []apitypes.Type{
				{Name: "details", Type: "PermitDetails"},
				{Name: "spender", Type: "address"},
				{Name: "sigDeadline", Type: "uint256"},
			},
		},
		PrimaryType: "PermitSingle",
		Domain: apitypes.TypedDataDomain{
			Name:              "Permit2",
			ChainId:           math.NewHexOrDecimal256(p.ChainID),
			VerifyingContract: p.Permit2Addr,
		},
		Message: apitypes.TypedDataMessage{
			"details": map[string]interface{}{
				"token":      p.Token,
				"amount":     amount.String(),
				"expiration": fmt.Sprintf("%d", p.Deadline),
				"nonce":      fmt.Sprintf("%d", p.Nonce),
			},
			"spender":     p.Spender,
			"sigDeadline": fmt.Sprintf("%d", p.Deadline),
		},
	}, nil
}

// BuildEIP2612TypedData builds an ERC-2612 permit() typed data. tokenName/
// tokenVersion are the token's EIP712Domain fields (e.g. GCC: "Guaranteed
// Capacity Credit", "1").
func BuildEIP2612TypedData(p EIP2612PermitParams, tokenName, tokenVersion string) (*apitypes.TypedData, error) {
	if !looksLikeAddress(p.Token) || !looksLikeAddress(p.Owner) || !looksLikeAddress(p.Spender) {
		return nil, fmt.Errorf("eip2612: invalid address (token/owner/spender)")
	}
	value, err := decimalToBigInt(p.Value)
	if err != nil {
		return nil, fmt.Errorf("eip2612: value: %w", err)
	}
	if value.BitLen() > 256 {
		return nil, fmt.Errorf("eip2612: value overflows uint256")
	}
	if strings.TrimSpace(tokenName) == "" || strings.TrimSpace(tokenVersion) == "" {
		return nil, fmt.Errorf("eip2612: token name/version required")
	}
	return &apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": []apitypes.Type{
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"Permit": []apitypes.Type{
				{Name: "owner", Type: "address"},
				{Name: "spender", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "nonce", Type: "uint256"},
				{Name: "deadline", Type: "uint256"},
			},
		},
		PrimaryType: "Permit",
		Domain: apitypes.TypedDataDomain{
			Name:              tokenName,
			Version:           tokenVersion,
			ChainId:           math.NewHexOrDecimal256(p.ChainID),
			VerifyingContract: p.Token,
		},
		Message: apitypes.TypedDataMessage{
			"owner":    p.Owner,
			"spender":  p.Spender,
			"value":    value.String(),
			"nonce":    fmt.Sprintf("%d", p.Nonce),
			"deadline": fmt.Sprintf("%d", p.Deadline),
		},
	}, nil
}

// BuildEIP3009TypedData builds a transferWithAuthorization typed data.
func BuildEIP3009TypedData(p EIP3009TransferParams, tokenName, tokenVersion string) (*apitypes.TypedData, error) {
	if !looksLikeAddress(p.Token) || !looksLikeAddress(p.From) || !looksLikeAddress(p.To) {
		return nil, fmt.Errorf("eip3009: invalid address (token/from/to)")
	}
	value, err := decimalToBigInt(p.Value)
	if err != nil {
		return nil, fmt.Errorf("eip3009: value: %w", err)
	}
	nonce, err := bytes32HexToBytes(p.Nonce)
	if err != nil {
		return nil, fmt.Errorf("eip3009: nonce: %w", err)
	}
	if strings.TrimSpace(tokenName) == "" || strings.TrimSpace(tokenVersion) == "" {
		return nil, fmt.Errorf("eip3009: token name/version required")
	}
	return &apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": []apitypes.Type{
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"TransferWithAuthorization": []apitypes.Type{
				{Name: "from", Type: "address"},
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "validAfter", Type: "uint256"},
				{Name: "validBefore", Type: "uint256"},
				{Name: "nonce", Type: "bytes32"},
			},
		},
		PrimaryType: "TransferWithAuthorization",
		Domain: apitypes.TypedDataDomain{
			Name:              tokenName,
			Version:           tokenVersion,
			ChainId:           math.NewHexOrDecimal256(p.ChainID),
			VerifyingContract: p.Token,
		},
		Message: apitypes.TypedDataMessage{
			"from":        p.From,
			"to":          p.To,
			"value":       value.String(),
			"validAfter":  fmt.Sprintf("%d", p.ValidAfter),
			"validBefore": fmt.Sprintf("%d", p.ValidBefore),
			"nonce":       hexutil.Bytes(nonce),
		},
	}, nil
}

// SignTypedData hashes td via apitypes.TypedDataAndHash and signs with
// privKeyBytes (32-byte secp256k1 scalar). v normalised to 27/28. The caller
// owns + should Zeroize privKeyBytes.
func SignTypedData(privKeyBytes []byte, td *apitypes.TypedData) (SignedPayload, error) {
	digest, _, err := apitypes.TypedDataAndHash(*td)
	if err != nil {
		return SignedPayload{}, fmt.Errorf("typed-data hash: %w", err)
	}
	priv, err := ethcrypto.ToECDSA(privKeyBytes)
	if err != nil {
		return SignedPayload{}, fmt.Errorf("to-ecdsa: %w", err)
	}
	raw, err := ethcrypto.Sign(digest, priv)
	if err != nil {
		return SignedPayload{}, fmt.Errorf("sign: %w", err)
	}
	if len(raw) != 65 {
		return SignedPayload{}, fmt.Errorf("expected 65-byte signature, got %d", len(raw))
	}
	if raw[64] < 27 {
		raw[64] += 27
	}
	return SignedPayload{
		Signature: "0x" + hex.EncodeToString(raw),
		Digest:    "0x" + hex.EncodeToString(digest),
	}, nil
}

// RecoverTypedDataSigner ecrecovers the EIP-55 address that produced sigHex
// (0x-prefixed 65-byte) over td. Used by Authorizer to verify a submitted
// authorization.
func RecoverTypedDataSigner(td *apitypes.TypedData, sigHex string) (string, error) {
	digest, _, err := apitypes.TypedDataAndHash(*td)
	if err != nil {
		return "", fmt.Errorf("typed-data hash: %w", err)
	}
	sig, err := decodeSig65(sigHex)
	if err != nil {
		return "", err
	}
	pub, err := ethcrypto.Ecrecover(digest, sig)
	if err != nil {
		return "", fmt.Errorf("ecrecover: %w", err)
	}
	pk, err := ethcrypto.UnmarshalPubkey(pub)
	if err != nil {
		return "", fmt.Errorf("unmarshal pubkey: %w", err)
	}
	return ethcrypto.PubkeyToAddress(*pk).Hex(), nil
}

// --- helpers ---

func decimalToBigInt(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("not a base-10 integer: %q", s)
	}
	if v.Sign() < 0 {
		return nil, fmt.Errorf("negative")
	}
	return v, nil
}

func bitsForU64(v uint64) int {
	bits := 0
	for v > 0 {
		bits++
		v >>= 1
	}
	return bits
}

func looksLikeAddress(s string) bool {
	if len(s) != 42 || !strings.HasPrefix(s, "0x") {
		return false
	}
	_, err := hex.DecodeString(s[2:])
	return err == nil
}

func bytes32HexToBytes(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") {
		return nil, fmt.Errorf("missing 0x prefix")
	}
	if len(s) != 2+64 {
		return nil, fmt.Errorf("not 32 bytes hex (got %d chars after 0x)", len(s)-2)
	}
	return hex.DecodeString(s[2:])
}

// decodeSig65 decodes a 0x 65-byte signature, normalising v 27/28 → 0/1 for
// Ecrecover.
func decodeSig65(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	if len(s) != 130 {
		return nil, fmt.Errorf("expected 65-byte signature (130 hex), got %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("bad hex: %w", err)
	}
	out := make([]byte, 65)
	copy(out, b)
	if out[64] >= 27 {
		out[64] -= 27
	}
	return out, nil
}
