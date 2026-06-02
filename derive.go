// Package agentwallet is a self-contained toolkit for per-subject agent EOAs
// that pay on-chain via Uniswap Permit2 / EIP-2612 / EIP-3009 — extracted
// from the AI.GG (p2papi) Phase 2 agentic-wallet design so other products
// (e.g. onchainpal) can consume it instead of re-implementing the pieces.
//
// It owns ONLY the chain mechanics: deterministic key derivation, EIP-712
// signing, the Permit2 calldata codec, a Base/EVM RPC wrapper, and gas
// auto-funding. Persistence, the "subject → account" mapping, internal
// ledgers, TEE seed custody, and HTTP surfaces are the consumer's concern
// and plug in through small interfaces (see store.go / spend.go).
//
// Security: the master seed and derived private keys are sensitive. Derived
// keys are returned in AgentKey.PrivateKey; call Zeroize() as soon as the
// signature/tx is built. The default BIP44Signer does this internally.
package aiggwallet

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
)

const (
	// bip44Purpose is the canonical BIP-44 "purpose" (44').
	bip44Purpose uint32 = 44

	// DefaultCoinType binds derivation to Base mainnet (chain id 8453).
	// Non-SLIP-44, intentionally chain-id-scoped so cross-chain agents get
	// isolated addresses. Override via Derive's coinType for other chains.
	DefaultCoinType uint32 = 8453
)

// AgentKey is the output of Derive. Call Zeroize() once the signature/tx is
// built so the secp256k1 scalar does not linger. Address + DerivationPath
// are public and safe to persist/index; PrivateKey is sensitive.
type AgentKey struct {
	PrivateKey     []byte // 32-byte secp256k1 scalar (heap-allocated; Zeroize scrubs it)
	Address        string // EIP-55 checksum address
	DerivationPath string // canonical "m/44'/<coin>'/<account>'"
}

// Zeroize overwrites the private key in place. Safe on nil.
func (a *AgentKey) Zeroize() {
	if a == nil {
		return
	}
	for i := range a.PrivateKey {
		a.PrivateKey[i] = 0
	}
}

// Derive returns the agent EOA for (masterSeed, coinType, account) via the
// BIP-44 hardened path m/44'/<coinType>'/<account>'. account is typically a
// per-subject identifier (AI.GG: user_id). Hardened so child-key compromise
// can't reverse the seed.
//
// Errors: seed not in [16,64] bytes; account not in (0, 2^31).
//
// Note: this is the AI.GG path shape (3 hardened levels). Consumers using a
// different scheme (e.g. m/44'/60'/0'/0/<index>) should implement the Signer
// interface over their own derivation instead.
func Derive(masterSeed []byte, coinType, account uint32) (*AgentKey, error) {
	if len(masterSeed) < 16 || len(masterSeed) > 64 {
		return nil, fmt.Errorf("agentwallet: master seed must be 16-64 bytes (got %d)", len(masterSeed))
	}
	if account == 0 || account >= (1<<31) {
		return nil, fmt.Errorf("agentwallet: account %d outside hardened range (1, 2^31)", account)
	}
	master, err := bip32.NewMasterKey(masterSeed)
	if err != nil {
		return nil, fmt.Errorf("agentwallet: master key: %w", err)
	}
	off := uint32(bip32.FirstHardenedChild) // 0x80000000
	purpose, err := master.NewChildKey(bip44Purpose + off)
	if err != nil {
		return nil, fmt.Errorf("agentwallet: derive 44': %w", err)
	}
	coin, err := purpose.NewChildKey(coinType + off)
	if err != nil {
		return nil, fmt.Errorf("agentwallet: derive %d': %w", coinType, err)
	}
	acct, err := coin.NewChildKey(account + off)
	if err != nil {
		return nil, fmt.Errorf("agentwallet: derive %d': %w", account, err)
	}
	if len(acct.Key) != 32 {
		return nil, errors.New("agentwallet: bip32 returned non-32-byte key")
	}
	priv, err := ethcrypto.ToECDSA(acct.Key)
	if err != nil {
		return nil, fmt.Errorf("agentwallet: to-ecdsa: %w", err)
	}
	privCopy := make([]byte, 32)
	copy(privCopy, acct.Key)
	return &AgentKey{
		PrivateKey:     privCopy,
		Address:        common.Address(ethcrypto.PubkeyToAddress(priv.PublicKey)).Hex(),
		DerivationPath: fmt.Sprintf("m/44'/%d'/%d'", coinType, account),
	}, nil
}
