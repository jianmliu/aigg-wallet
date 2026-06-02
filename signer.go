package aiggwallet

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// ErrSignerNotConfigured is returned when a signer has no key material.
var ErrSignerNotConfigured = errors.New("agentwallet: signer not configured")

// Signer is the signing port the higher-level Spender/Authorizer depend on.
// The default implementation is BIP44Signer; consumers with a different
// derivation scheme (e.g. onchainpal's m/44'/60'/0'/0/<index>) implement this
// over their own key and plug it in.
type Signer interface {
	// Address returns the EIP-55 EOA address this signer signs as.
	Address(ctx context.Context) (string, error)
	// SignPermit2 signs a Uniswap Permit2 PermitSingle.
	SignPermit2(ctx context.Context, p Permit2TransferParams) (SignedPayload, error)
	// SignEIP2612 signs an ERC-2612 permit (tokenName/version = token domain).
	SignEIP2612(ctx context.Context, p EIP2612PermitParams, tokenName, tokenVersion string) (SignedPayload, error)
	// SignEIP3009 signs a transferWithAuthorization.
	SignEIP3009(ctx context.Context, p EIP3009TransferParams, tokenName, tokenVersion string) (SignedPayload, error)
	// SignTx signs a raw EVM transaction for chainID (used to broadcast the
	// agent's own Permit2.permit/transferFrom calls).
	SignTx(ctx context.Context, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)
}

// BIP44Signer derives the agent EOA from a master seed on each call via
// Derive(seed, coinType, account) and zeroizes the key immediately after.
// The seed never leaves this struct; the private key never escapes a method.
type BIP44Signer struct {
	masterSeed []byte
	coinType   uint32
	account    uint32
}

// NewBIP44Signer builds a signer for m/44'/<coinType>'/<account>'. coinType 0
// defaults to DefaultCoinType (Base, 8453).
func NewBIP44Signer(masterSeed []byte, coinType, account uint32) (*BIP44Signer, error) {
	if len(masterSeed) == 0 {
		return nil, ErrSignerNotConfigured
	}
	if coinType == 0 {
		coinType = DefaultCoinType
	}
	// Validate derivation up front so construction fails fast.
	k, err := Derive(masterSeed, coinType, account)
	if err != nil {
		return nil, err
	}
	k.Zeroize()
	seed := make([]byte, len(masterSeed))
	copy(seed, masterSeed)
	return &BIP44Signer{masterSeed: seed, coinType: coinType, account: account}, nil
}

func (s *BIP44Signer) derive() (*AgentKey, error) {
	if s == nil || len(s.masterSeed) == 0 {
		return nil, ErrSignerNotConfigured
	}
	return Derive(s.masterSeed, s.coinType, s.account)
}

// Address returns the agent EOA address.
func (s *BIP44Signer) Address(_ context.Context) (string, error) {
	k, err := s.derive()
	if err != nil {
		return "", err
	}
	defer k.Zeroize()
	return k.Address, nil
}

// SignPermit2 implements Signer.
func (s *BIP44Signer) SignPermit2(_ context.Context, p Permit2TransferParams) (SignedPayload, error) {
	k, err := s.derive()
	if err != nil {
		return SignedPayload{}, err
	}
	defer k.Zeroize()
	td, err := BuildPermit2TypedData(p)
	if err != nil {
		return SignedPayload{}, err
	}
	return SignTypedData(k.PrivateKey, td)
}

// SignEIP2612 implements Signer.
func (s *BIP44Signer) SignEIP2612(_ context.Context, p EIP2612PermitParams, name, version string) (SignedPayload, error) {
	k, err := s.derive()
	if err != nil {
		return SignedPayload{}, err
	}
	defer k.Zeroize()
	td, err := BuildEIP2612TypedData(p, name, version)
	if err != nil {
		return SignedPayload{}, err
	}
	return SignTypedData(k.PrivateKey, td)
}

// SignEIP3009 implements Signer.
func (s *BIP44Signer) SignEIP3009(_ context.Context, p EIP3009TransferParams, name, version string) (SignedPayload, error) {
	k, err := s.derive()
	if err != nil {
		return SignedPayload{}, err
	}
	defer k.Zeroize()
	td, err := BuildEIP3009TypedData(p, name, version)
	if err != nil {
		return SignedPayload{}, err
	}
	return SignTypedData(k.PrivateKey, td)
}

// SignTx implements Signer.
func (s *BIP44Signer) SignTx(_ context.Context, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	if tx == nil {
		return nil, fmt.Errorf("agentwallet: tx is nil")
	}
	if chainID == nil || chainID.Sign() <= 0 {
		return nil, fmt.Errorf("agentwallet: chainID must be > 0")
	}
	k, err := s.derive()
	if err != nil {
		return nil, err
	}
	defer k.Zeroize()
	priv, err := ethcrypto.ToECDSA(k.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("agentwallet: to-ecdsa: %w", err)
	}
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), priv)
	if err != nil {
		return nil, fmt.Errorf("agentwallet: sign tx: %w", err)
	}
	return signed, nil
}

var _ Signer = (*BIP44Signer)(nil)
