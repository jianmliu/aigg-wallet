package aiggwallet

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// Coinbase Smart Wallet ERC-1271 signature packaging (webauthn-sol format).
//
// CSW.isValidSignature(hash, signature) expects a
// SignatureWrapper{uint256 ownerIndex, bytes signatureData}. For a passkey
// owner, signatureData = abi.encode(WebAuthnAuth{...}). CSW verifies the P-256
// signature against replaySafeHash(hash) using the owner's (x,y), and REJECTS
// high-s — so the assertion's challenge MUST be replaySafeHash(hash) and s MUST
// be low-s (BuildCSWPasskeySignature normalises s).
//
// This is exactly the signature blob Permit2.permit forwards to
// isValidSignature when the PermitSingle owner is a CSW — verified on-chain by
// the Base Sepolia spike (docs/superpowers/spikes/permit2-csw-1271).

var (
	webAuthnAuthTuple = mustABIType("tuple",
		abi.ArgumentMarshaling{Name: "authenticatorData", Type: "bytes"},
		abi.ArgumentMarshaling{Name: "clientDataJSON", Type: "string"},
		abi.ArgumentMarshaling{Name: "challengeIndex", Type: "uint256"},
		abi.ArgumentMarshaling{Name: "typeIndex", Type: "uint256"},
		abi.ArgumentMarshaling{Name: "r", Type: "uint256"},
		abi.ArgumentMarshaling{Name: "s", Type: "uint256"},
	)
	signatureWrapperTuple = mustABIType("tuple",
		abi.ArgumentMarshaling{Name: "ownerIndex", Type: "uint256"},
		abi.ArgumentMarshaling{Name: "signatureData", Type: "bytes"},
	)
	webAuthnAuthArgs     = abi.Arguments{{Type: webAuthnAuthTuple}}
	signatureWrapperArgs = abi.Arguments{{Type: signatureWrapperTuple}}
)

type webAuthnAuthABI struct {
	AuthenticatorData []byte   `abi:"authenticatorData"`
	ClientDataJSON    string   `abi:"clientDataJSON"`
	ChallengeIndex    *big.Int `abi:"challengeIndex"`
	TypeIndex         *big.Int `abi:"typeIndex"`
	R                 *big.Int `abi:"r"`
	S                 *big.Int `abi:"s"`
}

type signatureWrapperABI struct {
	OwnerIndex    *big.Int `abi:"ownerIndex"`
	SignatureData []byte   `abi:"signatureData"`
}

// EncodeWebAuthnAuth abi.encodes a WebAuthnAuth tuple (the inner signatureData
// for a passkey owner).
func EncodeWebAuthnAuth(authenticatorData, clientDataJSON []byte, challengeIndex, typeIndex int, r, s *big.Int) ([]byte, error) {
	return webAuthnAuthArgs.Pack(webAuthnAuthABI{
		AuthenticatorData: authenticatorData,
		ClientDataJSON:    string(clientDataJSON),
		ChallengeIndex:    big.NewInt(int64(challengeIndex)),
		TypeIndex:         big.NewInt(int64(typeIndex)),
		R:                 r,
		S:                 s,
	})
}

// EncodeSignatureWrapper abi.encodes a CSW SignatureWrapper{ownerIndex, signatureData}.
func EncodeSignatureWrapper(ownerIndex uint64, signatureData []byte) ([]byte, error) {
	return signatureWrapperArgs.Pack(signatureWrapperABI{
		OwnerIndex:    new(big.Int).SetUint64(ownerIndex),
		SignatureData: signatureData,
	})
}

// BuildCSWPasskeySignature turns a raw WebAuthn assertion into the ERC-1271
// signature bytes a Coinbase Smart Wallet (and thus Permit2) accepts for the
// passkey owner at ownerIndex: parse DER → normalise s to low-s → compute the
// clientDataJSON indices → encode WebAuthnAuth → wrap in SignatureWrapper.
//
// The caller must ensure the assertion's challenge == replaySafeHash(hash) for
// the digest being authorised (e.g. the Permit2 PermitSingle digest). The
// owner's (x,y) and the on-chain replaySafeHash do the actual verification;
// this only packages the bytes.
func BuildCSWPasskeySignature(assertion WebAuthnAssertion, ownerIndex uint64) ([]byte, error) {
	r, s, err := DecodeECDSASignatureDER(assertion.Signature)
	if err != nil {
		return nil, err
	}
	s = NormalizeLowS(s)
	challengeIndex, typeIndex, err := clientDataIndices(assertion.ClientDataJSON)
	if err != nil {
		return nil, err
	}
	inner, err := EncodeWebAuthnAuth(assertion.AuthenticatorData, assertion.ClientDataJSON, challengeIndex, typeIndex, r, s)
	if err != nil {
		return nil, fmt.Errorf("aiggwallet erc1271: encode WebAuthnAuth: %w", err)
	}
	wrapped, err := EncodeSignatureWrapper(ownerIndex, inner)
	if err != nil {
		return nil, fmt.Errorf("aiggwallet erc1271: encode SignatureWrapper: %w", err)
	}
	return wrapped, nil
}
