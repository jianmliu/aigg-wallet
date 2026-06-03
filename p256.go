package aiggwallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
)

// secp256r1 (P-256) helpers for passkey / WebAuthn signatures — the basis of
// the non-custodial "Model B" smart-account path. Passkeys sign with P-256
// (not Ethereum's secp256k1), so a passkey controls a smart-contract account
// that verifies P-256 on-chain (RIP-7212 precompile on Base, or a fallback
// verifier). This SDK provides the OFF-CHAIN counterparts used to assemble and
// sanity-check the on-chain ERC-1271 blob; see webauthn.go + erc1271.go.

// P256VerifyPrecompileAddress is the RIP-7212 secp256r1 verification precompile
// (available on Base). On-chain verifiers call it; the SDK mirrors its result
// off-chain via VerifyP256.
const P256VerifyPrecompileAddress = "0x0000000000000000000000000000000000000100"

var (
	p256N     = elliptic.P256().Params().N
	p256NDiv2 = new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
)

// NormalizeLowS returns the low-s form of s (s itself, or N-s when s > N/2).
// Coinbase webauthn-sol (and most P-256 verifiers) REJECT high-s signatures
// for malleability, so always normalize before building the on-chain blob.
func NormalizeLowS(s *big.Int) *big.Int {
	if s == nil {
		return nil
	}
	if s.Cmp(p256NDiv2) > 0 {
		return new(big.Int).Sub(p256N, s)
	}
	return new(big.Int).Set(s)
}

// IsLowS reports whether s is in the low half (s <= N/2).
func IsLowS(s *big.Int) bool { return s != nil && s.Cmp(p256NDiv2) <= 0 }

// VerifyP256 checks a secp256r1 signature (r,s) over digest (an already-hashed
// 32-byte message) for the public key (x,y). Mirrors the on-chain P256VERIFY so
// callers can sanity-check a passkey assertion before submitting it.
func VerifyP256(x, y *big.Int, digest []byte, r, s *big.Int) bool {
	if x == nil || y == nil || r == nil || s == nil {
		return false
	}
	if !elliptic.P256().IsOnCurve(x, y) {
		return false
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	return ecdsa.Verify(pub, digest, r, s)
}

// ParseP256PublicKeyXY parses an uncompressed P-256 public key into (x,y).
// Accepts 64 bytes (x ‖ y) or 65 bytes (0x04 ‖ x ‖ y, SEC1).
func ParseP256PublicKeyXY(pub []byte) (x, y *big.Int, err error) {
	switch len(pub) {
	case 65:
		if pub[0] != 0x04 {
			return nil, nil, fmt.Errorf("aiggwallet p256: 65-byte key must start with 0x04")
		}
		pub = pub[1:]
	case 64:
	default:
		return nil, nil, fmt.Errorf("aiggwallet p256: public key must be 64 or 65 bytes (got %d)", len(pub))
	}
	x = new(big.Int).SetBytes(pub[:32])
	y = new(big.Int).SetBytes(pub[32:])
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, nil, fmt.Errorf("aiggwallet p256: point not on curve")
	}
	return x, y, nil
}
