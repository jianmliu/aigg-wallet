package aiggwallet

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// WebAuthn assertion decoding for the passkey / smart-account path.
//
// A passkey signature (navigator.credentials.get) yields three raw fields:
// authenticatorData, clientDataJSON, and a DER-encoded ECDSA-P256 signature.
// From these we (a) recover the signed digest + (r,s) to verify off-chain, and
// (b) compute the byte offsets a webauthn-sol on-chain verifier needs.

// WebAuthnAssertion is the raw output of a WebAuthn passkey assertion.
type WebAuthnAssertion struct {
	AuthenticatorData []byte // authenticatorData bytes
	ClientDataJSON    []byte // clientDataJSON (UTF-8 JSON)
	Signature         []byte // DER-encoded ECDSA (secp256r1) signature
}

// DecodeECDSASignatureDER parses a DER ECDSA signature into (r, s).
func DecodeECDSASignatureDER(der []byte) (r, s *big.Int, err error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, nil, fmt.Errorf("aiggwallet webauthn: DER signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, nil, fmt.Errorf("aiggwallet webauthn: trailing bytes after DER signature")
	}
	if sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, nil, fmt.Errorf("aiggwallet webauthn: invalid r/s")
	}
	return sig.R, sig.S, nil
}

// SignedDigest returns the 32-byte message the authenticator signed:
// sha256(authenticatorData ‖ sha256(clientDataJSON)). Verify the passkey
// signature against this with VerifyP256.
func (a WebAuthnAssertion) SignedDigest() []byte {
	cdh := sha256.Sum256(a.ClientDataJSON)
	msg := make([]byte, 0, len(a.AuthenticatorData)+len(cdh))
	msg = append(msg, a.AuthenticatorData...)
	msg = append(msg, cdh[:]...)
	d := sha256.Sum256(msg)
	return d[:]
}

// Challenge decodes the base64url (no padding) "challenge" of clientDataJSON
// and verifies type == "webauthn.get". In Model B this challenge equals the
// smart account's replaySafeHash(authorizationDigest).
func (a WebAuthnAssertion) Challenge() ([]byte, error) {
	var cd struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(a.ClientDataJSON, &cd); err != nil {
		return nil, fmt.Errorf("aiggwallet webauthn: clientDataJSON: %w", err)
	}
	if cd.Type != "webauthn.get" {
		return nil, fmt.Errorf("aiggwallet webauthn: type %q != webauthn.get", cd.Type)
	}
	b, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil {
		return nil, fmt.Errorf("aiggwallet webauthn: challenge base64url: %w", err)
	}
	return b, nil
}

// clientDataIndices returns the byte offsets a webauthn-sol verifier uses to
// locate the type + challenge fields without parsing JSON on-chain:
//   - challengeIndex: offset of `"challenge":"`
//   - typeIndex:      offset of `"type":"webauthn.get"`
func clientDataIndices(clientDataJSON []byte) (challengeIndex, typeIndex int, err error) {
	ci := bytes.Index(clientDataJSON, []byte(`"challenge":"`))
	if ci < 0 {
		return 0, 0, fmt.Errorf("aiggwallet webauthn: challenge field not found in clientDataJSON")
	}
	ti := bytes.Index(clientDataJSON, []byte(`"type":"webauthn.get"`))
	if ti < 0 {
		return 0, 0, fmt.Errorf("aiggwallet webauthn: type field not found in clientDataJSON")
	}
	return ci, ti, nil
}
