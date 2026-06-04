package aiggwallet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"reflect"
	"testing"
)

// buildSyntheticAssertion mints a real P-256 keypair and a valid WebAuthn
// assertion over `challenge`, mirroring what a browser passkey returns. Returns
// the assertion plus the owner pubkey coords.
func buildSyntheticAssertion(t *testing.T, challenge []byte) (WebAuthnAssertion, *big.Int, *big.Int) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}

	// authenticatorData: 32-byte rpIdHash + 1 flag byte (UP|UV) + 4-byte counter.
	authData := make([]byte, 37)
	for i := range authData[:32] {
		authData[i] = byte(i)
	}
	authData[32] = 0x05
	authData[36] = 0x01

	clientDataJSON := []byte(fmt.Sprintf(
		`{"type":"webauthn.get","challenge":"%s","origin":"https://wallet.ai.gg","crossOrigin":false}`,
		base64.RawURLEncoding.EncodeToString(challenge),
	))

	a := WebAuthnAssertion{AuthenticatorData: authData, ClientDataJSON: clientDataJSON}
	der, err := ecdsa.SignASN1(rand.Reader, priv, a.SignedDigest())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	a.Signature = der
	return a, priv.X, priv.Y
}

func TestWebAuthn_SignedDigestVerifies(t *testing.T) {
	challenge := bytes.Repeat([]byte{0xAB}, 32)
	a, x, y := buildSyntheticAssertion(t, challenge)

	r, s, err := DecodeECDSASignatureDER(a.Signature)
	if err != nil {
		t.Fatalf("decode DER: %v", err)
	}
	if !VerifyP256(x, y, a.SignedDigest(), r, s) {
		t.Fatal("VerifyP256 should accept the genuine assertion")
	}
	// Tampered digest must fail.
	bad := a.SignedDigest()
	bad[0] ^= 0xFF
	if VerifyP256(x, y, bad, r, s) {
		t.Fatal("VerifyP256 must reject a tampered digest")
	}
}

func TestWebAuthn_ChallengeRoundTrip(t *testing.T) {
	challenge := bytes.Repeat([]byte{0x42}, 32)
	a, _, _ := buildSyntheticAssertion(t, challenge)
	got, err := a.Challenge()
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if !bytes.Equal(got, challenge) {
		t.Fatalf("challenge mismatch: got %x want %x", got, challenge)
	}
}

func TestP256_NormalizeLowS(t *testing.T) {
	// A high-s value normalises to N-s and becomes low-s; a low-s stays put.
	high := new(big.Int).Sub(p256N, big.NewInt(1)) // N-1 is high-s
	if IsLowS(high) {
		t.Fatal("N-1 should be high-s")
	}
	norm := NormalizeLowS(high)
	if !IsLowS(norm) {
		t.Fatal("normalised s must be low-s")
	}
	if norm.Cmp(big.NewInt(1)) != 0 { // N-(N-1) = 1
		t.Fatalf("normalised value = %s, want 1", norm)
	}
	if NormalizeLowS(big.NewInt(5)).Cmp(big.NewInt(5)) != 0 {
		t.Fatal("already-low s must be unchanged")
	}
}

func TestParseP256PublicKeyXY(t *testing.T) {
	_, x, y := buildSyntheticAssertion(t, bytes.Repeat([]byte{1}, 32))
	raw := make([]byte, 64)
	x.FillBytes(raw[:32])
	y.FillBytes(raw[32:])
	px, py, err := ParseP256PublicKeyXY(raw)
	if err != nil {
		t.Fatalf("parse 64: %v", err)
	}
	if px.Cmp(x) != 0 || py.Cmp(y) != 0 {
		t.Fatal("64-byte parse mismatch")
	}
	// 65-byte SEC1 form.
	sec1 := append([]byte{0x04}, raw...)
	if _, _, err := ParseP256PublicKeyXY(sec1); err != nil {
		t.Fatalf("parse 65: %v", err)
	}
	if _, _, err := ParseP256PublicKeyXY(raw[:10]); err == nil {
		t.Fatal("short key must error")
	}
}

func TestBuildCSWPasskeySignature_RoundTrips(t *testing.T) {
	challenge := bytes.Repeat([]byte{0x7C}, 32) // stands in for replaySafeHash
	a, _, _ := buildSyntheticAssertion(t, challenge)
	origR, origS, err := DecodeECDSASignatureDER(a.Signature)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	blob, err := BuildCSWPasskeySignature(a, 0)
	if err != nil {
		t.Fatalf("BuildCSWPasskeySignature: %v", err)
	}

	// Decode the outer SignatureWrapper.
	wvals, err := signatureWrapperArgs.Unpack(blob)
	if err != nil {
		t.Fatalf("unpack wrapper: %v", err)
	}
	wrv := reflect.ValueOf(wvals[0])
	ownerIndex := wrv.FieldByName("OwnerIndex").Interface().(*big.Int)
	sigData := wrv.FieldByName("SignatureData").Interface().([]byte)
	if ownerIndex.Sign() != 0 {
		t.Fatalf("ownerIndex = %s, want 0", ownerIndex)
	}

	// Decode the inner WebAuthnAuth.
	avals, err := webAuthnAuthArgs.Unpack(sigData)
	if err != nil {
		t.Fatalf("unpack WebAuthnAuth: %v", err)
	}
	arv := reflect.ValueOf(avals[0])
	gotAuthData := arv.FieldByName("AuthenticatorData").Interface().([]byte)
	gotClientData := arv.FieldByName("ClientDataJSON").Interface().(string)
	gotChallengeIdx := arv.FieldByName("ChallengeIndex").Interface().(*big.Int)
	gotTypeIdx := arv.FieldByName("TypeIndex").Interface().(*big.Int)
	gotR := arv.FieldByName("R").Interface().(*big.Int)
	gotS := arv.FieldByName("S").Interface().(*big.Int)

	if !bytes.Equal(gotAuthData, a.AuthenticatorData) {
		t.Fatal("authenticatorData round-trip mismatch")
	}
	if gotClientData != string(a.ClientDataJSON) {
		t.Fatal("clientDataJSON round-trip mismatch")
	}
	if gotR.Cmp(origR) != 0 {
		t.Fatal("r round-trip mismatch")
	}
	// s must be the low-s normalisation of the original.
	if gotS.Cmp(NormalizeLowS(origS)) != 0 {
		t.Fatal("s must be low-s normalised")
	}
	if !IsLowS(gotS) {
		t.Fatal("encoded s must be low-s")
	}

	// The indices must locate the exact substrings a webauthn-sol verifier
	// slices out of clientDataJSON.
	ci := int(gotChallengeIdx.Int64())
	ti := int(gotTypeIdx.Int64())
	expectedChallenge := []byte(`"challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) + `"`)
	if !bytes.Equal(a.ClientDataJSON[ci:ci+len(expectedChallenge)], expectedChallenge) {
		t.Fatalf("challengeIndex slice mismatch: got %q", a.ClientDataJSON[ci:ci+len(expectedChallenge)])
	}
	expectedType := []byte(`"type":"webauthn.get"`)
	if !bytes.Equal(a.ClientDataJSON[ti:ti+len(expectedType)], expectedType) {
		t.Fatalf("typeIndex slice mismatch: got %q", a.ClientDataJSON[ti:ti+len(expectedType)])
	}
}

func TestDecodeECDSASignatureDER_Rejects(t *testing.T) {
	if _, _, err := DecodeECDSASignatureDER([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Fatal("garbage DER must error")
	}
}
