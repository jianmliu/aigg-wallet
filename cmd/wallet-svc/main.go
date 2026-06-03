// wallet-svc — a thin HTTP wrapper around the aigg-wallet library so non-Go
// products (e.g. onchainpal's TS kit) can derive per-subject agent EOAs and get
// EIP-712 signatures WITHOUT re-implementing key derivation/signing and without
// ever holding key material themselves. The master seed lives here (env today;
// dstack TEE sealed store in prod) and never leaves the process.
//
//	browser/TS  ──(no keys)──▶  TS RemoteAgentWallet  ──HTTP+Bearer──▶  wallet-svc  ──▶  signs with TEE-held seed
//
// Endpoints:
//	GET  /healthz                         → { ok }
//	POST /address  { subject }            → { address, derivationPath }   (Bearer)
//	POST /sign     { subject, typedData } → { address, signature, digest } (Bearer; gated)
//
// SECURITY: /sign is a generic EIP-712 signer, enabled only when
// WALLET_ALLOW_GENERIC_SIGN=1 (dev). In production it MUST be replaced by scoped
// endpoints that build the typed data here from fixed config (GCC token, payTo,
// maxAmount) via the library's SignEIP3009/SignPermit2 — so a caller can never
// redirect funds or sign an arbitrary message. See README.
package main

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	aiggwallet "github.com/jianmliu/aigg-wallet"
)

var (
	seed             []byte
	coin             = aiggwallet.DefaultCoinType
	authToken        string
	allowGenericSign bool
)

// accountFor maps a subject (npcId / user id) to a deterministic BIP-44 account
// index (uint31). The address is whatever this derivation yields — callers index
// by it, they don't recompute it.
func accountFor(subject string) uint32 {
	h := crypto.Keccak256([]byte(subject))
	v := uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
	return v & 0x7fffffff
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func authed(r *http.Request) bool {
	if authToken == "" { // fail-closed
		return false
	}
	const p = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(h[len(p):])), []byte(authToken)) == 1
}

type addressReq struct {
	Subject string `json:"subject"`
}
type signReq struct {
	Subject   string              `json:"subject"`
	TypedData apitypes.TypedData  `json:"typedData"`
}

func addressHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "method"})
		return
	}
	if !authed(r) {
		writeJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	var req addressReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Subject == "" {
		writeJSON(w, 400, map[string]string{"error": "subject_required"})
		return
	}
	key, err := aiggwallet.Derive(seed, coin, accountFor(req.Subject))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer key.Zeroize()
	writeJSON(w, 200, map[string]string{"address": key.Address, "derivationPath": key.DerivationPath})
}

func signHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "method"})
		return
	}
	if !authed(r) {
		writeJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	if !allowGenericSign {
		writeJSON(w, 403, map[string]string{"error": "generic_sign_disabled", "hint": "set WALLET_ALLOW_GENERIC_SIGN=1 (dev) or use a scoped endpoint"})
		return
	}
	var req signReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Subject == "" {
		writeJSON(w, 400, map[string]string{"error": "bad_request"})
		return
	}
	key, err := aiggwallet.Derive(seed, coin, accountFor(req.Subject))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer key.Zeroize()
	sp, err := aiggwallet.SignTypedData(key.PrivateKey, &req.TypedData)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "sign_failed", "detail": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"address": key.Address, "signature": sp.Signature, "digest": sp.Digest})
}

func main() {
	raw := strings.TrimPrefix(strings.TrimSpace(os.Getenv("WALLET_MASTER_SEED")), "0x")
	if raw == "" {
		log.Fatal("[wallet-svc] WALLET_MASTER_SEED required (hex; dstack TEE sealed in prod)")
	}
	var err error
	seed, err = hex.DecodeString(raw)
	if err != nil || len(seed) < 16 {
		log.Fatal("[wallet-svc] WALLET_MASTER_SEED must be hex, >=16 bytes")
	}
	authToken = strings.TrimSpace(os.Getenv("WALLET_AUTH_TOKEN"))
	allowGenericSign = os.Getenv("WALLET_ALLOW_GENERIC_SIGN") == "1"
	listen := os.Getenv("WALLET_LISTEN")
	if listen == "" {
		listen = ":8091"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "genericSign": allowGenericSign})
	})
	mux.HandleFunc("/address", addressHandler)
	mux.HandleFunc("/sign", signHandler)

	log.Printf("[wallet-svc] listening %s (coin=%d, genericSign=%v)", listen, coin, allowGenericSign)
	log.Fatal(http.ListenAndServe(listen, mux))
}
