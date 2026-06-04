// wallet-svc — a thin HTTP wrapper around the aigg-wallet library so non-Go
// products (e.g. onchainpal's TS kit) can derive per-subject agent EOAs and get
// SCOPED EIP-3009 GCC payment signatures WITHOUT re-implementing key derivation/
// signing and without ever holding key material themselves. The master seed lives
// here (env today; dstack TEE sealed store in prod) and never leaves the process.
//
//	browser/TS ──(no keys)──▶ TS RemoteAgentWallet ──HTTP+Bearer──▶ wallet-svc ──▶ signs with TEE-held seed
//
// Endpoints:
//	GET  /healthz
//	POST /address       { subject }                                  → { address, derivationPath }       (Bearer)
//	POST /sign/eip3009  { subject, value, validAfter?, validBefore?, nonce? }
//	                                                                  → { address, signature, payload, requirements } (Bearer)
//	POST /sign          { subject, typedData }                       → { address, signature, digest }   (Bearer; DEV-gated)
//
// /sign/eip3009 is the PRODUCTION path: the service builds the EIP-3009
// TransferWithAuthorization typed data itself from FIXED config (GCC token/name/
// version/chainId/payTo) and enforces scope (recipient locked to payTo, value ≤
// maxValue) before signing — a caller cannot redirect funds or sign an off-policy
// message. /sign (generic EIP-712) stays gated behind WALLET_ALLOW_GENERIC_SIGN
// for dev only.
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	aiggwallet "github.com/jianmliu/aigg-wallet"
)

var (
	seed             []byte
	coin             = aiggwallet.DefaultCoinType
	authToken        string
	allowGenericSign bool

	// Scope config for /sign/eip3009 (fixed; the caller cannot override these).
	gccToken    string
	gccName     string
	gccVersion  string
	gccDecimals int
	payTo       string
	chainID     int64
	maxValue    *big.Int // nil = no cap
	timeoutSecs int64

	// Model B (Coinbase Smart Wallet): optional RPC to resolve a CSW
	// counterfactual address. nil → /csw/account omits "address" (still
	// returns owner bytes + factory calldata).
	cswRPC aiggwallet.BaseRPC
)

func networkStr() string { return "eip155:" + strconv.FormatInt(chainID, 10) }

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

func randomNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(b), nil
}

type addressReq struct {
	Subject string `json:"subject"`
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

type eip3009Req struct {
	Subject     string `json:"subject"`
	Value       string `json:"value"` // GCC atoms (uint256, decimal string)
	ValidAfter  int64  `json:"validAfter"`
	ValidBefore int64  `json:"validBefore"`
	Nonce       string `json:"nonce"` // optional; service generates if empty
}

// signEip3009Handler is the SCOPED production signer: token/name/version/chainId/
// payTo all come from server config; the caller only supplies value + validity +
// (optional) nonce. Recipient is forced to payTo; value is capped at maxValue.
func signEip3009Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "method"})
		return
	}
	if !authed(r) {
		writeJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	if gccToken == "" || payTo == "" || chainID == 0 {
		writeJSON(w, 501, map[string]string{"error": "eip3009_not_configured", "hint": "set WALLET_GCC_TOKEN, WALLET_PAY_TO, WALLET_CHAIN_ID"})
		return
	}
	var req eip3009Req
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Subject == "" || req.Value == "" {
		writeJSON(w, 400, map[string]string{"error": "subject_and_value_required"})
		return
	}
	value, ok := new(big.Int).SetString(req.Value, 10)
	if !ok || value.Sign() < 0 {
		writeJSON(w, 400, map[string]string{"error": "bad_value"})
		return
	}
	if maxValue != nil && value.Cmp(maxValue) > 0 {
		writeJSON(w, 403, map[string]string{"error": "value_exceeds_max", "max": maxValue.String()})
		return
	}
	now := time.Now().Unix()
	validAfter := req.ValidAfter
	if validAfter == 0 {
		validAfter = now - 10
	}
	validBefore := req.ValidBefore
	if validBefore == 0 {
		validBefore = now + timeoutSecs
	}
	nonce := strings.TrimSpace(req.Nonce)
	if nonce == "" {
		var err error
		if nonce, err = randomNonce(); err != nil {
			writeJSON(w, 500, map[string]string{"error": "nonce_gen"})
			return
		}
	}

	signer, err := aiggwallet.NewBIP44Signer(seed, coin, accountFor(req.Subject))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	from, err := signer.Address(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	params := aiggwallet.EIP3009TransferParams{
		Token:       gccToken,
		From:        from,
		To:          payTo, // FORCED — caller cannot redirect
		Value:       value.String(),
		ValidAfter:  validAfter,
		ValidBefore: validBefore,
		Nonce:       nonce,
		ChainID:     chainID,
	}
	sp, err := signer.SignEIP3009(r.Context(), params, gccName, gccVersion)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "sign_failed", "detail": err.Error()})
		return
	}

	// Assemble the x402 v2 wire the AIGG facilitator expects (single source of truth).
	authorization := map[string]any{
		"from": from, "to": payTo, "value": value.String(),
		"validAfter": strconv.FormatInt(validAfter, 10), "validBefore": strconv.FormatInt(validBefore, 10),
		"nonce": nonce,
	}
	payload := map[string]any{
		"x402Version": 2,
		"accepted":    map[string]any{"scheme": "exact", "network": networkStr(), "amount": value.String(), "asset": gccToken, "payTo": payTo},
		"payload":     map[string]any{"signature": sp.Signature, "authorization": authorization},
	}
	requirements := map[string]any{
		"scheme": "exact", "network": networkStr(), "asset": gccToken, "amount": value.String(),
		"maxTimeoutSeconds": timeoutSecs, "payTo": payTo,
		"extra": map[string]any{"name": gccName, "version": gccVersion, "verifyingContract": gccToken},
	}
	writeJSON(w, 200, map[string]any{"address": from, "signature": sp.Signature, "digest": sp.Digest, "payload": payload, "requirements": requirements})
}

type signReq struct {
	Subject   string             `json:"subject"`
	TypedData apitypes.TypedData `json:"typedData"`
}

// signHandler — DEV-only generic EIP-712 signer (gated). Prefer /sign/eip3009.
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
		writeJSON(w, 403, map[string]string{"error": "generic_sign_disabled", "hint": "use /sign/eip3009 (scoped) or set WALLET_ALLOW_GENERIC_SIGN=1 (dev)"})
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

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func main() {
	raw := strings.TrimPrefix(envOr("WALLET_MASTER_SEED", ""), "0x")
	if raw == "" {
		log.Fatal("[wallet-svc] WALLET_MASTER_SEED required (hex; dstack TEE sealed in prod)")
	}
	var err error
	seed, err = hex.DecodeString(raw)
	if err != nil || len(seed) < 16 {
		log.Fatal("[wallet-svc] WALLET_MASTER_SEED must be hex, >=16 bytes")
	}
	authToken = envOr("WALLET_AUTH_TOKEN", "")
	allowGenericSign = os.Getenv("WALLET_ALLOW_GENERIC_SIGN") == "1"

	// Scope config for /sign/eip3009
	gccToken = envOr("WALLET_GCC_TOKEN", "")
	gccName = envOr("WALLET_GCC_NAME", "Guaranteed Capacity Credit")
	gccVersion = envOr("WALLET_GCC_VERSION", "1")
	gccDecimals, _ = strconv.Atoi(envOr("WALLET_GCC_DECIMALS", "18"))
	payTo = envOr("WALLET_PAY_TO", "")
	chainID, _ = strconv.ParseInt(envOr("WALLET_CHAIN_ID", "84532"), 10, 64)
	timeoutSecs, _ = strconv.ParseInt(envOr("WALLET_TIMEOUT_SECONDS", "300"), 10, 64)
	if mv := envOr("WALLET_MAX_VALUE", ""); mv != "" {
		if v, ok := new(big.Int).SetString(mv, 10); ok {
			maxValue = v
		}
	}
	_ = gccDecimals // reserved (display conversions live caller-side)

	// Model B: optional RPC for CSW counterfactual-address resolution.
	if u := envOr("WALLET_CSW_RPC_URL", ""); u != "" {
		if rpc, err := aiggwallet.NewBaseRPC(context.Background(), u); err != nil {
			log.Printf("[wallet-svc] WALLET_CSW_RPC_URL set but dial failed (CSW address resolution disabled): %v", err)
		} else {
			cswRPC = rpc
		}
	}

	listen := envOr("WALLET_LISTEN", ":8091")

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "genericSign": allowGenericSign, "eip3009": gccToken != "" && payTo != "", "network": networkStr(), "csw": true, "cswAddressResolution": cswRPC != nil})
	})
	mux.HandleFunc("/address", addressHandler)
	mux.HandleFunc("/sign/eip3009", signEip3009Handler)
	mux.HandleFunc("/sign", signHandler)
	// Model B (Coinbase Smart Wallet / passkey) — no key material, packaging only.
	mux.HandleFunc("/csw/erc1271", cswErc1271Handler)
	mux.HandleFunc("/csw/account", cswAccountHandler)

	log.Printf("[wallet-svc] listening %s (coin=%d, network=%s, eip3009=%v, genericSign=%v)",
		listen, coin, networkStr(), gccToken != "" && payTo != "", allowGenericSign)
	log.Fatal(http.ListenAndServe(listen, mux))
}
