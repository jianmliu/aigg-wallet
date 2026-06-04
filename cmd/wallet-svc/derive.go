package main

// Structured / explicit-path derivation endpoints.
//
// The legacy POST /address hashes an opaque subject into ONE 31-bit account
// index (keccak(subject)&0x7fffffff) — which collides at ~55k subjects
// (birthday bound). These endpoints derive by EXPLICIT indices instead:
//
//	POST /address/agent { owner, agent }  → m/44'/<coin>'/<owner>'/<agent>'
//	POST /address/path  { path:[i0,i1,…] } → m/<i0>'/<i1>'/…
//
// Benefits: collision-free per (owner, agent); encodes the owner→agents tree;
// enumerable/recoverable from the seed; address decoupled from any subject
// string; standard BIP-44 (derivable/verifiable offline). The owner/agent
// index allocation is the caller's registry concern.

import (
	"encoding/json"
	"net/http"

	aiggwallet "github.com/jianmliu/aigg-wallet"
)

type agentAddrReq struct {
	Owner uint32 `json:"owner"`
	Agent uint32 `json:"agent"`
}

// agentAddressHandler derives the structured agent EOA
// m/44'/<coin>'/<owner>'/<agent>' (the collision-free "one owner, many agents"
// scheme).
func agentAddressHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "method"})
		return
	}
	if !authed(r) {
		writeJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	var req agentAddrReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad_request"})
		return
	}
	key, err := aiggwallet.DeriveAgent(seed, coin, req.Owner, req.Agent)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	defer key.Zeroize()
	writeJSON(w, 200, map[string]string{"address": key.Address, "derivationPath": key.DerivationPath})
}

type pathAddrReq struct {
	Path []uint32 `json:"path"`
}

// pathAddressHandler derives an arbitrary all-hardened path m/<i0>'/<i1>'/...
func pathAddressHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "method"})
		return
	}
	if !authed(r) {
		writeJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	var req pathAddrReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Path) == 0 {
		writeJSON(w, 400, map[string]string{"error": "path_required"})
		return
	}
	key, err := aiggwallet.DerivePath(seed, req.Path...)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	defer key.Zeroize()
	writeJSON(w, 200, map[string]string{"address": key.Address, "derivationPath": key.DerivationPath})
}
