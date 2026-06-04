package main

// Model B (Coinbase Smart Wallet / passkey) endpoints.
//
// Unlike the EIP-3009 path, these hold NO key material: a passkey signs on the
// USER's device (WebAuthn), so wallet-svc only (a) packages a WebAuthn
// assertion into the CSW ERC-1271 blob (the exact ABI was cross-validated
// on-chain against the deployed CSW) and (b) derives the CSW account address /
// factory calldata. This lets non-Go callers (onchainpal's TS kit) use Model B
// without re-implementing the WebAuthnAuth/SignatureWrapper encoding.
//
// Endpoints (Bearer):
//	POST /csw/erc1271  { authenticatorData, clientDataJSON, signature, ownerIndex? }
//	                                       → { erc1271, challenge }
//	POST /csw/account  { owners:[{x,y}|{address}], nonce? }
//	                   → { factory, ownerBytes[], createAccountCalldata, getAddressCalldata, address? }

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	aiggwallet "github.com/jianmliu/aigg-wallet"
)

func parseHexBytes(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
}

func parseBigHex(s string) (*big.Int, bool) {
	return new(big.Int).SetString(strings.TrimPrefix(strings.TrimSpace(s), "0x"), 16)
}

type cswErc1271Req struct {
	AuthenticatorData string `json:"authenticatorData"` // hex
	ClientDataJSON    string `json:"clientDataJSON"`    // hex (UTF-8 JSON bytes)
	Signature         string `json:"signature"`         // hex (DER ECDSA-P256, from the authenticator)
	OwnerIndex        uint64 `json:"ownerIndex"`        // passkey owner index in the CSW (default 0)
}

// cswErc1271Handler packages a WebAuthn assertion into the CSW ERC-1271 blob
// (the bytes Permit2/isValidSignature accepts). No key material involved.
func cswErc1271Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "method"})
		return
	}
	if !authed(r) {
		writeJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	var req cswErc1271Req
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad_request"})
		return
	}
	ad, e1 := parseHexBytes(req.AuthenticatorData)
	cdj, e2 := parseHexBytes(req.ClientDataJSON)
	sig, e3 := parseHexBytes(req.Signature)
	if e1 != nil || e2 != nil || e3 != nil || len(ad) == 0 || len(cdj) == 0 || len(sig) == 0 {
		writeJSON(w, 400, map[string]string{"error": "authenticatorData/clientDataJSON/signature must be non-empty hex"})
		return
	}
	assertion := aiggwallet.WebAuthnAssertion{AuthenticatorData: ad, ClientDataJSON: cdj, Signature: sig}
	blob, err := aiggwallet.BuildCSWPasskeySignature(assertion, req.OwnerIndex)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "build_failed", "detail": err.Error()})
		return
	}
	resp := map[string]string{"erc1271": "0x" + hex.EncodeToString(blob)}
	// Echo the decoded challenge so the caller can confirm it == replaySafeHash.
	if ch, err := assertion.Challenge(); err == nil {
		resp["challenge"] = "0x" + hex.EncodeToString(ch)
	}
	writeJSON(w, 200, resp)
}

type cswOwnerSpec struct {
	X       string `json:"x"`       // passkey pubkey x (hex)
	Y       string `json:"y"`       // passkey pubkey y (hex)
	Address string `json:"address"` // OR an EOA owner address (hex)
}

type cswAccountReq struct {
	Owners []cswOwnerSpec `json:"owners"`
	Nonce  uint64         `json:"nonce"`
}

// cswAccountHandler derives the CSW owner encodings + factory calldata for a set
// of owners (passkey {x,y} and/or EOA {address}), and — if WALLET_CSW_RPC_URL is
// configured — the counterfactual account address.
func cswAccountHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "method"})
		return
	}
	if !authed(r) {
		writeJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	var req cswAccountReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Owners) == 0 {
		writeJSON(w, 400, map[string]string{"error": "owners_required"})
		return
	}
	owners := make([][]byte, 0, len(req.Owners))
	ownerHex := make([]string, 0, len(req.Owners))
	for i, o := range req.Owners {
		var ob []byte
		if strings.TrimSpace(o.Address) != "" {
			if !common.IsHexAddress(o.Address) {
				writeJSON(w, 400, map[string]string{"error": "bad_owner_address", "index": strconv.Itoa(i)})
				return
			}
			ob = aiggwallet.EOAOwnerBytes(common.HexToAddress(o.Address))
		} else {
			x, ok1 := parseBigHex(o.X)
			y, ok2 := parseBigHex(o.Y)
			if !ok1 || !ok2 {
				writeJSON(w, 400, map[string]string{"error": "bad_owner_xy", "index": strconv.Itoa(i)})
				return
			}
			ob = aiggwallet.PasskeyOwnerBytes(x, y)
		}
		owners = append(owners, ob)
		ownerHex = append(ownerHex, "0x"+hex.EncodeToString(ob))
	}
	create, err := aiggwallet.CreateAccountCalldata(owners, req.Nonce)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	getAddr, err := aiggwallet.GetAddressCalldata(owners, req.Nonce)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	resp := map[string]any{
		"factory":               aiggwallet.CoinbaseSmartWalletFactory,
		"ownerBytes":            ownerHex,
		"createAccountCalldata": "0x" + hex.EncodeToString(create),
		"getAddressCalldata":    "0x" + hex.EncodeToString(getAddr),
	}
	if cswRPC != nil {
		if addr, err := aiggwallet.CounterfactualAddress(r.Context(), cswRPC, owners, req.Nonce); err == nil {
			resp["address"] = addr.Hex()
		} else {
			resp["addressError"] = err.Error()
		}
	}
	writeJSON(w, 200, resp)
}
