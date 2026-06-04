package main

// /sign/tx — sign a raw EIP-1559 transaction with a per-agent key, so a trusted
// orchestrator (aigg-src) can drive the Permit2 spend (build permit() /
// transferFrom() calldata + nonce + gas itself, get it signed here, broadcast
// itself). wallet-svc never broadcasts and never holds business state.
//
// POWERFUL PRIMITIVE: this signs an ARBITRARY tx with the agent key, so the
// bearer holder can make the agent do anything the agent can on-chain (bounded
// by the agent's Permit2 allowance + its gas balance). It is therefore
// fail-closed: OFF unless WALLET_ALLOW_SIGN_TX=1, and Bearer-gated. The caller
// (aigg-src) is the trusted policy layer that decides token/recipient/amount.

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	aiggwallet "github.com/jianmliu/aigg-wallet"
)

type signTxReq struct {
	// Agent key selector (pick one): structured (owner, agent) — default — or an
	// explicit hardened path.
	Owner uint32   `json:"owner"`
	Agent uint32   `json:"agent"`
	Path  []uint32 `json:"path,omitempty"`

	// EIP-1559 (DynamicFeeTx) fields. Wei amounts are decimal strings.
	ChainID   int64  `json:"chainID"`
	Nonce     uint64 `json:"nonce"`
	To        string `json:"to"`
	Data      string `json:"data"`  // hex calldata
	Value     string `json:"value"` // decimal wei (default 0)
	Gas       uint64 `json:"gas"`
	GasTipCap string `json:"gasTipCap"` // decimal wei (maxPriorityFeePerGas)
	GasFeeCap string `json:"gasFeeCap"` // decimal wei (maxFeePerGas)
}

func decWeiOrZero(s string) (*big.Int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return big.NewInt(0), true
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.Sign() < 0 {
		return nil, false
	}
	return v, true
}

func signTxHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "method"})
		return
	}
	if !authed(r) {
		writeJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	if !allowSignTx {
		writeJSON(w, 403, map[string]string{"error": "sign_tx_disabled", "hint": "set WALLET_ALLOW_SIGN_TX=1"})
		return
	}
	var req signTxReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad_request"})
		return
	}
	if req.ChainID <= 0 || req.Gas == 0 || !common.IsHexAddress(req.To) {
		writeJSON(w, 400, map[string]string{"error": "chainID>0, gas>0, valid to required"})
		return
	}
	data, err := parseHexBytes(req.Data)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad_data_hex"})
		return
	}
	value, ok1 := decWeiOrZero(req.Value)
	tip, ok2 := decWeiOrZero(req.GasTipCap)
	feeCap, ok3 := decWeiOrZero(req.GasFeeCap)
	if !ok1 || !ok2 || !ok3 {
		writeJSON(w, 400, map[string]string{"error": "bad value/gasTipCap/gasFeeCap (decimal wei)"})
		return
	}

	var key *aiggwallet.AgentKey
	if len(req.Path) > 0 {
		key, err = aiggwallet.DerivePath(seed, req.Path...)
	} else {
		key, err = aiggwallet.DeriveAgent(seed, coin, req.Owner, req.Agent)
	}
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "derive: " + err.Error()})
		return
	}
	defer key.Zeroize()
	priv, err := ethcrypto.ToECDSA(key.PrivateKey)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "to-ecdsa: " + err.Error()})
		return
	}

	chainID := big.NewInt(req.ChainID)
	to := common.HexToAddress(req.To)
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     req.Nonce,
		GasTipCap: tip,
		GasFeeCap: feeCap,
		Gas:       req.Gas,
		To:        &to,
		Value:     value,
		Data:      data,
	})
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), priv)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "sign: " + err.Error()})
		return
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "marshal: " + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{
		"from":        key.Address,
		"rawSignedTx": "0x" + hex.EncodeToString(raw),
		"hash":        signed.Hash().Hex(),
	})
}
