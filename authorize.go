package agentwallet

import (
	"context"
	"fmt"
	"strings"
)

// Authorizer verifies a user-submitted Permit2 PermitSingle and caches it.
// It is stateless beyond the store.
type Authorizer struct {
	Store AuthorizationStore
	// NowUnix lets tests inject a clock. Defaults to time.Now in Verify's
	// caller if nil — pass an explicit `now` to Verify instead.
}

// VerifyAndCache runs the verifier pipeline and upserts on success:
//  1. bounds: amount > 0, deadline > now, owner is an address
//  2. anti-spoof: params.Spender must equal expectedAgent (the agent EOA the
//     consumer derived for this subject) — a user must not authorize someone
//     else's agent
//  3. reconstruct the Permit2 EIP-712 digest, ecrecover the signature,
//     recovered address must equal claimedOwner
//  4. Upsert into the store (idempotent on owner+agent+token+nonce)
//
// Returns nil on success (row cached or already present).
func (a *Authorizer) VerifyAndCache(
	ctx context.Context,
	params Permit2TransferParams,
	signatureHex string,
	claimedOwner string,
	expectedAgent string,
	now int64,
) error {
	if a == nil || a.Store == nil {
		return fmt.Errorf("agentwallet authorizer: not configured")
	}
	// 1. bounds
	if params.Amount == "" || params.Amount == "0" {
		return fmt.Errorf("agentwallet authorize: amount must be > 0")
	}
	if params.Deadline <= now {
		return fmt.Errorf("agentwallet authorize: deadline already passed")
	}
	if !looksLikeAddress(claimedOwner) {
		return fmt.Errorf("agentwallet authorize: invalid owner address")
	}
	// 2. anti-spoof
	if !strings.EqualFold(expectedAgent, params.Spender) {
		return fmt.Errorf("agentwallet authorize: spender %s != expected agent %s", params.Spender, expectedAgent)
	}
	// 3. rebuild digest + ecrecover
	td, err := BuildPermit2TypedData(params)
	if err != nil {
		return fmt.Errorf("agentwallet authorize: rebuild typed data: %w", err)
	}
	recovered, err := RecoverTypedDataSigner(td, signatureHex)
	if err != nil {
		return fmt.Errorf("agentwallet authorize: %w", err)
	}
	if !strings.EqualFold(recovered, claimedOwner) {
		return fmt.Errorf("agentwallet authorize: signature recovers to %s, expected owner %s", recovered, claimedOwner)
	}
	// 4. cache (store normalised sig)
	sig := normalizeSigHex(signatureHex)
	if sig == "" {
		return fmt.Errorf("agentwallet authorize: malformed signature")
	}
	_, err = a.Store.Upsert(ctx, Authorization{
		Owner:         claimedOwner,
		Agent:         params.Spender,
		Token:         params.Token,
		AmountAtoms:   params.Amount,
		Expiration:    params.Deadline,
		Nonce:         int64(params.Nonce),
		SignatureHex:  sig,
		CreatedAtUnix: now,
	})
	if err != nil {
		return fmt.Errorf("agentwallet authorize: upsert: %w", err)
	}
	return nil
}

// normalizeSigHex returns "0x"+lowercase 130-hex (preserving wallet v) or "".
func normalizeSigHex(s string) string {
	t := strings.TrimSpace(s)
	t = strings.TrimPrefix(t, "0x")
	t = strings.TrimPrefix(t, "0X")
	if len(t) != 130 {
		return ""
	}
	for _, c := range t {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return ""
		}
	}
	return "0x" + strings.ToLower(t)
}
