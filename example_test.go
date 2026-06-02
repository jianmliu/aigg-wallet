package aiggwallet_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jianmliu/aigg-wallet"
)

// Example shows the typical service-side flow: derive a per-subject agent EOA,
// sign a Permit2 PermitSingle for it, and recover the signer to confirm.
func Example() {
	// 32-byte master seed (in production: dstack TEE sealed store / KMS).
	seed, _ := hex.DecodeString(strings.Repeat("ab", 32))

	// Per-subject signer (subject = user_id / npcId / etc.).
	signer, err := aiggwallet.NewBIP44Signer(seed, aiggwallet.DefaultCoinType, 42)
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	agent, _ := signer.Address(ctx)

	params := aiggwallet.Permit2TransferParams{
		Token:       "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // USDC on Base
		Spender:     agent,
		Amount:      "100000000", // 100 USDC
		Nonce:       0,
		Deadline:    1_900_000_000,
		ChainID:     8453,
		Permit2Addr: aiggwallet.CanonicalPermit2Address,
	}
	sp, _ := signer.SignPermit2(ctx, params)

	td, _ := aiggwallet.BuildPermit2TypedData(params)
	recovered, _ := aiggwallet.RecoverTypedDataSigner(td, sp.Signature)

	fmt.Println("recovered == agent:", strings.EqualFold(recovered, agent))
	// Output: recovered == agent: true
}
