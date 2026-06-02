package agentwallet

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// A deterministic 32-byte test seed (NEVER production).
func testSeed() []byte {
	b, _ := hex.DecodeString(strings.Repeat("ab", 32))
	return b
}

func TestDerive_DeterministicAndDistinct(t *testing.T) {
	a1, err := Derive(testSeed(), DefaultCoinType, 42)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	a1b, _ := Derive(testSeed(), DefaultCoinType, 42)
	if a1.Address != a1b.Address {
		t.Fatalf("derivation not deterministic: %s != %s", a1.Address, a1b.Address)
	}
	a2, _ := Derive(testSeed(), DefaultCoinType, 43)
	if a1.Address == a2.Address {
		t.Fatalf("distinct accounts share an address")
	}
	if a1.DerivationPath != "m/44'/8453'/42'" {
		t.Fatalf("path: %s", a1.DerivationPath)
	}
	// different coin type → different address
	aC, _ := Derive(testSeed(), 60, 42)
	if aC.Address == a1.Address {
		t.Fatalf("coin type ignored")
	}
}

func TestDerive_RejectsBadInputs(t *testing.T) {
	if _, err := Derive([]byte{1, 2, 3}, DefaultCoinType, 1); err == nil {
		t.Fatal("expected error on short seed")
	}
	if _, err := Derive(testSeed(), DefaultCoinType, 0); err == nil {
		t.Fatal("expected error on account 0")
	}
}

func TestBIP44Signer_SignPermit2_RoundTrips(t *testing.T) {
	s, err := NewBIP44Signer(testSeed(), DefaultCoinType, 42)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	addr, _ := s.Address(context.Background())
	p := Permit2TransferParams{
		Token:       "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
		Spender:     "0x2222222222222222222222222222222222222222",
		Amount:      "100000000",
		Nonce:       0,
		Deadline:    1_900_000_000,
		ChainID:     8453,
		Permit2Addr: CanonicalPermit2Address,
	}
	sp, err := s.SignPermit2(context.Background(), p)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sp.Signature) != 132 { // 0x + 65 bytes
		t.Fatalf("sig len %d", len(sp.Signature))
	}
	// recovered signer == the agent address
	td, _ := BuildPermit2TypedData(p)
	rec, err := RecoverTypedDataSigner(td, sp.Signature)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if !strings.EqualFold(rec, addr) {
		t.Fatalf("recovered %s != signer %s", rec, addr)
	}
}

func TestPermit2Codec_Selectors(t *testing.T) {
	if hex.EncodeToString(permit2SelectorPermit) != "2b67b570" {
		t.Fatalf("permit selector: %x", permit2SelectorPermit)
	}
	if hex.EncodeToString(permit2SelectorTransferFrom) != "36c78516" {
		t.Fatalf("transferFrom selector: %x", permit2SelectorTransferFrom)
	}
}

func TestEncodePermitCall_HasSelectorAndOwner(t *testing.T) {
	sig := make([]byte, 65)
	data, err := EncodePermitCall(PermitSingleCallArgs{
		Owner: "0x1111111111111111111111111111111111111111",
		Token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
		Spender: "0x2222222222222222222222222222222222222222",
		Amount: big.NewInt(1), Expiration: 1_900_000_000, Nonce: 0,
		SigDeadline: big.NewInt(1_900_000_000), Signature: sig,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if hex.EncodeToString(data[:4]) != "2b67b570" {
		t.Fatalf("selector: %x", data[:4])
	}
}

func TestBuildPermit2TypedData_DomainShape(t *testing.T) {
	td, err := BuildPermit2TypedData(Permit2TransferParams{
		Token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
		Spender: "0x2222222222222222222222222222222222222222",
		Amount: "1", Nonce: 0, Deadline: 1_900_000_000, ChainID: 84532,
		Permit2Addr: CanonicalPermit2Address,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if td.Domain.Name != "Permit2" || td.Domain.Version != "" {
		t.Fatalf("domain: name=%q version=%q (version must be empty)", td.Domain.Name, td.Domain.Version)
	}
	if got := (*big.Int)(td.Domain.ChainId).Int64(); got != 84532 {
		t.Fatalf("chainId %d", got)
	}
	var _ apitypes.TypedData = *td
}
