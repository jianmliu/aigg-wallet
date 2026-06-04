package aiggwallet

import (
	"bytes"
	"strings"
	"testing"
)

func structSeed() []byte { return bytes.Repeat([]byte{0xCD}, 32) }

func TestDeriveAgent_PathAndDeterminism(t *testing.T) {
	seed := structSeed()
	k, err := DeriveAgent(seed, DefaultCoinType, 7, 3)
	if err != nil {
		t.Fatalf("DeriveAgent: %v", err)
	}
	if k.DerivationPath != "m/44'/8453'/7'/3'" {
		t.Fatalf("path = %q, want m/44'/8453'/7'/3'", k.DerivationPath)
	}
	// Deterministic.
	k2, _ := DeriveAgent(seed, DefaultCoinType, 7, 3)
	if k.Address != k2.Address {
		t.Fatal("DeriveAgent must be deterministic")
	}
}

func TestDeriveAgent_DistinctAndNoTranspositionCollision(t *testing.T) {
	seed := structSeed()
	seen := map[string]string{}
	// A grid of (owner, agent) pairs — every address must be unique, and in
	// particular (a,b) must differ from (b,a).
	for owner := uint32(0); owner < 6; owner++ {
		for agent := uint32(0); agent < 6; agent++ {
			k, err := DeriveAgent(seed, DefaultCoinType, owner, agent)
			if err != nil {
				t.Fatalf("DeriveAgent(%d,%d): %v", owner, agent, err)
			}
			if prev, dup := seen[k.Address]; dup {
				t.Fatalf("collision: (%d,%d) == %s", owner, agent, prev)
			}
			seen[k.Address] = k.DerivationPath
		}
	}
}

func TestDeriveAgent_DiffersFromThreeLevelDerive(t *testing.T) {
	seed := structSeed()
	three, _ := Derive(seed, DefaultCoinType, 7) // m/44'/8453'/7'
	four, _ := DeriveAgent(seed, DefaultCoinType, 7, 0)
	if three.Address == four.Address {
		t.Fatal("m/44'/8453'/7' must differ from m/44'/8453'/7'/0'")
	}
}

func TestDerivePath_GeneralAndBounds(t *testing.T) {
	seed := structSeed()
	k, err := DerivePath(seed, 44, 8453, 1, 2, 3)
	if err != nil {
		t.Fatalf("DerivePath: %v", err)
	}
	if k.DerivationPath != "m/44'/8453'/1'/2'/3'" {
		t.Fatalf("path = %q", k.DerivationPath)
	}
	if _, err := DerivePath(seed); err == nil {
		t.Fatal("empty path must error")
	}
	if _, err := DerivePath(seed, 1<<31); err == nil {
		t.Fatal("index >= 2^31 must error")
	}
}

func TestDerive_BackwardCompatible(t *testing.T) {
	seed := structSeed()
	k, err := Derive(seed, DefaultCoinType, 42)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if k.DerivationPath != "m/44'/8453'/42'" {
		t.Fatalf("path = %q", k.DerivationPath)
	}
	if !strings.HasPrefix(k.Address, "0x") {
		t.Fatal("bad address")
	}
	if _, err := Derive(seed, DefaultCoinType, 0); err == nil {
		t.Fatal("account 0 must still be rejected by Derive")
	}
}
