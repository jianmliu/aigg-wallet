package aiggwallet

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestPasskeyOwnerBytes(t *testing.T) {
	x := new(big.Int).SetBytes(bytes.Repeat([]byte{0x11}, 32))
	y := new(big.Int).SetBytes(bytes.Repeat([]byte{0x22}, 32))
	b := PasskeyOwnerBytes(x, y)
	if len(b) != 64 {
		t.Fatalf("len = %d, want 64", len(b))
	}
	if !bytes.Equal(b[:32], bytes.Repeat([]byte{0x11}, 32)) || !bytes.Equal(b[32:], bytes.Repeat([]byte{0x22}, 32)) {
		t.Fatal("x‖y layout wrong")
	}
}

func TestEOAOwnerBytes(t *testing.T) {
	addr := common.HexToAddress("0x00000000000000000000000000000000000000aB")
	b := EOAOwnerBytes(addr)
	if len(b) != 32 {
		t.Fatalf("len = %d, want 32", len(b))
	}
	if !bytes.Equal(b[12:], addr.Bytes()) {
		t.Fatal("address must be right-aligned in 32 bytes")
	}
	for _, x := range b[:12] {
		if x != 0 {
			t.Fatal("left padding must be zero")
		}
	}
}

func TestFactoryCalldata_SelectorsAndRoundTrip(t *testing.T) {
	owners := [][]byte{PasskeyOwnerBytes(big.NewInt(7), big.NewInt(9))}

	create, err := CreateAccountCalldata(owners, 3)
	if err != nil {
		t.Fatalf("CreateAccountCalldata: %v", err)
	}
	if got := hex.EncodeToString(create[:4]); got != hex.EncodeToString(funcSelector("createAccount(bytes[],uint256)")) {
		t.Fatalf("createAccount selector = %s", got)
	}

	get, err := GetAddressCalldata(owners, 3)
	if err != nil {
		t.Fatalf("GetAddressCalldata: %v", err)
	}
	if got := hex.EncodeToString(get[:4]); got != hex.EncodeToString(funcSelector("getAddress(bytes[],uint256)")) {
		t.Fatalf("getAddress selector = %s", got)
	}

	// Round-trip the args of createAccount.
	vals, err := cswFactoryArgs.Unpack(create[4:])
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	gotOwners := vals[0].([][]byte)
	gotNonce := vals[1].(*big.Int)
	if len(gotOwners) != 1 || !bytes.Equal(gotOwners[0], owners[0]) {
		t.Fatal("owners round-trip mismatch")
	}
	if gotNonce.Cmp(big.NewInt(3)) != 0 {
		t.Fatalf("nonce = %s, want 3", gotNonce)
	}
}
