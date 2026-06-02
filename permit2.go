package aiggwallet

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// CanonicalPermit2Address is Uniswap's Permit2 — the same address on every
// EVM chain it's deployed to.
const CanonicalPermit2Address = "0x000000000022D473030F116dDEE9F6B43aC78BA3"

var (
	permit2SelectorPermit       []byte
	permit2SelectorTransferFrom []byte
	permit2PermitArgs           abi.Arguments
	permit2TransferFromArgs     abi.Arguments
)

func init() {
	permit2SelectorPermit = funcSelector("permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)")
	permit2SelectorTransferFrom = funcSelector("transferFrom(address,address,uint160,address)")

	addrT := mustABIType("address")
	uint160T := mustABIType("uint160")
	bytesT := mustABIType("bytes")
	permitSingleT := mustABIType("tuple",
		abi.ArgumentMarshaling{Name: "details", Type: "tuple", Components: []abi.ArgumentMarshaling{
			{Name: "token", Type: "address"},
			{Name: "amount", Type: "uint160"},
			{Name: "expiration", Type: "uint48"},
			{Name: "nonce", Type: "uint48"},
		}},
		abi.ArgumentMarshaling{Name: "spender", Type: "address"},
		abi.ArgumentMarshaling{Name: "sigDeadline", Type: "uint256"},
	)
	permit2PermitArgs = abi.Arguments{
		{Name: "owner", Type: addrT},
		{Name: "permitSingle", Type: permitSingleT},
		{Name: "signature", Type: bytesT},
	}
	permit2TransferFromArgs = abi.Arguments{
		{Name: "from", Type: addrT},
		{Name: "to", Type: addrT},
		{Name: "amount", Type: uint160T},
		{Name: "token", Type: addrT},
	}
}

func funcSelector(sig string) []byte {
	h := ethcrypto.Keccak256([]byte(sig))
	out := make([]byte, 4)
	copy(out, h[:4])
	return out
}

func mustABIType(typeStr string, components ...abi.ArgumentMarshaling) abi.Type {
	t, err := abi.NewType(typeStr, "", components)
	if err != nil {
		panic(fmt.Sprintf("agentwallet permit2: NewType(%q): %v", typeStr, err))
	}
	return t
}

type permitDetailsTuple struct {
	Token      common.Address `abi:"token"`
	Amount     *big.Int       `abi:"amount"`
	Expiration *big.Int       `abi:"expiration"`
	Nonce      *big.Int       `abi:"nonce"`
}

type permitSingleTuple struct {
	Details     permitDetailsTuple `abi:"details"`
	Spender     common.Address     `abi:"spender"`
	SigDeadline *big.Int           `abi:"sigDeadline"`
}

// PermitSingleCallArgs is the input to EncodePermitCall.
type PermitSingleCallArgs struct {
	Owner       string
	Token       string
	Spender     string
	Amount      *big.Int
	Expiration  uint64
	Nonce       uint64
	SigDeadline *big.Int
	Signature   []byte // verbatim 65-byte wallet signature
}

// EncodePermitCall returns calldata for Permit2.permit(owner, permitSingle, signature).
func EncodePermitCall(args PermitSingleCallArgs) ([]byte, error) {
	if !common.IsHexAddress(args.Owner) {
		return nil, fmt.Errorf("permit2: bad owner %q", args.Owner)
	}
	if !common.IsHexAddress(args.Token) {
		return nil, fmt.Errorf("permit2: bad token %q", args.Token)
	}
	if !common.IsHexAddress(args.Spender) {
		return nil, fmt.Errorf("permit2: bad spender %q", args.Spender)
	}
	if args.Amount == nil || args.Amount.Sign() <= 0 {
		return nil, fmt.Errorf("permit2: amount must be > 0")
	}
	if args.SigDeadline == nil || args.SigDeadline.Sign() <= 0 {
		return nil, fmt.Errorf("permit2: sigDeadline must be > 0")
	}
	if len(args.Signature) != 65 {
		return nil, fmt.Errorf("permit2: signature must be 65 bytes, got %d", len(args.Signature))
	}
	permitSingle := permitSingleTuple{
		Details: permitDetailsTuple{
			Token:      common.HexToAddress(args.Token),
			Amount:     new(big.Int).Set(args.Amount),
			Expiration: new(big.Int).SetUint64(args.Expiration),
			Nonce:      new(big.Int).SetUint64(args.Nonce),
		},
		Spender:     common.HexToAddress(args.Spender),
		SigDeadline: new(big.Int).Set(args.SigDeadline),
	}
	packed, err := permit2PermitArgs.Pack(common.HexToAddress(args.Owner), permitSingle, args.Signature)
	if err != nil {
		return nil, fmt.Errorf("permit2: pack permit args: %w", err)
	}
	return append(append([]byte{}, permit2SelectorPermit...), packed...), nil
}

// TransferFromCallArgs is the input to EncodeTransferFromCall.
type TransferFromCallArgs struct {
	From   string
	To     string
	Amount *big.Int
	Token  string
}

// EncodeTransferFromCall returns calldata for Permit2.transferFrom(from, to, amount, token).
func EncodeTransferFromCall(args TransferFromCallArgs) ([]byte, error) {
	if !common.IsHexAddress(args.From) {
		return nil, fmt.Errorf("permit2: bad from %q", args.From)
	}
	if !common.IsHexAddress(args.To) {
		return nil, fmt.Errorf("permit2: bad to %q", args.To)
	}
	if !common.IsHexAddress(args.Token) {
		return nil, fmt.Errorf("permit2: bad token %q", args.Token)
	}
	if args.Amount == nil || args.Amount.Sign() <= 0 {
		return nil, fmt.Errorf("permit2: amount must be > 0")
	}
	packed, err := permit2TransferFromArgs.Pack(
		common.HexToAddress(args.From), common.HexToAddress(args.To),
		new(big.Int).Set(args.Amount), common.HexToAddress(args.Token),
	)
	if err != nil {
		return nil, fmt.Errorf("permit2: pack transferFrom args: %w", err)
	}
	return append(append([]byte{}, permit2SelectorTransferFrom...), packed...), nil
}
