package aiggwallet

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// Coinbase Smart Wallet (CSW) account plumbing for the non-custodial Model B
// path: owner encoding, factory calldata, and counterfactual address lookup.
// The CSW verifies passkey signatures via ERC-1271 (see erc1271.go) — proven
// to be Permit2-acceptable by the Base Sepolia spike.

// CoinbaseSmartWalletFactory is the CSW factory address — deployed at the same
// address across chains, including Base mainnet + Base Sepolia.
const CoinbaseSmartWalletFactory = "0x0BA5ED0c6AA8c49038F819E587E2633c4A9F428a"

// EOAOwnerBytes encodes an EOA owner as a CSW owner: abi.encode(address) =
// the address left-padded to 32 bytes.
func EOAOwnerBytes(addr common.Address) []byte {
	out := make([]byte, 32)
	copy(out[12:], addr.Bytes())
	return out
}

// PasskeyOwnerBytes encodes a P-256 passkey public key as a CSW owner:
// abi.encode(x, y) = x ‖ y, 32 bytes each (64 bytes total).
func PasskeyOwnerBytes(x, y *big.Int) []byte {
	out := make([]byte, 64)
	x.FillBytes(out[:32])
	y.FillBytes(out[32:])
	return out
}

var cswFactoryArgs = abi.Arguments{
	{Type: mustABIType("bytes[]")},
	{Type: mustABIType("uint256")},
}

// CreateAccountCalldata builds calldata for
// CoinbaseSmartWalletFactory.createAccount(bytes[] owners, uint256 nonce),
// which deterministically deploys (or returns) the account.
func CreateAccountCalldata(owners [][]byte, nonce uint64) ([]byte, error) {
	args, err := cswFactoryArgs.Pack(owners, new(big.Int).SetUint64(nonce))
	if err != nil {
		return nil, fmt.Errorf("aiggwallet smartaccount: pack createAccount: %w", err)
	}
	return append(funcSelector("createAccount(bytes[],uint256)"), args...), nil
}

// GetAddressCalldata builds calldata for
// factory.getAddress(bytes[] owners, uint256 nonce) (the counterfactual address).
func GetAddressCalldata(owners [][]byte, nonce uint64) ([]byte, error) {
	args, err := cswFactoryArgs.Pack(owners, new(big.Int).SetUint64(nonce))
	if err != nil {
		return nil, fmt.Errorf("aiggwallet smartaccount: pack getAddress: %w", err)
	}
	return append(funcSelector("getAddress(bytes[],uint256)"), args...), nil
}

// CounterfactualAddress returns the CSW address for (owners, nonce) by calling
// the factory's getAddress over the given RPC. The account need not be deployed
// yet — it can receive funds at this address before first use.
func CounterfactualAddress(ctx context.Context, rpc BaseRPC, owners [][]byte, nonce uint64) (common.Address, error) {
	if rpc == nil {
		return common.Address{}, fmt.Errorf("aiggwallet smartaccount: nil rpc")
	}
	data, err := GetAddressCalldata(owners, nonce)
	if err != nil {
		return common.Address{}, err
	}
	to := common.HexToAddress(CoinbaseSmartWalletFactory)
	out, err := rpc.CallContract(ctx, ethereum.CallMsg{To: &to, Data: data}, nil)
	if err != nil {
		return common.Address{}, fmt.Errorf("aiggwallet smartaccount: getAddress call: %w", err)
	}
	if len(out) < 32 {
		return common.Address{}, fmt.Errorf("aiggwallet smartaccount: getAddress returned %d bytes", len(out))
	}
	return common.BytesToAddress(out[12:32]), nil
}
