package agentwallet

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// BaseRPC is the minimal EVM JSON-RPC surface the toolkit needs. Implemented
// by RealBaseRPC (ethclient) and trivially fakeable in tests.
type BaseRPC interface {
	ChainID(ctx context.Context) (*big.Int, error)
	BlockNumber(ctx context.Context) (uint64, error)
	FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error)
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
	BalanceAt(ctx context.Context, account common.Address) (*big.Int, error)
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
	SuggestGasPrice(ctx context.Context) (*big.Int, error)
	EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error)
	SendTransaction(ctx context.Context, tx *types.Transaction) error
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
	Close()
}

// ErrReceiptTimeout signals "broadcast but no receipt within the window" —
// the on-chain fate is indeterminate (the tx may still mine).
var ErrReceiptTimeout = errors.New("agentwallet rpc: receipt wait timed out")

// RealBaseRPC is the ethclient-backed implementation.
type RealBaseRPC struct{ client *ethclient.Client }

// NewBaseRPC dials an EVM JSON-RPC endpoint (e.g. https://mainnet.base.org).
func NewBaseRPC(ctx context.Context, rpcURL string) (*RealBaseRPC, error) {
	if rpcURL == "" {
		return nil, errors.New("agentwallet rpc: empty url")
	}
	c, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("agentwallet rpc: dial %s: %w", rpcURL, err)
	}
	return &RealBaseRPC{client: c}, nil
}

func (r *RealBaseRPC) ChainID(ctx context.Context) (*big.Int, error) { return r.client.ChainID(ctx) }
func (r *RealBaseRPC) BlockNumber(ctx context.Context) (uint64, error) {
	return r.client.BlockNumber(ctx)
}
func (r *RealBaseRPC) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	return r.client.FilterLogs(ctx, q)
}
func (r *RealBaseRPC) PendingNonceAt(ctx context.Context, a common.Address) (uint64, error) {
	return r.client.PendingNonceAt(ctx, a)
}
func (r *RealBaseRPC) BalanceAt(ctx context.Context, a common.Address) (*big.Int, error) {
	return r.client.BalanceAt(ctx, a, nil)
}
func (r *RealBaseRPC) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	return r.client.SuggestGasTipCap(ctx)
}
func (r *RealBaseRPC) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	return r.client.SuggestGasPrice(ctx)
}
func (r *RealBaseRPC) EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
	return r.client.EstimateGas(ctx, msg)
}
func (r *RealBaseRPC) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	return r.client.SendTransaction(ctx, tx)
}
func (r *RealBaseRPC) TransactionReceipt(ctx context.Context, h common.Hash) (*types.Receipt, error) {
	return r.client.TransactionReceipt(ctx, h)
}
func (r *RealBaseRPC) CallContract(ctx context.Context, msg ethereum.CallMsg, bn *big.Int) ([]byte, error) {
	return r.client.CallContract(ctx, msg, bn)
}
func (r *RealBaseRPC) Close() {
	if r != nil && r.client != nil {
		r.client.Close()
	}
}

// WaitForReceipt polls until the receipt is found, the window expires
// (ErrReceiptTimeout), or ctx is cancelled.
func WaitForReceipt(ctx context.Context, rpc BaseRPC, txHash common.Hash, timeout, pollInterval time.Duration) (*types.Receipt, error) {
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		receipt, err := rpc.TransactionReceipt(ctx, txHash)
		if err == nil {
			return receipt, nil
		}
		if !errors.Is(err, ethereum.NotFound) {
			return nil, fmt.Errorf("agentwallet rpc: receipt %s: %w", txHash.Hex(), err)
		}
		if time.Now().After(deadline) {
			return nil, ErrReceiptTimeout
		}
		t := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}
