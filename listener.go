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
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// Event topic hashes (keccak256 of the canonical signatures).
var (
	topicPermit   common.Hash
	topicLockdown common.Hash
	topicTransfer common.Hash
)

func init() {
	topicPermit = common.BytesToHash(keccak256Sig("Permit(address,address,address,uint160,uint48,uint48)"))
	topicLockdown = common.BytesToHash(keccak256Sig("Lockdown(address,address,address)"))
	topicTransfer = common.BytesToHash(keccak256Sig("Transfer(address,address,uint256)"))
}

func keccak256Sig(s string) []byte { return ethcrypto.Keccak256([]byte(s)) }

// PermitEvent / LockdownEvent / TransferEvent decoded from logs.
type PermitEvent struct {
	Owner, Token, Spender string
	AmountAtoms           string
	Expiration, Nonce     int64
}
type LockdownEvent struct{ Owner, Token, Spender string }
type TransferEvent struct {
	Token, From, To, ValueAtoms, TxHash string
}

// DecodePermit decodes a Permit2 Permit log (4 topics + 96-byte data).
func DecodePermit(l types.Log) (PermitEvent, error) {
	if len(l.Topics) != 4 || l.Topics[0] != topicPermit {
		return PermitEvent{}, fmt.Errorf("not a Permit log")
	}
	if len(l.Data) != 96 {
		return PermitEvent{}, fmt.Errorf("permit data must be 96 bytes, got %d", len(l.Data))
	}
	return PermitEvent{
		Owner:       topicAddr(l.Topics[1]),
		Token:       topicAddr(l.Topics[2]),
		Spender:     topicAddr(l.Topics[3]),
		AmountAtoms: new(big.Int).SetBytes(l.Data[0:32]).String(),
		Expiration:  new(big.Int).SetBytes(l.Data[32:64]).Int64(),
		Nonce:       new(big.Int).SetBytes(l.Data[64:96]).Int64(),
	}, nil
}

// DecodeLockdown decodes a Permit2 Lockdown log (4 topics).
func DecodeLockdown(l types.Log) (LockdownEvent, error) {
	if len(l.Topics) != 4 || l.Topics[0] != topicLockdown {
		return LockdownEvent{}, fmt.Errorf("not a Lockdown log")
	}
	return LockdownEvent{Owner: topicAddr(l.Topics[1]), Token: topicAddr(l.Topics[2]), Spender: topicAddr(l.Topics[3])}, nil
}

// DecodeTransfer decodes an ERC-20 Transfer log (3 topics + 32-byte data).
// Token comes from the log address.
func DecodeTransfer(l types.Log) (TransferEvent, error) {
	if len(l.Topics) != 3 || l.Topics[0] != topicTransfer {
		return TransferEvent{}, fmt.Errorf("not a Transfer log")
	}
	if len(l.Data) != 32 {
		return TransferEvent{}, fmt.Errorf("transfer data must be 32 bytes, got %d", len(l.Data))
	}
	return TransferEvent{
		Token: l.Address.Hex(), From: topicAddr(l.Topics[1]), To: topicAddr(l.Topics[2]),
		ValueAtoms: new(big.Int).SetBytes(l.Data[0:32]).String(), TxHash: l.TxHash.Hex(),
	}, nil
}

func topicAddr(h common.Hash) string { return common.BytesToAddress(h.Bytes()[12:32]).Hex() }

// WatermarkStore persists the last-processed block.
type WatermarkStore interface {
	GetWatermark(ctx context.Context) (uint64, error)
	SetWatermark(ctx context.Context, block uint64) error
}

// EventLoop polls Permit2 (Permit+Lockdown) and optionally USDC Transfer
// (to=treasury) events and reconciles the AuthorizationStore.
type EventLoop struct {
	RPC            BaseRPC
	Store          AuthorizationStore
	Watermark      WatermarkStore
	Permit2Address string // default CanonicalPermit2Address

	// AgentFilter, if set, returns true for spender addresses the consumer
	// owns; events for other spenders are ignored. nil → process all.
	AgentFilter func(agent string) bool

	// Transfer-side reconciliation (optional): set both to enable.
	USDCAddress       string
	TreasuryAddressFn func(ctx context.Context) (string, error)
	Crediter          Crediter

	PollInterval          time.Duration
	MaxBlocksPerTick      uint64
	InitialBackfillBlocks uint64
}

func (l *EventLoop) defaults() {
	if l.Permit2Address == "" {
		l.Permit2Address = CanonicalPermit2Address
	}
	if l.PollInterval <= 0 {
		l.PollInterval = 12 * time.Second
	}
	if l.MaxBlocksPerTick == 0 {
		l.MaxBlocksPerTick = 5000
	}
}

// Run blocks until ctx is cancelled. Per-tick errors are returned to the
// caller's logger via the returned error from Tick (Run swallows + continues).
func (l *EventLoop) Run(ctx context.Context, onError func(error)) error {
	if l == nil || l.RPC == nil || l.Store == nil || l.Watermark == nil {
		return errors.New("agentwallet eventloop: missing deps")
	}
	l.defaults()
	if err := l.Tick(ctx); err != nil && onError != nil {
		onError(err)
	}
	t := time.NewTicker(l.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := l.Tick(ctx); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

// Tick does one filter+apply pass. Exported for tests / manual stepping.
func (l *EventLoop) Tick(ctx context.Context) error {
	l.defaults()
	head, err := l.RPC.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("head: %w", err)
	}
	wm, err := l.Watermark.GetWatermark(ctx)
	if err != nil {
		return fmt.Errorf("watermark: %w", err)
	}
	if wm == 0 {
		seed := head
		if l.InitialBackfillBlocks > 0 && head > l.InitialBackfillBlocks {
			seed = head - l.InitialBackfillBlocks
		}
		if err := l.Watermark.SetWatermark(ctx, seed); err != nil {
			return fmt.Errorf("seed watermark: %w", err)
		}
		wm = seed
	}
	if wm >= head {
		return nil
	}
	from := wm + 1
	to := head
	if to > from+l.MaxBlocksPerTick-1 {
		to = from + l.MaxBlocksPerTick - 1
	}

	// Permit2 events
	p2logs, err := l.RPC.FilterLogs(ctx, ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from), ToBlock: new(big.Int).SetUint64(to),
		Addresses: []common.Address{common.HexToAddress(l.Permit2Address)},
		Topics:    [][]common.Hash{{topicPermit, topicLockdown}},
	})
	if err != nil {
		return fmt.Errorf("filter permit2 %d-%d: %w", from, to, err)
	}
	for _, lg := range p2logs {
		_ = l.applyPermit2(ctx, lg) // per-log errors are swallowed; store ops are idempotent
	}

	// USDC Transfer → treasury (optional)
	if l.USDCAddress != "" && l.TreasuryAddressFn != nil {
		if treasury, terr := l.TreasuryAddressFn(ctx); terr == nil && common.IsHexAddress(treasury) {
			tlogs, terr := l.RPC.FilterLogs(ctx, ethereum.FilterQuery{
				FromBlock: new(big.Int).SetUint64(from), ToBlock: new(big.Int).SetUint64(to),
				Addresses: []common.Address{common.HexToAddress(l.USDCAddress)},
				Topics:    [][]common.Hash{{topicTransfer}, nil, {common.BytesToHash(common.HexToAddress(treasury).Bytes())}},
			})
			if terr == nil {
				for _, lg := range tlogs {
					_ = l.applyTransfer(ctx, lg)
				}
			}
		}
	}

	return l.Watermark.SetWatermark(ctx, to)
}

func (l *EventLoop) applyPermit2(ctx context.Context, lg types.Log) error {
	switch {
	case len(lg.Topics) > 0 && lg.Topics[0] == topicPermit:
		ev, err := DecodePermit(lg)
		if err != nil {
			return err
		}
		if l.AgentFilter != nil && !l.AgentFilter(ev.Spender) {
			return nil
		}
		_, err = l.Store.Upsert(ctx, Authorization{
			Owner: ev.Owner, Agent: ev.Spender, Token: ev.Token,
			AmountAtoms: ev.AmountAtoms, Expiration: ev.Expiration, Nonce: ev.Nonce,
			CreatedAtUnix: int64(lg.BlockNumber), // monotonic ordering proxy
		})
		return err
	case len(lg.Topics) > 0 && lg.Topics[0] == topicLockdown:
		ev, err := DecodeLockdown(lg)
		if err != nil {
			return err
		}
		if l.AgentFilter != nil && !l.AgentFilter(ev.Spender) {
			return nil
		}
		return l.Store.MarkLocked(ctx, ev.Owner, ev.Spender, ev.Token)
	}
	return nil
}

func (l *EventLoop) applyTransfer(ctx context.Context, lg types.Log) error {
	ev, err := DecodeTransfer(lg)
	if err != nil {
		return err
	}
	row, err := l.Store.ActiveForOwner(ctx, ev.From, ev.Token, int64(^uint64(0)>>1))
	if err != nil {
		return nil // not ours / no matching authorization → ignore
	}
	var replayed bool
	if l.Crediter != nil {
		_, _, rep, cerr := l.Crediter.CreditAfterSpend(ctx, ev.From, ev.Token, ev.ValueAtoms, ev.TxHash)
		if cerr != nil {
			return cerr
		}
		replayed = rep
	}
	if replayed {
		return nil // 5c already accounted for spent_amount
	}
	return l.Store.BumpSpent(ctx, row.Owner, row.Agent, row.Token, row.Nonce, ev.ValueAtoms)
}
