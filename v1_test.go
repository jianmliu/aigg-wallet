package aiggwallet

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// ---- shared fakes ----

type fakeRPC struct {
	chainID     func(context.Context) (*big.Int, error)
	nonce       func(context.Context, common.Address) (uint64, error)
	tip         func(context.Context) (*big.Int, error)
	price       func(context.Context) (*big.Int, error)
	estimate    func(context.Context, ethereum.CallMsg) (uint64, error)
	send        func(context.Context, *types.Transaction) error
	receipt     func(context.Context, common.Hash) (*types.Receipt, error)
	call        func(context.Context, ethereum.CallMsg, *big.Int) ([]byte, error)
	blockNumber func(context.Context) (uint64, error)
	filterLogs  func(context.Context, ethereum.FilterQuery) ([]types.Log, error)
}

func (f *fakeRPC) ChainID(c context.Context) (*big.Int, error)     { return f.chainID(c) }
func (f *fakeRPC) BlockNumber(c context.Context) (uint64, error)   { return f.blockNumber(c) }
func (f *fakeRPC) FilterLogs(c context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	return f.filterLogs(c, q)
}
func (f *fakeRPC) PendingNonceAt(c context.Context, a common.Address) (uint64, error) { return f.nonce(c, a) }
func (f *fakeRPC) BalanceAt(context.Context, common.Address) (*big.Int, error)        { return big.NewInt(0), nil }
func (f *fakeRPC) SuggestGasTipCap(c context.Context) (*big.Int, error)               { return f.tip(c) }
func (f *fakeRPC) SuggestGasPrice(c context.Context) (*big.Int, error)                { return f.price(c) }
func (f *fakeRPC) EstimateGas(c context.Context, m ethereum.CallMsg) (uint64, error)  { return f.estimate(c, m) }
func (f *fakeRPC) SendTransaction(c context.Context, t *types.Transaction) error      { return f.send(c, t) }
func (f *fakeRPC) TransactionReceipt(c context.Context, h common.Hash) (*types.Receipt, error) {
	return f.receipt(c, h)
}
func (f *fakeRPC) CallContract(c context.Context, m ethereum.CallMsg, b *big.Int) ([]byte, error) {
	return f.call(c, m, b)
}
func (f *fakeRPC) Close() {}

func spendRPC(allowanceCovers bool) *fakeRPC {
	receipts := map[common.Hash]*types.Receipt{}
	return &fakeRPC{
		chainID:     func(context.Context) (*big.Int, error) { return big.NewInt(84532), nil },
		blockNumber: func(context.Context) (uint64, error) { return 100, nil },
		filterLogs:  func(context.Context, ethereum.FilterQuery) ([]types.Log, error) { return nil, nil },
		nonce:       func(context.Context, common.Address) (uint64, error) { return 7, nil },
		tip:         func(context.Context) (*big.Int, error) { return big.NewInt(1_000_000), nil },
		price:       func(context.Context) (*big.Int, error) { return big.NewInt(50_000_000), nil },
		estimate:    func(context.Context, ethereum.CallMsg) (uint64, error) { return 100_000, nil },
		send: func(_ context.Context, t *types.Transaction) error {
			receipts[t.Hash()] = &types.Receipt{Status: 1, TxHash: t.Hash()}
			return nil
		},
		receipt: func(_ context.Context, h common.Hash) (*types.Receipt, error) {
			if r, ok := receipts[h]; ok {
				return r, nil
			}
			return nil, ethereum.NotFound
		},
		call: func(context.Context, ethereum.CallMsg, *big.Int) ([]byte, error) {
			out := make([]byte, 96)
			if allowanceCovers {
				big.NewInt(999_999_999).FillBytes(out[0:32])
				big.NewInt(1_900_000_000).FillBytes(out[32:64])
			}
			return out, nil
		},
	}
}

const testNow = 1_750_000_000

// cache a real signed authorization for the signer's agent EOA.
func seedAuth(t *testing.T, store *MemoryStore, signer Signer, token string) {
	t.Helper()
	ctx := context.Background()
	agent, _ := signer.Address(ctx)
	params := Permit2TransferParams{
		Token: token, Spender: agent, Amount: "100000000", Nonce: 0,
		Deadline: 1_900_000_000, ChainID: 84532, Permit2Addr: CanonicalPermit2Address,
	}
	sp, err := signer.SignPermit2(ctx, params)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	az := &Authorizer{Store: store}
	if err := az.VerifyAndCache(ctx, params, sp.Signature, agent /*owner==agent (signer signs as itself here)*/, agent, testNow); err != nil {
		t.Fatalf("authorize: %v", err)
	}
}

func TestAuthorizer_RejectsSpenderMismatchAndForgery(t *testing.T) {
	store := NewMemoryStore()
	signer, _ := NewBIP44Signer(testSeed(), DefaultCoinType, 42)
	agent, _ := signer.Address(context.Background())
	params := Permit2TransferParams{
		Token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", Spender: agent,
		Amount: "1", Nonce: 0, Deadline: 1_900_000_000, ChainID: 84532, Permit2Addr: CanonicalPermit2Address,
	}
	sp, _ := signer.SignPermit2(context.Background(), params)
	az := &Authorizer{Store: store}
	// spender mismatch
	if err := az.VerifyAndCache(context.Background(), params, sp.Signature, agent, "0x"+strings.Repeat("11", 20), testNow); err == nil {
		t.Fatal("expected spender-mismatch rejection")
	}
	// forged owner (claim a different owner than the signature recovers to)
	if err := az.VerifyAndCache(context.Background(), params, sp.Signature, "0x"+strings.Repeat("22", 20), agent, testNow); err == nil {
		t.Fatal("expected ecrecover-mismatch rejection")
	}
}

func TestSpender_HappyPath_PermitThenTransfer(t *testing.T) {
	store := NewMemoryStore()
	signer, _ := NewBIP44Signer(testSeed(), DefaultCoinType, 42)
	const token = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
	seedAuth(t, store, signer, token)
	rpc := spendRPC(false)
	sp := &Spender{
		Store: store, RPC: rpc, Signer: signer,
		SellerAddressFn: func(context.Context) (string, error) { return "0x30B10c22F2b136b3dCcFe8d5904A85FE45426b26", nil },
	}
	res, err := sp.Spend(context.Background(), big.NewInt(50_000_000), testNow)
	if err != nil {
		t.Fatalf("spend: %v", err)
	}
	if res.PermitTxHash == "" || res.TransferTxHash == "" {
		t.Fatalf("expected both tx hashes, got %+v", res)
	}
	// spent bumped
	agent, _ := signer.Address(context.Background())
	row, _ := store.ActiveForAgent(context.Background(), agent, testNow)
	if row.SpentAtoms != "50000000" {
		t.Fatalf("spent = %s, want 50000000", row.SpentAtoms)
	}
}

func TestSpender_SkipsPermitWhenAllowanceCovers(t *testing.T) {
	store := NewMemoryStore()
	signer, _ := NewBIP44Signer(testSeed(), DefaultCoinType, 42)
	seedAuth(t, store, signer, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
	sp := &Spender{
		Store: store, RPC: spendRPC(true), Signer: signer,
		SellerAddressFn: func(context.Context) (string, error) { return "0x30B10c22F2b136b3dCcFe8d5904A85FE45426b26", nil },
	}
	res, err := sp.Spend(context.Background(), big.NewInt(1_000_000), testNow)
	if err != nil {
		t.Fatalf("spend: %v", err)
	}
	if res.PermitTxHash != "" {
		t.Fatal("permit should be skipped when allowance covers")
	}
	if res.TransferTxHash == "" {
		t.Fatal("transfer must still run")
	}
}

func TestSpender_RejectsOverAllowance(t *testing.T) {
	store := NewMemoryStore()
	signer, _ := NewBIP44Signer(testSeed(), DefaultCoinType, 42)
	seedAuth(t, store, signer, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
	sp := &Spender{
		Store: store, RPC: spendRPC(false), Signer: signer,
		SellerAddressFn: func(context.Context) (string, error) { return "0x30B10c22F2b136b3dCcFe8d5904A85FE45426b26", nil },
	}
	_, err := sp.Spend(context.Background(), big.NewInt(200_000_000), testNow) // > 100 allowance
	if !errors.Is(err, ErrAllowanceExceeded) {
		t.Fatalf("want ErrAllowanceExceeded, got %v", err)
	}
}

func TestSpender_NoAuthorization(t *testing.T) {
	signer, _ := NewBIP44Signer(testSeed(), DefaultCoinType, 99)
	sp := &Spender{
		Store: NewMemoryStore(), RPC: spendRPC(false), Signer: signer,
		SellerAddressFn: func(context.Context) (string, error) { return "0x30B10c22F2b136b3dCcFe8d5904A85FE45426b26", nil },
	}
	_, err := sp.Spend(context.Background(), big.NewInt(1), testNow)
	if !errors.Is(err, ErrNoAuthorization) {
		t.Fatalf("want ErrNoAuthorization, got %v", err)
	}
}

// ---- listener ----

type memWatermark struct{ v uint64 }

func (m *memWatermark) GetWatermark(context.Context) (uint64, error)  { return m.v, nil }
func (m *memWatermark) SetWatermark(_ context.Context, b uint64) error { m.v = b; return nil }

func addrTopic(a string) common.Hash {
	return common.BytesToHash(common.HexToAddress(a).Bytes())
}

func TestEventLoop_AppliesPermitAndLockdown(t *testing.T) {
	store := NewMemoryStore()
	const owner = "0x1111111111111111111111111111111111111111"
	const agent = "0x2222222222222222222222222222222222222222"
	const token = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
	permitData := make([]byte, 96)
	big.NewInt(100).FillBytes(permitData[0:32])
	big.NewInt(1_900_000_000).FillBytes(permitData[32:64])
	big.NewInt(5).FillBytes(permitData[64:96])
	permitLog := types.Log{
		Address: common.HexToAddress(CanonicalPermit2Address),
		Topics:  []common.Hash{topicPermit, addrTopic(owner), addrTopic(token), addrTopic(agent)},
		Data:    permitData, BlockNumber: 105,
	}
	rpc := &fakeRPC{
		blockNumber: func(context.Context) (uint64, error) { return 110, nil },
		filterLogs:  func(context.Context, ethereum.FilterQuery) ([]types.Log, error) { return []types.Log{permitLog}, nil },
	}
	loop := &EventLoop{RPC: rpc, Store: store, Watermark: &memWatermark{v: 100}}
	if err := loop.Tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	row, err := store.ActiveForOwner(context.Background(), owner, token, testNow)
	if err != nil {
		t.Fatalf("expected upserted row: %v", err)
	}
	if row.Nonce != 5 || row.AmountAtoms != "100" {
		t.Fatalf("row mismatch: %+v", row)
	}
	// now a lockdown for the same triple
	lockLog := types.Log{
		Address: common.HexToAddress(CanonicalPermit2Address),
		Topics:  []common.Hash{topicLockdown, addrTopic(owner), addrTopic(token), addrTopic(agent)},
		BlockNumber: 108,
	}
	rpc.filterLogs = func(context.Context, ethereum.FilterQuery) ([]types.Log, error) { return []types.Log{lockLog}, nil }
	loop.Watermark = &memWatermark{v: 106}
	rpc.blockNumber = func(context.Context) (uint64, error) { return 112, nil }
	if err := loop.Tick(context.Background()); err != nil {
		t.Fatalf("tick2: %v", err)
	}
	if _, err := store.ActiveForOwner(context.Background(), owner, token, testNow); !errors.Is(err, ErrNoAuthorization) {
		t.Fatalf("expected row locked out, got %v", err)
	}
}
