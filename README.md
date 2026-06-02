# agentwallet

`github.com/p2papi/agentwallet` — a self-contained Go toolkit for **per-subject
agent EOAs that pay on-chain via Uniswap Permit2 / EIP-2612 / EIP-3009**.

Extracted from the AI.GG (p2papi) Phase 2 agentic-wallet design so other
products (e.g. onchainpal) can consume it instead of re-implementing key
derivation, EIP-712 signing, the Permit2 calldata codec, an EVM RPC wrapper,
and gas auto-funding.

> **Self-built layer, standard primitives.** This module is the orchestration
> glue. It builds ON Uniswap's canonical **Permit2** contract (used as-is, not
> re-deployed) + standard EIPs (712/2612/3009/1559) + go-ethereum + BIP-44.

## What's in this module

| File | Capability |
|---|---|
| `derive.go` | `Derive(seed, coinType, account)` → agent EOA (BIP-44 `m/44'/<coin>'/<account>'`), `AgentKey.Zeroize()` |
| `eip712.go` | `BuildPermit2TypedData` / `BuildEIP2612TypedData` / `BuildEIP3009TypedData`, `SignTypedData`, `RecoverTypedDataSigner` |
| `permit2.go` | `EncodePermitCall` / `EncodeTransferFromCall` (selectors `0x2b67b570` / `0x36c78516` pinned), `CanonicalPermit2Address` |
| `rpc.go` | `BaseRPC` interface + `RealBaseRPC` (ethclient) + `WaitForReceipt` / `ErrReceiptTimeout` |
| `signer.go` | `Signer` interface + `BIP44Signer` (derives + zeroizes per call) |
| `gasfunder.go` | `GasFunder` interface + `RealGasFunder` (tops up an agent EOA's gas, EIP-1559 fee, nonce-serialized) |

### Orchestration layer (v1)

| File | Capability |
|---|---|
| `store.go` | `Authorization` + `AuthorizationStore` port + thread-safe `MemoryStore` + `ErrNoAuthorization` / `ErrAuthorizationMissingSignature` |
| `authorize.go` | `Authorizer.VerifyAndCache` — bounds + spender anti-spoof + ecrecover, then upsert |
| `spend.go` | `Spender.Spend` — load authz → (gas-fund) → skip-permit-if-covered → `Permit2.permit` → `transferFrom` → wait receipts → bump spent → optional `Crediter`. `ErrAllowanceExceeded`, `SpendResult` |
| `listener.go` | `DecodePermit/Lockdown/Transfer` + `EventLoop` (dual filter: Permit2 Permit/Lockdown + USDC Transfer→treasury) over `AuthorizationStore` + `WatermarkStore`, optional `AgentFilter` |

## What's NOT here (the consumer's ports)

The toolkit owns only chain mechanics. These plug in:

- **Master seed custody** — pass the seed to `NewBIP44Signer`, or implement
  `Signer` over your own key (TEE / KMS / a different derivation path like
  onchainpal's `m/44'/60'/0'/0/<index>`).
- **Persistence** — implement `AuthorizationStore` over your DB (a `MemoryStore`
  is included for tests / simple use). Row identity is (Owner, Agent, Token,
  Nonce); your "subject" (user_id / npcId) is your own concern.
- **Internal ledger / crediting** — implement the optional `Crediter`.
- The subject→account mapping, HTTP surfaces, the x402 facilitator — all
  consumer-side.

## Quick start

```go
seed := loadMasterSeedFromTEEorKMS()            // 32 bytes, kept secret
signer, _ := agentwallet.NewBIP44Signer(seed, agentwallet.DefaultCoinType, userID)

addr, _ := signer.Address(ctx)                  // the agent EOA address

// User authorizes the agent via Permit2 PermitSingle (signed in their wallet,
// or here for a service-side signer):
sp, _ := signer.SignPermit2(ctx, agentwallet.Permit2TransferParams{
    Token: usdc, Spender: addr, Amount: "100000000",
    Nonce: onchainPermit2Nonce, Deadline: deadline,
    ChainID: 8453, Permit2Addr: agentwallet.CanonicalPermit2Address,
})

// Build the on-chain calls the agent EOA broadcasts:
permitData, _ := agentwallet.EncodePermitCall(...)         // Permit2.permit
transferData, _ := agentwallet.EncodeTransferFromCall(...) // Permit2.transferFrom

// Auto-fund gas before broadcasting:
funder, _ := agentwallet.NewGasFunder(rpc, funderKeyHex, nil, nil)
funder.EnsureGas(ctx, addr, chainID)
```

## End-to-end (v1)

```go
store := myAuthorizationStore{}                 // your DB, or agentwallet.NewMemoryStore()
signer, _ := agentwallet.NewBIP44Signer(seed, agentwallet.DefaultCoinType, userID)
agent, _ := signer.Address(ctx)

// user submits a signed PermitSingle → verify + cache
authz := &agentwallet.Authorizer{Store: store}
authz.VerifyAndCache(ctx, params, sigHex, ownerAddr, agent, now)

// later: spend (gas auto-funded, permit+transferFrom, spent bumped, credited)
spender := &agentwallet.Spender{
    Store: store, RPC: rpc, Signer: signer,
    SellerAddressFn: treasuryFn, GasFunder: funder, Crediter: ledger,
}
res, _ := spender.Spend(ctx, big.NewInt(amount), now)   // res.TransferTxHash, res.GasFundedTxHash, …

// background reconciliation
loop := &agentwallet.EventLoop{RPC: rpc, Store: store, Watermark: wm,
    USDCAddress: usdc, TreasuryAddressFn: treasuryFn, Crediter: ledger}
go loop.Run(ctx, func(err error){ log.Warn(err) })
```

## Migration note

p2papi itself still uses its in-tree `internal/service/agent_*` copies. Pointing
p2papi at this module is a separate, deliberate refactor (touches the live
backend) — do it after the module is published + version-pinned.
