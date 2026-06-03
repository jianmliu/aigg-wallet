# wallet-svc

Thin HTTP wrapper around the `aigg-wallet` library so **non-Go callers** (e.g.
onchainpal's TS kit) can derive per-subject agent EOAs and obtain EIP-712
signatures **without ever holding key material**. The master seed lives only in
this process (env today; dstack TEE sealed store in production).

```
TS RemoteAgentWallet ──HTTP + Bearer──▶ wallet-svc ──▶ signs with the TEE-held seed
```

## Run

```bash
WALLET_MASTER_SEED=<hex, >=16 bytes>   # dstack TEE sealed in prod
WALLET_AUTH_TOKEN=<bearer>             # required (fail-closed if unset)
WALLET_LISTEN=:8091                    # default
WALLET_ALLOW_GENERIC_SIGN=1            # dev only — see SECURITY
go run ./cmd/wallet-svc
```

## Endpoints

| Method / path | Body | Returns |
|---|---|---|
| `GET /healthz` | — | `{ ok, genericSign }` |
| `POST /address` | `{ subject }` | `{ address, derivationPath }` — `m/44'/<coin>'/<account(keccak(subject))>'` |
| `POST /sign` | `{ subject, typedData }` | `{ address, signature, digest }` — generic EIP-712 (gated) |

Auth: `Authorization: Bearer <WALLET_AUTH_TOKEN>` on `/address` + `/sign`
(fail-closed when the token is unset).

## SECURITY

`/sign` is a **generic** EIP-712 signer, enabled only with
`WALLET_ALLOW_GENERIC_SIGN=1` for development. A generic signing oracle lets any
authorized caller sign arbitrary messages with the agent key. **In production,
replace it with scoped endpoints** that build the typed data *here* from fixed
config (GCC token, `payTo`, `maxAmount`) using the library's `SignEIP3009` /
`SignPermit2` — so a caller can never redirect funds or sign an off-policy
message. The seed must come from a TEE sealed store, not a plain env var.
