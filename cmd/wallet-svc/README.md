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
| `GET /healthz` | — | `{ ok, genericSign, eip3009, network, csw, cswAddressResolution }` |
| `POST /address` | `{ subject }` | `{ address, derivationPath }` — `m/44'/<coin>'/<account(keccak(subject))>'` |
| **`POST /sign/eip3009`** | `{ subject, value, validAfter?, validBefore?, nonce? }` | `{ address, signature, digest, payload, requirements }` — **scoped, production** |
| `POST /sign` | `{ subject, typedData }` | `{ address, signature, digest }` — generic EIP-712, **DEV-gated** |
| `POST /csw/erc1271` | `{ authenticatorData, clientDataJSON, signature, ownerIndex? }` (all hex) | `{ erc1271, challenge }` — **Model B** |
| `POST /csw/account` | `{ owners:[{x,y}\|{address}], nonce? }` | `{ factory, ownerBytes[], createAccountCalldata, getAddressCalldata, address? }` — **Model B** |

Auth: `Authorization: Bearer <WALLET_AUTH_TOKEN>` (fail-closed when unset).

### Model B — Coinbase Smart Wallet / passkey (no key material)

Unlike the EIP-3009 path, these hold **no key material**: a passkey signs on the
**user's device** (WebAuthn). wallet-svc only **packages** the assertion into the
Coinbase Smart Wallet (CSW) ERC-1271 blob and derives the CSW account
address/calldata, so non-Go callers (onchainpal) don't re-implement the exact
`WebAuthnAuth`/`SignatureWrapper` ABI (cross-validated on-chain against the
deployed CSW; see `aigg-src/docs/superpowers/spikes/permit2-csw-1271`).

- **`/csw/erc1271`** — turn a WebAuthn passkey assertion (`authenticatorData`,
  `clientDataJSON`, DER `signature`, all 0x-hex) into the ERC-1271 `erc1271` blob
  that `Permit2.permit` / `isValidSignature` accept. Echoes the decoded
  `challenge` so the caller can confirm it equals the CSW `replaySafeHash`.
- **`/csw/account`** — for a set of owners (passkey `{x,y}` and/or EOA
  `{address}`), returns the CSW factory, the per-owner `ownerBytes`, the
  `createAccount` / `getAddress` calldata, and (when `WALLET_CSW_RPC_URL` is set)
  the counterfactual `address`.

```
WALLET_CSW_RPC_URL=https://sepolia.base.org   # optional — enables /csw/account "address"
```

### `/sign/eip3009` — the production signer

The service builds the EIP-3009 `TransferWithAuthorization` typed data itself from
**fixed config** and **enforces scope** before signing — the caller only supplies
`value` (+ optional validity/nonce):

- recipient (`to`) is **forced to `WALLET_PAY_TO`** — a caller cannot redirect funds;
- token/name/version/chainId come from config — cannot sign other assets;
- `value` is rejected if it exceeds `WALLET_MAX_VALUE`;
- returns the full **x402 v2 `payload` + `requirements`**, ready to POST to the facilitator.

```
WALLET_GCC_TOKEN=0x…           # GCC ERC-20 (verifyingContract)
WALLET_PAY_TO=0x…              # AIGG seller — recipient is LOCKED to this
WALLET_CHAIN_ID=84532          # default (Base Sepolia)
WALLET_GCC_NAME="Guaranteed Capacity Credit"
WALLET_GCC_VERSION=1
WALLET_MAX_VALUE=1000000000000000000   # optional per-call cap (atoms)
WALLET_TIMEOUT_SECONDS=300
```

## SECURITY

`/sign` is a **generic** EIP-712 signer (signing oracle) — enabled only with
`WALLET_ALLOW_GENERIC_SIGN=1` for development. **Production uses `/sign/eip3009`**
(scoped) and leaves the generic endpoint off, so a caller can never redirect
funds or sign an off-policy message. The seed must come from a TEE sealed store,
not a plain env var.

## Deploy (node1 / Docker)

```bash
# 1) cross-compile static linux/amd64 binary
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o wallet-svc ./cmd/wallet-svc
# 2) build + ship the image
docker buildx build --platform linux/amd64 -f cmd/wallet-svc/Dockerfile -t onchainpal-wallet-svc:latest .
docker save onchainpal-wallet-svc:latest | gzip | ssh node1 'sudo docker load'
# 3) on node1 (/opt/sub2api-staging): seed + token in .env (generated on-box, never echoed)
#    WALLET_MASTER_SEED=$(openssl rand -hex 32)   WALLET_AUTH_TOKEN=$(openssl rand -hex 16)
#    then `docker-compose -f docker-compose.yml -f wallet-svc.override.yml up -d wallet-svc`
```
Joins the sub2api-staging docker network → reachable internally at
`http://wallet-svc:8091` (e.g. from the inference-proxy). Manage both proxy +
wallet-svc together by passing both override files to one `docker-compose` call.
