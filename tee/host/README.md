# xlayer-tee-host

TEE Host (scheduler) bridging the op-succinct **proposer** and the
**xlayer-tee-prover enclave**.

- **Spec**: see [`../SPEC.md`](../SPEC.md) for the authoritative
  contract this crate implements (v2.0.0+).
- **Workspace**: member of the parent `op-succinct` workspace. The host
  itself does not transitively need any `op-succinct` runtime code
  (witness body is byte-forwarded; never decoded).

## What it does

```
proposer (HTTP, rkyv body)  ─►  tee-host  ─►  enclave (HTTP, rkyv body)
                                  ▲   │
                                  │   │  forwards bytes verbatim
                                  │   ▼
                          host doesn't decode the witness
```

- **North side** (proposer-facing):
  - `POST /tee/task` — accept `rkyv(DefaultWitnessData)` body, generate
    `task_id`, forward to enclave
  - `GET  /tee/task/{task_id}` — poll; assembles `proofBytes` when enclave
    reports Finished
  - `DELETE /tee/task/{task_id}` — propagate to enclave (real `AbortHandle.abort()`)
  - `GET  /tee/info` — proxy enclave attestation + signer pubkey
- **South side** (enclave-facing): `/tasks/range`, `/tasks/{id}` GET/DELETE,
  `/attestation`, `/health` over HTTP/1.1 + keep-alive on either vsock (prod)
  or TCP (dev/CI).

Error codes use the proposer-facing numeric convention
(`0 / 10001 / 10004 / 20001`).

## Layout

```
xlayer-tee-host/
├── Cargo.toml
├── README.md              ← this file
├── (spec lives at ../SPEC.md, one level up)
├── config.example.toml    ← starter config
└── src/
    ├── main.rs            ← binary entry
    ├── lib.rs             ← module wiring
    ├── server.rs          ← M1: axum routes
    ├── task_manager.rs    ← M2: in-memory registry + retention sweeper
    ├── enclave_client.rs  ← M3: hyper http1 over vsock/TCP, auto-reconnect
    ├── packager.rs        ← M4: RangeJournal → abi.encode(journal, sig)
    ├── config.rs          ← M5: toml + TEE_HOST__* env
    ├── api.rs             ← north-side JSON shapes + enclave JSON decode
    └── error.rs           ← Error enum + 4 numeric codes + ErrorKind mapping
```

## Build

```bash
cd optimism/rust/xlayer-tee-prover/crates/xlayer-tee-host

# Dev (TCP enclave transport; default)
cargo build

# Production (vsock enclave transport; Linux + Nitro only)
cargo build --features vsock --release

# Lint
cargo clippy --all-targets
```

## Run

```bash
# Copy and edit config first
cp config.example.toml config.toml

# Default config path is ./config.toml; override with TEE_HOST_CONFIG
RUST_LOG=info cargo run

# Or with a different config
TEE_HOST_CONFIG=/etc/xlayer-tee-host/config.toml cargo run --release

# Any field can be overridden via env (TEE_HOST__SECTION__FIELD)
TEE_HOST__SERVER__BIND_ADDR=0.0.0.0:8080 \
TEE_HOST__ENCLAVE__TCP_ADDR=127.0.0.1:7878 \
  cargo run
```

## Local dev workflow

> **Status note**: `xlayer-tee-prover-mock` and `xlayer-tee-enclave` (`v0.1`) are
> still **sync** — POST returns the proof in body, no `task_id` / GET / DELETE.
> Host is built against the **async** enclave contract defined in SPEC §4.
> Full E2E happy path requires either:
>
> 1. A separate mock async enclave server matching SPEC §4 (recommended for
>    host CI), OR
> 2. A local-only dev branch of `xlayer-tee-enclave` that adds the async layer
>    (does not land in main; tracking item in SPEC §10.2 belongs to the
>    enclave team).
>
> See SPEC §9.4.4 for the discussion. Until enclave async ships, host
> integration testing relies on the unit tests in `src/*.rs` (`cargo test`).

```bash
# Unit + integration tests (no enclave needed)
cargo test

# Run binary against your async enclave at 127.0.0.1:7878 (whatever path you took)
cp config.example.toml config.toml
RUST_LOG=info,xlayer_tee_host=debug cargo run
# host listens on 0.0.0.0:18080
```

Build flavors:
- **default** (`cargo build`): TCP transport, suitable for dev / CI
- **`--features vsock`**: vsock transport, for production Nitro Enclave host

## Configuration reference

| toml key | env override | default | meaning |
|---|---|---|---|
| `server.bind_addr` | `TEE_HOST__SERVER__BIND_ADDR` | — | north-side listen address |
| `server.task_retention_secs` | `TEE_HOST__SERVER__TASK_RETENTION_SECS` | 3600 | terminal-task in-memory retention |
| `enclave.vsock_cid` | `TEE_HOST__ENCLAVE__VSOCK_CID` | 0 | vsock CID (`--features vsock` only) |
| `enclave.vsock_port` | `TEE_HOST__ENCLAVE__VSOCK_PORT` | 0 | vsock port |
| `enclave.tcp_addr` | `TEE_HOST__ENCLAVE__TCP_ADDR` | `127.0.0.1:7878` | TCP target (otherwise) |
| `enclave.request_timeout_secs` | `TEE_HOST__ENCLAVE__REQUEST_TIMEOUT_SECS` | 180 | per-request timeout |
| `attestation.cache_ttl_secs` | `TEE_HOST__ATTESTATION__CACHE_TTL_SECS` | 60 | `/tee/info` cache TTL |

## Error codes

The four numeric codes in unified `ApiResponse { code, message, data }`
envelope:

| code | name | meaning |
|---|---|---|
| `0` | OK | success |
| `10001` | INVALID_ARGUMENT | bad request / `ClaimMismatch` / `InvalidWitness` |
| `10004` | RESOURCE_NOT_FOUND | `task_id` not in host registry |
| `20001` | INTERNAL_ERROR | host or enclave fault (retryable) |

Enclave `ErrorKind` (`KonaExec` / `ClaimMismatch` / ...) is mapped to one of
these codes; the original kind string is preserved in `message` for
diagnostics. See SPEC §6 for the full mapping table.

## Related crates

| crate | role |
|---|---|
| [`xlayer-tee-types`](../xlayer-tee-types/) | shared interface types (journal / response / error / eip712 / limits / paths) — host depends on this |
| [`xlayer-tee-witness`](../xlayer-tee-witness/) | re-export of `op_succinct_client_utils::witness::DefaultWitnessData` — host does **not** depend on this (witness body is opaque to host) |
| [`xlayer-tee-enclave`](../xlayer-tee-enclave/) | the prover ELF running inside Nitro Enclave |
| [`xlayer-tee-prover-mock`](../xlayer-tee-prover-mock/) | all-zero placeholder enclave for protocol shake-out |
