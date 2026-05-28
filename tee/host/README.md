# xlayer-tee-host

Stateful scheduler sitting between the op-succinct proposer (north side) and
the `xlayer-tee-enclave` (south side). Forwards opaque rkyv witness bodies
without decoding them, multiplexes concurrent tasks, and surfaces a single
attestation document for the SP1 aggregation guest.

Spec: see [`../SPEC.md`](../SPEC.md).

## Endpoints

North side (proposer-facing JSON envelope `{ code, message, data }`):

| Route | Method | Body | Response |
|---|---|---|---|
| `/tee/task` | POST | `rkyv(DefaultWitnessData)` (octet-stream) | `{ taskId }` |
| `/tee/task/{task_id}` | GET | — | `{ status, proofBytes, detail }` |
| `/tee/task/{task_id}` | DELETE | — | `{ taskId }` |
| `/tee/info` | GET | — | `{ attestationDoc }` (base64 COSE_Sign1) |

`proofBytes` is the ABI-encoding of `(RangeJournal, signature)` once the task
reaches `Finished`. The full PCR0 + enclave pubkey live inside
`attestationDoc`; the host does not surface them separately.

South side (enclave-facing, octet-stream rkyv):

```
POST   /tasks/range         submit a range task
GET    /tasks/{task_id}     poll task state
DELETE /tasks/{task_id}     cancel
GET    /tasks               (diagnostics) list all tasks
GET    /attestation         raw COSE_Sign1 doc
```

Transport is HTTP/1.1 + keep-alive over vsock (production, `--features vsock`)
or TCP (dev / macOS / CI).

## Concurrency

The host imposes **no inflight cap**. Multiple `POST /tee/task` requests run
in parallel; if the enclave returns `TooManyTasks` (429) the per-task monitor
sleeps `POST_RETRY_INTERVAL = 2s` and retries the POST. From the proposer's
side the task simply stays `Running ("queued; enclave at capacity")` until
the enclave has a slot — never a failure.

## Build

```bash
# Dev (TCP enclave transport; default — works on macOS and Linux)
cargo build -p xlayer-tee-host

# Production (vsock enclave transport; Linux + Nitro only)
cargo build -p xlayer-tee-host --features vsock --release
```

## Run

```bash
cp tee/host/config.example.toml tee/host/config.toml
# edit config.toml, then:

RUST_LOG=info,xlayer_tee_host=debug \
TEE_HOST_CONFIG=tee/host/config.toml \
cargo run -p xlayer-tee-host
```

Any field is overridable via env in `TEE_HOST__SECTION__FIELD` form, e.g.

```bash
TEE_HOST__SERVER__BIND_ADDR=0.0.0.0:18080 \
TEE_HOST__ENCLAVE__TCP_ADDR=127.0.0.1:7878 \
  cargo run -p xlayer-tee-host
```

## Configuration

| toml key | env override | default | meaning |
|---|---|---|---|
| `server.bind_addr` | `TEE_HOST__SERVER__BIND_ADDR` | — | north-side listen address |
| `server.task_retention_secs` | `TEE_HOST__SERVER__TASK_RETENTION_SECS` | 3600 | terminal-task in-memory retention |
| `server.dedup_ttl_secs` | `TEE_HOST__SERVER__DEDUP_TTL_SECS` | 300 | identical witness body within this window returns the existing `taskId` |
| `server.monitor_interval_secs` | `TEE_HOST__SERVER__MONITOR_INTERVAL_SECS` | 30 | per-task status log frequency |
| `enclave.vsock_cid` | `TEE_HOST__ENCLAVE__VSOCK_CID` | 0 | vsock CID (`--features vsock` only) |
| `enclave.vsock_port` | `TEE_HOST__ENCLAVE__VSOCK_PORT` | 0 | vsock port |
| `enclave.tcp_addr` | `TEE_HOST__ENCLAVE__TCP_ADDR` | `127.0.0.1:7878` | TCP target (otherwise) |
| `enclave.request_timeout_secs` | `TEE_HOST__ENCLAVE__REQUEST_TIMEOUT_SECS` | 180 | per-request timeout |
| `attestation.cache_ttl_secs` | `TEE_HOST__ATTESTATION__CACHE_TTL_SECS` | 60 | `/tee/info` cache TTL |

## Error codes

`code` field in `ApiResponse`:

| code | name | meaning |
|---|---|---|
| `0` | OK | success |
| `10001` | INVALID_ARGUMENT | bad request / `ClaimMismatch` / `InvalidWitness` |
| `10004` | RESOURCE_NOT_FOUND | `task_id` not in host registry |
| `20001` | INTERNAL_ERROR | host or enclave fault (retryable) |

Enclave `ErrorKind` is mapped to one of these codes; the original kind string
is preserved in `message` for diagnostics. See `../SPEC.md` for the full
mapping.

## Layout

```
tee/host/
├── Cargo.toml
├── config.example.toml
└── src/
    ├── main.rs           binary entry
    ├── lib.rs            module wiring
    ├── server.rs         axum routes + per-task monitor with TooManyTasks retry
    ├── task_manager.rs   in-memory registry + dedup + retention sweeper
    ├── enclave_client.rs hyper http1 over vsock/TCP + auto-reconnect
    ├── packager.rs       RangeJournal → abi.encode(journal, sig)
    ├── config.rs         toml + TEE_HOST__* env
    ├── api.rs            north-side JSON shapes
    └── error.rs          Error enum + numeric codes
```

## Related crates

| crate | role |
|---|---|
| [`xlayer-tee-types`](../types/) | shared HTTP interface (journal / response / error / limits / paths) — host depends on this |
| [`xlayer-tee-enclave`](../enclave/) | prover binary running inside the Nitro Enclave |
| [`xlayer-tee-prover-mock`](../prover-mock/) | all-zero placeholder enclave for protocol shake-out |
| [`xlayer-tee-mock-proposer`](../mock-proposer/) | local-dev proposer that drives the host end-to-end |
