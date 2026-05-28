# xlayer-tee-enclave

Range prover that runs inside an AWS Nitro Enclave. Accepts a witness over
HTTP, runs the op-succinct `ETHDAWitnessExecutor` (real kona derivation +
execution + claim verification), and returns a `RangeJournal` signed by an
in-enclave ECDSA key. The aggregation guest verifies the signature against
the attestation-derived signer.

Spec: see [`../SPEC.md`](../SPEC.md).

## Build flavors

| Build | Feature | Target | Notes |
|---|---|---|---|
| Dev | (none) | any | TCP `127.0.0.1:7878`, hardcoded Anvil acct #0 key, placeholder PCR0 = `[0u8; 32]` |
| Production | `--features vsock` | Linux + Nitro | vsock listener, fresh `OsRng` ENCLAVE_KEY, real NSM attestation, PCR0 = `keccak256(NSM_PCR0)` |

The default build is opt-in dev (so a build with no flags can never look
like production by accident).

## Endpoints

All bodies are rkyv (octet-stream); error responses are JSON
`{ error_kind, message }`. Paths come from `xlayer_tee_types::wire`.

| Route | Method | Body | Response |
|---|---|---|---|
| `/tasks/range` | POST | `rkyv(DefaultWitnessData)` | `rkyv(CreateTaskResponse)` |
| `/tasks/{task_id}` | GET | — | `rkyv(TaskStateView)` |
| `/tasks/{task_id}` | DELETE | — | `rkyv(DeleteTaskResponse)` |
| `/tasks` | GET | — | `rkyv(TaskListResponse)` (diagnostics) |
| `/attestation` | GET | — | raw COSE_Sign1 NSM doc |

Required headers on `POST /tasks/range`:

- `x-task-id`: client-generated UUID. Reusing it within the retention window
  returns the existing task (idempotent).

`POST /tasks/range` registers the task and returns immediately; the kona
pipeline runs on a spawned tokio task. Poll `GET /tasks/{task_id}` until
`status == Finished` (or `Failed` / `Cancelled`).

## Concurrency model

```
MAX_INFLIGHT_TASKS    cap on simultaneously running tasks
                      0 = auto (num_cpus / 2)
TERMINAL_TTL_SECS     how long terminal task state lingers (default 3600s)
```

Submissions beyond `MAX_INFLIGHT_TASKS` receive HTTP 429
`{ error_kind: "TooManyTasks" }`. The host's per-task monitor retries every
2 s — clients never see this as a failure.

## Signing

Per-range:

```
digest    = keccak256(packed_journal)        // 168 bytes, see ../types/src/journal.rs
signature = ECDSA(ENCLAVE_KEY, digest)       // 65 bytes (r ‖ s ‖ v), v ∈ {27, 28}
```

`RangeJournal` is binding (`pcr0`, `configHash`, `l1OriginHash`,
`l2BlockNumber`, `prevOutputRoot`, `outputRoot`). No EIP-712, no domain, no
chainId: the aggregation guest binds the chain via `configHash =
hash_rollup_config(rollup_config)`.

The signer pubkey appears inside `attestationDoc.public_key`, so the
aggregation guest trusts only signatures from the keypair that the NSM
endorsed for this enclave session.

## Run (dev)

```bash
cargo run -p xlayer-tee-enclave
# listening on 127.0.0.1:7878
# signer = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266   (Anvil account #0)
```

Environment:

| Variable | Default | Meaning |
|---|---|---|
| `LISTEN` | `127.0.0.1:7878` | bind address (dev build only) |
| `MAX_INFLIGHT_TASKS` | `0` (auto) | concurrent task cap |
| `TERMINAL_TTL_SECS` | `3600` | terminal-task retention |
| `RUST_LOG` | `info` | log level |

## Run (production, inside the EIF)

The vsock build listens on `(VMADDR_CID_ANY, 7878)`. The Nitro CLI launches
the EIF; nothing to configure outside of `MAX_INFLIGHT_TASKS` /
`TERMINAL_TTL_SECS` if you want to override defaults.

## Layout

```
tee/enclave/
└── src/
    ├── main.rs          tokio entry + axum bind + per-feature listener
    ├── lib.rs           module declarations
    ├── server.rs        axum router + handlers
    ├── task_manager.rs  registry, per-task abort handle, inflight cap
    ├── runner.rs        spawned pipeline: replay → sign → store
    ├── replay.rs        ETHDAWitnessExecutor driver
    ├── witness.rs       rkyv decode + bounds checks
    ├── signing.rs       keccak256(packed) + k256 prehash sign + v-normalize
    ├── keys.rs          dev key bootstrap; OsRng key for vsock build
    ├── attestation.rs   NSM call (vsock) / placeholder (dev)
    ├── gc.rs            background sweep of terminal tasks
    └── error.rs         internal Error → wire ErrorKind
```

## Testing

```bash
cargo test -p xlayer-tee-enclave
```

Unit tests cover key bootstrap, witness bounds, attestation shape, and
sign → ecrecover round-trip. Integration tests under `tests/` exercise the
axum router via `tower::ServiceExt::oneshot` (no real TCP).

A full happy-path test (real witness → real signature) requires a
host-recorded witness fixture (preimage store + 4844 blobs). The included
synthetic fixture only carries Local keys and therefore exercises the
`InvalidWitness` branch.

## Out of scope

- proposer-side `RangeProverBackend` integration (lives in op-succinct)
- on-chain `approvedEnclaves` registry / SP1 aggregation guest
- attestation-doc parsing / signature verification (lives in the aggregation
  guest under `programs/aggregation/`)
