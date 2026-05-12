---
name: "feature-types"
description: "DA feature flags, ELF embedding, build patterns and compile-time dispatch in op-succinct"
---
# Feature Types and Build Patterns

## DA Layer Feature Flags

| Feature | Selects | Compile-time gate |
|--------|---------|-------------------|
| `ethereum` (default) | `op-succinct-ethereum-host-utils` + `op-succinct-ethereum-client-utils` | `cfg_if` branch in `utils/proof/src/lib.rs::initialize_host()` |
| `celestia` | `op-succinct-celestia-host-utils` + `op-succinct-celestia-client-utils`, `hana-*` deps | Same branch; mutually exclusive with `ethereum` |
| `eigenda` | `op-succinct-eigenda-host-utils` + `op-succinct-eigenda-client-utils`, `hokulea-*` deps, canoe verifier | Same branch; mutually exclusive |

[Convention] Each consumer of `proof-utils` (validity, fault-proof) re-exports the same three features so the binary's DA layer is selected at build time.

[Rule] `utils/proof/src/lib.rs`: must never enable two DA features simultaneously — `cfg_if` only emits one `initialize_host` impl.

## ELF Embedding

`utils/elfs/src/lib.rs` exposes pre-built ELFs as static byte slices via `include_bytes!`:

| ELF | Constant | Purpose |
|-----|---------|---------|
| Range (Ethereum) | `RANGE_ELF_EMBEDDED` (feature-gated) | zkVM program for Ethereum-DA range proof |
| Range (Celestia) | `RANGE_ELF_EMBEDDED` (feature-gated) | Celestia-DA range proof |
| Range (EigenDA) | `RANGE_ELF_EMBEDDED` (feature-gated) | EigenDA-DA range proof |
| Aggregation | `AGGREGATION_ELF` | Combine multiple range proofs |

[Rule] ELF compilation happens **externally** via `sp1_build::build_program_with_args` invoked in Docker (`tag v6.1.0`); `utils/build/src/lib.rs` programmatic build calls are commented out by default. Don't run `cargo prove build` from inside the workspace build script.

## SP1 Cluster vs Network Modes

| Mode | Path | Selection |
|------|-----|-----------|
| Network | `sp1-sdk::NetworkProver` | Default; `proof_id` (B256) persisted as DB column |
| Cluster | `proof-utils::ClusterArtifactStore` + `sp1-cluster-*` (Redis + S3 via gateway proxy) | When cluster env vars set; `cluster_proof_handle` (JSON) persisted instead |
| Mock | `sp1-sdk::CpuProver` | `RequestMode::Mock`; local mock proofs for development |

[Rule] `proof-utils::is_cluster_mode()` decides at runtime; `validity` writes either `proof_request_id` or `cluster_proof_handle` to the same `requests` row — never both populated simultaneously.

## Pagination, Imports/Exports, Async

| Pattern | Where | Notes |
|---------|-------|-------|
| Batch size resolution | `scripts/utils/src/lib.rs::HostExecutorArgs::effective_batch_size()` | Precedence: explicit `--batch-size` > `(--start --end)` range > `DEFAULT_BATCH_SIZE` (10) |
| Async runtime | `tokio = { features = ["full"] }` | Long-running services use `#[tokio::main]`; CPU-bound provers spawned via `spawn_blocking` |
| Migration runner | `sqlx::migrate!()` in `validity/src/db/client.rs` | Runs at `DriverDBClient::new()` on every startup; migrations under `validity/migrations/0[1-9]_*.sql` |

## Build / Release Profiles

| Profile | Defined where | Purpose |
|---------|---------------|---------|
| `release-client-lto` | Root `Cargo.toml` | `lto = "fat"`, `codegen-units = 1`, `panic = "abort"` — used for zkVM-guest builds where size matters |
| `dev` (default) | Cargo default | Used during local development; expects ELFs already built and cached |

## Patched Dependencies

[Rule] Root `Cargo.toml` `[patch.crates-io]` section pins all `sp1-*`, `slop-*`, `sha2`, `sha3`, `tiny-keccak`, `k256`, `p256`, `substrate-bn` to OKX or SP1-patches forks. Removing any patch breaks production cluster auth or zkVM precompile performance. See `knowledge-base.md` for the canonical rule.
