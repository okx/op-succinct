---
name: "dependency"
description: "Crate dependency map, storage, and external services for op-succinct"
---
# Dependency Map

## Upstream Callers

| Caller | Protocol | Entry Point |
|--------|----------|------------|
| Operator CLI (`cargo run -p op-succinct-validity`) | binary launch | `validity/bin/validity.rs` |
| Operator CLI (`cargo run -p op-succinct-fp --bin proposer`) | binary launch | `fault-proof/bin/proposer.rs` |
| Operator CLI (`cargo run -p op-succinct-fp --bin challenger`) | binary launch | `fault-proof/bin/challenger.rs` |
| Operator CLI (scripts) | binary launch | `scripts/utils/bin/*` (config, cost_estimator, preflight, fetch_*) |
| Operator CLI (manual proving) | binary launch | `scripts/prove/bin/{agg,multi,save_program}.rs` |
| L1 RPC node | HTTPS / WebSocket | All services call `eth_*` on the configured L1 RPC |
| L2 RPC node | HTTPS / WebSocket | All services call `eth_*` / `optimism_*` on the configured L2 RPC |
| Beacon API | HTTP | `host-utils` fetches blob sidecars |
| SP1 prover network | gRPC (`sp1-sdk`) | Network mode prover requests |
| SP1 cluster | gRPC + Redis + S3 | Cluster mode prover requests via gateway proxy |
| Asset-onchain remote signer | HTTP (POST + GET poll) | `XLayerRemoteClient` sign request |

## Inter-Module Dependencies

| From | To | Mechanism |
|------|----|-----------|
| `validity` | `proof-utils` | rust-crate; passes through DA feature flag |
| `validity` | `signer-utils` | rust-crate; constructs `Signer::from_env()` and wraps in `SignerLock` |
| `validity` | `host-utils` | rust-crate; uses `OPSuccinctDataFetcher` |
| `validity` | `bindings` | rust-crate; alloy contract instances |
| `fault-proof` | `proof-utils` | rust-crate; generates range/agg proofs |
| `fault-proof` | `signer-utils` | rust-crate; signs dispute game txs |
| `fault-proof` | `host-utils` | rust-crate; L1/L2 RPC, output-root computation |
| `fault-proof` | `bindings` | rust-crate; alloy contract instances |
| `proof-utils` → `ethereum-host-utils` | rust-crate (feature: `ethereum`) | `initialize_host()` cfg-if branch |
| `proof-utils` → `celestia-host-utils` | rust-crate (feature: `celestia`) | `initialize_host()` cfg-if branch |
| `proof-utils` → `eigenda-host-utils` | rust-crate (feature: `eigenda`) | `initialize_host()` cfg-if branch |
| `proof-utils` → `elfs` | rust-crate; static `include_bytes!` | Range / aggregation ELFs |
| `proof-utils` → `client-utils` | rust-crate; shared `BootInfoStruct`, `AggregationInputs`, witness types | Cross-boundary data contract |
| `host-utils` → `client-utils` | rust-crate; uses witness types and `precompiles::cycle_tracker` | Guest-side contracts referenced in host |
| `programs/range/ethereum` → `ethereum-client-utils` | rust-crate (guest) | DA driver, block execution |
| `programs/range/celestia` → `celestia-client-utils` | rust-crate (guest) | Celestia DA driver |
| `programs/range/eigenda` → `eigenda-client-utils` | rust-crate (guest) | EigenDA driver + canoe verifier |
| `programs/aggregation` → `client-utils` | rust-crate (guest) | Verifies range proofs via SP1 + reads BootInfo |
| `scripts/prove` → `proof-utils`, `host-utils` | rust-crate | CLI orchestration |
| `scripts/utils` → `host-utils`, `bindings` | rust-crate | Config-fetching CLI |
| `fault-proof/tee/{enclave,host,proposer}` → `xlayer-tee-types` | rust-crate (path dep) | Shared TEE contract types (journal, wire, task, error) |
| `xlayer-tee-host` → `axum`, `hyper`, `hyper-util`, `http-body`, `http-body-util`, `tower-http` | rust-crate | Northbound REST server + southbound HTTP client; `http-body` for `SliceBody` Body trait impl |
| `xlayer-tee-host` → `rkyv` | rust-crate (workspace) | Southbound enclave request/response encoding (AlignedVec + CheckBytes) |
| `xlayer-tee-host` → `alloy-primitives`, `alloy-sol-types` | rust-crate (workspace) | keccak256 hashing + abi_encode_params for proofBytes |
| `xlayer-tee-host` → `config`, `dotenvy` | rust-crate | TOML config + env overlay (TEE_HOST__ prefix) |
| `xlayer-tee-host` → `tokio-vsock` (optional) | rust-crate | vsock transport for Nitro Enclave (Linux production only) |

## Storage and Middleware

| Component | Type | Usage |
|-----------|------|-------|
| Postgres | `sqlx::PgPool` | `validity` persistent state: `requests`, `chain_locks` tables; migrations under `validity/migrations/` |
| In-memory proof_cache / witness_cache | LRU `Arc<Mutex<…>>` | `host-utils` shared read-only proof artifacts and witness blobs |
| SP1 cluster artifact store | Redis + S3 (gateway-proxy) | `proof-utils::ClusterArtifactStore` distributed proof artifacts; configured via `ArtifactStoreConfig` |
| Local on-disk proof bytes | filesystem | `scripts/prove` writes saved program / agg outputs |
| File-based proposer backup | `serde_json` file | `fault-proof/src/backup.rs` periodically serialises `ProposerState` |

## External Services

| Service | SDK/Client | Purpose |
|---------|-----------|---------|
| SP1 v6.1.0 (Hypercube) | `sp1-sdk`, `sp1-zkvm`, `sp1-lib`, `sp1-prover` (all patched to `okx/sp1#feat/gateway-proxy-v6.1.0`) | zkVM prover engine |
| Kona v1.2.13 | `kona-driver`, `kona-executor`, `kona-preimage`, `kona-derive`, `kona-proof`, `kona-genesis` | Full-node execution, derivation, output-root computation |
| Hana v1.6.0-mocha | `hana-host`, `hana-blobstream`, `hana-oracle` | Celestia blobstream oracle and blob validation |
| Hokulea v1.1.7 | `hokulea-eigenda`, `hokulea-host-bin`, `hokulea-proof`, `hokulea-compute-proof`, canoe-sp1-cc-* | EigenDA commitment verification, KZG proofs |
| Alloy v1.6.3 / 1.5.6 | `alloy-provider`, `alloy-signer-*`, `alloy-rpc-types-*`, `alloy-consensus`, `alloy-contract` | Ethereum RPC + contract ABI |
| Op-Alloy v1.2.13 (monorepo) | `op-alloy-consensus`, `op-alloy-network`, `op-alloy-rpc-types*` | OP Stack types |
| Google Cloud KMS | `alloy-signer-gcp`, `gcloud-sdk` | HSM-backed transaction signing |
| Web3Signer | HTTP / `alloy` | External remote signer protocol |
| Asset-onchain remote signer (XLayer) | HTTP (custom) — `XLayerRemoteClient` | OKX-specific HSM-backed signing with AES-ECB + HMAC auth |

## Prohibited Patterns

[Rule] `fault-proof` ↔ `validity`: must NEVER mutually import. — Both call `proof-utils` and `signer-utils` but never each other's contract state machine.

[Rule] `utils/client/*`: must NEVER import `utils/host`, `utils/signer`, `utils/proof`, or any `*-host-utils`. — zkVM-guest isolation; only `kona-proof`, `sp1-lib`, `alloy-primitives`, and shared client crates.

[Rule] `utils/host/Cargo.toml`: must NEVER add `kona-rpc`. — Triggers `reth-optimism-primitives` → alloy version conflict with hokulea. Locally-defined RPC types live in `utils/host/src/rpc_types.rs`.

[Rule] `Cargo.toml` patch section: must NEVER remove the `okx/sp1#feat/gateway-proxy-v6.1.0` patches. — Production cluster auth depends on these forks.

[Rule] `utils/proof`: must NEVER attempt to enable multiple DA features simultaneously. — `cfg_if` in `initialize_host()` allows only one host impl per binary.
