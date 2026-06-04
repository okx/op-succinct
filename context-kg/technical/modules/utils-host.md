---
name: "utils-host"
description: "Host-side utilities — RPC fetching, block-range planning, witness generation orchestration, proof caching"
---
# utils/host Module

## Responsibilities
- `OPSuccinctDataFetcher`: unified L1/L2/beacon RPC client + rollup config loader.
- Block-range planning (`block_range.rs`) and split logic for proof requests.
- Witness generation orchestration via the `WitnessGenerator` trait and its `PreimageWitnessCollector` / `OnlineBlobStore` wrappers.
- Proof + witness caching (`proof_cache.rs`, `witness_cache.rs`).
- Metrics, logger, and OTel telemetry setup.
- DA-agnostic `OPSuccinctHost` trait — each DA-host crate provides one impl.

## NOT Responsible For
- DA-specific fetching logic — that lives in `utils/{ethereum,celestia,eigenda}/host`.
- Proof generation — `utils/proof`.
- Transaction sending — `utils/signer`.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `OPSuccinctDataFetcher` | l1/l2/beacon providers, rollup config | `Arc`-shared RPC handle |
| `OPSuccinctHost` (trait) | `fetch_args`, `calculate_safe_l1_head`, `get_finalized_l2_block_number` | DA boundary |
| `WitnessGenerator` (trait) | `get_executor`, `get_sp1_stdin`, default `run` | Async orchestration template |
| `PreimageWitnessCollector` | inner oracle, `Arc<Mutex<PreimageStore>>` | Captures preimages during execution |
| `OnlineBlobStore` | inner blob provider, `Arc<Mutex<BlobData>>` | Captures blob KZG data during execution |
| Local `rpc_types` (`rpc_types.rs`) | `OpExecutionPayload` etc. | Replaces the omitted `kona-rpc` types |

## Dependencies
- Refer to `arch/dependency.md` for full details.

## Relevant Flows
- See `core-flows/witness-generation.md`.

## Module-Specific Pitfalls

[Rule] `utils/host/Cargo.toml`: must NOT add `kona-rpc` — RPC types are defined locally in `rpc_types.rs` to avoid an alloy version conflict with hokulea v1.1.4.

[Pitfall] `utils/host/src/fetcher.rs:58`: fetcher requests have no retry policy (FIXME). Add 3-retry policy or upstream alloy retry middleware.

[Pitfall] Isthmus pre/post `withdrawals_root` handling — pre-Isthmus headers carry `nil` withdrawals root; we fall back to `eth_getProof` for the message-passer storage root. Future hardforks may change this again.

[Pitfall] `PreimageStore` lock contention — multi-threaded oracle access under `Arc<Mutex<…>>` can stall. Release lock before heavy operations; never nest locks.

[Pitfall] `get_agg_proof_stdin` fills `range_proofs` with `vec![RangeProof::Sp1; boot_infos.len()]` for SP1-only batches. When adding TEE batch support (proposer-side), the caller must construct the correct `RangeProof::Tee { signature }` variants and ensure parallel-index alignment with `boot_infos`. The stdin also conditionally carries attestation bytes after `AggregationInputs` when the batch has TEE leaves.
