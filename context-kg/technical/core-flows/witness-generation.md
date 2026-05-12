---
name: "witness-generation"
description: "Host-side witness generation flow — orchestrate kona pipeline, capture preimages and blob KZG data"
---
# Witness Generation Flow

## Entry Point
`WitnessGenerator::run(preimage_chan, hint_chan)` on the DA-specific generator (`utils/{eth,celestia,eigenda}/host`).

## Primary Entities
`WitnessGenerator` (trait), `WitnessExecutor` (DA-specific), `PreimageWitnessCollector`, `OnlineBlobStore`, `OPSuccinctDataFetcher`, `WitnessData` (or `EigenDAWitnessData`).

## State Transitions
N/A — bounded async operation that either returns `WitnessData` or an error.

## Normal Flow Steps

| Step | Action | Module |
|------|--------|--------|
| 1 | Caller constructs `OPSuccinctDataFetcher` and passes it (plus L2 block range) to the host's witness generator | `OPSuccinctHost::fetch_args` |
| 2 | Generator builds `CachingOracle` from RPC + preimage channels | `host/src/witness_generation/mod.rs` |
| 3 | Wrap oracle in `PreimageWitnessCollector(Arc<Mutex<PreimageStore>>)` — auto-captures every `get`/`get_exact`/`write` call | `preimage_witness_collector.rs` |
| 4 | Build `OnlineBlobStore(Arc<Mutex<BlobData>>)` wrapping the network blob provider — auto-captures KZG commitments + proofs on `get_and_validate_blobs` | `online_blob_store.rs` |
| 5 | Compose `WitnessExecutor` (DA-specific) and `OraclePipeline`; call `executor.run(pipeline)` to derive + execute the L2 block range | `utils/{eth,celestia,eigenda}/host` |
| 6 | After execution, unlock both `Arc<Mutex<…>>` and snapshot into `WitnessData` (or `EigenDAWitnessData`) | generator `run()` |
| 7 | Serialize witness via rkyv (+ serde_cbor for EigenDA canoe proof) and store in cache or pass to prover | caller |

## Exception Branches

| Trigger | State Change | Compensation |
|---------|-------------|-------------|
| Oracle RPC fetch fails | Propagate `anyhow::Error` | Retry policy is the caller's responsibility (today: none — FIXME `host/src/fetcher.rs:58`) |
| Beacon blob fetch fails | Same | Retry / fall back to alternate beacon |
| Lock contention on preimage store | Stall in `tokio::Mutex::lock()` | Avoid heavy operations while holding the lock |
| Rollup config mismatch | Pipeline panic | Regenerate with correct config |

## Flow-Specific Pitfalls

[Pitfall] `PreimageStore` lock contention — multi-threaded oracle access under `Arc<Mutex<…>>` can stall. Release locks before heavy operations; never nest locks.

[Pitfall] Blob order matters — guest consumes LIFO. Host must serialize blobs in reverse order, or the first block won't find its blob.

[Pitfall] No fetcher retry — single transient RPC error fails the entire witness generation. FIXME at `host/src/fetcher.rs:58`.

[Pitfall] Isthmus withdrawals_root: pre-Isthmus headers carry nil; fall back to `eth_getProof` for the message-passer storage root.

[Pitfall] EigenDA witness adds `eigenda_data: Option<Vec<u8>>` (canoe proof); forgetting to populate this on the host causes guest panic on `.expect()`.

[Pitfall] Celestia witness path uses Blobstream oracle for safe-head computation; never apply the generic +20 block offset.
