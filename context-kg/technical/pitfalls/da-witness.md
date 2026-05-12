---
name: "da-witness"
description: "DA and witness pitfalls — blob ordering, EigenDA canoe proof, Celestia safe-head, Isthmus, rollup config hash"
---
# DA & Witness Pitfalls

## Blob LIFO Ordering

[Pitfall] `utils/client/src/oracle/blob_provider.rs::BlobStore::from(BlobData)` reverses the blob list and consumes it via `Vec::pop` (LIFO). Trigger: host serializes blobs in natural order. Correct approach: host MUST pre-reverse the blob list before writing the witness. Affected: all DA layers (Ethereum, Celestia, EigenDA range programs).

## EigenDA Canoe Proof

[Pitfall] `programs/range/eigenda/src/main.rs`: `EigenDAWitnessData.eigenda_data` carries the canoe proof; the guest deserializes it via serde_cbor and calls `.expect()`. Missing data panics the guest. Trigger: host forgets to populate `eigenda_data`. Correct approach: host's `EigenDAHost::fetch_args` must always include the canoe proof for EigenDA flows.

## Celestia Safe Head

[Pitfall] `utils/celestia/host/src/host.rs`: safe-head computation must use `get_celestia_safe_head_info()` from `hana-blobstream` — NOT the generic +20 block offset. The `--safe_db_fallback` flag is intentionally IGNORED for Celestia. Trigger: applying a uniform safe-head policy across all DA layers. Correct approach: keep Celestia's path special-cased.

## EigenDA Safe Head Offset

[Pitfall] `utils/eigenda/host/src/host.rs`: safe-head fallback mirrors Ethereum's +20 block offset. May be under-conservative for EigenDA finality assumptions. Trigger: faster L1 finality than expected. Correct approach: revisit when EigenDA finality model changes; consider longer offset.

## Isthmus withdrawals_root

[Pitfall] `fault-proof/src/lib.rs:94`, `utils/host/src/fetcher.rs`: pre-Isthmus L2 block headers carry `nil` for `withdrawals_root`; post-Isthmus they carry the message-passer storage root. We fall back to `eth_getProof` when nil. Trigger: hardfork boundary. Correct approach: keep the dual path until pre-Isthmus support is dropped.

## Rollup Config Hash

[Pitfall] `utils/client/src/boot.rs::hash_rollup_config()` uses `serde_json::to_string_pretty` (deterministic). Mismatch with the on-chain expected hash silently invalidates all proofs. Trigger: changing the serializer style. Correct approach: never alter the hash computation without coordinated contract redeploy.

## Multi-Block VKey Layout

[Pitfall] `multi_block_vkey: [u32; 8]` uses `hash_u32` layout — eight little-endian u32s representing the SP1 vkey hash. Mismatch between host-computed and guest-expected layouts produces verification failure with no useful error. Affected: `utils/client/src/types.rs::AggregationInputs`.

## Range vs Aggregation Vkey Pairing

[Pitfall] `programs/aggregation/src/main.rs`: ALL aggregated ranges must share the same `multi_block_vkey`. Mixing range proofs from different program versions cannot be aggregated. Trigger: gradual rollout of new range program. Correct approach: drain in-flight ranges before changing the range vkey.

## Sequencing Assertion

[Pitfall] Aggregation must assert `prev.l2PostRoot == curr.l2PreRoot` on every `windows(2)` pair. Skipping the assertion would silently aggregate malformed sequences. Trigger: refactoring the aggregation main loop. Correct approach: keep the windows(2) iteration intact.

## L1 Header Chain Continuity

[Pitfall] Aggregation walks L1 headers backwards (`headers.iter().rev()`). Each `current_hash` must equal the next header's `hash_slow()`. Off-by-one breaks proof. Affected: `programs/aggregation/src/main.rs`.
