---
name: "range-program-execution"
description: "zkVM-guest range proof execution — read witness, run kona pipeline, commit BootInfo"
---
# Range Program Execution

## Entry Point
`#[sp1_zkvm::entrypoint!(main)]` in one of `programs/range/{ethereum,celestia,eigenda}/src/main.rs`.

## Primary Entities
`DefaultWitnessData` (or `EigenDAWitnessData`), `WitnessExecutor` (DA-specific), `OraclePipeline`, `BootInfoStruct`, `BlobStore`.

## State Transitions
N/A — the guest program is a single-shot execution that either commits a valid `BootInfoStruct` or panics inside the zkVM (which aborts the proof).

## Normal Flow Steps

| Step | Action | Module |
|------|--------|--------|
| 1 | Read witness from stdin: `DefaultWitnessData` (rkyv) or `EigenDAWitnessData` (rkyv + serde_cbor canoe-proof bytes) | `programs/range/*/src/main.rs` |
| 2 | Construct in-guest oracle (`PreimageStore` wrapping `CommsClient`) + `BlobStore` (verifies KZG batch on construction) | `utils/client/src/oracle/blob_provider.rs` |
| 3 | Compose DA-specific `WitnessExecutor` (ETH / Celestia / EigenDA) wiring oracle + blob provider into `OraclePipeline` | `utils/{eth,celestia,eigenda}/client/*` |
| 4 | Run `executor.run(pipeline)` — kona derives + executes the block range | `programs/range/utils` |
| 5 | Compute final L2 post-state root via kona executor | `kona-executor` |
| 6 | Construct `BootInfoStruct { l1Head, l2PreRoot, l2PostRoot, l2BlockNumber, rollupConfigHash }` | `utils/client/src/boot.rs` |
| 7 | `sp1_zkvm::io::commit(&boot_info)` → public output | guest entrypoint |

## Exception Branches

| Trigger | State Change | Compensation |
|---------|-------------|-------------|
| Witness deserialization fails | guest panic → proof fails | None — must regenerate witness host-side |
| KZG blob batch verification fails | guest panic | None — must investigate blob data |
| `rollupConfigHash` does not match expected on-chain hash | proof rejected on-chain | Re-deploy contract with new rollup config hash, or regenerate proof |
| Block execution panic (invalid state transition) | guest panic | None — fix block data or rollup config |

## Flow-Specific Pitfalls

[Pitfall] `BlobStore` consumes blobs LIFO via `Vec::pop` — host must pre-reverse the blob list before serialization, or first-block blobs will be missed.

[Pitfall] `hash_rollup_config()` uses `serde_json::to_string_pretty` (deterministic). Mismatch with the contract's expected hash silently invalidates all proofs.

[Pitfall] EigenDA witness layout differs from ETH/Celestia (extra `eigenda_data` field). Forgetting to encode the canoe proof bytes panics the guest.

[Pitfall] L1 head safety: derived L1 head must be a safe block. For Ethereum/EigenDA, use the +20 block offset OR `--safe_db_fallback`; for Celestia, use `get_celestia_safe_head_info()` from blobstream.
