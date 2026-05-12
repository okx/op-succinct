---
name: "aggregation-proof"
description: "zkVM-guest aggregation flow — verify range proofs, chain L1 headers, emit consolidated BootInfo"
---
# Aggregation Proof Flow

## Entry Point
`#[sp1_zkvm::entrypoint!(main)]` in `programs/aggregation/src/main.rs`.

## Primary Entities
`AggregationInputs`, `BootInfoStruct[]`, `multi_block_vkey[8]`, `latest_l1_checkpoint_head`, `prover_address`, `AggregationOutputs`.

## State Transitions
N/A — single-shot guest program.

## Normal Flow Steps

| Step | Action | Module |
|------|--------|--------|
| 1 | Read `AggregationInputs` from stdin | `utils/client/src/types.rs` |
| 2 | Read L1 headers (serde_cbor encoded list) | `programs/aggregation/src/main.rs` |
| 3 | For each `boot_info` in `boot_infos[]`: call `sp1_lib::verify_sp1_proof(multi_block_vkey, &boot_info_hash)` | `sp1_lib` |
| 4 | Walk L1 headers backwards (`headers.iter().rev()`) — each `current_hash` must equal next header's `hash_slow()` | aggregation `main.rs` |
| 5 | Every `boot_info.l1Head` must appear in the reversed header chain (continuity check) | aggregation `main.rs` |
| 6 | Sequencing assert (`windows(2)`): `prev.l2PostRoot == curr.l2PreRoot` for every consecutive pair | aggregation `main.rs` |
| 7 | Construct `AggregationOutputs { consolidated_boot_info, multi_block_vkey }` and commit to public output | aggregation `main.rs` |

## Exception Branches

| Trigger | State Change | Compensation |
|---------|-------------|-------------|
| `verify_sp1_proof` fails for any range | guest panic | None — root cause is bad range proof or vkey mismatch |
| L1 header chain breaks (`current_hash != header.hash_slow()`) | guest panic | None — regenerate aggregation with correct header bundle |
| Missing `boot_info.l1Head` in header chain | guest panic | None — ensure full header chain back to earliest `l1Head` |
| Sequencing mismatch | guest panic | None — re-bundle ranges; do not skip blocks |

## Flow-Specific Pitfalls

[Pitfall] Off-by-one in header linking silently breaks proof. Validation must traverse in reverse and compare `hash_slow()` strictly.

[Pitfall] `multi_block_vkey` is `[u32; 8]` (hash_u32 layout). Host-computed and guest-expected layouts must match byte-for-byte.

[Pitfall] All ranges must share the same `multi_block_vkey` — proofs from different range program versions cannot be aggregated together.
