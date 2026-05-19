---
name: "programs-aggregation"
description: "zkVM-guest aggregation program — verifies range proofs, chains L1 headers, emits consolidated BootInfo"
---
# programs/aggregation Module

## Responsibilities
- SP1 zkVM guest program (`#[sp1_zkvm::entrypoint!(main)]`).
- Read `AggregationInputs` from stdin (boot_infos + multi-block vkey + prover address).
- Verify each range proof via `sp1_lib::verify_sp1_proof()`.
- Walk L1 headers backwards (`serde_cbor`-encoded) and verify chain continuity.
- Enforce sequencing rule: `prev.l2PostRoot == curr.l2PreRoot` (`windows(2)` iteration).
- Commit `AggregationOutputs` (consolidated BootInfo + multi-block vkey).

## NOT Responsible For
- DA-specific verification — delegated to range programs.
- Host-side work; runs only inside the zkVM.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `AggregationInputs` | `boot_infos[]`, `latest_l1_checkpoint_head`, `multi_block_vkey[8]`, `prover_address` | Stdin bundle |
| `AggregationOutputs` | Consolidated `BootInfo` (l1Head, l2PreRoot, l2PostRoot, l2BlockNumber, rollupConfigHash) + multiBlockVKey | Public output |

## Dependencies
- Refer to `arch/dependency.md`. Direct deps: `op-succinct-client-utils`, `sp1-lib`, `sp1-zkvm`, `serde_cbor`, `alloy-consensus` (`Header`).

## Relevant Flows
- See `core-flows/aggregation-proof.md`.

## Module-Specific Pitfalls

[Pitfall] L1 header chain walking is backwards (`headers.iter().rev()`). Off-by-one in the linking check (`current_hash == header.hash_slow()`) breaks the entire proof silently in production.

[Pitfall] Every boot_info's `l1Head` must appear in the reversed header chain — missing one fails verification.

[Pitfall] Sequencing assertion `prev.l2PostRoot == curr.l2PreRoot` must run on every `windows(2)` pair; skipping silently proves a malformed range.

[Pitfall] `multi_block_vkey` is serialized as `[u32; 8]` (hash_u32). Mismatch between host-computed and guest-expected layout produces a verification failure with no useful error.
