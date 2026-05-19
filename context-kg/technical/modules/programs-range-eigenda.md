---
name: "programs-range-eigenda"
description: "zkVM-guest range program for EigenDA — derives via hokulea + canoe proof verification"
---
# programs/range/eigenda Module

## Responsibilities
- SP1 zkVM guest binary.
- Read `EigenDAWitnessData` (rkyv-encoded with optional `eigenda_data` field) from stdin.
- Deserialize canoe proof bytes (`serde_cbor`); wrap in `EigenDAWitness`.
- Run `EigenDAWitnessExecutor<O, B, E>` with preloaded EigenDA provider and canoe verifier.
- Commit `BootInfoStruct`.

## NOT Responsible For
- Ethereum / Celestia DA flows.
- Reading EigenDA blob preimages directly (delegated to preloaded provider).

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `EigenDAWitnessData` | inherits + `eigenda_data: Option<Vec<u8>>` (canoe proof) | EigenDA-specific witness |
| `EigenDAWitnessExecutor<O, B, E>` | 3-generic; `E: EigenDAPreimageProvider` | Driver |
| `CanoeSp1CCVerifier` | from hokulea / canoe | Verifies the canoe proof inside the guest |

## Dependencies
- Refer to `arch/dependency.md`. Pulls in `hokulea-eigenda`, `hokulea-proof`, `canoe-sp1-cc-verifier`.

## Relevant Flows
- See `core-flows/range-program-execution.md`.

## Module-Specific Pitfalls

[Pitfall] Witness is deserialized twice (once `serde_cbor`, once rkyv). Missing `eigenda_data` causes a guest panic on `.expect()`.

[Pitfall] `EigenDAWitnessExecutor` needs three generic bounds (`O`, `B`, `E`); forgetting `E` produces a confusing type-mismatch error.

[Pitfall] EigenDA safe-head fallback mirrors Ethereum's +20 block offset, which may be under-conservative; revisit if EigenDA finality assumptions tighten.
