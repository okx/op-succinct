---
name: "utils-eigenda-client"
description: "zkVM-guest EigenDA client utilities — pipeline composition using hokulea + canoe verifier"
---
# utils/eigenda/client Module

## Responsibilities
- Compose the kona pipeline with `EigenDADataSource` and a preloaded EigenDA provider.
- Provide `EigenDAWitnessExecutor<O, B, E>` consumed by `programs/range/eigenda`.
- Surface `EigenDAWitness` type for embedding canoe proof bytes.

## NOT Responsible For
- Host-side EigenDA fetching (`utils/eigenda/host`).
- Other DA layers.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `EigenDAWitnessExecutor<O, B, E>` | 3-generic; `E: EigenDAPreimageProvider` | Implements `WitnessExecutor` for EigenDA |
| `EigenDAPreimageSource` (wrapper) | wraps `EthereumDataSource` | Dual-stacks L1 settlement + EigenDA blobs |
| `EigenDAWitness` | inherits + `eigenda_data: Option<Vec<u8>>` | Canoe-proof container |

## Dependencies
- Refer to `arch/dependency.md`. Direct deps: `hokulea-eigenda`, `hokulea-proof`, `canoe-sp1-cc-verifier`, kona stack.

## Relevant Flows
- See `core-flows/range-program-execution.md`.

## Module-Specific Pitfalls

[Pitfall] Forgetting the `E` generic bound on `EigenDAWitnessExecutor` produces confusing type-mismatch errors at compile time.
