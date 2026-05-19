---
name: "utils-celestia-client"
description: "zkVM-guest Celestia DA client utilities — pipeline composition for hana-blobstream-backed derivation"
---
# utils/celestia/client Module

## Responsibilities
- Compose the kona pipeline with Celestia-specific data source (`CelestiaDADataSource` wrapping `EthereumDataSource`).
- Provide the `CelestiaDAWitnessExecutor` consumed by `programs/range/celestia`.

## NOT Responsible For
- Host-side fetching (`utils/celestia/host`).
- Other DA layers.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `CelestiaDAWitnessExecutor` | generic over Oracle + BlobProvider | Implements `WitnessExecutor` for Celestia |
| `CelestiaDASource` (wrapper) | wraps `EthereumDataSource` | Dual-stacks L1 settlement + Celestia blobs |

## Dependencies
- Refer to `arch/dependency.md`. Direct deps: `op-succinct-client-utils`, `hana-celestia`, `hana-oracle`, kona stack.

## Relevant Flows
- See `core-flows/range-program-execution.md`.

## Module-Specific Pitfalls

[Pitfall] Must wrap Ethereum source — Celestia derivation depends on L1 batches for settlement.
