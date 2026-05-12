---
name: "utils-ethereum-client"
description: "zkVM-guest Ethereum DA client utilities — pipeline composition for blob-based L2 derivation"
---
# utils/ethereum/client Module

## Responsibilities
- Compose the kona pipeline with `EthereumDataSource` driven by `OracleBlobProvider`.
- Provide `ETHDAWitnessExecutor<O, B>` consumed by `programs/range/ethereum`.

## NOT Responsible For
- Host-side fetching (`utils/ethereum/host`).
- Other DA layers.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `ETHDAWitnessExecutor<O, B>` | 2-generic Oracle + BlobProvider | Implements `WitnessExecutor` for Ethereum |
| `OracleBlobProvider` | preimage-oracle-backed blob fetcher | Wired into pipeline |

## Dependencies
- Refer to `arch/dependency.md`. `op-succinct-client-utils`, `kona-proof`, `kona-derive`.

## Relevant Flows
- See `core-flows/range-program-execution.md`.

## Module-Specific Pitfalls

[Pitfall] Blob ordering: `BlobStore` consumes blobs LIFO; pre-reverse before instantiation.
