---
name: "programs-range-ethereum"
description: "zkVM-guest range program for Ethereum DA — derives + executes a range of L2 blocks with blob data from L1"
---
# programs/range/ethereum Module

## Responsibilities
- SP1 zkVM guest binary (`#[sp1_zkvm::entrypoint!(main)]`).
- Read `DefaultWitnessData` (rkyv) from stdin.
- Run `ETHDAWitnessExecutor` over the kona pipeline with `EthereumDataSource`.
- Commit `BootInfoStruct` to the public output.

## NOT Responsible For
- Celestia / EigenDA derivation.
- Host-side work.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `DefaultWitnessData` | preimages, blob data | rkyv-encoded witness |
| `ETHDAWitnessExecutor<O, B>` | Generic over Oracle + BlobProvider | DA-specific driver |

## Dependencies
- Refer to `arch/dependency.md`. Direct deps: `op-succinct-ethereum-client-utils`, `op-succinct-client-utils`, `programs/range/utils`, `kona-proof`, `kona-derive`, `sp1-zkvm`.

## Relevant Flows
- See `core-flows/range-program-execution.md`.

## Module-Specific Pitfalls

[Pitfall] Blob ordering: `BlobStore` consumes blobs LIFO (reversed list); pre-reverse before instantiation in the host-side witness gen.
