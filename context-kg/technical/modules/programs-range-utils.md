---
name: "programs-range-utils"
description: "Shared async driver for range zkVM programs — pipeline init, executor.run, BootInfo commit"
---
# programs/range/utils Module

## Responsibilities
- Provide the common range-program driver invoked by `programs/range/{ethereum,celestia,eigenda}` `main()`.
- Construct the `OraclePipeline`, wire in the DA-specific `WitnessExecutor`, run the driver, and commit `BootInfoStruct`.

## NOT Responsible For
- DA-specific logic — that lives in `utils/{eth,celestia,eigenda}/client`.
- Host-side work.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| Range driver | rollup config, oracle, blob provider, executor | Composed from generics in caller |

## Dependencies
- Refer to `arch/dependency.md`. Pulls in `op-succinct-client-utils`, `kona-proof`, `kona-driver`, `sp1-zkvm`.

## Relevant Flows
- See `core-flows/range-program-execution.md`.

## Module-Specific Pitfalls

[Pitfall] Generic over `WitnessExecutor<O, B, …>` — type bounds differ per DA (EigenDA adds a third generic `E: EigenDAPreimageProvider`). Forgetting the third generic in EigenDA causes confusing compile errors.
