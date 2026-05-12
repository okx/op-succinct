---
name: "bindings"
description: "alloy-sol-types contract bindings — L2OutputOracle, DisputeGameFactory, FaultDisputeGame, AnchorStateRegistry, AccessManager"
---
# bindings Module

## Responsibilities
- Generated and hand-maintained alloy `sol!` bindings for the Solidity contracts under `contracts/`.
- Expose `*Instance` types (e.g. `DisputeGameFactoryInstance`, `OPSuccinctL2OOContract`) consumed by `validity` and `fault-proof`.

## NOT Responsible For
- Runtime logic.
- Reading ELFs or building artifacts.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `DisputeGameFactoryInstance` | alloy contract instance | DGF — creates dispute games |
| `OPSuccinctL2OOContract` | alloy contract instance | L2OutputOracle — receives validity-mode aggregated proofs |
| `OPSuccinctFaultDisputeGame` | alloy contract instance | FDG — per-game contract |
| `AnchorStateRegistry` | alloy contract instance | Tracks anchor + respected game type |
| `AccessManager` | alloy contract instance | Role-based access control |

## Dependencies
- Refer to `arch/dependency.md`. Only `alloy-sol-types`.

## Relevant Flows
- See `core-flows/fault-proof-proposer.md` and `core-flows/fault-proof-challenger.md` for how each binding is used.

## Module-Specific Pitfalls

[Rule] Never hand-write contract calldata encoding — always go through the generated `*Instance` methods.

[Pitfall] Regenerating bindings from updated Solidity must preserve the `*Instance` suffix and method signatures; downstream code matches them by name.
