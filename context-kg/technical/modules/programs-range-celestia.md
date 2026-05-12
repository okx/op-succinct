---
name: "programs-range-celestia"
description: "zkVM-guest range program for Celestia DA — derives via hana-blobstream oracle wrapping Ethereum L1"
---
# programs/range/celestia Module

## Responsibilities
- SP1 zkVM guest binary.
- Read `DefaultWitnessData` from stdin.
- Run `CelestiaDAWitnessExecutor` (composes `EthereumDataSource` + `CelestiaDADataSource`).
- Commit `BootInfoStruct`.

## NOT Responsible For
- Ethereum-only or EigenDA-only flows.
- Blobstream RPC fetching (only verification inside the guest).

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `CelestiaDAWitnessExecutor<O, B>` | wraps `EthereumDataSource` for L1 settlement | Dual-stacked DA |
| `CelestiaDADataSource` | from `hana-celestia` | Celestia blob source |

## Dependencies
- Refer to `arch/dependency.md`. Pulls in `hana-celestia`, `hana-oracle`, kona stack.

## Relevant Flows
- See `core-flows/range-program-execution.md`.

## Module-Specific Pitfalls

[Pitfall] Celestia safe-head computation uses `get_celestia_safe_head_info()` — NOT simple +20 block offset; `--safe_db_fallback` is ignored.

[Pitfall] Witness data layout is the same `DefaultWitnessData` as Ethereum; differences are encoded inside Celestia oracle calls.
