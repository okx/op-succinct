---
name: "scripts-prove"
description: "CLI proving entrypoints — manual / batch proof generation for development and one-off jobs"
---
# scripts/prove Module

## Responsibilities
- CLI binaries: `agg` (aggregate proofs), `multi` (multi-block range), `save_program` (dump compiled program).
- Provide a library (`src/lib.rs`) of helpers used by the binaries: SP1 setup, host fetch, stdin construction.

## NOT Responsible For
- Long-running services (`validity` / `fault-proof` are separate daemons).
- Persistent state.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| CLI binaries | clap-parsed args | Entry points for manual proof runs |
| `op-succinct-prove` lib | host + proof helpers | Shared between binaries |

## Dependencies
- Refer to `arch/dependency.md`. `op-succinct-proof-utils`, `op-succinct-host-utils`, `op-succinct-client-utils`, `op-succinct-elfs`.

## Relevant Flows
- N/A — one-shot CLI invocations; consult `scripts/prove/bin/*.rs` for argument shapes.

## Module-Specific Pitfalls

[Pitfall] `CpuProver` creates its own tokio runtime — call inside `spawn_blocking` when used in async test harnesses.
