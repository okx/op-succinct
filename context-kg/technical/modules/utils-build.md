---
name: "utils-build"
description: "SP1 ELF build helpers — currently most build_program calls are commented out; ELFs are built externally"
---
# utils/build Module

## Responsibilities
- Provide `sp1_build::build_program_with_args` invocations for the range / aggregation programs.
- Today: all entry points are commented out. ELF compilation happens **externally** via Docker (`tag v6.1.0`).

## NOT Responsible For
- Running proofs.
- RPC.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| (none active) | — | All `build_program` calls in `src/lib.rs` are intentionally commented out |

## Dependencies
- Refer to `arch/dependency.md` (would depend on `sp1-build` when active).

## Relevant Flows
- See `conventions/feature-types.md` § ELF Embedding.

## Module-Specific Pitfalls

[Warning] Re-enabling `build_program_with_args` from inside the workspace will trigger SP1 native-binary build scripts that may be blocked by host-machine endpoint security (e.g. macOS Santa). Prefer the external Docker pipeline.
