---
name: "utils-elfs"
description: "Pre-built ELF binary registry — feature-gated range ELFs and one aggregation ELF embedded via include_bytes!"
---
# utils/elfs Module

## Responsibilities
- Expose pre-built SP1 ELF binaries as static `&[u8]` constants via `include_bytes!`.
- Feature-gate the range ELF by DA: Ethereum / Celestia / EigenDA.

## NOT Responsible For
- Building or signing ELFs at runtime.
- Embedding secrets.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `RANGE_ELF_EMBEDDED` (feature-gated) | static `&'static [u8]` | DA-specific range program ELF |
| `AGGREGATION_ELF` | static `&'static [u8]` | Aggregation program ELF |
| `range-elf-bump` | static `&'static [u8]` | Updated range program variant (see `elf/` directory at repo root) |

## Dependencies
- Refer to `arch/dependency.md`. Used by `proof-utils` (static include).

## Relevant Flows
- See `conventions/feature-types.md` § ELF Embedding.

## Module-Specific Pitfalls

[Rule] ELFs live under `/elf/` at the repo root and are checked in. Updates must be reproduced via the external Docker build pipeline (`Dockerfile`); never patch the byte content directly.

[Pitfall] Adding a new DA layer requires both a new feature flag in this crate and a matching `cfg_if` branch in `utils/proof::initialize_host()`.
