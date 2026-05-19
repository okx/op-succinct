---
name: "scripts-utils"
description: "Operator CLI tools — config generation, cost estimation, preflight checks, fetch helpers"
---
# scripts/utils Module

## Responsibilities
- Library + 8 CLI binaries for operator workflows: `config`, `cost_estimator`, `block_data`, `fetch_l2oo_config`, `fetch_and_save_proof`, `fetch_fault_dispute_game_config`, `gen_sp1_test_artifacts`, `preflight`.
- Shared lib (`src/lib.rs`, `src/config_common.rs`) exposes `HostExecutorArgs` with `effective_batch_size()` resolution and `get_shared_config_data()` for contract-config generation.

## NOT Responsible For
- Submitting on-chain transactions.
- Long-running services.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `HostExecutorArgs` | `start`, `end`, `batch_size`, etc. | Shared CLI args parser |
| `get_shared_config_data()` | range/agg vkey hashes + verifier address | Used in config generation |

## Dependencies
- Refer to `arch/dependency.md`. `op-succinct-host-utils`, `op-succinct-proof-utils`, `op-succinct-bindings`.

## Relevant Flows
- N/A — one-shot CLI usage.

## Module-Specific Pitfalls

[Pitfall] Batch-size resolution precedence (`effective_batch_size`): explicit `--batch-size` > `(--start --end)` range as one batch > `DEFAULT_BATCH_SIZE` (10). Easy to mis-interpret as "default 10 even when range given".

[Pitfall] Genesis block intentionally excluded from config fetch (block 0 disallowed); documented as a NOTE.
