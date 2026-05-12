---
name: "utils-celestia-host"
description: "Host-side Celestia DA utilities — blob fetching, blobstream oracle, witness generation"
---
# utils/celestia/host Module

## Responsibilities
- Implement `OPSuccinctHost` for Celestia.
- `fetch_args`, `calculate_safe_l1_head` (uses `get_celestia_safe_head_info`), `get_finalized_l2_block_number`.
- Celestia-specific witness generator (composes `PreimageWitnessCollector` + `OnlineBlobStore` with `CelestiaDADataSource`).

## NOT Responsible For
- Ethereum / EigenDA support.
- zkVM-guest execution.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `CelestiaHost` (impl `OPSuccinctHost`) | rollup config, Celestia RPC | DA host impl |
| Celestia witness generator | uses `hana-host` | Generates `DefaultWitnessData` for Celestia range program |

## Dependencies
- Refer to `arch/dependency.md`. `hana-host`, `hana-blobstream`, `hana-oracle`, `op-succinct-host-utils`, `op-succinct-celestia-client-utils`.

## Relevant Flows
- See `core-flows/witness-generation.md`.

## Module-Specific Pitfalls

[Pitfall] Safe-head computation must use the Blobstream oracle, not the generic +20 block offset; the `--safe_db_fallback` flag is intentionally ignored for Celestia.
