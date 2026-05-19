---
name: "utils-eigenda-host"
description: "Host-side EigenDA utilities — commitment verification, witness generation, canoe proof construction"
---
# utils/eigenda/host Module

## Responsibilities
- Implement `OPSuccinctHost` for EigenDA.
- Build EigenDA-specific witness payload (`EigenDAWitnessData` with `eigenda_data` containing the canoe proof).
- Drive `hokulea-host-bin` for blob fetching and `canoe-sp1-cc-host` for canoe-proof preparation.

## NOT Responsible For
- Ethereum / Celestia support.
- zkVM-guest execution.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `EigenDAHost` (impl `OPSuccinctHost`) | rollup config, EigenDA RPC, canoe host | DA host impl |
| EigenDA witness generator | uses `hokulea-host-bin`, `hokulea-witgen` | Produces `EigenDAWitnessData` |

## Dependencies
- Refer to `arch/dependency.md`. Hokulea + canoe + op-succinct-eigenda-client + host-utils.

## Relevant Flows
- See `core-flows/witness-generation.md`.

## Module-Specific Pitfalls

[Pitfall] Canoe proof construction is expensive and happens on the host; the guest only verifies. Misalignment between host canoe-proof format and guest verifier expectations is silent in production until a real proof fails.

[Pitfall] Safe-head fallback mirrors Ethereum's +20 block offset; revisit if EigenDA finality assumptions tighten.
