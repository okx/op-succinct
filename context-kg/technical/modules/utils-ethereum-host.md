---
name: "utils-ethereum-host"
description: "Host-side Ethereum DA utilities — blob sidecar fetching, safe-head estimator, witness generation"
---
# utils/ethereum/host Module

## Responsibilities
- Implement `OPSuccinctHost` for Ethereum.
- Fetch L1 blob sidecars via beacon API.
- Safe L1 head estimator with optional `--safe_db_fallback` for environments where the estimator can't see ahead.
- Ethereum witness generator producing `DefaultWitnessData`.

## NOT Responsible For
- Celestia / EigenDA flows.
- zkVM-guest execution.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `EthereumHost` (impl `OPSuccinctHost`) | rollup config, L1 + beacon clients | DA host impl |
| Ethereum witness generator | `PreimageWitnessCollector` + `OnlineBlobStore` | Produces `DefaultWitnessData` |

## Dependencies
- Refer to `arch/dependency.md`. `op-succinct-ethereum-client-utils`, `op-succinct-host-utils`, kona stack.

## Relevant Flows
- See `core-flows/witness-generation.md`.

## Module-Specific Pitfalls

[Pitfall] L1 head safety: estimator requires an L1 block beyond the batch posting block. SafeDB fallback activated via `--safe_db_fallback`. Documented as FIXME upstream.

[Pitfall] Isthmus withdrawals_root handling — pre-Isthmus headers carry `nil`; we fall back to `eth_getProof` for the message-passer storage root.
