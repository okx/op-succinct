---
name: "validity"
description: "Validity proposer service — Postgres-backed daemon that proves L2 ranges and submits aggregated proofs to L2OutputOracle/DGF"
---
# validity Module

## Responsibilities
- Long-running daemon (`validity/bin/validity.rs`) monitoring L1 finality and L2 progress.
- Enqueue range and aggregation proofs into Postgres (`requests` table).
- Drive proof lifecycle: witness generation → execution → proving (network or cluster) → completion → on-chain relay.
- Submit aggregated proofs to `OPSuccinctL2OutputOracle` (or `DisputeGameFactory`) with `SignerLock`.
- Hold a chain lock to prevent concurrent proposers on the same `(L1, L2)` pair.

## NOT Responsible For
- Generating proofs locally — delegates to `op-succinct-proof-utils`.
- Signing — delegates to `op-succinct-signer-utils::SignerLock`.
- Challenging dispute games — that is `fault-proof`'s responsibility.
- DA-specific block fetching — `op-succinct-host-utils` + the active DA feature.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `OPSuccinctRequest` | `id`, `block_range`, `status`, `request_type`, `request_mode`, `proof_request_id`, `cluster_proof_handle`, `proof_bytes` | One DB row per proof request |
| `RequestStatus` | `Unrequested`, `WitnessGeneration`, `Execution`, `Prove`, `Complete`, `Relayed`, `Failed`, `Cancelled` | Lifecycle enum (i16-backed) |
| `RequestType` | `Range = 0`, `Aggregation = 1` | Proof category |
| `RequestMode` | `Real = 0` (SP1 network/cluster), `Mock = 1` | Execution backend |
| `ProgramConfig` | `range_{p,v}key`, `agg_{p,v}key`, commitment hashes | Cryptographic identity used to validate on-chain |
| `RequesterConfig` | Chain IDs, contract addresses, gas/cycle/concurrency caps, timeouts, signer | Runtime config |
| `DriverDBClient` | `PgPool`, migration runner | Single Postgres handle for the proposer |

## Dependencies
- Refer to `arch/dependency.md` for full dependency details.

## Relevant Flows
- See `core-flows/validity-proposer-loop.md` for the run loop, state transitions, and exception branches.

## Module-Specific Pitfalls

[Pitfall] `validity/src/proposer.rs:1034-1036`: `unwrap()` on `checkpointed_l1_block_number` and proof bytes during agg submission. Trigger: aggregation row reaches submission without these fields. Correct approach: validate completeness in `create_aggregation_proofs` and filter incomplete rows before reaching `submit_agg_proofs`.

[Pitfall] `validity/src/db/client.rs:57`: `PgInterval::try_from(interval).unwrap()` panics on very large durations. Correct approach: propagate as `Result`.

[Pitfall] `validity/src/db/types.rs:24-38, 49-57`: `From<i16>` for `RequestStatus`/`RequestType`/`RequestMode` panics on out-of-range DB values. Correct approach: use `TryFrom` with explicit default fallback, or assert schema integrity at migration time.

[Pitfall] `validity/src/proposer.rs:1346-1390`: `request_queued_proofs` spawns up to `max_concurrent_proof_requests` tasks but does not synchronously join completed handles — memory leak if tasks panic before updating DB.

[Pitfall] Migration 04 (`cluster_proof_handle`) coexists with `proof_request_id` (BYTEA). No documentation tracks which prover backend wrote a given row. Correct approach: add an explicit `proof_mode` column.

[Warning] Chain-lock release relies on `NOW() > NOW() - interval` SQL — clock skew or DB restart can falsely release the lock; validate signer address on lock acquisition.

[Warning] `tx_confirmation_timeout` defaults to 60s; on congested L1 the tx may land after timeout and the proposer submits a duplicate. Recommend ≥180s on mainnet.
