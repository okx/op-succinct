---
name: "validity-proposer-loop"
description: "Validity proposer main loop — state transitions, run iteration, exception branches"
---
# Validity Proposer Loop

## Entry Point
`validity/bin/validity.rs::main()` → loads env, builds `DriverDBClient` (runs migrations), constructs `Proposer`, calls `Proposer::run()`.

## Primary Entities
`OPSuccinctRequest`, `RequestStatus`, `Proposer`, `OPSuccinctProofRequester`, `DriverDBClient`, `SignerLock`, `RequesterConfig`.

## State Transitions

| Current State | Trigger | Target State |
|--------------|---------|-------------|
| Unrequested | `make_proof_request` spawned | WitnessGeneration |
| WitnessGeneration | witness produced | Execution |
| Execution | `request_range_proof` / `request_agg_proof` succeeded | Prove |
| Prove | proof returned by network/cluster prover | Complete |
| Complete | `submit_agg_proofs` confirmed on-chain | Relayed |
| Prove | `auction_deadline` exceeded | Cancelled |
| Prove | `proving_deadline` exceeded OR 3 consecutive poll failures | Failed |
| WitnessGeneration / Execution / Prove | task panic / orphaned | Failed |

**[Rule] Terminal states must never be reversed**: `Relayed`, `Failed`, `Cancelled`.

## Normal Flow Steps

| Step | Action | Module |
|------|--------|--------|
| 1 | Read env, build `EnvironmentConfig`, instantiate `DriverDBClient` (with migrations), build `Proposer`, spawn `proposer.run()` | `bin/validity.rs`, `env.rs`, `db/client.rs`, `proposer.rs` |
| 2 | `Proposer::run()` enters infinite loop → `run_loop_iteration()` every `loop_interval` seconds | `proposer.rs` |
| 3 | `validate_contract_config()` — assert on-chain commitment equals `ProgramConfig` commitment | `proposer.rs` |
| 4 | `log_proposer_metrics()` — emit balance, chain heights, etc. | `proposer.rs` |
| 5 | `handle_ongoing_tasks()` — join completed `JoinHandle`s, update DB status | `proposer.rs` |
| 6 | `set_orphaned_tasks_to_failed()` — DB rows in WitnessGeneration/Execution with no task → Failed | `proposer.rs` |
| 7 | `handle_proving_requests()` — poll proof status (network or cluster), transition Prove → Complete | `proposer.rs`, `proof_requester.rs` |
| 8 | `add_new_ranges()` — call `get_finalized_l2_block_number`, identify gaps, split into ranges | `utils.rs`, `OPSuccinctHost` |
| 9 | `create_aggregation_proofs()` — bundle consecutive Complete ranges into Aggregation rows | `proposer.rs` |
| 10 | `request_queued_proofs()` — spawn tasks (capped by `max_concurrent_witness_gen` + `max_concurrent_proof_requests`) | `proposer.rs`, `proof_requester.rs` |
| 11 | `submit_agg_proofs()` — submit aggregated proof to L2OO/DGF using `SignerLock` | `proposer.rs`, `contract.rs` |
| 12 | `update_chain_lock()` — refresh chain lock to keep ownership | `db/client.rs` |
| 13 | Sleep `loop_interval` and repeat | `proposer.rs` |

## Exception Branches

| Trigger | State Change | Compensation |
|---------|-------------|-------------|
| Network timeout (`proving_timeout`) | Prove → Failed | `handle_failed_request`; `ProofRequestTimeoutErrorCount++`; range re-queued by `add_new_ranges` next iteration |
| `auction_deadline` exceeded | Prove → Cancelled | `network_prover.cancel_request`; `handle_cancelled_request` updates DB |
| Witness generation fails | WitnessGeneration → Failed (via task error caught in `handle_ongoing_tasks`) | `WitnessgenErrorCount++`; request re-queued if gap persists |
| Cluster poll fails 3+ times | Prove → Failed | `handle_failed_request`; `cluster_proof_handle` retained for debugging |
| Orphaned task (status without `JoinHandle`) | WitnessGeneration / Execution → Failed | `set_orphaned_tasks_to_failed`; retry next iteration |
| Commitment mismatch on-chain vs `ProgramConfig` | (none) | `validate_contract_config` errors; proposer sleeps 10s, retries (no auto-recovery) |
| Loop iteration error | (none) | Log + increment `TotalErrorCount`; sleep 10s; retry |

## Flow-Specific Pitfalls

[Pitfall] `proposer.rs:1034-1036` unwrap on `checkpointed_l1_block_number` and proof bytes — agg row reaches submission without these fields. Trigger condition: incomplete agg row. Correct approach: validate completeness in `create_aggregation_proofs` and filter incomplete rows before `submit_agg_proofs`.

[Pitfall] `request_queued_proofs` (`proposer.rs:1346-1390`) spawns tasks but doesn't synchronously join completed ones — completed tasks accumulate until next `handle_ongoing_tasks`. Trigger condition: tasks panic before updating DB. Correct approach: always write DB status before spawning the task; implement TTL cleanup for orphans.

[Pitfall] `proof_request_id` (BYTEA) vs `cluster_proof_handle` (JSON) coexist in the same row — code paths must NOT cross-read; no `proof_mode` column tracks which backend was used. Trigger condition: switching prover backend mid-run. Correct approach: add explicit `proof_mode` column.

[Pitfall] `tx_confirmation_timeout` defaults to 60s; on congested L1 the proposer may submit duplicate proofs. Trigger condition: slow L1 confirmation. Correct approach: raise to ≥180s on mainnet; add idempotency guard if retries enabled.
