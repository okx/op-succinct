---
name: "fault-proof"
description: "Fault-dispute proposer & challenger services — propose, prove, challenge, and resolve OP Stack dispute games"
---
# fault-proof Module

## Responsibilities
- Two daemons: `proposer` (creates `DisputeGame`s and defends them) and `challenger` (monitors all games and challenges invalid claims).
- Maintain a cached game DAG anchored at `AnchorStateRegistry`'s anchor game.
- Generate SP1 range + aggregation proofs to `prove()` games when challenged or for fast finality.
- Submit `challenge()` / `resolve()` / `resolveClaim()` / `claimCredit()` to `OPSuccinctFaultDisputeGame`.
- Periodic backup of `ProposerState` to disk for restart recovery.

## NOT Responsible For
- Submitting to `OPSuccinctL2OutputOracle` — that is `validity`'s responsibility.
- ELF artifact building — uses pre-built ELFs from `op-succinct-elfs`.
- Managing remote signer — delegates to `signer-utils::SignerLock`.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `Game` (cached) | `index`, `address`, `parent_index`, `l2_block`, `status`, `proposal_status`, `deadline`, ownership flags | In-memory game record |
| `GameStatus` | `IN_PROGRESS`, `DEFENDER_WINS`, `CHALLENGER_WINS` | Terminal on-chain state |
| `ProposalStatus` | `Unchallenged`, `Challenged`, `UnchallengedAndValidProofProvided`, `ChallengedAndValidProofProvided`, `Resolved` | Claim-level state |
| `ProposerIdentity` | `range_vkey`, `agg_vkey`, `rollup_config_hash` | Hardfork compatibility identity |
| `Anchor Game` | Latest finalized game | Read from `AnchorStateRegistry` |
| `Canonical Head` | Proposer's best-known parent for the next game | Recomputed each `sync_state()` |
| `TaskInfo` | `GameCreation`, `GameProving`, `GameResolution`, `BondClaim`, `HostVerification` | Task type enum for `TaskMap`; each variant maps to spawn/completion/failure handlers |
| `last_verified_l2_block` | `Arc<AtomicU64>` on `OPSuccinctProposer` | Highest L2 block that passed native host verification; written by HostVerification task, read atomically by `should_create_game` |

## Dependencies
- Refer to `arch/dependency.md` for full dependency details.

## Relevant Flows
- See `core-flows/fault-proof-proposer.md` for host verification, game creation, defense (prove), resolution, and bond claiming.
- See `core-flows/fault-proof-challenger.md` for game monitoring, challenge, resolve, and claim.

## Module-Specific Pitfalls

[Pitfall] `fault-proof/src/proposer.rs:82-87`, `config.rs:82-88`: duplicate sibling games on retry. Trigger: tx times out before confirmation, proposer retries; both txs eventually land. Correct approach: raise `tx_confirmation_timeout` (≥180s on slow networks).

[Pitfall] `fault-proof/src/proposer.rs:1524-1566`: no explicit single-game-twice guard; relies on `tx_confirmation_timeout` + network latency as an implicit retry guard.

[Pitfall] `fault-proof/src/proposer.rs:217-227`, `lib.rs:192-207`: `CHALLENGER_WINS` invalidates the entire subtree. Trigger: child game has a pending proving task when parent resolves `CHALLENGER_WINS`. Correct approach: `remove_subtree()` is called, but task cleanup may race; ensure task cancellation on parent resolution.

[Pitfall] `fault-proof/src/proposer.rs:1242-1250, 1834`: fast-finality proving fills `max_concurrent_defense_tasks` and can deadlock defense. Mitigation: separate fast-finality concurrency budget; ensure provers have timeouts. TODO at line 1834 is to unify.

[Pitfall] `fault-proof/src/proposer.rs:1985-1988`, `lib.rs:86-113`: `get_finalized_l2_block_number()` may silently return `None`. Game creation skipped without error. Correct approach: alert on extended silence.

[Pitfall] `fault-proof/src/proposer.rs:1637-1680, 2087-2190`: proving task hangs forever if the prover process is killed; `JoinHandle` never completes. Correct approach: add prover-side timeout and explicit `tokio::time::timeout` wrapper.

[Pitfall] `fault-proof/src/backup.rs:136-137`: `serde_json::to_value().unwrap()` + `.as_object().unwrap()` panics the proposer on serialization failure. Correct approach: graceful skip with warn log.

[Pitfall] `fault-proof/src/proposer.rs:1744`: zero `HOST_VERIFICATION_CHUNK_SIZE` causes infinite loop in `spawn_host_verification_task` inline chunk iteration. Correct approach: validate chunk_size > 0 at config parse or clamp before loop.

[Warning] `fault-proof/src/challenger.rs:357-359, 375`: `sync_state()` recomputes `output_root` for every cached game every interval — O(n) L2 RPC calls. Scale issue on large game DAGs; consider lazy evaluation.

[Warning] `fault-proof/src/challenger.rs:78-85, 457-499`: `malicious_challenge_percentage > 0.0` is testing-only but has no env/feature gate to prevent accidental production enable.
