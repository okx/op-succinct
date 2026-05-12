---
name: "fault-proof-proposer"
description: "Fault-proof proposer flow — game creation, defense (prove), resolution, bond claiming"
---
# Fault-Proof Proposer Flow

## Entry Point
`fault-proof/bin/proposer.rs::main()` → `OPSuccinctProposer::new(config, signer, providers)` → `proposer.run()`.

## Primary Entities
`OPSuccinctProposer`, `Game` (cached), `GameStatus`, `ProposalStatus`, `Anchor Game`, `Canonical Head`, `DisputeGameFactoryInstance`, `OPSuccinctFaultDisputeGame`, `AnchorStateRegistry`.

## State Transitions

| Current State | Trigger | Target State |
|--------------|---------|-------------|
| (no game) | factory.create() emits `DisputeGameCreated` | Game created (IN_PROGRESS, Unchallenged) |
| Unchallenged | challenger.challenge() | Challenged |
| Unchallenged | proposer.prove() (fast finality) | UnchallengedAndValidProofProvided |
| Challenged | proposer.prove() | ChallengedAndValidProofProvided |
| IN_PROGRESS | resolve() — no valid challenge OR proof provided in deadline | DEFENDER_WINS |
| IN_PROGRESS | resolve() — challenge succeeded with no valid proof | CHALLENGER_WINS |
| any | claimCredit(recipient) after finalization | Credit claimed |

**[Rule] Terminal states must never be reversed**: `DEFENDER_WINS`, `CHALLENGER_WINS`.

## Normal Flow Steps

| Step | Action | Module |
|------|--------|--------|
| 1 | `try_init()` — validate anchor, game type, init bond, contract params, restore backup | `proposer.rs` |
| 2 | `sync_state()` — `sync_games` (backward walk from latest_index), `sync_anchor_game`, `compute_canonical_head` | `proposer.rs` |
| 3 | Periodic `backup()` — serialize `ProposerState` to JSON file (semaphore-gated) | `backup.rs` |
| 4 | `handle_completed_tasks()` — poll finished `JoinHandle`s, update cache + metrics | `proposer.rs` |
| 5 | `spawn_pending_operations()` — evaluate 4 task types and spawn (game creation / defense / resolution / bond claim) | `proposer.rs` |
| 6 | `spawn_game_creation_task()` — check capacity, vkey match, finalized L2 block; `handle_game_creation` → `generate_range_proofs` → `generate_agg_proof` → factory.create() | `proposer.rs` |
| 7 | (fast finality) `spawn_game_proving_task()` — generate proof and submit `prove()`; updates `ProposalStatus` to `*ValidProofProvided` | `proposer.rs` |
| 8 | `spawn_game_defense_tasks()` — prove defense for IN_PROGRESS + Challenged games, prioritized by deadline | `proposer.rs` |
| 9 | `handle_game_resolution()` — find `should_attempt_to_resolve` games (owned, parent resolved, game over); submit `resolve()` | `proposer.rs` |
| 10 | `claim_bonds()` — finalized + credit > 0 games; submit `claimCredit(signer)` | `proposer.rs` |
| 11 | Sleep `fetch_interval`; loop | `proposer.rs` |

## Exception Branches

| Trigger | State Change | Compensation |
|---------|-------------|-------------|
| New game in factory not in cache | (cache add) | Fetch full metadata; validate type + vkey + output root; drop silently if invalid |
| Output root mismatch (`compute != rootClaim`) | `is_invalid = true` | Flag for challenge in challenger; ignore in proposer (proposer never challenges its own subtree) |
| TX revert | (no cache change) | Log; do not retry within same cycle; re-evaluate next sync |
| TX timeout (`tx_confirmation_timeout`) | (no cache change) | Skip; rely on next `sync_state` to detect outcome; **risk: duplicate sibling games** |
| Parent not finalized | `should_attempt_to_resolve = false` | Wait for parent to resolve |
| Hardfork detected — `on_chain_vkeys_match() == false` | Game creation skipped | Log warning; operator must redeploy with new vkeys |
| Anchor mismatch (registry address vs factory.game_impl.anchorStateRegistry()) | Startup halts | Prevents misconfiguration |
| `CHALLENGER_WINS` on a parent | Children dropped | `remove_subtree()` purges descendants from cache |

## Flow-Specific Pitfalls

[Pitfall] Duplicate sibling games on retry — when `tx_confirmation_timeout` is too low, a retry can land a second game with identical output root. Correct approach: raise timeout to ≥180s on slow networks.

[Pitfall] No explicit "same output_root + extra_data in one cycle" guard — relies on `tx_confirmation_timeout` + network latency as an implicit dedupe.

[Pitfall] `CHALLENGER_WINS` invalidates subtree but child proving tasks may already be in flight; `remove_subtree()` doesn't cancel them. Correct approach: track and cancel descendant tasks on parent resolution.

[Pitfall] Proving task deadlock — fast finality and standard defense share `max_concurrent_defense_tasks`; a hung proving task can deadlock new defenses. TODO at `proposer.rs:1834` to split.

[Pitfall] `get_finalized_l2_block_number()` may silently return `None` (node not synced); game creation pauses without surfacing the cause. Correct approach: alert on extended silence via metrics.

[Pitfall] Proof generation interrupt — if the prover process is killed mid-proof, `JoinHandle` never completes and the task lingers forever. Correct approach: add `tokio::time::timeout` wrapper and prover-side hard deadline.

[Pitfall] `serde_json::to_value().unwrap()` in `backup.rs:136-137` panics the proposer on corruption; consider a graceful skip.
