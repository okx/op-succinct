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

## Dependencies
- Refer to `arch/dependency.md` for full dependency details.

## Relevant Flows
- See `core-flows/fault-proof-proposer.md` for game creation, defense (prove), resolution, and bond claiming.
- See `core-flows/fault-proof-challenger.md` for game monitoring, challenge, resolve, and claim.

## Module-Specific Pitfalls

[Pitfall] `fault-proof/src/proposer.rs:82-87`, `config.rs:82-88`: duplicate sibling games on retry. Trigger: tx times out before confirmation, proposer retries; both txs eventually land. Correct approach: raise `tx_confirmation_timeout` (≥180s on slow networks).

[Pitfall] `fault-proof/src/proposer.rs:1524-1566`: no explicit single-game-twice guard; relies on `tx_confirmation_timeout` + network latency as an implicit retry guard.

[Pitfall] `fault-proof/src/proposer.rs:217-227`, `lib.rs:192-207`: `CHALLENGER_WINS` invalidates the entire subtree. Trigger: child game has a pending proving task when parent resolves `CHALLENGER_WINS`. Correct approach: `remove_subtree()` is called, but task cleanup may race; ensure task cancellation on parent resolution.

[Pitfall] `fault-proof/src/proposer.rs:1242-1250, 1834`: fast-finality proving fills `max_concurrent_defense_tasks` and can deadlock defense. Mitigation: separate fast-finality concurrency budget; ensure provers have timeouts. TODO at line 1834 is to unify.

[Pitfall] `fault-proof/src/proposer.rs:1985-1988`, `lib.rs:86-113`: `get_finalized_l2_block_number()` may silently return `None`. Game creation skipped without error. Correct approach: alert on extended silence.

[Pitfall] `fault-proof/src/proposer.rs:1637-1680, 2087-2190`: proving task hangs forever if the prover process is killed; `JoinHandle` never completes. Correct approach: add prover-side timeout and explicit `tokio::time::timeout` wrapper.

[Pitfall] `fault-proof/src/backup.rs:136-137`: `serde_json::to_value().unwrap()` + `.as_object().unwrap()` panics the proposer on serialization failure. Correct approach: graceful skip with warn log.

[Warning] `fault-proof/src/challenger.rs:357-359, 375`: `sync_state()` recomputes `output_root` for every cached game every interval — O(n) L2 RPC calls. Scale issue on large game DAGs; consider lazy evaluation.

[Warning] `fault-proof/src/challenger.rs:78-85, 457-499`: `malicious_challenge_percentage > 0.0` is testing-only but has no env/feature gate to prevent accidental production enable.

## tz Submodule (Cargo feature `tz`)

`fault-proof/src/tz/` is a leaf submodule activated by `--features tz`. Adds support for the TradeZone (tz) L2 chain — a non-OP-Stack-compatible L2 where checkpoints are exposed via REST `GET /chain/confirmed_block_info` rather than `eth_getBlockByNumber("finalized")`, and rootClaims follow `keccak256(blockHash ‖ stateHash)` rather than the xlayer 4-field output-root formula.

| File | Responsibility |
|------|----------------|
| `tz/mod.rs` | Module root; re-exports `chain_client`, `config`, `l2_provider` |
| `tz/chain_client.rs` | `TzChainClient`, `TzBlockInfo`, `TzCacheMissError`; multi-endpoint failover; sync `std::sync::Mutex<HashMap<u64, TzBlockInfo>>` cache; `evict_below(anchor)` |
| `tz/l2_provider.rs` | `TzL2Provider` impl of `L2ProviderTrait`; `compute_tz_root_claim` formula; `get_next_proposal_block` interval gate |
| `tz/config.rs` | `TzConfig::{from_env, challenger_from_env}`; `parse_game_type`; `DEFAULT_TZ_GAME_TYPE = 1961` |
| `tz/proposer.rs` | Method-override `impl OPSuccinctProposer<P,H>::new_with_l2_provider` injecting trait-object L2 provider; reads `rollup_config_hash` from L1 via `factory.game_impl(...).rollupConfigHash().call()`; included in `proposer.rs` via `#[path = "tz/proposer.rs"] mod tz_impl;` |
| `tz/challenger.rs` | Method-override `impl OPSuccinctChallenger<P>::new_with_l2_provider`; included via the same `#[path]` pattern |

Two new binaries gated by `required-features = ["tz"]`:

| Binary | File | Lifecycle |
|--------|------|-----------|
| `tz-proposer` | `bin/tz_proposer.rs` | sync `main()` → `TzConfig::from_env()` → `unsafe { env::set_var("L2_RPC", ...) }` → tokio runtime → `TzChainClient` + `TzL2Provider` → `OPSuccinctProposer::new_with_l2_provider` → `run()` |
| `tz-challenger` | `bin/tz_challenger.rs` | Same as proposer plus a 60 s `tokio::spawn` background poll that pre-warms the checkpoint cache |

Field type changes in shared code (gated implicitly by impl): `OPSuccinctProposer.l2_provider` and `OPSuccinctChallenger.l2_provider` are now `Arc<dyn L2ProviderTrait + Send + Sync>` — the xlayer `L2Provider` is wrapped with `Arc::new(...)` in `new()`. Vtable indirection is dwarfed by network IO.

xlayer-vs-tz divergence sites in `proposer.rs` / `challenger.rs` are all `#[cfg]`-gated:

- `proposer.rs::startup_validations` — `validate_anchor_l2_block` skipped under `feature="tz"` (tz has no `eth_getBlockByNumber("finalized")`)
- `proposer.rs::on_chain_vkeys_match` — short-circuits to `Ok(true)` under `feature="tz"` (Phase 1 vkey-poisoning suppression; see ADR-009)
- `proposer.rs::should_create_game` — final target-selection step diverges (delegates to `L2ProviderTrait::get_next_proposal_block`); pre-checks remain shared
- `proposer.rs::handle_game_creation` — UUID one-shot (return `Ok(())` on existing game) under `feature="tz"`; xlayer keeps the while-loop increment retry
- `proposer.rs::fetch_game` — cache-miss tolerance (`TzCacheMissError` ⇒ keep game in `state.games`, skip rootClaim check)
- `proposer.rs::sync_state` — calls `evict_cache_below(anchor_game.l2_block)` at end-of-iteration under `feature="tz"`
- `proposer.rs::fetch_proposer_metrics` — skips `FinalizedL2BlockNumber` gauge under `feature="tz"`
- `challenger.rs::fetch_game` — cache-miss safe-skip (`TzCacheMissError` ⇒ cursor advances, no challenge tx, `state.games.insert` is bypassed)

Pitfalls: see `pitfalls/tz-binaries.md` (env-var coupling, unsafe set_var ordering) and `pitfalls/tz-cache.md` (eviction boundary, cache-key invariant, sync mutex discipline). Phase 1 design rationale and Phase 2 cutover sequence: `decisions/ADR-009-tz-phase-1-vkey-suppression.md`.
