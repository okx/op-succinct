---
name: "ADR-009-tz-phase-1-vkey-suppression"
description: "ADR: tz Phase 1 — short-circuit on_chain_vkeys_match + reuse cluster_setup_keys + accept window-of-risk for off-chain proof"
---

# ADR-009: tz Phase 1 vkey-poisoning suppression and accepted security tradeoffs

## Status

Accepted (Phase 1 only — Phase 2 cutover plan documented below)

## Date

2026-05-19

## Context

PRD §3.2 ("tz 的 SP1 ZK 证明生成流水线 ... 留 Phase 2") explicitly defers tz SP1 program development to a later phase. Phase 1 (this PR) ships off-chain `tz-proposer` / `tz-challenger` services that:

- Submit `TeeDisputeGame` (game type `1961`) proposals with `rootClaim = keccak256(blockHash ‖ stateHash)` derived from REST `/chain/confirmed_block_info`.
- Challenge invalid proposals by recomputing the same `rootClaim` locally.

The shared `op-succinct-fp` codebase, however, computes a `ProposerIdentity { range_vkey, agg_vkey, rollup_config_hash }` at construction time, and `OPSuccinctFaultDisputeGame` uses these vkeys to attribute games (`Game.is_owned`) and to gate proof generation. tz has no SP1 program in Phase 1, so any vkey it computes is structurally meaningless — but the type system still requires one.

Three options were considered:

1. **TD §4.5.1 / §4.9 spec**: skip `cluster_setup_keys()`, inline `CpuProver::setup(Elf::Static(range_elf))` against a 2–3 KB SP1 ELF skeleton committed at `fault-proof/elfs/tz-range.elf`. Rationale: avoid "poisoning" the local identity with xlayer-derived vkeys.
2. **Implementation-chosen path**: reuse `cluster_setup_keys()` as-is, accept that local vkeys derive from xlayer's `RANGE_ELF_EMBEDDED`, and rely on a `feature="tz"` short-circuit to neuter the comparison surface.
3. Build a real tz SP1 program now and remove the entire Phase 1 / Phase 2 split. **Rejected** — out of PRD scope.

## Decision

**Phase 1 implements option (2): reuse `cluster_setup_keys()` and short-circuit `on_chain_vkeys_match` to `Ok(true)` under `#[cfg(feature = "tz")]`.**

The full suppression cascade:

1. `tz/proposer.rs::new_with_l2_provider` calls `cluster_setup_keys().await?` from `utils/proof`. Local `ProposerIdentity` carries xlayer-derived `range_vkey` / `agg_vkey`.
2. `proposer.rs::on_chain_vkeys_match` short-circuits: under `#[cfg(feature = "tz")]` it returns `Ok(true)` without comparing local vs on-chain vkeys; the original xlayer comparison is preserved under `#[cfg(not(feature = "tz"))]`.
3. `Game.is_owned` (`fault-proof/src/lib.rs`) requires ALL THREE identity fields to match the on-chain values. Tz on-chain games carry tz-specific vkeys ⇒ `is_owned == false` for every tz game.
4. Every proposer-initiated proving / resolving / bond-claim path is filtered by `is_owned`, so they are structurally suppressed even though the `ProposerIdentity` log line prints xlayer vkey values.
5. Operators set `FAST_FINALITY_MODE=false` and `MAX_CONCURRENT_DEFENSE_TASKS=0` per TD §11.1, ensuring the proving worker pool stays empty as a defense-in-depth belt.
6. The startup `tracing::warn!("tz: Phase 1 — local proposer identity uses xlayer-derived placeholder vkeys; on_chain_vkeys_match is short-circuited to true. Phase 2 must wire up the real tz SP1 program and remove the short-circuit.")` (`tz/proposer.rs:89-93`) is the operator's "Phase 1 mode" indicator.

`tz_config.rollup_config_hash` is not part of `TzConfig`; instead `new_with_l2_provider` calls `factory.game_impl(game_type).rollupConfigHash().call()` to fetch it from L1 at construction time. This couples the local identity to the on-chain deployment and removes one operator env-var to misconfigure.

## Accepted security tradeoffs

The strategy is sound for Phase 1 but has two known limitations that Phase 2 must close:

1. **Multi-proposer window-of-risk**: After a `tz-proposer` restart, in-memory cache is empty. Until the background poll repopulates it (≤ 60 s for the challenger, the next `sync_state` tick for the proposer), a malicious external party can submit a `TeeDisputeGame` with an invalid `rootClaim` against an old `l2_block_number`. The proposer's `fetch_game` cache-miss tolerance (FR-5) writes that game into `state.games` without verifying its `rootClaim`. The challenger's cache-miss safe-skip (FR-7) advances its cursor past the game without challenging it. Net: an invalid game can persist in `state.games` and on-chain until proof phase. Phase 1 has no proof phase, so the game is left in `IN_PROGRESS` indefinitely; Phase 2's real SP1 proofs will fail to derive from an invalid parent state and naturally expose the fraud.
2. **`ProposerIdentity` log line is operationally misleading**: the startup banner prints xlayer-derived `range_vkey` / `agg_vkey` values, which an unaware operator could mistake for the active tz vkeys. Mitigated by the `tz: Phase 1 — short-circuit active` warning line at startup, which explicitly disclaims the values.

## Alternatives Considered

| Option | Pros | Cons | Decision |
|---|---|---|---|
| (1) Inline `CpuProver::setup` + tz-range.elf skeleton | Local identity reflects placeholder, not xlayer; matches TD spec | Requires committing 2–3 KB binary file; Phase 2 cutover replaces both ELF and short-circuit | Rejected (more moving parts for no behavior gain) |
| (2) Reuse `cluster_setup_keys` + short-circuit | No committed binary; ~80 LoC simpler; behavior-equivalent given `is_owned == false` cascade | Local identity log line is misleading; Phase 2 cutover must remove short-circuit AND replace `cluster_setup_keys` call | **Accepted** |
| (3) Implement real tz SP1 program now | No Phase 1 / Phase 2 split | Out of PRD scope; multi-quarter scope | Rejected |

## Phase 2 cutover sequence (when real tz SP1 program lands)

1. Add `op-succinct-elfs::TZ_RANGE_ELF_EMBEDDED` (or a tz-aware variant of `get_range_elf_embedded()` in `utils/proof/src/lib.rs`).
2. Replace the `cluster_setup_keys().await?` call at `tz/proposer.rs:83` with a tz-specific setup that loads the new ELF.
3. Remove the `Ok(true)` short-circuit in `proposer.rs::on_chain_vkeys_match` (lines `1041-1051`); the `#[cfg(not(feature = "tz"))]` mirror branch becomes the universal path.
4. Remove the network-mode `bail!` / `ensure!` in `tz/proposer.rs::new_with_l2_provider` once `MockProofProvider`'s constructor signature can accept the tz prover bundle.
5. Apply the `unsafe { env::set_var("L2_NODE_RPC", ...) }` companion (review-finding F-01, ADR follow-up).
6. Re-attempt deferred behavioral tests DM-9.7 / DM-9.8 / DM-10.9 once the bindings/forge/solc env blocker is resolved.

## Consequences

- **Positive**: Phase 1 ships ~80 LoC simpler with no committed binary; xlayer build is byte-identical; the `is_owned == false` cascade structurally suppresses all proof paths so the misleading vkey log line cannot cause behavioral harm.
- **Negative**: Phase 2 cutover is more involved (must remove short-circuit AND replace the `cluster_setup_keys` call), and a misconfigured operator could be confused by the `ProposerIdentity` log line.
- **Neutral**: The window-of-risk is bounded at the protocol level by the absence of finalization for unproved games, and at the operations level by the 60 s background polling cadence.

## Source

review-finding F-02, F-05 (TDD Summary A-06, Code Review A-08 M2/M3, Adversarial Review A-15)
