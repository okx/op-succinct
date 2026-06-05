---
name: "fault-proof-proposer"
description: "Fault-proof proposer flow — game creation, typed proof dispatch (ZK/TEE), defense (prove), resolution, bond claiming"
---
# Fault-Proof Proposer Flow

## Entry Point
`fault-proof/bin/proposer.rs::main()` → `OPSuccinctProposer::new(config, signer, providers)` → `proposer.run()`.

## Primary Entities
`OPSuccinctProposer`, `Game` (cached), `GameStatus`, `ProposalStatus`, `ProofType` (sol! enum: TEE=0, ZK=1), `Anchor Game`, `Canonical Head`, `DisputeGameFactoryInstance`, `XLayerOPSuccinctFaultDisputeGame`, `AnchorStateRegistry`, `TeeHostClient` (optional, configured via `TEE_HOST_URL`).

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
| 5 | `spawn_pending_operations()` — evaluate 5 task types and spawn (host verification / game creation / defense / resolution / bond claim) | `proposer.rs` |
| 5a | `spawn_host_verification_task()` (opt-in, `ENABLE_HOST_VERIFICATION=true`) — snap baseline to `canonical_head` on startup, fetch `get_finalized_l2_block_number` as ceiling, split `[last_verified+1, ceiling]` into chunks of `host_verification_chunk_size`, per-chunk: `host.fetch()` + `host.run()` (native kona), update `last_verified_l2_block` atomically on success, increment `HostVerificationErrors` gauge on failure | `proposer.rs`, `host_verification.rs` |
| 6 | `spawn_game_creation_task()` — check capacity, vkey match, finalized L2 block; **when `enable_host_verification=true`, gate on `last_verified_l2_block >= target`** instead of `get_finalized_l2_block_number`; `handle_game_creation` → `generate_range_proofs` → `generate_agg_proof` → factory.create() | `proposer.rs` |
| 7 | (fast finality) `spawn_game_proving_task()` — dispatches to `prove_game` which selects ZK or TEE path based on game state; updates `ProposalStatus` to `*ValidProofProvided` | `proposer.rs` |
| 8 | `spawn_game_defense_tasks()` — prove defense for IN_PROGRESS + Challenged games, prioritized by deadline; `prove_game` dispatches by proof type (see Proof Dispatch below) | `proposer.rs` |
| 9 | `handle_game_resolution()` — find `should_attempt_to_resolve` games (owned, parent resolved, game over); submit `resolve()` | `proposer.rs` |
| 10 | `claim_bonds()` — finalized + credit > 0 games; submit `claimCredit(signer)` | `proposer.rs` |
| 11 | Sleep `fetch_interval`; loop | `proposer.rs` |

## Proof Dispatch (`prove_game`)

`prove_game(game_address, start_block, end_block)` is the entry point for both fast-finality and defense proving. It reads `claimData()` to determine proof type:

1. If `counteredBy == Address::ZERO` (unchallenged) → use `config.default_proof_type`
2. If challenged → read `challengedProofType()` from on-chain
3. Route to `prove_game_zk` (prefix `0x01`) or `prove_game_tee` (prefix `0x00`)

**[Rule] `counteredBy == Address::ZERO` MUST be checked BEFORE reading `challengedProofType()`** — Solidity default for ProofType is TEE (0). Without this guard, unchallenged games incorrectly route to TEE.

### ZK Path (`prove_game_zk`)

Existing flow: range split → concurrent SP1 range proofs → `get_agg_proof_stdin` → SP1 aggregation → `0x01 ++ agg_proof.bytes()` → `game.prove()`.

### TEE Path (`prove_game_tee`)

| Step | Action |
|------|--------|
| 1 | Verify `tee_client` is `Some` (constructed at startup when `TEE_HOST_URL` is set) |
| 2 | Split block range into sub-ranges (same `range_split_count.split()` as ZK) |
| 3 | Concurrent sub-range execution (`buffer_unordered(max_concurrent)`): |
| 3a | → `host.fetch()` + `host.run()` → WitnessData |
| 3b | → `witness_data.into_parts()` → `DefaultWitnessData` → `rkyv::to_bytes()` |
| 3c | → `tee_client.submit_task(witness_bytes)` → task_id |
| 3d | → `tee_client.wait_for_proof(task_id)` (with `tokio::time::timeout`) → proof_bytes |
| 3e | → `unpack_proof_bytes(proof_bytes)` (`abi_decode_params`) → (RangeJournal, signature) |
| 3f | → `journal_to_boot_info(&journal)` → BootInfoStruct |
| 4 | `tee_client.get_attestation()` → attestation bytes (one per batch) |
| 5 | `get_agg_proof_stdin_tee(sigs, attestation, boot_infos, headers, ...)` → SP1Stdin |
| 6 | `prover.generate_agg_proof(sp1_stdin)` → agg_proof |
| 7 | `0x00 ++ agg_proof.bytes()` → `game.prove()` |
| 8 | Returns `(tx_hash, 0, 0)` — TEE path reports zero instruction cycles and SP1 gas |

### Startup Validation

`startup_validations()` now includes: if `default_proof_type == TEE && tee_host_url.is_none()` → bail with human-readable error before entering main loop.

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
| TEE host unreachable | `prove_game_tee` fails | Game stays `Challenged`; retried on next loop iteration |
| TEE task status `Failed` | `prove_game_tee` fails | Failure message logged; no partial proof submitted on-chain |
| Enclave restarts mid-batch (attestation signer changes) | Agg proof fails on-chain verification | Proposer logs revert; full batch retried next iteration |
| TEE poll timeout exceeded (`TEE_TASK_TIMEOUT`) | `prove_game_tee` fails | `tokio::time::timeout` fires; game stays `Challenged` for retry |
| `default_proof_type == TEE` but `tee_host_url` unset | Startup halts | Fail-fast with human-readable error |

## Flow-Specific Pitfalls

[Pitfall] Duplicate sibling games on retry — when `tx_confirmation_timeout` is too low, a retry can land a second game with identical output root. Correct approach: raise timeout to ≥180s on slow networks.

[Pitfall] No explicit "same output_root + extra_data in one cycle" guard — relies on `tx_confirmation_timeout` + network latency as an implicit dedupe.

[Pitfall] `CHALLENGER_WINS` invalidates subtree but child proving tasks may already be in flight; `remove_subtree()` doesn't cancel them. Correct approach: track and cancel descendant tasks on parent resolution.

[Pitfall] Proving task deadlock — fast finality, standard defense, and TEE defense all share `max_concurrent_defense_tasks`; a hung proving task (ZK or TEE) can deadlock new defenses. TEE tasks additionally risk indefinite slot occupation if the poll loop lacks a timeout. TODO at `proposer.rs:1834` to split budgets.

[Pitfall] `get_finalized_l2_block_number()` may silently return `None` (node not synced); game creation pauses without surfacing the cause. Correct approach: alert on extended silence via metrics.

[Pitfall] Proof generation interrupt — if the prover process is killed mid-proof, `JoinHandle` never completes and the task lingers forever. Correct approach: add `tokio::time::timeout` wrapper and prover-side hard deadline.

[Pitfall] `serde_json::to_value().unwrap()` in `backup.rs:136-137` panics the proposer on corruption; consider a graceful skip.
