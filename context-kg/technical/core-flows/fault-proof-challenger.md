---
name: "fault-proof-challenger"
description: "Fault-proof challenger flow — monitor games, typed challenge (ProofType), resolve, claim bonds"
---
# Fault-Proof Challenger Flow

## Entry Point
`fault-proof/bin/challenger.rs::main()` → `OPSuccinctChallenger::new()` → `challenger.run()`.

## Primary Entities
`OPSuccinctChallenger`, `Game` (cached), `GameStatus`, `ProposalStatus`, `ProofType` (sol! enum: TEE=0, ZK=1), `DisputeGameFactoryInstance`, `XLayerOPSuccinctFaultDisputeGame`.

## State Transitions

Challenger consumes the same state machine as proposer (see `fault-proof-proposer.md` § State Transitions). Distinct transitions the challenger drives:

| Current State | Trigger | Target State |
|--------------|---------|-------------|
| Unchallenged | challenger.challenge() — output root mismatch OR parent lost | Challenged |
| Challenged | resolve() — no valid proof in deadline | CHALLENGER_WINS |

## Normal Flow Steps

| Step | Action | Module |
|------|--------|--------|
| 1 | `sync_state()` — load new games from factory; sync status of every cached game; mark for challenge/resolve/claim based on output-root validity and parent state | `challenger.rs` |
| 2 | `handle_game_challenging()` — for every game flagged should-challenge, submit `challenge(config.challenge_proof_type)` with bond via `XLayerOPSuccinctFaultDisputeGame` | `challenger.rs` |
| 3 | `handle_game_resolution()` — for every flagged should-resolve, submit `resolve()` | `challenger.rs` |
| 4 | `handle_bond_claiming()` — finalized + credit > 0 games; submit `claimCredit(signer)` | `challenger.rs` |
| 5 | Sleep `fetch_interval`; loop | `challenger.rs` |

## Exception Branches

| Trigger | State Change | Compensation |
|---------|-------------|-------------|
| `malicious_challenge_percentage > 0.0` | Challenger randomly challenges valid games | Test mode only; logs in red |
| Output root computation fails | (game flag not set) | Logged; re-tried next sync |
| TX revert | (no state change) | Re-evaluate next cycle |
| Game evicted (finalized + no credit) | Cache cleanup | Stops monitoring |

## Flow-Specific Pitfalls

[Pitfall] `sync_state()` recomputes output root for every cached game every interval — O(n) L2 RPC calls. At scale this becomes a bottleneck. Correct approach: lazy evaluation, or cache invalidation tied to L2 block updates.

[Pitfall] `malicious_challenge_percentage` is testing-only but has no explicit env/feature gate; accidental production enable is possible. Correct approach: gate behind a build feature like `--features test-malicious`.

[Pitfall] Bond claim double-spend — `claimCredit()` reverts on insufficient credit and gets retried; safe only if contract credit tracking is atomic. Mitigation: contract enforces atomicity; nothing to do.
