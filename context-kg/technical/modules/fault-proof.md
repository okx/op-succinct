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

## Sub-Crates

### `tee/types` (`xlayer-tee-types`)

Shared contract crate for the TEE fault-proof path. Contains only types, constants, and pure functions — no business logic, no runtime, no network stack. Serves as the single source of truth for enclave/host/proposer/verifier protocol definitions.

| Module | Contents |
|--------|----------|
| `journal.rs` | `RangeJournal` (sol! struct), 168-byte `pack()`, `RangeJournalWire` (rkyv mirror), `RangeTaskResponse` |
| `wire.rs` | HTTP protocol constants (endpoint paths, headers, content types, body limit) |
| `task.rs` | `TaskPhase` state machine, `TaskStatusView`, task wire types (all rkyv-Archive) |
| `error.rs` | `ErrorKind` (13 variants), `status_code()`, `is_retryable()`, `ErrorResponse` (JSON) |

[Rule] `RangeJournal` field order and 168-byte pack layout are frozen from v0.1 — any reorder breaks existing signatures and on-chain ABI decoding. Golden-value regression test guards this in CI.

[Rule] This crate must never depend on witness crates — host must not gain witness parsing capability through this dependency.

[Rule] Consumers reference via `path = "…/tee/types"` (not `workspace.dependencies`) — each caller declares its own dependency.

### `tee/enclave` (`xlayer-tee-enclave`)

Nitro Enclave L2 replay and RangeJournal signing service. Runs inside an AWS Nitro Enclave (no network, no disk). Re-executes L2 block ranges via kona, verifies output roots, and signs 168-byte packed `RangeJournal` with secp256k1. Exposes an async task model (POST/GET/DELETE/list) over TCP (dev) or vsock (prod).

| Module | Contents |
|--------|----------|
| `main.rs` | Binary entry: init keys, start server (TCP dev / vsock prod) |
| `server.rs` | axum router (5 endpoints from wire constants + attestation) |
| `task_manager.rs` | Task registry, UUID idempotency, concurrency cap, cooperative cancellation |
| `runner.rs` | 4-phase pipeline: Deserialize → Boot → Kona → Sign |
| `witness.rs` | `check_bounds()` validation (claimed_l2_block_number > 0) |
| `signing.rs` | `sign_range_wire()` → keccak256(pack) + k256 prehash → 65-byte signature |
| `keys.rs` | `ENCLAVE_KEY` OnceLock (dev: Anvil#0 / vsock: OsRng) |
| `attestation.rs` | Dev marker attestation + prod NSM (cfg-gated) |
| `error.rs` | Internal Error enum + `CLAIM_MISMATCH_SENTINEL` + `to_wire_kind()` |
| `gc.rs` | Background TTL sweep loop for terminal tasks |

[Rule] `CLAIM_MISMATCH_SENTINEL` couples to `utils/client/src/witness/executor.rs:163` error format — pin deps and maintain a golden integration test. See `pitfalls/dependencies.md` "Upstream Error String Coupling".

[Rule] Dev key (`DEV_KEY_HEX`) is `#[cfg(not(feature = "vsock"))]` only — production builds use OsRng-generated key at startup.

[Rule] Build features: `tz` (enables tests with dev key) and `vsock` (production, enables NSM attestation + vsock listener). Mutually exclusive runtime paths.

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
