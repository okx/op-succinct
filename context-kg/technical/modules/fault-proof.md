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

### `tee/host` (`xlayer-tee-host`)

TEE host coordination layer — sits between the proposer and Nitro Enclave. Northbound: 4 JSON REST endpoints via axum (POST/GET/DELETE /tee/task, GET /tee/info). Southbound: rkyv-over-HTTP to enclave via hyper HTTP/1.1 (vsock for production, TCP for dev, compile-time feature flag). First inbound HTTP service in op-succinct.

| Module | Contents |
|--------|----------|
| `server.rs` | axum router, 4 handlers (create/query/delete task, attestation), delivery coroutine, monitor loop, sweeper loop |
| `task_manager.rs` | `TaskManager` (in-memory registry), `TaskEntry`, `TaskStatus`, `DedupMap` (std::sync::Mutex), witness hash dedup, state transitions, sweep/retention |
| `enclave_client.rs` | `EnclaveClient` (hyper HTTP/1.1), vsock/TCP compile-time switch, 3-attempt retry with backoff, rkyv decode (concrete per-type decoders) |
| `packager.rs` | `pack_proof_bytes`: `RangeJournalWire` → `RangeJournal` → `(journal, sig).abi_encode_params()` |
| `config.rs` | TOML + `TEE_HOST__<SECTION>__<FIELD>` env overlay, defaults, exit(2) on missing config |
| `error.rs` | `HostError` enum, `code() -> i32` mapping to 4 bands (0/10001/10004/20001) |
| `api.rs` | `ApiResponse<T>` JSON envelope with `IntoResponse` |
| `main.rs` | Entry: CLI → config → `AppState` → spawn background tasks → axum serve |

[Rule] `xlayer-tee-host` uses `abi_encode_params()` (NOT `abi_encode()`) for proofBytes — the extra 32-byte offset prefix from `abi_encode()` breaks on-chain `abi.decode(proofBytes, (RangeJournal, bytes))`.

[Rule] `std::sync::Mutex` for dedup map (NOT `tokio::sync::Mutex`) — critical section contains only HashMap operations, no `.await`.

[Rule] Host uses 4 numeric error codes (0/10001/10004/20001) as an intentional deviation from the "no centralized error codes" convention — this is a proposer contract requirement.

[Rule] Task removal must always clear the associated dedup entry — see `pitfalls/tee-host.md`.

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
