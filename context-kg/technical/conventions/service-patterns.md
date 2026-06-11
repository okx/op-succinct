---
name: "service-patterns"
description: "Service patterns: signer dispatch, witness collection, polling, retries, locking"
---
# Service Patterns

## Signer Dispatch

`utils/signer/src/lib.rs` exposes a 4-arm `Signer` enum:

```
Signer::Web3Signer | Signer::LocalSigner | Signer::CloudHsmSigner | Signer::XLayerRemoteSigner
```

[Convention] Construct via `Signer::from_env()` — priority order: XLayer → CloudHSM (GCP-KMS) → Web3Signer → LocalSigner. Each arm exposes `send_transaction_request_with_timeout(rpc, tx_request, timeout_secs)`.

[Rule] Wrap every production `Signer` in `SignerLock` (`Arc<Mutex<Signer>>`); always call `.address()` lock-free and `.send_transaction_request_*()` under the mutex — prevents concurrent senders from racing nonces.

[Rule] `LocalSigner` is for tests and dev only; production must use one of the remote variants.

## XLayer Remote Signing Flow

`utils/signer/src/xlayer_remote_client.rs` implements the OKX-specific signer protocol:

1. Detect `OperateType` from the tx selector via `detect_operate_type()` — maps to one of `Proposer(20)`, `ChallengerResolveClaim(21)`, `ChallengerResolve(22)`, `ChallengerClaimCredit(23)`, `Prove(27)`, `Challenge(28)`.
2. Build `OtherInfo` JSON with base tx fields + selector-specific business params (e.g. `gameType`/`rootClaim`/`extraData` for Proposer; `claimIndex`/`numToResolve` for ResolveClaim; `proofBytes`/`operateType` for TEE Prove).
3. Build sorted JSON for `XLayerSignRequest` (alphabetical keys).
4. POST to `request_sign_uri` with `accessKey` + `sign` headers (signature = `base64(AES-ECB(sha256_hex(sorted_url_values + body), secret_key))`).
5. Poll `query_sign_uri` via GET with `userId` / `orderId` / `projectSymbol` query params; retry up to `MAX_SIGNING_RETRIES = 3` with `RETRY_DELAY = 5s`; total poll budget = 300 × 1s = 5 min.
6. Server returns hex-encoded signed transaction; decode via `hex::decode` + `TxEnvelope::decode_2718`.

[Rule] `XLayerConfig.secret_key` must be 16/24/32 bytes (AES-128/192/256). Empty `access_key` OR `secret_key` skips auth entirely (mirrors Go `addAuth`).

## Witness Collection (Host Side)

`utils/host/src/witness_generation/traits.rs::WitnessGenerator` async trait:

1. `get_executor()` returns the DA-specific `WitnessExecutor`.
2. `get_sp1_stdin()` builds the SP1 stdin bundle.
3. Default `run(preimage_chan, hint_chan)` wraps the oracle in `PreimageWitnessCollector` and the blob provider in `OnlineBlobStore`, runs the executor, then unlocks and returns `WitnessData`.

[Convention] Implement only `get_executor` + `get_sp1_stdin` in new DA layers; never override `run()`.

[Rule] `PreimageWitnessCollector` and `OnlineBlobStore` both wrap inner providers in `Arc<Mutex<…>>`; release the lock before heavy operations to avoid deadlock.

## Proof Polling

`utils/proof/src/lib.rs::ClusterProofHandle`:

```
proof_id, proof_output_id, consecutive_poll_failures
```

[Convention] `validity::proposer::process_proof_request_status` polls `cluster_poll_proof` (or `sp1-sdk::NetworkProver::get_proof_status`); set deadlines at submission time (`auction_deadline`, `proving_deadline`); reconstruct handle from DB JSON on restart.

[Rule] After `MAX_CONSECUTIVE_POLL_FAILURES = 3` consecutive poll errors, transition to `RequestStatus::Failed`.

## Concurrent Task Management

`fault-proof/src/proposer.rs::TaskMap` and `validity/src/proposer.rs::TaskMap`:

- `Arc<Mutex<HashMap<TaskId, (JoinHandle, …)>>>` — track in-flight async tasks per request.
- `handle_completed_tasks()` polls finished handles each iteration; updates `ProposerState` cache.
- Concurrency caps: `max_concurrent_witness_gen`, `max_concurrent_proof_requests`, `max_concurrent_defense_tasks`, `fast_finality_proving_limit`.

[Pitfall] Tasks that fail to update DB or panic mid-flight remain in the map until next `handle_completed_tasks()`; ensure DB status is written before spawning the task.

## TEE Host Task Management

`fault-proof/tee/host/src/task_manager.rs::TaskManager`:

- **Two-level locking**: `Mutex<HashMap<String, Arc<Mutex<TaskEntry>>>>` — outer lock protects map insert/remove/lookup (take `Arc` clone, release immediately); inner per-task mutex protects individual task state mutations.
- **Separate dedup mutex**: `Mutex<HashMap<B256, DedupEntry>>` — keccak256 computed outside lock; only HashMap ops inside (p99 ≤ 5ms).
- **No .await inside any mutex guard** — sequential lock-release-reacquire pattern throughout.
- **Cancellation**: `oneshot::Sender<()>` + `tokio::select! { biased; }` in background delivery coroutine provides immediate preemption on DELETE.
- **Terminal one-shot**: `set_finished`/`set_failed`/`set_cancelled` are no-ops if task is already terminal.
- **Resident witness budget**: `AppState.resident_witness_bytes: Arc<AtomicUsize>` tracks total in-flight witness bytes. Pre-check before body read rejects with `BufferFull` when budget exceeded (soft limit, `Ordering::Relaxed`). `ResidentGuard` RAII type increments on create, decrements on drop — held by delivery coroutine, released on coroutine exit (success/failure/cancel).

[Convention] When implementing per-task or per-entity concurrent management with in-memory HashMap, prefer the two-level lock pattern over a single global lock. Heavy computation (ABI encoding, hashing) must happen outside the global lock scope.

[Rule] Lock ordering: never hold both the registry mutex and dedup mutex simultaneously. Use sequential lock-release-reacquire to avoid deadlocks.

## Chain Lock (validity)

`validity/src/db/client.rs::is_chain_locked` / `add_chain_lock` / `update_chain_lock`:

- Table `chain_locks (l1_chain_id, l2_chain_id, ...)` with `ON CONFLICT` upsert.
- Lock duration = `loop_interval`; renewed every iteration.

[Rule] Startup must call `is_chain_locked()` and bail if another proposer holds the lock on the same `(L1, L2)` pair — prevents duplicate proposers.

[Pitfall] Naive `NOW() > NOW() - interval` comparison; clock skew across DB and proposer hosts can cause false releases. Consider deterministic Postgres `CURRENT_TIMESTAMP` only.

## Backup / Restart

`fault-proof/src/backup.rs::ProposerBackup`:

- Periodic JSON snapshot of `ProposerState` to file (`backup_path` env).
- Restore on `try_init()`; one in-flight save at a time, gated by a semaphore.

[Pitfall] `serde_json::to_value().unwrap()` in the save path panics the proposer on corruption; consider a graceful skip.

## Logging

`utils/host/src/logger.rs::setup_logger()` configures `tracing-subscriber` + `tracing-opentelemetry`:

- Hard-coded filter directives suppress noisy modules (`sp1_*`, `kona_*`, `execute`, `boot_loader`).
- Both stdout (human) and OTLP exporter.

[Convention] Call `setup_logger()` exactly once at binary `main()` entry; never inside library code.

## Sensitive-Data Redaction

[Rule] `XLayerConfig::Debug` impl redacts `access_key` / `secret_key` as `***REDACTED***`. The `[xlayer] >>>` HTTP log lines never include `accessKey`/`sign` headers (only the URL, method, body, status, and response body).

[Convention] Any new field that holds key material must follow the same redaction pattern; reviewers should reject diffs that print raw key material.
