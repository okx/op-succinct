---
name: "concurrency"
description: "Concurrency pitfalls — task management, nonce serialization, chain locks, backup save"
---
# Concurrency Pitfalls

## Nonce Conflicts

[Pitfall] Multiple async tasks calling `Signer::send_transaction_request` concurrently race nonces on the same address. Trigger: parallel proving tasks or background bond-claim loop. Correct approach: always wrap `Signer` in `SignerLock` (`Arc<Mutex<Signer>>`). `SignerLock::address()` is lock-free; `SignerLock::send_transaction_request*()` acquires the mutex for the full RPC round-trip. Affected modules: `validity/src/proposer.rs`, `fault-proof/src/proposer.rs`, `fault-proof/src/challenger.rs`.

## Task Map Cleanup

[Pitfall] `fault-proof/src/proposer.rs` and `validity/src/proposer.rs` use `TaskMap = Arc<Mutex<HashMap<TaskId, (JoinHandle, …)>>>`. Tasks that panic or hang never report back; `handle_completed_tasks()` only sees `JoinHandle`s that finished. Trigger: prover process killed mid-proof, or panic before DB write. Correct approach: wrap proving futures in `tokio::time::timeout`; always update DB status before spawning so orphan detection (`set_orphaned_tasks_to_failed`) finds them. Affected modules: `fault-proof/src/proposer.rs:1637-1680, 2087-2190`, `validity/src/proposer.rs:1346-1390`.

## Chain Lock Race

[Pitfall] `validity/src/db/client.rs::is_chain_locked` compares `NOW() > NOW() - interval` — clock skew or DB restart can falsely release the lock. Trigger: multi-host deployment where DB and proposer clocks drift. Correct approach: use Postgres `CURRENT_TIMESTAMP` consistently, validate signer address on lock acquisition. Affected module: `validity/src/proposer.rs` startup + `update_chain_lock()` per iteration.

## Backup Save Panic

[Resolved] `fault-proof/src/backup.rs`: the main `save()` path now uses `.context()` error propagation instead of `.unwrap()`. The remaining `.unwrap()` calls are in a test-only schema assertion, not the production save path.

## Fast Finality vs Defense Concurrency

[Pitfall] `fault-proof/src/proposer.rs:1242-1250, 1834`: fast-finality proving and standard defense both consume `max_concurrent_defense_tasks`. TEE proving tasks also share this same budget. Trigger: hung proving task (ZK or TEE). Correct approach: separate budgets (TODO at line 1834). Affected module: `fault-proof/src/proposer.rs`.

## TEE Poll Loop Timeout

[Pitfall] `fault-proof/src/tee_client.rs::wait_for_proof` polls `GET /tee/task/{id}` in a loop while status is `Running`. Without an outer timeout, a stuck TEE task (TEE host bug, network partition returning `Running` indefinitely) permanently occupies a defense slot.
**Trigger**: TEE host hangs or network partition returns `Running` status indefinitely for one or more tasks.
**Correct**: Wrap the poll loop in `tokio::time::timeout(Duration::from_secs(task_timeout), poll_future)`. The `task_timeout` config field (env `TEE_TASK_TIMEOUT`, default 14400s) mirrors the ZK path's `proof_provider.timeout`.

```rust
// WRONG — loops forever if TEE host never returns Finished/Failed
loop {
    let status = poll_task(task_id).await?;
    match status { "Running" => sleep(interval).await, ... }
}

// CORRECT — bounded by task_timeout
tokio::time::timeout(self.task_timeout, async {
    loop {
        let status = poll_task(task_id).await?;
        match status { "Running" => sleep(interval).await, ... }
    }
}).await.context("TEE task timed out")?
```

[Rule] Every async poll loop in proposer code (ZK or TEE) must have an outer `tokio::time::timeout` to prevent indefinite slot occupation.
**Module**: `fault-proof/src/tee_client.rs`
**Source**: Adversarial review finding #1 (XLOP-1090)
**Date**: 2026-06-04
**Hit count**: 1

## Preimage Store Lock Contention

[Pitfall] `utils/host/src/witness_generation/preimage_witness_collector.rs` and `online_blob_store.rs` wrap inner providers in `Arc<Mutex<…>>`. Holding the lock during heavy oracle operations stalls peers. Trigger: high-throughput witness generation. Correct approach: clone the inner provider via `Arc`, release the lock before fetching, never nest locks.

## CHALLENGER_WINS Subtree Race

[Pitfall] `fault-proof/src/proposer.rs:217-227`, `lib.rs:192-207`: when parent resolves `CHALLENGER_WINS`, `remove_subtree()` purges descendants but does NOT cancel their in-flight `JoinHandle`s. Trigger: child game has a pending proving task at the moment parent resolves. Correct approach: track and cancel descendant tasks on parent resolution.

