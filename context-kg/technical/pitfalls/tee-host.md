---
name: "tee-host"
description: "TEE host coordination layer pitfalls — Instant vs SystemTime, dedup lifecycle, rkyv decode patterns"
---
# TEE Host Pitfalls

## Instant Cannot Produce Wall-Clock Timestamps

[Pitfall] `std::time::Instant` is monotonic-only — it cannot produce ISO 8601 strings for API responses. If an API contract specifies absolute timestamps (e.g. `"startTime": "2026-05-28T08:15:23.124+00:00"`), using `Instant` alone forces a relative format like `"42s ago"` which changes on every call and is not machine-parseable by upstream consumers.

**Trigger**: Designing a task metrics endpoint that needs to report start/end times in a standard format, while only storing `Instant` for elapsed-time calculations.

**Correct approach**: Store `SystemTime` (or `chrono::DateTime<Utc>`) alongside `Instant` at task creation. Use `SystemTime` for API-facing timestamps and `Instant` for internal elapsed-time arithmetic. Alternatively, compute and cache the ISO 8601 string at creation time.

```rust
pub struct TaskEntry {
    pub created_at: Instant,           // for elapsed calculations
    pub created_at_wall: SystemTime,   // for API response timestamps
    // ...
}
```

[Rule] Any task/metrics struct that exposes timestamps in a northbound API must store wall-clock time separately from monotonic time.

**Module**: `fault-proof/tee/host/src/server.rs`
**Source**: Code Review A-08, findings R3-1/R5-1
**Date**: 2026-06-02
**Hit count**: 1

---

## Task Removal Must Always Clear Dedup Entry

[Pitfall] When a task is removed from the registry (for any reason), its associated dedup entry in the `DedupMap` must also be cleared. If only the task is removed but the dedup entry survives, proposer re-submission of the same witness hits the stale dedup entry, gets the old `task_id`, then `GET /tee/task/{id}` returns 10004 (not found). This creates a livelock lasting up to `dedup_ttl_secs` (300s default) until the sweeper cleans the orphan.

**Trigger**: Multiple code paths remove tasks (query handler on enclave-404+submitted, DELETE handler, monitor loop, sweeper). If any path forgets to also clear the dedup entry, the inconsistency window opens.

**Correct approach**: Implement `remove_task()` as a single method that always looks up `TaskEntry.witness_hash` and removes both the task entry and the dedup entry atomically. All removal call sites use this one method.

```rust
impl TaskManager {
    pub fn remove_task(&self, task_id: &str) {
        let mut tasks = self.tasks.write().unwrap();
        if let Some(entry) = tasks.remove(task_id) {
            let mut dedup = self.dedup.lock().unwrap();
            dedup.remove(&entry.witness_hash);
        }
    }
}
```

[Rule] Never remove a task without also removing its dedup entry. Use a single `remove_task` method for all removal paths.

**Module**: `fault-proof/tee/host/src/task_manager.rs`
**Source**: Adversarial Review A-15, Finding #1 (Major); verified fixed in A-05 implementation
**Date**: 2026-06-02
**Hit count**: 1

---

## rkyv 0.8 Generic Decode Is Impractical

[Pitfall] Writing a generic `fn decode_rkyv<T: Archive>(bytes: &[u8]) -> Result<T>` with rkyv 0.8 requires complex trait bounds: `T: Archive`, `T::Archived: Deserialize<T, Strategy<Pool, rkyv::rancor::Error>>`, plus `Portable` constraints. The compiler error messages are opaque, and the bounds differ between `rkyv::access` and `rkyv::deserialize`. Three functions with identical structure but different concrete types look like duplication but are actually **coincidental** — they may diverge if one type needs custom error handling.

**Trigger**: Refactoring multiple rkyv decode functions into a single generic helper during code cleanup.

**Correct approach**: Keep concrete per-type decode functions (`decode_create_task_response`, `decode_task_state_view`, `decode_delete_task_response`). Each is ~8 lines. The trait-bound complexity of a generic version outweighs the duplication cost. If a shared pattern is truly needed, use a macro instead of generics.

[Rule] Do not force rkyv 0.8 decode into a generic function — use concrete per-type decoders; treat structural similarity as coincidental duplication.

**Module**: `fault-proof/tee/host/src/enclave_client.rs`
**Source**: Code Review A-08 (R2 assessment); TDD Summary A-06 (design decision #3)
**Date**: 2026-06-02
**Hit count**: 1
