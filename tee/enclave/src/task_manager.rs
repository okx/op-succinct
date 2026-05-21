//! In-enclave task manager for the async `POST/poll` HTTP API.
//!
//! Key invariants:
//!
//! - **Single map**: `HashMap<TaskId, Arc<TaskEntry>>` guarded by an outer
//!   `parking_lot::Mutex`. The map lock is held only for the duration of an
//!   insert / remove / scan — never across `.await`. Per-task long-lived
//!   state (phase / status) sits behind an inner `tokio::sync::Mutex` on
//!   each `TaskEntry`.
//! - **Caller-allocated `task_id`**: the host generates a UUID v4 and sends
//!   it as `x-task-id`. We validate shape but never invent IDs. This makes
//!   POST idempotent w.r.t. the network: the same `x-task-id` always maps
//!   to the same enclave-side task.
//! - **Cooperative cancel**: dropping the future at the next `.await` is the
//!   tokio idiom; we don't try to instrument every kona internal. The
//!   `oneshot::Receiver<()>` races against the pipeline future inside
//!   `spawn_task` via `tokio::select!`.
//! - **TTL GC**: see [`crate::gc`].

use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy_sol_types::Eip712Domain;
use parking_lot::Mutex as PlMutex;
use tokio::sync::{Mutex as TokioMutex, oneshot};
use tracing::{info, warn};
use xlayer_tee_types::{
    CreateTaskResponse, DeleteTaskResponse, ErrorKind, RangeTaskResponse, TaskListResponse,
    TaskPhase, TaskStateView, TaskStatusView, TaskSummary,
};

use crate::{error::Error, runner::run_pipeline};

/// Default for `max_inflight_tasks` when caller passes 0.
fn default_max_inflight() -> usize {
    std::thread::available_parallelism()
        .map(|n| (n.get() / 2).max(1))
        .unwrap_or(2)
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// Outer state of a single task. `state` is held across `.await` (so it's a
/// tokio mutex), `abort_tx` is fired-and-dropped (so it can be an option
/// behind a parking_lot mutex without crossing await — but tokio mutex is
/// also fine and matches lifetime of `state`, simpler).
///
/// `domain` is the EIP712 domain used to sign this task's response journal.
/// Captured per-task from the `x-eip712-chain-id` and
/// `x-eip712-verifying-contract` headers on `POST /tasks/range` so that
/// **the same EIF can serve any number of verifier contracts and L1 chains**
/// without re-build / re-attest.
pub struct TaskEntry {
    pub task_id: String,
    pub start_time_ms: u64,
    domain: Arc<Eip712Domain>,
    state: TokioMutex<TaskInnerState>,
    abort_tx: TokioMutex<Option<oneshot::Sender<()>>>,
}

#[derive(Debug)]
struct TaskInnerState {
    phase: TaskPhase,
    status: TaskStatusInternal,
    end_time_ms: Option<u64>,
}

#[derive(Debug)]
enum TaskStatusInternal {
    Running,
    Finished(Box<RangeTaskResponse>),
    Failed { kind: ErrorKind, message: String },
    Cancelled { at_phase: TaskPhase },
}

impl TaskStatusInternal {
    fn is_terminal(&self) -> bool {
        !matches!(self, Self::Running)
    }
}

impl TaskEntry {
    fn new(task_id: String, domain: Arc<Eip712Domain>) -> (Arc<Self>, oneshot::Receiver<()>) {
        let (abort_tx, abort_rx) = oneshot::channel();
        let entry = Arc::new(Self {
            task_id,
            start_time_ms: now_ms(),
            domain,
            state: TokioMutex::new(TaskInnerState {
                phase: TaskPhase::Pending,
                status: TaskStatusInternal::Running,
                end_time_ms: None,
            }),
            abort_tx: TokioMutex::new(Some(abort_tx)),
        });
        (entry, abort_rx)
    }

    /// Called from inside the pipeline to advance the phase indicator.
    pub async fn set_phase(&self, phase: TaskPhase) {
        let mut s = self.state.lock().await;
        s.phase = phase;
    }

    async fn snapshot_view(&self) -> TaskStateView {
        let s = self.state.lock().await;
        TaskStateView {
            task_id: self.task_id.clone(),
            status: match &s.status {
                TaskStatusInternal::Running => TaskStatusView::Running,
                TaskStatusInternal::Finished(resp) => {
                    TaskStatusView::Finished(Box::new((**resp).clone()))
                }
                TaskStatusInternal::Failed { kind, message } => {
                    TaskStatusView::Failed { kind: *kind, message: message.clone() }
                }
                TaskStatusInternal::Cancelled { at_phase } => {
                    TaskStatusView::Cancelled { at_phase: *at_phase }
                }
            },
            phase: s.phase,
            start_time_ms: self.start_time_ms,
            end_time_ms: s.end_time_ms,
        }
    }

}

/// Outcome of [`TaskManager::create`].
pub enum CreateOutcome {
    Created(CreateTaskResponse),
    AlreadyExists(CreateTaskResponse),
}

pub struct TaskManager {
    tasks: PlMutex<HashMap<String, Arc<TaskEntry>>>,
    pcr0: [u8; 32],
    max_inflight: usize,
    /// How long a terminal entry stays in the map before GC removes it.
    pub(crate) ttl_ms: u64,
}

impl TaskManager {
    pub fn new(pcr0: [u8; 32], max_inflight: usize, ttl_secs: u64) -> Arc<Self> {
        let cap = if max_inflight == 0 { default_max_inflight() } else { max_inflight };
        info!(max_inflight = cap, ttl_secs, "TaskManager initialized");
        Arc::new(Self {
            tasks: PlMutex::new(HashMap::new()),
            pcr0,
            max_inflight: cap,
            ttl_ms: ttl_secs.saturating_mul(1000),
        })
    }

    pub fn pcr0(&self) -> [u8; 32] {
        self.pcr0
    }

    pub fn max_inflight(&self) -> usize {
        self.max_inflight
    }

    pub fn inflight_count(&self) -> usize {
        // We count map entries whose status is Running. Since each entry
        // uses a tokio mutex (async-only lock), we don't try to read it
        // synchronously — we approximate by counting `end_time_ms == None`
        // requires await. Use map size minus terminal entries via try_lock:
        let map = self.tasks.lock();
        map.values()
            .filter(|e| e.state.try_lock().map(|s| !s.status.is_terminal()).unwrap_or(true))
            .count()
    }

    /// Submit a new task or return the existing one if `task_id` is already
    /// present (idempotent). Returns `Error::TooManyTasks` when the cap is
    /// reached **and the request would create a new entry** — idempotent
    /// hits on existing tasks bypass the cap.
    ///
    /// `domain` is the EIP712 domain (chainId + verifyingContract) that this
    /// specific task will sign under — caller parses it from per-request
    /// headers. Different tasks may carry different domains.
    pub fn create(
        self: &Arc<Self>,
        task_id: String,
        domain: Eip712Domain,
        witness_bytes: bytes::Bytes,
    ) -> Result<CreateOutcome, Error> {
        // Idempotent fast path: same id already present → just report state.
        {
            let map = self.tasks.lock();
            if let Some(existing) = map.get(&task_id) {
                return Ok(CreateOutcome::AlreadyExists(CreateTaskResponse {
                    task_id: existing.task_id.clone(),
                    accepted_at_ms: existing.start_time_ms,
                    already_existed: true,
                }));
            }
        }

        // Cap check + insert under the same lock to avoid two POSTs racing
        // past the cap.
        let domain_arc = Arc::new(domain);
        let (entry, abort_rx) = {
            let mut map = self.tasks.lock();
            // Re-check after acquiring the write-side lock.
            if let Some(existing) = map.get(&task_id) {
                return Ok(CreateOutcome::AlreadyExists(CreateTaskResponse {
                    task_id: existing.task_id.clone(),
                    accepted_at_ms: existing.start_time_ms,
                    already_existed: true,
                }));
            }
            let running = map
                .values()
                .filter(|e| e.state.try_lock().map(|s| !s.status.is_terminal()).unwrap_or(true))
                .count();
            if running >= self.max_inflight {
                return Err(Error::TooManyTasks {
                    inflight: running,
                    cap: self.max_inflight,
                });
            }
            let (entry, abort_rx) = TaskEntry::new(task_id.clone(), Arc::clone(&domain_arc));
            map.insert(task_id.clone(), Arc::clone(&entry));
            (entry, abort_rx)
        };

        let response = CreateTaskResponse {
            task_id: entry.task_id.clone(),
            accepted_at_ms: entry.start_time_ms,
            already_existed: false,
        };

        // Spawn the pipeline; it runs to completion or until abort_rx fires.
        let mgr = Arc::clone(self);
        tokio::spawn(spawn_task(mgr, Arc::clone(&entry), witness_bytes, abort_rx));

        Ok(CreateOutcome::Created(response))
    }

    pub async fn snapshot(&self, task_id: &str) -> Option<TaskStateView> {
        let entry = {
            let map = self.tasks.lock();
            map.get(task_id).cloned()
        }?;
        Some(entry.snapshot_view().await)
    }

    /// Fire the abort channel if the task is still running. Returns the
    /// `was_running` flag for the wire response.
    pub async fn cancel(&self, task_id: &str) -> Result<DeleteTaskResponse, Error> {
        let entry = {
            let map = self.tasks.lock();
            map.get(task_id).cloned()
        }
        .ok_or_else(|| Error::TaskUnknown(task_id.to_string()))?;

        let was_running = {
            let mut tx_guard = entry.abort_tx.lock().await;
            if let Some(tx) = tx_guard.take() {
                let _ = tx.send(()); // ignore error: receiver may already be dropped
                true
            } else {
                false
            }
        };

        Ok(DeleteTaskResponse { task_id: task_id.to_string(), was_running })
    }

    /// Snapshot of all current tasks, bucketed by terminal status.
    pub async fn list(&self) -> TaskListResponse {
        // Clone Arcs out of the map under the short parking_lot lock.
        let entries: Vec<Arc<TaskEntry>> = {
            let map = self.tasks.lock();
            map.values().cloned().collect()
        };

        let mut running = Vec::new();
        let mut finished = Vec::new();
        let mut failed = Vec::new();
        let mut cancelled = Vec::new();

        for entry in entries {
            let s = entry.state.lock().await;
            let summary = TaskSummary {
                task_id: entry.task_id.clone(),
                phase: s.phase,
                start_time_ms: entry.start_time_ms,
                end_time_ms: s.end_time_ms,
            };
            match &s.status {
                TaskStatusInternal::Running => running.push(summary),
                TaskStatusInternal::Finished(_) => finished.push(summary),
                TaskStatusInternal::Failed { .. } => failed.push(summary),
                TaskStatusInternal::Cancelled { .. } => cancelled.push(summary),
            }
        }

        TaskListResponse { running, finished, failed, cancelled }
    }

    /// Run one pass of TTL eviction. Called by the GC loop.
    pub async fn gc_tick(&self) {
        if self.ttl_ms == 0 {
            return;
        }
        let now = now_ms();
        let candidates: Vec<Arc<TaskEntry>> = {
            let map = self.tasks.lock();
            map.values().cloned().collect()
        };

        let mut evict = Vec::new();
        for entry in candidates {
            let s = entry.state.lock().await;
            if let Some(end) = s.end_time_ms {
                if now.saturating_sub(end) >= self.ttl_ms {
                    evict.push(entry.task_id.clone());
                }
            }
        }
        if evict.is_empty() {
            return;
        }
        let mut map = self.tasks.lock();
        for id in &evict {
            map.remove(id);
        }
        info!(evicted = evict.len(), "TaskManager GC removed terminal tasks past TTL");
    }

    // ----- helpers used by spawn_task -------------------------------------

    async fn mark_finished(&self, entry: &TaskEntry, resp: RangeTaskResponse) {
        let mut s = entry.state.lock().await;
        s.status = TaskStatusInternal::Finished(Box::new(resp));
        s.phase = TaskPhase::Terminal;
        s.end_time_ms = Some(now_ms());
    }

    async fn mark_failed(&self, entry: &TaskEntry, err: Error) {
        let kind = err.to_wire_kind();
        let message = err.to_string();
        let mut s = entry.state.lock().await;
        s.status = TaskStatusInternal::Failed { kind, message };
        s.phase = TaskPhase::Terminal;
        s.end_time_ms = Some(now_ms());
    }

    async fn mark_cancelled(&self, entry: &TaskEntry) {
        let mut s = entry.state.lock().await;
        let at_phase = s.phase;
        s.status = TaskStatusInternal::Cancelled { at_phase };
        s.phase = TaskPhase::Terminal;
        s.end_time_ms = Some(now_ms());
    }
}

/// Top-level future per task: race the pipeline against the abort channel.
async fn spawn_task(
    mgr: Arc<TaskManager>,
    entry: Arc<TaskEntry>,
    witness_bytes: bytes::Bytes,
    mut abort_rx: oneshot::Receiver<()>,
) {
    let domain = Arc::clone(&entry.domain);
    let pcr0 = mgr.pcr0;
    let entry_for_pipeline = Arc::clone(&entry);

    let result = tokio::select! {
        // abort_rx fires when DELETE handler takes & sends on abort_tx.
        // Either side completing cancels the other (tokio future drop).
        _ = &mut abort_rx => {
            warn!(task_id = %entry.task_id, "task cancelled before completion");
            mgr.mark_cancelled(&entry).await;
            return;
        }
        res = run_pipeline(entry_for_pipeline, witness_bytes, domain, pcr0) => res,
    };

    match result {
        Ok(response) => {
            info!(
                task_id = %entry.task_id,
                l2_block_number = response.journal.l2_block_number,
                "task finished",
            );
            mgr.mark_finished(&entry, response).await;
        }
        Err(e) => {
            warn!(task_id = %entry.task_id, err = %e, "task failed");
            mgr.mark_failed(&entry, e).await;
        }
    }
}

/// Validate `task_id` shape — UUID v4 canonical form (36 chars with hyphens).
pub fn validate_task_id(id: &str) -> Result<(), Error> {
    uuid::Uuid::parse_str(id)
        .map(|_| ())
        .map_err(|e| Error::InvalidTaskId(format!("{id}: {e}")))
}
