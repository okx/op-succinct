//! In-memory task registry.
//!
//! Holds task lifecycle + witness-hash dedup. Each task wraps in
//! `Arc<Mutex<>>` so per-task lock doesn't block the global map.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::{keccak256, B256};
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::{oneshot, Mutex};
use uuid::Uuid;

/// Optional display metadata passed via headers on POST `/tee/task`.
/// Informational only — host does not parse the witness body.
#[derive(Clone, Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskArgs {
    pub start_blk_height: Option<u64>,
    pub end_blk_height: Option<u64>,
    pub claimed_output_root: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub enum TaskStatus {
    Running(String),
    Finished,
    Failed(String),
    Cancelled,
}

impl TaskStatus {
    pub const fn is_terminal(&self) -> bool {
        !matches!(self, Self::Running(_))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskMetrics {
    pub start_time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
    pub witness_size_bytes: usize,
}

pub struct TaskState {
    pub task_id: String,
    pub args: TaskArgs,
    pub status: TaskStatus,
    pub witness_hash: B256,
    pub created_at: Instant,
    pub start_time: DateTime<Utc>,
    pub finished_at: Option<Instant>,
    pub witness_size_bytes: usize,
    pub abort_tx: Option<oneshot::Sender<()>>,
}

impl TaskState {
    pub fn metrics(&self) -> TaskMetrics {
        let elapsed = self.elapsed();
        let (end_time, duration) = if self.finished_at.is_some() {
            let end = self.start_time + chrono::Duration::from_std(elapsed).unwrap_or_default();
            (Some(end.to_rfc3339()), Some(format_duration(elapsed)))
        } else {
            (None, None)
        };
        TaskMetrics {
            start_time: self.start_time.to_rfc3339(),
            end_time,
            duration,
            witness_size_bytes: self.witness_size_bytes,
        }
    }

    fn elapsed(&self) -> Duration {
        self.finished_at
            .map(|t| t.saturating_duration_since(self.created_at))
            .unwrap_or_else(|| self.created_at.elapsed())
    }
}

pub struct TaskManager {
    tasks: Mutex<HashMap<String, Arc<Mutex<TaskState>>>>,
    dedup: Mutex<HashMap<B256, (String, Instant)>>,
    retention: Duration,
    dedup_ttl: Duration,
}

pub enum RegisterOutcome {
    /// New task accepted; receiver hands the cancel signal to the monitor.
    Created { task_id: String, abort_rx: oneshot::Receiver<()> },
    /// Same witness was submitted recently; existing task_id is returned and
    /// no new work is started.
    Duplicate(String),
}

impl TaskManager {
    pub fn new(retention_secs: u64, dedup_ttl_secs: u64) -> Self {
        Self {
            tasks: Mutex::new(HashMap::new()),
            dedup: Mutex::new(HashMap::new()),
            retention: Duration::from_secs(retention_secs),
            dedup_ttl: Duration::from_secs(dedup_ttl_secs),
        }
    }

    pub async fn register(&self, witness_body: &[u8], args: TaskArgs) -> RegisterOutcome {
        let witness_hash = keccak256(witness_body);

        {
            let mut dedup = self.dedup.lock().await;
            evict_stale(&mut dedup, self.dedup_ttl);
            if let Some((task_id, _)) = dedup.get(&witness_hash) {
                return RegisterOutcome::Duplicate(task_id.clone());
            }
        }

        // No host-level in-flight cap. Multiple concurrent tasks are allowed
        // up to the enclave's own `max_inflight`; if the enclave responds
        // with `TooManyTasks`, `spawn_task_monitor` keeps retrying the POST
        // (the task stays Running ("queued; enclave at capacity") until a
        // slot opens).
        let task_id = Uuid::new_v4().to_string();
        let (abort_tx, abort_rx) = oneshot::channel::<()>();
        let state = TaskState {
            task_id: task_id.clone(),
            args,
            status: TaskStatus::Running("submitting to enclave".into()),
            witness_hash,
            created_at: Instant::now(),
            start_time: Utc::now(),
            finished_at: None,
            witness_size_bytes: witness_body.len(),
            abort_tx: Some(abort_tx),
        };

        self.tasks
            .lock()
            .await
            .insert(task_id.clone(), Arc::new(Mutex::new(state)));
        self.dedup
            .lock()
            .await
            .insert(witness_hash, (task_id.clone(), Instant::now()));

        RegisterOutcome::Created { task_id, abort_rx }
    }

    pub async fn get(&self, task_id: &str) -> Option<Arc<Mutex<TaskState>>> {
        self.tasks.lock().await.get(task_id).cloned()
    }

    pub async fn contains(&self, task_id: &str) -> bool {
        self.tasks.lock().await.contains_key(task_id)
    }

    pub async fn set_progress(&self, task_id: &str, msg: impl Into<String>) {
        if let Some(state) = self.get(task_id).await {
            let mut s = state.lock().await;
            if matches!(s.status, TaskStatus::Running(_)) {
                s.status = TaskStatus::Running(msg.into());
            }
        }
    }

    /// Mark Finished. Keeps the dedup entry so a re-submission of the same
    /// witness returns the same task_id (idempotent re-poll for proof).
    pub async fn set_finished(&self, task_id: &str) {
        self.transition_terminal(task_id, TaskStatus::Finished).await;
    }

    /// Mark Failed. Evicts the dedup entry so a re-submission of the same
    /// witness creates a fresh task (Failed is treated as retryable).
    pub async fn set_failed(&self, task_id: &str, error: impl Into<String>) {
        if let Some(witness_hash) =
            self.transition_terminal(task_id, TaskStatus::Failed(error.into())).await
        {
            self.dedup.lock().await.remove(&witness_hash);
        }
    }

    /// Mark Cancelled and trigger the abort signal. Evicts dedup so a
    /// resubmission of the same witness can start fresh. Returns true if we
    /// actually flipped a Running task; false if absent / already terminal.
    pub async fn cancel(&self, task_id: &str) -> bool {
        let Some(state) = self.get(task_id).await else {
            return false;
        };
        let (was_running, witness_hash) = {
            let mut s = state.lock().await;
            let was_running = matches!(s.status, TaskStatus::Running(_));
            if let Some(tx) = s.abort_tx.take() {
                let _ = tx.send(());
            }
            if was_running {
                s.status = TaskStatus::Cancelled;
                s.finished_at = Some(Instant::now());
            }
            (was_running, s.witness_hash)
        };
        if was_running {
            self.dedup.lock().await.remove(&witness_hash);
        }
        was_running
    }

    pub async fn list_ids(&self) -> Vec<String> {
        self.tasks.lock().await.keys().cloned().collect()
    }

    /// Transition Running → `new_status`. Returns the task's witness_hash if
    /// the transition actually happened (so the caller can decide whether to
    /// evict from dedup). Returns `None` if the task is absent or already
    /// terminal — those are no-ops.
    async fn transition_terminal(
        &self,
        task_id: &str,
        new_status: TaskStatus,
    ) -> Option<B256> {
        let state = self.get(task_id).await?;
        let mut s = state.lock().await;
        if !matches!(s.status, TaskStatus::Running(_)) {
            return None;
        }
        s.status = new_status;
        s.finished_at = Some(Instant::now());
        s.abort_tx = None;
        Some(s.witness_hash)
    }

    async fn sweep(&self) {
        let cutoff = Instant::now() - self.retention;
        let mut to_remove = Vec::new();
        {
            let tasks = self.tasks.lock().await;
            for (id, state) in tasks.iter() {
                let s = state.lock().await;
                if s.status.is_terminal() && s.created_at < cutoff {
                    to_remove.push(id.clone());
                }
            }
        }
        if !to_remove.is_empty() {
            let mut tasks = self.tasks.lock().await;
            for id in &to_remove {
                tasks.remove(id);
            }
        }
        let mut dedup = self.dedup.lock().await;
        evict_stale(&mut dedup, self.dedup_ttl);
    }
}

fn evict_stale(dedup: &mut HashMap<B256, (String, Instant)>, ttl: Duration) {
    dedup.retain(|_, (_, ts)| ts.elapsed() < ttl);
}

/// Background loop removing terminal tasks past retention + expired dedup entries.
pub async fn run_retention_sweeper(manager: Arc<TaskManager>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    ticker.tick().await;
    loop {
        ticker.tick().await;
        manager.sweep().await;
    }
}

fn format_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms < 1_000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.1}s", d.as_secs_f64())
    } else {
        let s = d.as_secs();
        format!("{}m {}s", s / 60, s % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr() -> TaskManager {
        TaskManager::new(3600, 300)
    }

    fn assert_created(outcome: RegisterOutcome) -> (String, oneshot::Receiver<()>) {
        match outcome {
            RegisterOutcome::Created { task_id, abort_rx } => (task_id, abort_rx),
            other => panic!("expected Created, got {:?}", outcome_kind(&other)),
        }
    }

    fn outcome_kind(o: &RegisterOutcome) -> &'static str {
        match o {
            RegisterOutcome::Created { .. } => "Created",
            RegisterOutcome::Duplicate(_) => "Duplicate",
        }
    }

    #[tokio::test]
    async fn first_register_creates_new_task() {
        let m = mgr();
        let (id, _rx) = assert_created(m.register(b"w-1", TaskArgs::default()).await);
        assert!(uuid::Uuid::parse_str(&id).is_ok(), "task_id is uuid v4");
    }

    #[tokio::test]
    async fn same_witness_running_returns_duplicate() {
        let m = mgr();
        let (id1, _rx) = assert_created(m.register(b"w-1", TaskArgs::default()).await);
        match m.register(b"w-1", TaskArgs::default()).await {
            RegisterOutcome::Duplicate(id2) => assert_eq!(id1, id2),
            other => panic!("expected Duplicate, got {}", outcome_kind(&other)),
        }
    }

    #[tokio::test]
    async fn different_witness_while_one_running_creates_concurrent_task() {
        // The host no longer enforces single-in-flight; concurrent tasks
        // share the enclave's `max_inflight` budget (see `spawn_task_monitor`
        // retry loop for backpressure).
        let m = mgr();
        let (id1, _rx) = assert_created(m.register(b"w-1", TaskArgs::default()).await);
        let (id2, _rx) = assert_created(m.register(b"w-2", TaskArgs::default()).await);
        assert_ne!(id1, id2, "different witnesses must get distinct task_ids");
    }

    #[tokio::test]
    async fn finished_keeps_dedup_idempotent_repoll() {
        let m = mgr();
        let (id1, _rx) = assert_created(m.register(b"w-1", TaskArgs::default()).await);
        m.set_finished(&id1).await;
        match m.register(b"w-1", TaskArgs::default()).await {
            RegisterOutcome::Duplicate(id2) => assert_eq!(id1, id2),
            other => panic!("Finished must dedup, got {}", outcome_kind(&other)),
        }
    }

    #[tokio::test]
    async fn failed_evicts_dedup_so_retry_is_a_new_task() {
        let m = mgr();
        let (id1, _rx) = assert_created(m.register(b"w-1", TaskArgs::default()).await);
        m.set_failed(&id1, "boom").await;
        let (id2, _rx) = assert_created(m.register(b"w-1", TaskArgs::default()).await);
        assert_ne!(id1, id2, "Failed must NOT dedup; retry should get a fresh id");
    }

    #[tokio::test]
    async fn cancelled_evicts_dedup_so_retry_is_a_new_task() {
        let m = mgr();
        let (id1, _rx) = assert_created(m.register(b"w-1", TaskArgs::default()).await);
        assert!(m.cancel(&id1).await);
        let (id2, _rx) = assert_created(m.register(b"w-1", TaskArgs::default()).await);
        assert_ne!(id1, id2, "Cancelled must NOT dedup");
    }

    #[tokio::test]
    async fn cancel_unknown_returns_false_no_panic() {
        let m = mgr();
        assert!(!m.cancel("does-not-exist").await);
    }

    #[tokio::test]
    async fn terminal_transition_is_one_shot() {
        let m = mgr();
        let (id, _rx) = assert_created(m.register(b"w", TaskArgs::default()).await);
        m.set_finished(&id).await;
        // Subsequent transitions on a terminal task are no-ops.
        m.set_failed(&id, "should not apply").await;
        m.set_finished(&id).await;
        let state = m.get(&id).await.unwrap();
        let s = state.lock().await;
        assert!(matches!(s.status, TaskStatus::Finished));
    }

    #[tokio::test]
    async fn args_are_preserved() {
        let m = mgr();
        let args = TaskArgs {
            start_blk_height: Some(1000),
            end_blk_height: Some(1800),
            claimed_output_root: Some("0xdead".into()),
        };
        let (id, _rx) = assert_created(m.register(b"w", args.clone()).await);
        let state = m.get(&id).await.unwrap();
        let s = state.lock().await;
        assert_eq!(s.args.start_blk_height, Some(1000));
        assert_eq!(s.args.end_blk_height, Some(1800));
        assert_eq!(s.args.claimed_output_root.as_deref(), Some("0xdead"));
        let _ = args;
    }

    #[tokio::test]
    async fn cancel_fires_abort_signal() {
        let m = mgr();
        let (id, mut rx) = assert_created(m.register(b"w", TaskArgs::default()).await);
        assert!(m.cancel(&id).await);
        // The oneshot must have been signaled.
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn metrics_record_size_and_durations() {
        let m = mgr();
        let body = b"hello-witness";
        let (id, _rx) = assert_created(m.register(body, TaskArgs::default()).await);
        m.set_finished(&id).await;
        let state = m.get(&id).await.unwrap();
        let s = state.lock().await;
        let metrics = s.metrics();
        assert_eq!(metrics.witness_size_bytes, body.len());
        assert!(metrics.end_time.is_some(), "end_time set after finish");
        assert!(metrics.duration.is_some(), "duration set after finish");
    }
}
