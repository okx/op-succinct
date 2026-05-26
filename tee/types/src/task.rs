//! Async task wire types — the enclave uses a fire-and-poll task model:
//! `POST /tasks/range` returns immediately with a `task_id`, and the host
//! polls `GET /tasks/{id}` until the task is terminal.
//!
//! All types are rkyv-Archive and serialized as `application/octet-stream`
//! over HTTP, mirroring the existing wire convention. The task lifecycle on
//! the enclave side is:
//!
//! ```text
//!  POST /tasks/range           -> CreateTaskResponse { task_id, accepted_at, already_existed }
//!  GET  /tasks/{id}            -> TaskStateView      { status, phase, start_time_ms, end_time_ms }
//!  DELETE /tasks/{id}          -> DeleteTaskResponse { task_id, was_running }
//!  GET  /tasks                 -> TaskListResponse   { running, finished, failed, cancelled }
//! ```

use rkyv::{Archive, Deserialize, Serialize};

use crate::{ErrorKind, RangeTaskResponse};

/// Caller-allocated UUID v4 string (canonical 36-char hyphenated form).
/// Validated by the enclave on `POST /tasks/range`; mismatching shape
/// returns [`ErrorKind::InvalidTaskId`].
pub type TaskId = String;

/// Phases the enclave passes through while processing a range task. The
/// proposer reads this from `TaskStateView.phase` to estimate progress
/// and to tag prometheus metrics.
///
/// Phases are monotonic — once `Signing` is reached the task transitions
/// to `Terminal` (and is no longer reachable through this enum on the
/// next poll; the status flips to `Finished` / `Failed` / `Cancelled`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Archive, Serialize, Deserialize)]
pub enum TaskPhase {
    /// Accepted by the manager; tokio task spawned but pipeline not started.
    Pending,
    /// rkyv-decoding witness body into `DefaultWitnessData`.
    DeserializingWitness,
    /// `BootInfo::load(oracle)` — reads the 7 Local preimage keys.
    LoadingBootInfo,
    /// `kona` derivation + execution pipeline running. **Hot phase**: this
    /// is where the wall-clock 5-15 minutes for a single range is spent.
    RunningKona,
    /// `compute_output_root` complete; ECDSA-signing the packed
    /// `RangeJournalWire`.
    Signing,
    /// Task has reached a terminal status. `TaskStatusView` will be
    /// `Finished` / `Failed` / `Cancelled` and `phase` will not change again.
    Terminal,
}

/// Body of a successful `POST /tasks/range` response.
///
/// Status code distinguishes the two outcomes:
/// - **201 Created** when a fresh task was registered (`already_existed: false`)
/// - **200 OK** when the same `task_id` was already known (`already_existed: true`,
///   idempotent hit)
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct CreateTaskResponse {
    pub task_id: TaskId,
    /// Unix epoch milliseconds when the manager accepted the task.
    pub accepted_at_ms: u64,
    /// `true` if this POST hit an existing entry (idempotent); `false` if
    /// the task was newly created by this request.
    pub already_existed: bool,
}

/// Body of `GET /tasks/{task_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct TaskStateView {
    pub task_id: TaskId,
    /// Snapshot of the task's current status. For `Finished`, holds the
    /// signed `RangeTaskResponse`; for `Failed` / `Cancelled`, holds a
    /// descriptive failure record.
    pub status: TaskStatusView,
    pub phase: TaskPhase,
    pub start_time_ms: u64,
    /// `None` while running; set to the terminal timestamp once status
    /// transitions away from `Running`.
    pub end_time_ms: Option<u64>,
}

/// Externally-visible task status. The `Finished` variant carries the full
/// `RangeTaskResponse` so a single `GET` is sufficient to retrieve the proof
/// once the task completes (saves a follow-up round trip).
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub enum TaskStatusView {
    /// Task is still in-flight; consult `TaskStateView.phase` for progress.
    Running,
    /// Pipeline completed successfully; payload is the same shape as the
    /// old sync `RangeTaskResponse` for transparent migration.
    Finished(Box<RangeTaskResponse>),
    /// Pipeline reported a terminal error. `kind` is `is_retryable()`'d
    /// by the proposer to choose between retry and abort.
    Failed { kind: ErrorKind, message: String },
    /// Task was `DELETE`'d after it had already entered `phase`. Always
    /// terminal — a fresh `task_id` is required to retry.
    Cancelled { at_phase: TaskPhase },
}

/// Body of `DELETE /tasks/{task_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct DeleteTaskResponse {
    pub task_id: TaskId,
    /// `true` if the DELETE actually fired the abort channel (i.e. the
    /// task was Running). `false` if the task was already terminal — the
    /// DELETE is a no-op then, the existing terminal status is preserved.
    pub was_running: bool,
}

/// One row in the `GET /tasks` listing — task_id + minimal status metadata.
/// Full state is on `TaskStateView` via `GET /tasks/{id}`.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct TaskSummary {
    pub task_id: TaskId,
    pub phase: TaskPhase,
    pub start_time_ms: u64,
    pub end_time_ms: Option<u64>,
}

/// Body of `GET /tasks`. Tasks are bucketed by terminal status to make
/// operational dashboards simpler (`running.len()` = current concurrency).
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct TaskListResponse {
    pub running: Vec<TaskSummary>,
    pub finished: Vec<TaskSummary>,
    pub failed: Vec<TaskSummary>,
    pub cancelled: Vec<TaskSummary>,
}

impl TaskStatusView {
    /// `true` if the task has reached a terminal state and will not change
    /// further (Finished / Failed / Cancelled).
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Running)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rkyv::rancor::Error as RkyvError;

    #[test]
    fn create_task_response_rkyv_roundtrip() {
        let r = CreateTaskResponse {
            task_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            accepted_at_ms: 1_700_000_000_000,
            already_existed: false,
        };
        let bytes = rkyv::to_bytes::<RkyvError>(&r).unwrap();
        let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
        aligned.extend_from_slice(&bytes);
        let back: CreateTaskResponse =
            rkyv::from_bytes::<CreateTaskResponse, RkyvError>(&aligned).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn task_state_view_running_roundtrip() {
        let v = TaskStateView {
            task_id: "x".into(),
            status: TaskStatusView::Running,
            phase: TaskPhase::RunningKona,
            start_time_ms: 1,
            end_time_ms: None,
        };
        let bytes = rkyv::to_bytes::<RkyvError>(&v).unwrap();
        let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
        aligned.extend_from_slice(&bytes);
        let back: TaskStateView =
            rkyv::from_bytes::<TaskStateView, RkyvError>(&aligned).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn task_status_terminality() {
        assert!(!TaskStatusView::Running.is_terminal());
        assert!(TaskStatusView::Failed {
            kind: ErrorKind::KonaExec,
            message: "boom".into()
        }
        .is_terminal());
        assert!(TaskStatusView::Cancelled { at_phase: TaskPhase::RunningKona }.is_terminal());
    }
}
