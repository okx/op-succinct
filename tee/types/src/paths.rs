//! HTTP endpoint paths exposed by the enclave's axum server.

/// `POST` — Submit a Range proof task. Async; returns a `task_id`, poll
/// [`TASKS_BY_ID`] for the proof.
///
/// Required headers:
/// - `x-task-id: <UUID v4>` — caller-allocated id for idempotency / polling.
pub const TASKS_RANGE: &str = "/tasks/range";

/// `GET` — Snapshot the state of a previously submitted task.
pub const TASKS_BY_ID: &str = "/tasks/{task_id}";

/// `GET` — List summaries of all in-memory tasks.
pub const TASKS_LIST: &str = "/tasks";

/// `GET` — Raw Nitro NSM `COSE_Sign1` attestation document.
pub const ATTESTATION: &str = "/attestation";

/// HTTP header carrying the host-allocated UUID v4 task id.
pub const HEADER_TASK_ID: &str = "x-task-id";

/// Format the client-side path for a single task — `/tasks/{id}`.
pub fn task_path(task_id: &str) -> String {
    format!("/tasks/{task_id}")
}
