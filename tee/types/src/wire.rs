//! HTTP wire-protocol constants shared by host and enclave.
//!
//! Three categories of plain constants live here so they share a single
//! review surface — any change to the wire contract should be visible in
//! one diff:
//!
//! - **Endpoint paths** (`TASKS_*`, `ATTESTATION`) and the matching header name
//! - **Content types** for binary (rkyv) and JSON (error) bodies
//! - **Size limits** the enclave actively enforces

// ---------------------------------------------------------------------------
// Endpoint paths
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Content types
// ---------------------------------------------------------------------------

/// Binary rkyv-encoded bodies (task request/response, attestation document).
pub const OCTET_STREAM: &str = "application/octet-stream";

/// JSON error bodies.
pub const JSON: &str = "application/json";

// ---------------------------------------------------------------------------
// Body size limits
// ---------------------------------------------------------------------------

/// Maximum size of a single `/tasks/range` request body (rkyv DefaultWitnessData).
/// Proposer MUST reject witnesses exceeding this. Enclave axum body limit
/// is configured to this value.
pub const MAX_RANGE_BODY_BYTES: usize = 256 * 1024 * 1024; // 256 MiB
