//! HTTP endpoint paths exposed by the enclave's axum server.

/// `POST` — Submit a Range proof task. **Async**: returns immediately with
/// a `task_id`; poll [`TASKS_BY_ID`] for the proof.
///
/// Request body: `rkyv(op_succinct_client_utils::witness::DefaultWitnessData)`.
/// Required headers:
/// - `x-task-id: <UUID v4>` — caller-allocated task id used for idempotency
///   and subsequent polling / cancellation. See [`HEADER_TASK_ID`].
/// - `x-eip712-chain-id: <u64 decimal>` — chainId for the EIP712 domain used
///   to sign the response journal. See [`HEADER_CHAIN_ID`].
/// - `x-eip712-verifying-contract: 0x<20 bytes hex>` — `verifyingContract`
///   for the EIP712 domain. See [`HEADER_VERIFYING_CONTRACT`].
///
/// The enclave does **not** carry a default chainId/verifier — every task
/// must specify them. Mirrors `tradezone/bin/enclave/enclave_task_manager.rs`
/// where `compute_batch_digest` takes `verifier_addr` and `chain_id` as
/// per-call arguments. Rationale: one EIF can serve multiple verifier
/// contracts / multiple L1 chains, redeploying the verifier does not change
/// PCR0.
///
/// Response body: `rkyv(CreateTaskResponse)`.
/// Status: `201 Created` for new task / `200 OK` if the `x-task-id` already
/// exists (idempotent hit) / `429 Too Many Requests` if `max_inflight_tasks`
/// is exceeded / `400 Bad Request` if any of the three headers are missing or
/// malformed.
pub const TASKS_RANGE: &str = "/tasks/range";

/// `POST` — Aggregate N range proofs into a single signed AggregationJournal.
/// Request body: `rkyv(Vec<RangeTaskResponse>)`.
/// Response body: `rkyv(AggregationTaskResponse)`.
pub const TASKS_AGGREGATION: &str = "/tasks/aggregation";

/// `GET` — Snapshot the state of a previously submitted task.
/// Path param: `task_id`. Response body: `rkyv(TaskStateView)`.
/// Status: `200 OK` / `404 Not Found` (unknown task — never created or
/// already GC'd).
///
/// Registered with axum using the brace-wrapped form below (axum 0.8 syntax).
/// Clients should use [`task_path`] to format the actual request path.
pub const TASKS_BY_ID: &str = "/tasks/{task_id}";

/// `GET` — List summaries of all in-memory tasks (running / finished /
/// failed / cancelled). Operational introspection only.
/// Response body: `rkyv(TaskListResponse)`. Status: `200 OK`.
pub const TASKS_LIST: &str = "/tasks";

/// `GET` — Returns the raw Nitro NSM `COSE_Sign1` attestation document
/// binding the enclave's signer public key to PCR0.
/// Response body: raw bytes (`application/octet-stream`).
pub const ATTESTATION: &str = "/attestation";

/// `GET` — Liveness probe. Response JSON includes `signer_address`,
/// `signer_pubkey`, `pcr0`, `elf_version`, `inflight_count`, `max_inflight`.
pub const HEALTH: &str = "/health";

/// HTTP header carrying the host-allocated UUID v4 task id on
/// `POST /tasks/range` requests.
pub const HEADER_TASK_ID: &str = "x-task-id";

/// HTTP header carrying the `chainId` (decimal `u64`) for the EIP712 domain
/// used when signing this task's response journal. Set per-task by the host
/// so one EIF can serve multiple L1 chains.
pub const HEADER_CHAIN_ID: &str = "x-eip712-chain-id";

/// HTTP header carrying the `verifyingContract` address (0x-prefixed
/// 20-byte hex) for the EIP712 domain. Set per-task so the enclave is not
/// rebuilt when the on-chain verifier is redeployed.
pub const HEADER_VERIFYING_CONTRACT: &str = "x-eip712-verifying-contract";

/// Format the client-side path for a single task — `/tasks/{id}`.
/// Use this on the host side; the axum route uses [`TASKS_BY_ID`].
pub fn task_path(task_id: &str) -> String {
    format!("/tasks/{task_id}")
}
