//! axum HTTP server exposing the 4 north-side endpoints.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use serde_json::{json, Value};
use tokio::sync::{oneshot, Mutex};
use tracing::{info, warn};

use xlayer_tee_types::{limits, TaskStateView, TaskStatusView};

use crate::api::{
    ApiResponse, CreateTaskData, DeleteTaskData, EnclaveInfoData, TaskStatusData,
};
use crate::config::Config;
use crate::enclave_client::EnclaveClient;
use crate::error::{CODE_INVALID_ARGUMENT, CODE_RESOURCE_NOT_FOUND};
use crate::packager;
use crate::task_manager::{RegisterOutcome, TaskArgs, TaskManager, TaskStatus};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub tasks: Arc<TaskManager>,
    pub enclave: Arc<EnclaveClient>,
    pub info_cache: Arc<Mutex<Option<CachedInfo>>>,
}

pub struct CachedInfo {
    pub data: EnclaveInfoData,
    pub fetched_at: Instant,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/tee/task", post(create_task))
        .route("/tee/task/{task_id}", get(get_task).delete(delete_task))
        .route("/tee/info", get(get_info))
        .layer(DefaultBodyLimit::max(limits::MAX_RANGE_BODY_BYTES))
        .with_state(state)
}

// -----------------------------------------------------------------------------
// POST /tee/task
// -----------------------------------------------------------------------------

async fn create_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Json<ApiResponse<CreateTaskData>> {
    if body.is_empty() {
        return Json(ApiResponse::err(CODE_INVALID_ARGUMENT, "empty witness body"));
    }
    if body.len() > limits::MAX_RANGE_BODY_BYTES {
        return Json(ApiResponse::err(
            CODE_INVALID_ARGUMENT,
            format!("body {} bytes > limit {}", body.len(), limits::MAX_RANGE_BODY_BYTES),
        ));
    }

    let args = parse_task_args(&headers);

    let (task_id, abort_rx) = match state.tasks.register(&body, args).await {
        RegisterOutcome::Created { task_id, abort_rx } => (task_id, abort_rx),
        RegisterOutcome::Duplicate(task_id) => {
            info!(%task_id, "duplicate witness; returning existing task_id");
            return Json(ApiResponse::ok(CreateTaskData { task_id }));
        }
        RegisterOutcome::Busy { running_task_id } => {
            return Json(ApiResponse::err(
                CODE_INVALID_ARGUMENT,
                format!(
                    "another task is in flight: {running_task_id}; \
                     wait for it to finish or DELETE it first"
                ),
            ));
        }
    };

    spawn_task_monitor(state.clone(), task_id.clone(), body, abort_rx);

    Json(ApiResponse::ok(CreateTaskData { task_id }))
}

/// Background coordinator per task: POST to enclave, then watch the abort
/// channel. On abort, mark Cancelled here; the enclave-side cancel runs from
/// `delete_task` via `delete_task_with_retry`.
fn spawn_task_monitor(
    state: AppState,
    task_id: String,
    body: Bytes,
    mut abort_rx: oneshot::Receiver<()>,
) {
    tokio::spawn(async move {
        tokio::select! {
            biased;
            _ = &mut abort_rx => {
                info!(%task_id, "monitor received local abort signal");
            }
            res = state.enclave.post_range(
                &task_id,
                state.config.verifier.chain_id,
                &state.config.verifier.verifying_contract,
                body,
            ) => {
                if let Err(e) = res {
                    state.tasks.set_failed(&task_id, e.to_string()).await;
                    warn!(%task_id, error = %e, "enclave POST failed");
                    return;
                }
                state.tasks.set_progress(&task_id, "submitted; awaiting result").await;
                info!(%task_id, "submitted to enclave");
            }
        }
    });
}

// -----------------------------------------------------------------------------
// GET /tee/task/{task_id}
// -----------------------------------------------------------------------------

async fn get_task(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
) -> Json<ApiResponse<TaskStatusData>> {
    let Some(local) = state.tasks.get(&task_id).await else {
        return Json(ApiResponse::err(
            CODE_RESOURCE_NOT_FOUND,
            format!("task {task_id} not found"),
        ));
    };

    // Pull live enclave state (rkyv-decoded TaskStateView). The enclave is the
    // source of truth for Finished/Failed/Cancelled transitions.
    let enclave_state = match state.enclave.get_task(&task_id).await {
        Ok(es) => Some(es),
        Err(e) => {
            warn!(%task_id, error = %e, "enclave GET /tasks/{{id}} failed; using local state only");
            None
        }
    };

    // Mirror the enclave's transition into the local registry so dedup /
    // single-in-flight see consistent state.
    if let Some(ref es) = enclave_state {
        apply_enclave_state(&state.tasks, &task_id, es).await;
    }

    let snapshot = {
        let s = local.lock().await;
        Snapshot::from(&*s)
    };

    let (status, proof_bytes) = match enclave_state.as_ref().map(|es| &es.status) {
        Some(TaskStatusView::Finished(resp)) => {
            match packager::encode_proof_bytes_from_response(resp) {
                Ok(bytes) => ("Finished".into(), format!("0x{}", hex::encode(&bytes))),
                Err(e) => return Json(ApiResponse::err(e.code(), e.to_string())),
            }
        }
        Some(TaskStatusView::Failed { .. }) | Some(TaskStatusView::Cancelled { .. }) => {
            ("Failed".into(), String::new())
        }
        Some(TaskStatusView::Running) => ("Running".into(), String::new()),
        // Enclave unreachable — fall back to local snapshot.
        None => match snapshot.status {
            TaskStatus::Finished => ("Finished".into(), String::new()),
            TaskStatus::Failed(_) | TaskStatus::Cancelled => ("Failed".into(), String::new()),
            TaskStatus::Running(_) => ("Running".into(), String::new()),
        },
    };

    let detail = build_detail_json(&snapshot, enclave_state.as_ref());
    Json(ApiResponse::ok(TaskStatusData { status, proof_bytes, detail }))
}

// -----------------------------------------------------------------------------
// DELETE /tee/task/{task_id}
// -----------------------------------------------------------------------------

async fn delete_task(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
) -> Json<ApiResponse<DeleteTaskData>> {
    // 1) Tell enclave to kill (3-attempt retry with backoff).
    if let Err(e) = state.enclave.delete_task_with_retry(&task_id).await {
        warn!(%task_id, error = %e, "all enclave DELETE attempts failed; proceeding with local cancel");
    }
    // 2) Local cancel: signal abort, mark Cancelled.
    let was_running = state.tasks.cancel(&task_id).await;
    info!(%task_id, was_running, "task deleted");
    Json(ApiResponse::ok(DeleteTaskData { task_id }))
}

// -----------------------------------------------------------------------------
// GET /tee/info
// -----------------------------------------------------------------------------

async fn get_info(State(state): State<AppState>) -> Json<ApiResponse<EnclaveInfoData>> {
    let ttl = Duration::from_secs(state.config.attestation.cache_ttl_secs);
    if let Some(c) = state.info_cache.lock().await.as_ref() {
        if c.fetched_at.elapsed() < ttl {
            return Json(ApiResponse::ok(c.data.clone()));
        }
    }
    match fetch_enclave_info(&state.enclave).await {
        Ok(data) => {
            *state.info_cache.lock().await = Some(CachedInfo {
                data: data.clone(),
                fetched_at: Instant::now(),
            });
            Json(ApiResponse::ok(data))
        }
        Err(e) => Json(ApiResponse::err(e.code(), e.to_string())),
    }
}

async fn fetch_enclave_info(client: &EnclaveClient) -> crate::error::Result<EnclaveInfoData> {
    let attestation = client.get_attestation().await?;
    let health = client.get_health().await?;
    let s = |k: &str| health.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    Ok(EnclaveInfoData {
        attestation_doc: base64::engine::general_purpose::STANDARD.encode(&attestation),
        commit: s("elf_version"),
        pub_key: s("signer_pubkey"),
    })
}

// -----------------------------------------------------------------------------
// Helpers: header parsing + detail JSON
// -----------------------------------------------------------------------------

fn parse_task_args(headers: &HeaderMap) -> TaskArgs {
    let u64_header = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
    };
    let str_header = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    TaskArgs {
        start_blk_height: u64_header("x-start-blk-height"),
        end_blk_height: u64_header("x-end-blk-height"),
        claimed_output_root: str_header("x-claimed-output-root"),
    }
}

/// Plain-data clone used only for the response detail field.
struct Snapshot {
    task_id: String,
    status: TaskStatus,
    args: TaskArgs,
    metrics: crate::task_manager::TaskMetrics,
    witness_hash: String,
}

impl From<&crate::task_manager::TaskState> for Snapshot {
    fn from(s: &crate::task_manager::TaskState) -> Self {
        Self {
            task_id: s.task_id.clone(),
            status: s.status.clone(),
            args: s.args.clone(),
            metrics: s.metrics(),
            witness_hash: format!("0x{}", hex::encode(s.witness_hash.as_slice())),
        }
    }
}

/// Merge the local snapshot with optional enclave-reported `start_time_ms`,
/// `end_time_ms`, and `phase`. Enclave fields appear under `enclave.*` so the
/// host's own metrics remain unambiguous.
fn build_detail_json(s: &Snapshot, enclave: Option<&TaskStateView>) -> Value {
    let mut detail = json!({
        "taskId": s.task_id,
        "status": s.status,
        "args": s.args,
        "metrics": s.metrics,
        "witnessHash": s.witness_hash,
    });
    if let Some(es) = enclave {
        detail["enclave"] = json!({
            "phase": format!("{:?}", es.phase),
            "startTimeMs": es.start_time_ms,
            "endTimeMs": es.end_time_ms,
        });
    }
    detail
}

/// Apply an enclave-reported `TaskStateView` into the local registry. Used by
/// both the GET handler (proposer-driven) and the background monitor loop
/// (host-driven), so the same transition rules apply regardless of who pulls.
async fn apply_enclave_state(tasks: &TaskManager, task_id: &str, es: &TaskStateView) {
    match &es.status {
        TaskStatusView::Running => { /* host stays Running too */ }
        TaskStatusView::Finished(_) => tasks.set_finished(task_id).await,
        TaskStatusView::Failed { kind, message } => {
            tasks.set_failed(task_id, format!("{kind:?}: {message}")).await;
        }
        TaskStatusView::Cancelled { at_phase } => {
            tasks.set_failed(task_id, format!("cancelled at {at_phase:?}")).await;
        }
    }
}

/// Background loop that periodically GETs `/tasks/{id}` from the enclave for
/// every non-terminal task, mirrors the result into the local registry, and
/// logs the current phase. Mirrors tradezone's `run_task_monitor` so terminal
/// transitions surface in host logs without waiting for a proposer poll.
pub async fn run_task_monitor(
    tasks: Arc<TaskManager>,
    enclave: Arc<EnclaveClient>,
    interval_secs: u64,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    ticker.tick().await;
    loop {
        ticker.tick().await;
        for id in tasks.list_ids().await {
            // Skip tasks already terminal in our registry — enclave state has
            // already been mirrored or the task was created without the enclave
            // ever knowing about it (e.g. POST failed locally).
            let Some(local) = tasks.get(&id).await else { continue };
            let is_terminal = {
                let s = local.lock().await;
                s.status.is_terminal()
            };
            if is_terminal {
                continue;
            }

            match enclave.get_task(&id).await {
                Ok(es) => {
                    apply_enclave_state(&tasks, &id, &es).await;
                    info!(
                        task_id = %id,
                        phase = ?es.phase,
                        status = ?es.status,
                        "task status (from enclave)"
                    );
                }
                Err(e) => {
                    warn!(task_id = %id, error = %e, "monitor: enclave GET failed");
                }
            }
        }
    }
}
