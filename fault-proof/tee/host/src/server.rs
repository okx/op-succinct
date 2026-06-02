use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
    routing::{delete, get, post},
    Router,
};
use bytes::Bytes;
use serde::Serialize;
use tokio::sync::Mutex;
use tower_http::limit::RequestBodyLimitLayer;

use crate::{
    api::ApiResponse,
    config::HostConfig,
    enclave_client::EnclaveClient,
    error::HostError,
    packager,
    task_manager::{TaskEntry, TaskManager, TaskMetadata, TaskStatus},
};
use xlayer_tee_types::{wire::MAX_RANGE_BODY_BYTES, TaskStatusView};

pub struct AppState {
    pub task_manager: TaskManager,
    pub enclave_client: EnclaveClient,
    pub attestation: Mutex<AttestationCache>,
    pub config: HostConfig,
}

pub struct AttestationCache {
    pub doc: Option<String>,
    pub fetched_at: Option<Instant>,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/tee/task", post(create_task))
        .route("/tee/task/{task_id}", get(query_task))
        .route("/tee/task/{task_id}", delete(delete_task))
        .route("/tee/info", get(get_info))
        .layer(RequestBodyLimitLayer::new(MAX_RANGE_BODY_BYTES + 1024))
        .with_state(state)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateData {
    task_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteData {
    task_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InfoData {
    attestation_doc: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QueryData {
    status: String,
    proof_bytes: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<TaskDetail>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskDetail {
    task_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    running_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    args: Option<TaskArgs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<TaskMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    witness_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enclave: Option<EnclaveInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    start_blk_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_blk_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claimed_output_root: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskMetrics {
    start_time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration: Option<String>,
    witness_size_bytes: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnclaveInfo {
    phase: String,
    start_time_ms: Option<u64>,
    end_time_ms: Option<u64>,
}

async fn create_task(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if body.is_empty() {
        return ApiResponse::<CreateData>::from_error(&HostError::EmptyBody).into_response();
    }
    if body.len() > MAX_RANGE_BODY_BYTES {
        return ApiResponse::<CreateData>::from_error(&HostError::BodyTooLarge {
            actual: body.len(),
            limit: MAX_RANGE_BODY_BYTES,
        })
        .into_response();
    }

    let witness_hash = alloy_primitives::keccak256(&body);
    let metadata = TaskMetadata {
        start_blk_height: headers
            .get("x-start-blk-height")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok()),
        end_blk_height: headers
            .get("x-end-blk-height")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok()),
        claimed_output_root: headers
            .get("x-claimed-output-root")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string()),
    };

    let result = state.task_manager.register(witness_hash, body.len(), metadata);

    if !result.already_existed {
        let state_clone = state.clone();
        let task_id = result.task_id.clone();
        let cancel_token = state.task_manager.get_cancel_token(&task_id);
        let witness_body = Arc::new(body);
        tokio::spawn(async move {
            delivery_coroutine(state_clone, task_id, witness_body, cancel_token).await;
        });
    }

    ApiResponse::ok(CreateData { task_id: result.task_id }).into_response()
}

const MAX_TOO_MANY_RETRIES: usize = 60;
const POST_RETRY_INTERVAL: Duration = Duration::from_secs(2);

async fn delivery_coroutine(
    state: Arc<AppState>,
    task_id: String,
    witness_body: Arc<Bytes>,
    cancel_token: Option<tokio_util::sync::CancellationToken>,
) {
    for _attempt in 0..MAX_TOO_MANY_RETRIES {
        if let Some(ref token) = cancel_token {
            if token.is_cancelled() {
                return;
            }
        }
        match state.enclave_client.post_range(&task_id, witness_body.clone()).await {
            Ok(_) => {
                state.task_manager.set_submitted(&task_id, "submitted; awaiting result");
                return;
            }
            Err(e) if e.is_too_many_tasks() => {
                state.task_manager.set_progress(&task_id, "queued; enclave at capacity");
                tokio::time::sleep(POST_RETRY_INTERVAL).await;
            }
            Err(e) => {
                state.task_manager.set_failed(&task_id, &e.to_string());
                return;
            }
        }
    }
    state.task_manager.set_failed(&task_id, "enclave at capacity for 120s; giving up");
}

async fn query_task(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<String>,
) -> impl IntoResponse {
    let task_info = state.task_manager.with_task(&task_id, |entry| {
        (entry.status.is_terminal(), entry.submitted_to_enclave, build_query_data(entry))
    });

    let Some((is_terminal, submitted, mut data)) = task_info else {
        return ApiResponse::<QueryData>::from_error(&HostError::TaskNotFound(task_id))
            .into_response();
    };

    if is_terminal {
        return ApiResponse::ok(data).into_response();
    }

    match state.enclave_client.get_task(&task_id).await {
        Ok(view) => {
            if view.status.is_terminal() {
                mirror_terminal_state(&state, &task_id, &view);
                if let Some(updated) = state.task_manager.with_task(&task_id, build_query_data) {
                    data = updated;
                }
            } else if let Some(detail) = &mut data.detail {
                detail.enclave = Some(EnclaveInfo {
                    phase: format!("{:?}", view.phase),
                    start_time_ms: Some(view.start_time_ms),
                    end_time_ms: view.end_time_ms,
                });
            }
        }
        Err(e) if e.is_task_unknown() => {
            if submitted {
                state.task_manager.remove_task(&task_id);
                return ApiResponse::<QueryData>::from_error(&HostError::TaskNotFound(task_id))
                    .into_response();
            }
        }
        Err(_) => {}
    }

    ApiResponse::ok(data).into_response()
}

fn build_query_data(entry: &TaskEntry) -> QueryData {
    let (status, proof_bytes, running_msg, failure_msg) = match &entry.status {
        TaskStatus::Running(msg) => ("Running", String::new(), Some(msg.clone()), None),
        TaskStatus::Finished { proof_bytes } => {
            ("Finished", packager::format_proof_hex(proof_bytes), None, None)
        }
        TaskStatus::Failed { message } => ("Failed", String::new(), None, Some(message.clone())),
        TaskStatus::Cancelled => ("Cancelled", String::new(), None, None),
    };

    let elapsed = entry.created_at.elapsed();
    let duration = entry.terminal_time.map(|t| format_duration(t.duration_since(entry.created_at)));

    QueryData {
        status: status.into(),
        proof_bytes,
        detail: Some(TaskDetail {
            task_id: entry.task_id.clone(),
            running_message: running_msg,
            error_kind: None,
            failure_message: failure_msg,
            args: Some(TaskArgs {
                start_blk_height: entry.metadata.start_blk_height,
                end_blk_height: entry.metadata.end_blk_height,
                claimed_output_root: entry.metadata.claimed_output_root.clone(),
            }),
            metrics: Some(TaskMetrics {
                start_time: format!("{}s ago", elapsed.as_secs()),
                end_time: entry
                    .terminal_time
                    .map(|t| format!("{}s", t.duration_since(entry.created_at).as_secs())),
                duration,
                witness_size_bytes: entry.witness_size_bytes,
            }),
            witness_hash: Some(format!("0x{}", hex::encode(entry.witness_hash))),
            enclave: None,
        }),
    }
}

fn format_duration(d: Duration) -> String {
    let total_secs = d.as_secs();
    let mins = total_secs / 60;
    let secs = total_secs % 60;
    if mins > 0 {
        format!("{mins}m {secs}s")
    } else {
        format!("{secs}s")
    }
}

fn mirror_terminal_state(state: &AppState, task_id: &str, view: &xlayer_tee_types::TaskStateView) {
    match &view.status {
        TaskStatusView::Finished(response) => {
            let proof_bytes = packager::pack_proof_bytes(response);
            state.task_manager.set_finished(task_id, proof_bytes);
        }
        TaskStatusView::Failed { kind, message } => {
            state.task_manager.set_failed(task_id, &format!("{kind:?}: {message}"));
        }
        TaskStatusView::Cancelled { .. } => {
            state.task_manager.set_cancelled(task_id);
        }
        TaskStatusView::Running => {}
    }
}

async fn delete_task(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<String>,
) -> impl IntoResponse {
    if !state.task_manager.contains(&task_id) {
        return ApiResponse::<DeleteData>::from_error(&HostError::TaskNotFound(task_id))
            .into_response();
    }
    state.task_manager.set_cancelled(&task_id);
    let _ = state.enclave_client.delete_task(&task_id).await;
    ApiResponse::ok(DeleteData { task_id }).into_response()
}

async fn get_info(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cache_ttl = Duration::from_secs(state.config.attestation.cache_ttl_secs);
    let grace_window = cache_ttl * 2;
    let mut cache = state.attestation.lock().await;

    if let (Some(ref doc), Some(fetched_at)) = (&cache.doc, cache.fetched_at) {
        if fetched_at.elapsed() < cache_ttl {
            return ApiResponse::ok(InfoData { attestation_doc: doc.clone() }).into_response();
        }
    }

    match state.enclave_client.get_attestation().await {
        Ok(doc) => {
            cache.doc = Some(doc.clone());
            cache.fetched_at = Some(Instant::now());
            ApiResponse::ok(InfoData { attestation_doc: doc }).into_response()
        }
        Err(_) => {
            if let (Some(ref doc), Some(fetched_at)) = (&cache.doc, cache.fetched_at) {
                if fetched_at.elapsed() < grace_window {
                    tracing::warn!("serving stale attestation");
                    return ApiResponse::ok(InfoData { attestation_doc: doc.clone() })
                        .into_response();
                }
            }
            ApiResponse::<InfoData>::from_error(&HostError::EnclaveUnreachable(
                "enclave unreachable".into(),
            ))
            .into_response()
        }
    }
}

pub async fn monitor_loop(state: Arc<AppState>) {
    let mut interval =
        tokio::time::interval(Duration::from_secs(state.config.server.monitor_interval_secs));
    loop {
        interval.tick().await;
        for task_id in state.task_manager.non_terminal_task_ids() {
            match state.enclave_client.get_task(&task_id).await {
                Ok(view) if view.status.is_terminal() => {
                    mirror_terminal_state(&state, &task_id, &view);
                }
                Err(e) if e.is_task_unknown() => {
                    if state.task_manager.is_submitted(&task_id) {
                        state.task_manager.remove_task(&task_id);
                    }
                }
                _ => {}
            }
        }
    }
}

pub async fn sweeper_loop(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        state.task_manager.sweep();
    }
}
