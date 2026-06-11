use std::{sync::Arc, time::Duration};

use alloy_primitives::keccak256;
use axum::{
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::Serialize;
use tokio::{
    sync::{oneshot, Mutex},
    time::Instant,
};
use tracing;

use xlayer_tee_types::{wire, TaskStatusView};

use crate::{
    api::ApiResponse,
    config::HostConfig,
    enclave_client::EnclaveClient,
    error::HostError,
    mem,
    packager::pack_proof_bytes,
    task_manager::{format_duration, EnclaveInfo, TaskArgs, TaskManager, TaskMetrics, TaskStatus},
};

const POST_RETRY_INTERVAL: Duration = Duration::from_secs(2);
const MAX_TOO_MANY_RETRIES: u32 = 60;

pub struct AppState {
    pub task_manager: Arc<TaskManager>,
    pub enclave: Arc<EnclaveClient>,
    pub config: Arc<HostConfig>,
    pub attestation_cache: Arc<Mutex<AttestationCache>>,
}

pub struct AttestationCache {
    pub data: Option<Vec<u8>>,
    pub last_success: Option<Instant>,
}

impl Default for AttestationCache {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationCache {
    pub fn new() -> Self {
        Self { data: None, last_success: None }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTaskData {
    pub task_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryTaskData {
    pub status: String,
    pub proof_bytes: String,
    pub detail: TaskDetail,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskDetail {
    pub task_id: String,
    pub args: TaskArgs,
    pub metrics: TaskMetrics,
    pub witness_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclave: Option<EnclaveInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub running_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancelled_at_phase: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteTaskData {
    pub task_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationData {
    pub attestation_doc: String,
}

pub async fn create_task(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Snapshot RSS as soon as the request lands so we can correlate big bodies
    // with memory pressure spikes.
    let rss_on_entry_mib = mem::vm_rss_kb() / 1024;
    let body_mib = body.len() / 1024 / 1024;

    if body.is_empty() {
        return ApiResponse::<CreateTaskData>::from_error(&HostError::EmptyBody).into_response();
    }

    let max_bytes = wire::MAX_RANGE_BODY_BYTES;
    if body.len() > max_bytes {
        return ApiResponse::<CreateTaskData>::from_error(&HostError::BodyTooLarge {
            actual: body.len(),
            limit: max_bytes,
        })
        .into_response();
    }

    let witness_hash = keccak256(&body);
    let witness_size = body.len();

    let args = TaskArgs {
        start_blk_height: parse_u64_header(&headers, "x-start-blk-height"),
        end_blk_height: parse_u64_header(&headers, "x-end-blk-height"),
        claimed_output_root: headers
            .get("x-claimed-output-root")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
    };

    let (cancel_tx, cancel_rx) = oneshot::channel();
    let result =
        state.task_manager.register_task(witness_hash, witness_size, args, cancel_tx).await;

    if result.is_new {
        let task_id = result.task_id.clone();
        let witness_body = Arc::new(body);
        let enclave = Arc::clone(&state.enclave);
        let tm = Arc::clone(&state.task_manager);

        tokio::spawn(async move {
            deliver_to_enclave(task_id, witness_body, enclave, tm, cancel_rx).await;
        });
    }

    let rss_after_spawn_mib = mem::vm_rss_kb() / 1024;
    tracing::info!(
        task_id = %result.task_id,
        body_mib,
        rss_on_entry_mib,
        rss_after_spawn_mib,
        delta_mib = rss_after_spawn_mib.saturating_sub(rss_on_entry_mib),
        is_new = result.is_new,
        "create_task memory profile",
    );

    ApiResponse::ok(CreateTaskData { task_id: result.task_id }).into_response()
}

pub async fn query_task(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<String>,
) -> impl IntoResponse {
    let entry_arc = match state.task_manager.get_task(&task_id).await {
        Some(e) => e,
        None => {
            return ApiResponse::<QueryTaskData>::from_error(&HostError::TaskNotFound(
                task_id.clone(),
            ))
            .into_response();
        }
    };

    let entry = entry_arc.lock().await;

    if !entry.status.is_terminal() && entry.submitted_to_enclave {
        let enclave_result = state.enclave.get_task(&task_id).await;
        match enclave_result {
            Ok(view) => {
                if view.status.is_terminal() {
                    drop(entry);
                    mirror_enclave_state(&state, &task_id, &view).await;
                    let entry = entry_arc.lock().await;
                    return build_query_response(&entry).into_response();
                }
                let mut detail = build_task_detail(&entry);
                detail.enclave = Some(EnclaveInfo {
                    phase: format!("{:?}", view.phase),
                    start_time_ms: view.start_time_ms,
                    end_time_ms: view.end_time_ms,
                });
                drop(entry);
                return build_query_response_from_detail("Running", "", detail).into_response();
            }
            Err(e) if e.is_task_unknown() => {
                drop(entry);
                state.task_manager.remove_task(&task_id).await;
                return ApiResponse::<QueryTaskData>::from_error(&HostError::TaskNotFound(task_id))
                    .into_response();
            }
            Err(_) => {}
        }
    } else if !entry.status.is_terminal() && !entry.submitted_to_enclave {
        // Pre-ack shielding: ignore enclave state
    }

    build_query_response(&entry).into_response()
}

pub async fn delete_task(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<String>,
) -> impl IntoResponse {
    match state.task_manager.cancel_task(&task_id).await {
        Ok(()) => {
            let enclave = Arc::clone(&state.enclave);
            let tid = task_id.clone();
            tokio::spawn(async move {
                if let Err(e) = enclave.delete_task(&tid).await {
                    tracing::warn!(task_id = %tid, error = %e, "enclave DELETE failed (local cancel succeeded)");
                }
            });
            ApiResponse::ok(DeleteTaskData { task_id }).into_response()
        }
        Err(e) => ApiResponse::<DeleteTaskData>::from_error(&e).into_response(),
    }
}

pub async fn query_attestation(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let ttl = Duration::from_secs(state.config.attestation.cache_ttl_secs);
    let grace = ttl * 2;
    let now = Instant::now();

    {
        let cache = state.attestation_cache.lock().await;
        if let (Some(data), Some(last)) = (&cache.data, cache.last_success) {
            if now.duration_since(last) < ttl {
                let doc = base64::engine::general_purpose::STANDARD.encode(data);
                return ApiResponse::ok(AttestationData { attestation_doc: doc }).into_response();
            }
        }
    }

    match state.enclave.get_attestation().await {
        Ok(raw_bytes) => {
            let doc = base64::engine::general_purpose::STANDARD.encode(&raw_bytes);
            let mut cache = state.attestation_cache.lock().await;
            cache.data = Some(raw_bytes);
            cache.last_success = Some(Instant::now());
            ApiResponse::ok(AttestationData { attestation_doc: doc }).into_response()
        }
        Err(_) => {
            let cache = state.attestation_cache.lock().await;
            if let (Some(data), Some(last)) = (&cache.data, cache.last_success) {
                if now.duration_since(last) < grace {
                    tracing::warn!("serving stale attestation");
                    let doc = base64::engine::general_purpose::STANDARD.encode(data);
                    return ApiResponse::ok(AttestationData { attestation_doc: doc })
                        .into_response();
                }
            }
            ApiResponse::<AttestationData>::from_error(&HostError::EnclaveUnreachable(
                "enclave unreachable".to_string(),
            ))
            .into_response()
        }
    }
}

use base64::Engine;

async fn deliver_to_enclave(
    task_id: String,
    witness_body: Arc<Bytes>,
    enclave: Arc<EnclaveClient>,
    task_manager: Arc<TaskManager>,
    cancel_rx: oneshot::Receiver<()>,
) {
    let witness_body_mib = witness_body.len() / 1024 / 1024;
    let rss_start_mib = mem::vm_rss_kb() / 1024;
    tracing::info!(
        task_id = %task_id,
        witness_body_mib,
        rss_start_mib,
        "delivery coroutine started",
    );

    // Run the delivery work in an inner fn that borrows witness_body.
    // When this returns, the Arc<Bytes> is still in this outer scope.
    deliver_to_enclave_inner(
        &task_id,
        &witness_body,
        &enclave,
        &task_manager,
        cancel_rx,
    )
    .await;

    // Drop the witness body explicitly so we can measure how much memory it released.
    drop(witness_body);
    // Yield once so the runtime can run any pending drop / dealloc work.
    tokio::task::yield_now().await;

    let rss_end_mib = mem::vm_rss_kb() / 1024;
    tracing::info!(
        task_id = %task_id,
        witness_body_mib,
        rss_start_mib,
        rss_end_mib,
        rss_released_mib = rss_start_mib.saturating_sub(rss_end_mib),
        "delivery coroutine done",
    );
}

async fn deliver_to_enclave_inner(
    task_id: &str,
    witness_body: &Bytes,
    enclave: &EnclaveClient,
    task_manager: &TaskManager,
    mut cancel_rx: oneshot::Receiver<()>,
) {
    for attempt in 0..MAX_TOO_MANY_RETRIES {
        if cancel_rx.try_recv().is_ok() {
            tracing::info!(task_id = %task_id, "delivery cancelled before attempt");
            return;
        }

        let result = tokio::select! {
            biased;
            _ = &mut cancel_rx => {
                tracing::info!(task_id = %task_id, "delivery cancelled during POST");
                return;
            }
            res = enclave.post_range_task(task_id, witness_body) => res,
        };

        match result {
            Ok(()) => {
                task_manager.set_submitted(task_id).await;
                tracing::info!(task_id = %task_id, "POST accepted by enclave");
                return;
            }
            Err(e) if e.is_too_many_tasks() => {
                tracing::warn!(
                    task_id = %task_id,
                    attempt = attempt + 1,
                    max = MAX_TOO_MANY_RETRIES,
                    "enclave at capacity, retrying"
                );
                task_manager.update_running_message(task_id, "queued; enclave at capacity").await;
                tokio::time::sleep(POST_RETRY_INTERVAL).await;
            }
            Err(e) => {
                tracing::error!(task_id = %task_id, error = %e, "delivery failed (non-429)");
                task_manager.set_failed_from_host_error(task_id, &e).await;
                return;
            }
        }
    }

    tracing::error!(task_id = %task_id, "429 budget exhausted");
    task_manager.set_failed_capacity_exhausted(task_id).await;
}

pub async fn run_monitor(state: Arc<AppState>) {
    let interval = Duration::from_secs(state.config.server.monitor_interval_secs);
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await;

    loop {
        ticker.tick().await;
        let tasks = state.task_manager.non_terminal_task_ids().await;

        for (task_id, submitted) in tasks {
            match state.enclave.get_task(&task_id).await {
                Ok(view) => {
                    if view.status.is_terminal() {
                        mirror_enclave_state(&state, &task_id, &view).await;
                        tracing::info!(task_id = %task_id, status = ?view.status, "monitor: mirrored terminal state");
                    }
                }
                Err(e) if e.is_task_unknown() => {
                    if submitted {
                        state.task_manager.remove_task(&task_id).await;
                        tracing::warn!(task_id = %task_id, "monitor: submitted task unknown to enclave, removed");
                    }
                }
                Err(e) => {
                    tracing::warn!(task_id = %task_id, error = %e, "monitor: enclave unreachable, skipping");
                }
            }
        }
    }
}

pub async fn run_sweeper(state: Arc<AppState>) {
    let interval = Duration::from_secs(60);
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await;

    loop {
        ticker.tick().await;
        state.task_manager.sweep_expired().await;
    }
}

async fn mirror_enclave_state(
    state: &AppState,
    task_id: &str,
    view: &xlayer_tee_types::TaskStateView,
) {
    let enclave_info = Some(EnclaveInfo {
        phase: format!("{:?}", view.phase),
        start_time_ms: view.start_time_ms,
        end_time_ms: view.end_time_ms,
    });

    match &view.status {
        TaskStatusView::Finished(resp) => {
            let proof_bytes = pack_proof_bytes(&resp.journal, &resp.signature);
            state
                .task_manager
                .set_finished(task_id, proof_bytes, format!("{:?}", view.phase), enclave_info)
                .await;
        }
        TaskStatusView::Failed { kind, message } => {
            state.task_manager.set_failed(task_id, &format!("{kind:?}"), message).await;
        }
        TaskStatusView::Cancelled { at_phase } => {
            if let Some(entry_arc) = state.task_manager.get_task(task_id).await {
                let mut entry = entry_arc.lock().await;
                if !entry.status.is_terminal() {
                    entry.status = TaskStatus::Cancelled {
                        at_phase: format!("{at_phase:?}"),
                        end_time: Utc::now(),
                    };
                    entry.enclave_info = enclave_info;
                }
            }
            state.task_manager.remove_dedup_for_task(task_id).await;
        }
        TaskStatusView::Running => {}
    }
}

fn build_query_response(entry: &crate::task_manager::TaskEntry) -> ApiResponse<QueryTaskData> {
    let detail = build_task_detail(entry);
    let (status, proof_hex) = match &entry.status {
        TaskStatus::Running { .. } => ("Running".to_string(), String::new()),
        TaskStatus::Finished { proof_bytes, .. } => {
            ("Finished".to_string(), format!("0x{}", hex::encode(proof_bytes)))
        }
        TaskStatus::Failed { .. } => ("Failed".to_string(), String::new()),
        TaskStatus::Cancelled { .. } => ("Cancelled".to_string(), String::new()),
    };

    ApiResponse::ok(QueryTaskData { status, proof_bytes: proof_hex, detail })
}

fn build_query_response_from_detail(
    status: &str,
    proof_hex: &str,
    detail: TaskDetail,
) -> ApiResponse<QueryTaskData> {
    ApiResponse::ok(QueryTaskData {
        status: status.to_string(),
        proof_bytes: proof_hex.to_string(),
        detail,
    })
}

fn build_task_detail(entry: &crate::task_manager::TaskEntry) -> TaskDetail {
    let end_time = match &entry.status {
        TaskStatus::Finished { end_time, .. } |
        TaskStatus::Failed { end_time, .. } |
        TaskStatus::Cancelled { end_time, .. } => Some(*end_time),
        TaskStatus::Running { .. } => None,
    };

    let duration = end_time.map(|et| format_duration(entry.start_time, et));

    let (running_message, error_kind, failure_message, cancelled_at_phase) = match &entry.status {
        TaskStatus::Running { message } => (Some(message.clone()), None, None, None),
        TaskStatus::Failed { error_kind, message, .. } => {
            (None, Some(error_kind.clone()), Some(message.clone()), None)
        }
        TaskStatus::Cancelled { at_phase, .. } => (None, None, None, Some(at_phase.clone())),
        TaskStatus::Finished { .. } => (None, None, None, None),
    };

    TaskDetail {
        task_id: entry.task_id.clone(),
        args: entry.args.clone(),
        metrics: TaskMetrics {
            start_time: entry.start_time,
            end_time,
            duration,
            witness_size_bytes: entry.witness_size_bytes,
        },
        witness_hash: format!("0x{}", hex::encode(entry.witness_hash.as_slice())),
        enclave: entry.enclave_info.clone(),
        running_message,
        error_kind,
        failure_message,
        cancelled_at_phase,
    }
}

fn parse_u64_header(headers: &HeaderMap, name: &str) -> Option<u64> {
    headers.get(name)?.to_str().ok()?.parse().ok()
}

// -------------------- /debug/* proxy to enclave --------------------

/// Forward GET /debug/<rest>[?query] to the enclave's /debug/<rest>[?query].
/// Returns the enclave response verbatim (status + body), so jeprof heap
/// profile bytes etc. can be pulled out from a sealed enclave.
pub async fn proxy_debug(
    State(state): State<Arc<AppState>>,
    Path(rest): Path<String>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let mut uri = format!("/debug/{rest}");
    if !query.is_empty() {
        let qs = query
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding(k), urlencoding(v)))
            .collect::<Vec<_>>()
            .join("&");
        uri.push('?');
        uri.push_str(&qs);
    }

    match state.enclave.proxy_get(&uri).await {
        Ok((status, body)) => Response::builder()
            .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(body))
            .unwrap(),
        Err(e) => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(format!("enclave proxy error: {e}")))
            .unwrap(),
    }
}

fn urlencoding(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{:02X}", b),
        })
        .collect()
}
