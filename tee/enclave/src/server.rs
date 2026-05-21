//! axum router for the enclave HTTP API.
//!
//! ```text
//! POST   /tasks/range        → submit a range task, return CreateTaskResponse
//! GET    /tasks/{task_id}    → snapshot TaskStateView
//! DELETE /tasks/{task_id}    → cancel a running task
//! GET    /tasks              → list all in-memory tasks
//! GET    /attestation        → raw COSE_Sign1 NSM doc
//! GET    /health             → JSON status, includes inflight metrics
//! ```
//!
//! `POST /tasks/range` registers the task and returns immediately; the
//! kona pipeline runs on a spawned tokio task via `runner::run_pipeline`.

use std::sync::Arc;

use alloy_primitives::{Address, U256};
use alloy_sol_types::Eip712Domain;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rkyv::rancor::Error as RkyvError;
use tracing::{info, warn};

use xlayer_tee_types::{
    ErrorResponse, TaskListResponse, content_type,
    eip712::{NAME, VERSION},
    limits, paths,
};

use crate::{
    attestation::generate_attestation_doc,
    error::{Error, Result},
    keys::{enclave_address, enclave_pubkey_uncompressed},
    task_manager::{CreateOutcome, TaskManager, validate_task_id},
};

/// Application state shared by all handlers.
#[derive(Clone)]
pub struct AppState {
    pub task_manager: Arc<TaskManager>,
}

impl AppState {
    pub fn new(task_manager: Arc<TaskManager>) -> Self {
        Self { task_manager }
    }
}

/// Build the axum app router with the given state.
///
/// axum's matchit prefers static segments over `:placeholder`s, so the static
/// `POST /tasks/range` always wins over the dynamic `:task_id` route. The
/// same `/tasks/:task_id` path serves both GET and DELETE.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route(paths::TASKS_RANGE, post(tasks_range_post))
        .route(paths::TASKS_LIST, get(tasks_list))
        .route(paths::TASKS_BY_ID, get(tasks_get).delete(tasks_delete))
        .route(paths::ATTESTATION, get(attestation))
        .route(paths::HEALTH, get(health))
        .layer(DefaultBodyLimit::max(limits::MAX_RANGE_BODY_BYTES))
        .with_state(state)
}

// -----------------------------------------------------------------------------
// POST /tasks/range
// -----------------------------------------------------------------------------

async fn tasks_range_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match handle_tasks_range_post(&state, &headers, body).await {
        Ok(resp) => resp,
        Err(e) => internal_error_response(e),
    }
}

async fn handle_tasks_range_post(
    state: &AppState,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response> {
    // Read headers before touching the (potentially 200MB) body, so an
    // idempotent hit (existing task_id) or a malformed header can short-circuit
    // without paying for body parse.
    let task_id = headers
        .get(paths::HEADER_TASK_ID)
        .ok_or_else(|| Error::InvalidTaskId(format!("missing {} header", paths::HEADER_TASK_ID)))?
        .to_str()
        .map_err(|e| Error::InvalidTaskId(format!("non-ascii header: {e}")))?
        .to_string();
    validate_task_id(&task_id)?;

    let domain = parse_eip712_domain_headers(headers)?;

    let outcome = state.task_manager.create(task_id, domain, body)?;
    let (status, response) = match outcome {
        CreateOutcome::Created(r) => (StatusCode::CREATED, r),
        CreateOutcome::AlreadyExists(r) => (StatusCode::OK, r),
    };

    info!(
        task_id = %response.task_id,
        already_existed = response.already_existed,
        "task submitted",
    );

    rkyv_response(status, &response)
        .map_err(|e| Error::Internal(format!("rkyv encode CreateTaskResponse: {e}")))
}

/// Parse `x-eip712-chain-id` (u64 decimal) and `x-eip712-verifying-contract`
/// (0x-prefixed 20-byte hex) headers into an `Eip712Domain`. Both headers are
/// required.
fn parse_eip712_domain_headers(headers: &HeaderMap) -> Result<Eip712Domain> {
    let chain_id_raw = headers.get(paths::HEADER_CHAIN_ID).ok_or_else(|| {
        Error::InvalidEip712Header(format!("missing {} header", paths::HEADER_CHAIN_ID))
    })?;
    let chain_id: u64 = chain_id_raw
        .to_str()
        .map_err(|e| Error::InvalidEip712Header(format!("non-ascii chain_id header: {e}")))?
        .parse()
        .map_err(|e| Error::InvalidEip712Header(format!("chain_id not a u64: {e}")))?;

    let verifier_raw = headers.get(paths::HEADER_VERIFYING_CONTRACT).ok_or_else(|| {
        Error::InvalidEip712Header(format!(
            "missing {} header",
            paths::HEADER_VERIFYING_CONTRACT
        ))
    })?;
    let verifying_contract: Address = verifier_raw
        .to_str()
        .map_err(|e| Error::InvalidEip712Header(format!("non-ascii verifier header: {e}")))?
        .parse()
        .map_err(|e| {
            Error::InvalidEip712Header(format!("verifying_contract not 0x..20-byte hex: {e}"))
        })?;

    Ok(Eip712Domain {
        name: Some(NAME.into()),
        version: Some(VERSION.into()),
        chain_id: Some(U256::from(chain_id)),
        verifying_contract: Some(verifying_contract),
        salt: None,
    })
}

// -----------------------------------------------------------------------------
// GET /tasks/{task_id}
// -----------------------------------------------------------------------------

async fn tasks_get(State(state): State<AppState>, Path(task_id): Path<String>) -> Response {
    if let Err(e) = validate_task_id(&task_id) {
        return internal_error_response(e);
    }
    match state.task_manager.snapshot(&task_id).await {
        Some(view) => rkyv_or_error(StatusCode::OK, &view),
        None => internal_error_response(Error::TaskUnknown(task_id)),
    }
}

// -----------------------------------------------------------------------------
// DELETE /tasks/{task_id}
// -----------------------------------------------------------------------------

async fn tasks_delete(State(state): State<AppState>, Path(task_id): Path<String>) -> Response {
    if let Err(e) = validate_task_id(&task_id) {
        return internal_error_response(e);
    }
    match state.task_manager.cancel(&task_id).await {
        Ok(resp) => {
            info!(task_id = %resp.task_id, was_running = resp.was_running, "task delete request");
            rkyv_or_error(StatusCode::OK, &resp)
        }
        Err(e) => internal_error_response(e),
    }
}

// -----------------------------------------------------------------------------
// GET /tasks
// -----------------------------------------------------------------------------

async fn tasks_list(State(state): State<AppState>) -> Response {
    let resp: TaskListResponse = state.task_manager.list().await;
    rkyv_or_error(StatusCode::OK, &resp)
}

// -----------------------------------------------------------------------------
// GET /attestation
// -----------------------------------------------------------------------------

async fn attestation() -> Response {
    let pubkey = enclave_pubkey_uncompressed();
    match generate_attestation_doc(b"xlayer-tee-prover", b"", &pubkey) {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, HeaderValue::from_static(content_type::OCTET_STREAM))],
            bytes,
        )
            .into_response(),
        Err(e) => internal_error_response(e),
    }
}

// -----------------------------------------------------------------------------
// GET /health
// -----------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct HealthResponse {
    status: &'static str,
    signer_address: String,
    signer_pubkey: String,
    pcr0: String,
    elf_version: &'static str,
    inflight_count: usize,
    max_inflight: usize,
}

async fn health(State(state): State<AppState>) -> Response {
    let pubkey = enclave_pubkey_uncompressed();
    let body = HealthResponse {
        status: "ready",
        signer_address: format!("{:#x}", enclave_address()),
        signer_pubkey: format!("0x{}", hex::encode(pubkey)),
        pcr0: format!("0x{}", hex::encode(state.task_manager.pcr0())),
        elf_version: env!("CARGO_PKG_VERSION"),
        inflight_count: state.task_manager.inflight_count(),
        max_inflight: state.task_manager.max_inflight(),
    };
    Json(body).into_response()
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Encode `value` as rkyv and wrap it in a `Response` with the given status.
fn rkyv_response<T>(status: StatusCode, value: &T) -> std::result::Result<Response, RkyvError>
where
    T: for<'a> rkyv::Serialize<
        rkyv::api::high::HighSerializer<
            rkyv::util::AlignedVec,
            rkyv::ser::allocator::ArenaHandle<'a>,
            RkyvError,
        >,
    >,
{
    let bytes = rkyv::to_bytes::<RkyvError>(value)?;
    Ok((
        status,
        [(header::CONTENT_TYPE, HeaderValue::from_static(content_type::OCTET_STREAM))],
        bytes.to_vec(),
    )
        .into_response())
}

/// Like [`rkyv_response`] but converts the rkyv error into an internal error
/// response — used in handlers that should never fail to encode their reply.
fn rkyv_or_error<T>(status: StatusCode, value: &T) -> Response
where
    T: for<'a> rkyv::Serialize<
        rkyv::api::high::HighSerializer<
            rkyv::util::AlignedVec,
            rkyv::ser::allocator::ArenaHandle<'a>,
            RkyvError,
        >,
    >,
{
    rkyv_response(status, value)
        .unwrap_or_else(|e| internal_error_response(Error::Internal(format!("rkyv encode: {e}"))))
}

fn internal_error_response(err: Error) -> Response {
    let kind = err.to_wire_kind();
    let resp = ErrorResponse::new(kind, err.to_string());
    let json = serde_json::to_string(&resp).expect("error response always serializable");
    let status = StatusCode::from_u16(kind.status_code()).expect("valid status");
    warn!(?kind, message = %err, "request failed");
    (
        status,
        [(header::CONTENT_TYPE, HeaderValue::from_static(content_type::JSON))],
        json,
    )
        .into_response()
}
