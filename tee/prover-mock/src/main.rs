//! Mock implementation of the `xlayer-tee-prover` HTTP interface.
//!
//! **This binary does NOT generate real proofs.** It exists only to give the
//! proposer team a runnable endpoint to integrate against while the real
//! enclave implementation is in progress.
//!
//! Behavior:
//! - `POST /tasks/range` — reads body (no rkyv decoding), returns a
//!   zero-filled `RangeTaskResponse`.
//! - `GET /attestation` — returns 64 zero bytes (placeholder).
//! - `GET /health` — returns 200 OK.
//!
//! Inject `FAIL_KIND` env var (e.g. `FAIL_KIND=ClaimMismatch`) to make the
//! mock return that error instead of success — useful for testing the
//! proposer's retry / abort logic.
//!
//! Run:
//! ```bash
//! cargo run -p xlayer-tee-prover-mock
//! # listening on 127.0.0.1:7878
//! ```

use std::net::SocketAddr;

use axum::{
    Router,
    body::Bytes,
    extract::DefaultBodyLimit,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rkyv::rancor::Error as RkyvError;
use tracing::info;

use xlayer_tee_types::{
    ErrorKind, ErrorResponse, RangeTaskResponse, content_type, journal::RangeJournalWire, limits,
    paths,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let app = Router::new()
        .route(paths::TASKS_RANGE, post(tasks_range))
        .route(paths::ATTESTATION, get(attestation))
        .route(paths::HEALTH, get(health))
        .layer(DefaultBodyLimit::max(limits::MAX_RANGE_BODY_BYTES));

    let addr: SocketAddr = std::env::var("LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:7878".into())
        .parse()
        .expect("invalid LISTEN address");

    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind failed");
    info!(%addr, "xlayer-tee-prover-mock listening — not a real prover, returns placeholder responses");
    axum::serve(listener, app).await.expect("axum server failed");
}

/// `POST /tasks/range` — mock handler.
///
/// Validates wire-contract headers (`x-task-id`, `x-eip712-chain-id`,
/// `x-eip712-verifying-contract`) so clients get the same shape of errors as
/// from the real enclave. On success, returns
/// `rkyv(RangeTaskResponse { journal: zeros, signature: zeros })`.
async fn tasks_range(headers: HeaderMap, body: Bytes) -> Response {
    info!(body_size = body.len(), "tasks_range request received");

    if let Err(resp) = validate_required_headers(&headers) {
        return resp;
    }

    if let Some(kind) = fail_kind_from_env() {
        return error(kind, "FAIL_KIND env override active");
    }

    let response = RangeTaskResponse {
        journal: RangeJournalWire {
            pcr0: [0u8; 32],
            config_hash: [0u8; 32],
            l1_origin_hash: [0u8; 32],
            l2_block_number: 0,
            prev_output_root: [0u8; 32],
            output_root: [0u8; 32],
        },
        signature: [0u8; 65],
    };

    rkyv_ok(&response)
}

/// `GET /attestation` — returns 64 zero bytes as a placeholder COSE_Sign1 doc.
async fn attestation() -> Response {
    let payload: [u8; 64] = [0u8; 64];
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, HeaderValue::from_static(content_type::OCTET_STREAM))],
        payload.to_vec(),
    )
        .into_response()
}

/// `GET /health` — 200 OK with empty body.
async fn health() -> StatusCode {
    StatusCode::OK
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

fn rkyv_ok<T>(value: &T) -> Response
where
    T: for<'a> rkyv::Serialize<
        rkyv::api::high::HighSerializer<rkyv::util::AlignedVec, rkyv::ser::allocator::ArenaHandle<'a>, RkyvError>,
    >,
{
    match rkyv::to_bytes::<RkyvError>(value) {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, HeaderValue::from_static(content_type::OCTET_STREAM))],
            bytes.to_vec(),
        )
            .into_response(),
        Err(e) => error(ErrorKind::InternalEnclave, format!("rkyv serialize: {e}")),
    }
}

fn error(kind: ErrorKind, msg: impl Into<String>) -> Response {
    let body = ErrorResponse::new(kind, msg);
    let json = serde_json::to_string(&body).expect("error response serializable");
    let status = StatusCode::from_u16(kind.status_code()).expect("valid status");
    (
        status,
        [(header::CONTENT_TYPE, HeaderValue::from_static(content_type::JSON))],
        json,
    )
        .into_response()
}

/// Check that the three required headers are present and shaped right —
/// matches the real enclave's pre-body validation. Returns an `Err(Response)`
/// (400 JSON) on failure, mirroring the real wire contract.
fn validate_required_headers(headers: &HeaderMap) -> Result<(), Response> {
    let task_id = headers
        .get(paths::HEADER_TASK_ID)
        .ok_or_else(|| error(ErrorKind::InvalidTaskId, "missing x-task-id header"))?;
    let task_id_str = task_id
        .to_str()
        .map_err(|e| error(ErrorKind::InvalidTaskId, format!("non-ascii x-task-id: {e}")))?;
    if uuid::Uuid::parse_str(task_id_str).is_err() {
        return Err(error(
            ErrorKind::InvalidTaskId,
            format!("x-task-id not a valid UUID: {task_id_str}"),
        ));
    }

    let chain_id_raw = headers.get(paths::HEADER_CHAIN_ID).ok_or_else(|| {
        error(
            ErrorKind::InvalidEip712Header,
            format!("missing {} header", paths::HEADER_CHAIN_ID),
        )
    })?;
    chain_id_raw
        .to_str()
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| {
            error(
                ErrorKind::InvalidEip712Header,
                format!("{} not a u64", paths::HEADER_CHAIN_ID),
            )
        })?;

    let verifier_raw = headers.get(paths::HEADER_VERIFYING_CONTRACT).ok_or_else(|| {
        error(
            ErrorKind::InvalidEip712Header,
            format!("missing {} header", paths::HEADER_VERIFYING_CONTRACT),
        )
    })?;
    let verifier_str = verifier_raw.to_str().map_err(|e| {
        error(
            ErrorKind::InvalidEip712Header,
            format!("non-ascii {} header: {e}", paths::HEADER_VERIFYING_CONTRACT),
        )
    })?;
    // Light shape check: 0x + 40 hex chars; full Address::parse happens in the
    // real enclave path.
    if !(verifier_str.starts_with("0x") && verifier_str.len() == 42) {
        return Err(error(
            ErrorKind::InvalidEip712Header,
            format!(
                "{} not 0x..20-byte hex (got len={})",
                paths::HEADER_VERIFYING_CONTRACT,
                verifier_str.len()
            ),
        ));
    }

    Ok(())
}

fn fail_kind_from_env() -> Option<ErrorKind> {
    std::env::var("FAIL_KIND").ok().and_then(|s| match s.as_str() {
        "KonaExec" => Some(ErrorKind::KonaExec),
        "DeserializeRkyv" => Some(ErrorKind::DeserializeRkyv),
        "InternalEnclave" => Some(ErrorKind::InternalEnclave),
        "Timeout" => Some(ErrorKind::Timeout),
        "ClaimMismatch" => Some(ErrorKind::ClaimMismatch),
        "InvalidWitness" => Some(ErrorKind::InvalidWitness),
        _ => None,
    })
}
