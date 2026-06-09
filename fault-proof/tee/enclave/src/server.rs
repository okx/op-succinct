use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
    routing::{get, post},
    Router,
};
use bytes::Bytes;
use xlayer_tee_types::{wire, ErrorResponse};

use crate::{
    attestation, error::Error, keys::enclave_pubkey_uncompressed, task_manager::TaskManager,
};

pub fn build_router(manager: Arc<TaskManager>) -> Router {
    Router::new()
        .route(wire::TASKS_RANGE, post(handle_create_task))
        .route("/tasks/:task_id", get(handle_get_task).delete(handle_delete_task))
        .route(wire::TASKS_LIST, get(handle_list_tasks))
        .route(wire::ATTESTATION, get(handle_attestation))
        .route("/debug/heap-list", get(handle_heap_list))
        .route("/debug/heap-dump", get(handle_heap_dump))
        .route("/debug/heap-file", get(handle_heap_file))
        .layer(axum::extract::DefaultBodyLimit::max(wire::MAX_RANGE_BODY_BYTES))
        .with_state(manager)
}

// -------------------- jemalloc heap profile debug endpoints --------------------

/// GET /debug/heap-list — list profile files written by jemalloc in /tmp.
async fn handle_heap_list() -> Response {
    let mut out = String::new();
    if let Ok(read) = std::fs::read_dir("/tmp") {
        for entry in read.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("jeprof") && name.ends_with(".heap") {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                out.push_str(&format!("{name}\t{size}\n"));
            }
        }
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(out))
        .unwrap()
}

/// GET /debug/heap-dump — force jemalloc to dump a profile NOW.
/// Returns the path of the new file. Requires MALLOC_CONF=prof:true at boot.
async fn handle_heap_dump() -> Response {
    #[cfg(target_os = "linux")]
    {
        // Allocate the dump path in /tmp, ask jemalloc to write to it.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = format!("/tmp/jeprof-manual-{ts}.heap");
        let c_path = match std::ffi::CString::new(path.clone()) {
            Ok(s) => s,
            Err(_) => return text_500("invalid path"),
        };
        // mallctl("prof.dump", NULL, NULL, &path_ptr, sizeof(char*))
        let mut path_ptr = c_path.as_ptr();
        let name = std::ffi::CString::new("prof.dump").unwrap();
        let rc = unsafe {
            tikv_jemalloc_sys::mallctl(
                name.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut path_ptr as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<*const std::os::raw::c_char>(),
            )
        };
        if rc != 0 {
            return text_500(&format!(
                "mallctl prof.dump failed (rc={rc}). Was the enclave started with MALLOC_CONF=prof:true ?"
            ));
        }
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(path))
            .unwrap()
    }
    #[cfg(not(target_os = "linux"))]
    text_500("not linux")
}

/// GET /debug/heap-file?name=jeprof.NN.heap — return raw bytes of a profile file.
async fn handle_heap_file(
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let name = match q.get("name") {
        Some(n) => n.clone(),
        None => return text_400("missing ?name=..."),
    };
    // Path traversal guard: must be a bare filename in /tmp.
    if name.contains('/') || name.contains('\0') {
        return text_400("bad name");
    }
    let path = format!("/tmp/{name}");
    match std::fs::read(&path) {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(bytes))
            .unwrap(),
        Err(e) => text_500(&format!("read {path}: {e}")),
    }
}

fn text_400(msg: &str) -> Response {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(msg.to_string()))
        .unwrap()
}

fn text_500(msg: &str) -> Response {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(msg.to_string()))
        .unwrap()
}

fn error_response(err: &Error) -> Response {
    let kind = err.to_wire_kind();
    let status =
        StatusCode::from_u16(kind.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = ErrorResponse::new(kind, err.to_string());
    let json = serde_json::to_vec(&body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, wire::JSON)
        .body(Body::from(json))
        .unwrap()
}

fn rkyv_octet_response(status: StatusCode, bytes: Vec<u8>) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, wire::OCTET_STREAM)
        .body(Body::from(bytes))
        .unwrap()
}

async fn handle_create_task(
    State(manager): State<Arc<TaskManager>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let task_id = match headers.get(wire::HEADER_TASK_ID) {
        Some(val) => match val.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                return error_response(&Error::InvalidTaskId("invalid header encoding".into()));
            }
        },
        None => {
            return error_response(&Error::InvalidTaskId("missing x-task-id header".into()));
        }
    };

    match manager.create(task_id, body).await {
        Ok(resp) => {
            let status = if resp.already_existed { StatusCode::OK } else { StatusCode::CREATED };
            let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&resp)
                .map(|b| b.to_vec())
                .unwrap_or_default();
            rkyv_octet_response(status, bytes)
        }
        Err(err) => error_response(&err),
    }
}

async fn handle_get_task(
    State(manager): State<Arc<TaskManager>>,
    Path(task_id): Path<String>,
) -> Response {
    match manager.snapshot(&task_id) {
        Ok(view) => {
            let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&view)
                .map(|b| b.to_vec())
                .unwrap_or_default();
            rkyv_octet_response(StatusCode::OK, bytes)
        }
        Err(err) => error_response(&err),
    }
}

async fn handle_delete_task(
    State(manager): State<Arc<TaskManager>>,
    Path(task_id): Path<String>,
) -> Response {
    match manager.cancel(&task_id) {
        Ok(resp) => {
            let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&resp)
                .map(|b| b.to_vec())
                .unwrap_or_default();
            rkyv_octet_response(StatusCode::OK, bytes)
        }
        Err(err) => error_response(&err),
    }
}

async fn handle_list_tasks(State(manager): State<Arc<TaskManager>>) -> Response {
    let list = manager.list();
    let bytes =
        rkyv::to_bytes::<rkyv::rancor::Error>(&list).map(|b| b.to_vec()).unwrap_or_default();
    rkyv_octet_response(StatusCode::OK, bytes)
}

async fn handle_attestation(State(_manager): State<Arc<TaskManager>>) -> Response {
    let pubkey = enclave_pubkey_uncompressed();
    match attestation::generate_attestation_doc(&[], &[], &pubkey) {
        Ok(doc) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, wire::OCTET_STREAM)
            .body(Body::from(doc))
            .unwrap(),
        Err(err) => error_response(&err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, http::Request};
    use tower::ServiceExt;
    use xlayer_tee_types::ErrorKind;

    fn setup_router() -> Router {
        crate::keys::init_dev_keys();
        let manager = Arc::new(TaskManager::new([0u8; 32], 4, 3600));
        build_router(manager)
    }

    #[tokio::test]
    async fn create_task_missing_header_returns_400() {
        let app = setup_router();
        let req = Request::builder()
            .method("POST")
            .uri("/tasks/range")
            .header(header::CONTENT_TYPE, wire::OCTET_STREAM)
            .body(Body::from(vec![0u8; 10]))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err_resp: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err_resp.error_kind, ErrorKind::InvalidTaskId);
    }

    #[tokio::test]
    async fn create_task_invalid_uuid_returns_400() {
        let app = setup_router();
        let req = Request::builder()
            .method("POST")
            .uri("/tasks/range")
            .header(wire::HEADER_TASK_ID, "not-a-uuid")
            .header(header::CONTENT_TYPE, wire::OCTET_STREAM)
            .body(Body::from(vec![0u8; 10]))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err_resp: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err_resp.error_kind, ErrorKind::InvalidTaskId);
    }

    #[tokio::test]
    async fn create_task_valid_uuid_returns_201() {
        let app = setup_router();
        let task_id = uuid::Uuid::new_v4().to_string();
        let req = Request::builder()
            .method("POST")
            .uri("/tasks/range")
            .header(wire::HEADER_TASK_ID, &task_id)
            .header(header::CONTENT_TYPE, wire::OCTET_STREAM)
            .body(Body::from(vec![0u8; 10]))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(resp.headers().get(header::CONTENT_TYPE).unwrap(), wire::OCTET_STREAM);
    }

    #[tokio::test]
    async fn get_unknown_task_returns_404() {
        let app = setup_router();
        let req = Request::builder()
            .method("GET")
            .uri("/tasks/00000000-0000-0000-0000-000000000000")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err_resp: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err_resp.error_kind, ErrorKind::TaskUnknown);
    }

    #[tokio::test]
    async fn list_tasks_returns_200() {
        let app = setup_router();
        let req = Request::builder().method("GET").uri("/tasks").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::CONTENT_TYPE).unwrap(), wire::OCTET_STREAM);
    }

    #[tokio::test]
    async fn attestation_returns_dev_marker() {
        let app = setup_router();
        let req = Request::builder().method("GET").uri("/attestation").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::CONTENT_TYPE).unwrap(), wire::OCTET_STREAM);

        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert!(
            body.starts_with(attestation::DEV_ATTESTATION_MARKER),
            "response should start with dev marker"
        );
    }

    #[tokio::test]
    async fn delete_unknown_task_returns_404() {
        let app = setup_router();
        let req = Request::builder()
            .method("DELETE")
            .uri("/tasks/00000000-0000-0000-0000-000000000000")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
