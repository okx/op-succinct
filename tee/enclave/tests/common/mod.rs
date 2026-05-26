//! Shared test helpers — spin up an in-process axum app and exercise it via
//! `tower::Service`, no real TCP socket required.

#![allow(dead_code)]

pub mod witness_fixture;

use axum::{Router, body::Bytes, http::Request};
use http_body_util::BodyExt;
use tower::util::ServiceExt;
use xlayer_tee_enclave::{
    keys::init_dev_keys,
    server::{AppState, router},
    task_manager::TaskManager,
};

pub fn app() -> Router {
    init_dev_keys();
    let task_manager = TaskManager::new([0u8; 32], 1, 3600);
    router(AppState::new(task_manager))
}

pub async fn body_to_bytes(body: axum::body::Body) -> Bytes {
    body.collect().await.expect("collect body").to_bytes()
}

pub fn get(uri: &str) -> Request<axum::body::Body> {
    Request::builder().uri(uri).body(axum::body::Body::empty()).unwrap()
}

pub fn post(uri: &str, body: Vec<u8>) -> Request<axum::body::Body> {
    Request::builder()
        .uri(uri)
        .method("POST")
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(body))
        .unwrap()
}

pub async fn call(app: &Router, req: Request<axum::body::Body>) -> (axum::http::StatusCode, Bytes) {
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = body_to_bytes(resp.into_body()).await;
    (status, bytes)
}
