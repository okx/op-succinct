//! Shared test helpers — spin up an in-process axum app and exercise it via
//! `tower::Service`, no real TCP socket required.

#![allow(dead_code)]

pub mod witness_fixture;

use alloy_primitives::{Address, U256};
use alloy_sol_types::Eip712Domain;
use axum::{Router, body::Bytes, http::Request};
use http_body_util::BodyExt;
use tower::util::ServiceExt;
use xlayer_tee_enclave::{
    keys::init_dev_keys,
    server::{AppState, router},
};
use xlayer_tee_types::eip712::{NAME, VERSION};

pub fn app() -> Router {
    init_dev_keys();
    let domain = Eip712Domain {
        name: Some(NAME.into()),
        version: Some(VERSION.into()),
        chain_id: Some(U256::from(1u64)),
        verifying_contract: Some(
            "0x1111111111111111111111111111111111111111".parse::<Address>().unwrap(),
        ),
        salt: None,
    };
    router(AppState::new(domain, [0u8; 32]))
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
