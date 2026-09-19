//! HTTP verify server for the XLayer remote signer.
//!
//! Exposes `GET /signer/get?refOrderId=<id>` so the asset-management service
//! can confirm, before releasing funds, that a given `refOrderId` was issued
//! by THIS node. Read-only: it only reads the client's issued-ID record via
//! `has_ref_order_id`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use serde::Serialize;

use crate::xlayer_remote_client::XLayerRemoteClient;

/// Response envelope for the verify endpoint. Field names and semantics are
/// fixed by the asset-management service contract: `code = 0` found,
/// `code = 1` otherwise; `status` mirrors the HTTP status code; `detailMsg`
/// is always present; `data` is always null on this endpoint.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponseResult {
    pub status: i32,
    pub code: i32,
    pub msg: String,
    pub detail_msg: String,
    pub data: serde_json::Value,
}

/// Builds the response envelope for a single case (found / not-found /
/// bad-request / method-not-allowed).
fn verify_response(http: StatusCode, status: i32, code: i32, msg: &str) -> Response {
    (
        http,
        Json(VerifyResponseResult {
            status,
            code,
            msg: msg.to_string(),
            detail_msg: String::new(),
            data: serde_json::Value::Null,
        }),
    )
        .into_response()
}

/// Builds the router. Separated from `serve` so it can be unit-tested with
/// `tower::ServiceExt::oneshot` and no bound socket.
pub fn app(client: Arc<XLayerRemoteClient>) -> Router {
    // Register the route for ALL methods and gate on the method inside the
    // handler, so a non-GET request returns the 405 envelope (rather than an
    // empty method-not-allowed body) and a different path returns 404.
    Router::new().route("/signer/get", any(handle_get)).with_state(client)
}

async fn handle_get(
    method: Method,
    State(client): State<Arc<XLayerRemoteClient>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if method != Method::GET {
        return verify_response(StatusCode::METHOD_NOT_ALLOWED, 405, 1, "method not allowed");
    }

    // Missing / empty refOrderId is a client error (400), not a code=1 "not found".
    let Some(ref_order_id) = params.get("refOrderId").filter(|v| !v.is_empty()) else {
        return verify_response(StatusCode::BAD_REQUEST, 400, 1, "refOrderId is required");
    };

    if client.has_ref_order_id(ref_order_id).await {
        verify_response(StatusCode::OK, 200, 0, "success")
    } else {
        tracing::warn!("XLayer verify: refOrderId not found: {ref_order_id}");
        verify_response(StatusCode::OK, 200, 1, "not found")
    }
}

/// Starts the verify server on `addr`. Only called when a listen address is
/// configured. Returns on serve error so the caller can log it and continue.
pub async fn serve(addr: SocketAddr, client: Arc<XLayerRemoteClient>) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("XLayer verify server listening on {addr}");
    axum::serve(listener, app(client)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xlayer_remote_client::{XLayerConfig, XLayerRemoteClient};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt; // for `oneshot`

    async fn seeded_client(seed: Option<&str>) -> Arc<XLayerRemoteClient> {
        let client = Arc::new(XLayerRemoteClient::new(XLayerConfig::default()));
        if let Some(id) = seed {
            client.remember_ref_order_id(id).await;
        }
        client
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn test_verify_found_returns_code_0() {
        let id = "PROPOSER_TZ_20_1699999999999_a1b2c3d4";
        let app = app(seeded_client(Some(id)).await);
        let resp = app
            .oneshot(Request::get(format!("/signer/get?refOrderId={id}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["code"], 0);
        assert_eq!(json["status"], 200);
        assert_eq!(json["msg"], "success");
        assert_eq!(json["detailMsg"], "");
        assert!(json["data"].is_null());
        // Field names present exactly as the envelope contract:
        for k in ["status", "code", "msg", "detailMsg", "data"] {
            assert!(json.get(k).is_some(), "missing field {k}");
        }
    }

    #[tokio::test]
    async fn test_verify_not_found_returns_code_1() {
        let app = app(seeded_client(None).await);
        let resp = app
            .oneshot(Request::get("/signer/get?refOrderId=never-issued").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["code"], 1);
        assert_eq!(json["status"], 200);
        assert_eq!(json["msg"], "not found");
        assert!(json["data"].is_null());
    }

    #[tokio::test]
    async fn test_verify_missing_param_returns_400() {
        let app = app(seeded_client(None).await);
        let resp = app
            .oneshot(Request::get("/signer/get").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["code"], 1);
        assert_eq!(json["status"], 400);
        assert_eq!(json["msg"], "refOrderId is required");
    }

    #[tokio::test]
    async fn test_verify_empty_param_returns_400() {
        // A present-but-blank refOrderId is a client error, not a code=1 "not found".
        let app = app(seeded_client(None).await);
        let resp = app
            .oneshot(Request::get("/signer/get?refOrderId=").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_verify_wrong_method_returns_405() {
        let app = app(seeded_client(None).await);
        let resp = app
            .oneshot(Request::post("/signer/get?refOrderId=x").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        let json = body_json(resp).await;
        assert_eq!(json["code"], 1);
        assert_eq!(json["status"], 405);
        assert_eq!(json["msg"], "method not allowed");
    }
}
