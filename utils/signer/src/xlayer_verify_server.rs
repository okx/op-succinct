//! Standalone read-only HTTP endpoint that lets the asset-management service
//! verify whether a `refOrderId` was issued by this signer.
//!
//! The server only reads the client's issued-order LRU through
//! [`XLayerRemoteClient::has_ref_order_id`]; it never touches the signing lock,
//! so callback traffic cannot block transaction signing.

#[cfg(feature = "xlayer-verify")]
use std::sync::Arc;

#[cfg(feature = "xlayer-verify")]
use axum::{
    extract::{Query, Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::any,
    Router,
};
#[cfg(feature = "xlayer-verify")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "xlayer-verify")]
use crate::xlayer_remote_client::XLayerRemoteClient;

/// Envelope shared by every response of the lookup endpoint. All five fields
/// are always present in the JSON body.
#[cfg(feature = "xlayer-verify")]
#[derive(Debug, Serialize)]
struct VerifyResponse {
    status: u16,
    code: i32,
    msg: String,
    #[serde(rename = "detailMsg")]
    detail_msg: String,
    data: Option<()>,
}

#[cfg(feature = "xlayer-verify")]
impl VerifyResponse {
    fn new(status: u16, code: i32, msg: &str) -> Self {
        Self { status, code, msg: msg.to_string(), detail_msg: String::new(), data: None }
    }
}

/// Query string of the lookup endpoint. `refOrderId` is optional so that both
/// its absence and an empty value can be answered with the same error body.
#[cfg(feature = "xlayer-verify")]
#[derive(Debug, Deserialize)]
struct VerifyQuery {
    #[serde(rename = "refOrderId")]
    ref_order_id: Option<String>,
}

/// Message returned for every request whose method the endpoint does not serve.
#[cfg(feature = "xlayer-verify")]
const METHOD_NOT_ALLOWED_MSG: &str = "method not allowed";

/// The only method the endpoint serves. Reported in `Allow` on a 405, which a
/// 405 response is required to carry.
#[cfg(feature = "xlayer-verify")]
const ALLOWED_METHOD: &str = "GET";

/// Answers `GET /signer/get?refOrderId=<id>`.
#[cfg(feature = "xlayer-verify")]
async fn get_handler(
    State(client): State<Arc<XLayerRemoteClient>>,
    Query(params): Query<VerifyQuery>,
) -> (StatusCode, Json<VerifyResponse>) {
    match params.ref_order_id {
        Some(id) if !id.is_empty() => {
            if client.has_ref_order_id(&id).await {
                (StatusCode::OK, Json(VerifyResponse::new(200, 0, "success")))
            } else {
                (StatusCode::OK, Json(VerifyResponse::new(200, 1, "not found")))
            }
        }
        // Absent parameter and empty parameter are reported identically.
        _ => (StatusCode::BAD_REQUEST, Json(VerifyResponse::new(400, 1, "refOrderId is required"))),
    }
}

/// The answer every unsupported method receives: the documented envelope plus
/// the `Allow` header a 405 has to carry.
#[cfg(feature = "xlayer-verify")]
fn method_not_allowed() -> Response {
    let mut response =
        (StatusCode::METHOD_NOT_ALLOWED, Json(VerifyResponse::new(405, 1, METHOD_NOT_ALLOWED_MSG)))
            .into_response();
    response.headers_mut().insert(header::ALLOW, HeaderValue::from_static(ALLOWED_METHOD));
    response
}

/// The answer a `HEAD` request receives: status and `Allow` only. A HEAD
/// response never carries a body.
#[cfg(feature = "xlayer-verify")]
fn method_not_allowed_without_body() -> Response {
    let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
    response.headers_mut().insert(header::ALLOW, HeaderValue::from_static(ALLOWED_METHOD));
    response
}

/// Refuses every method the endpoint does not serve, before the lookup handler
/// and its extractors run.
///
/// This has to sit in front of the handler: axum's `get()` route also matches
/// `HEAD`, and an extractor answers a request it cannot read before the handler
/// ever sees the method. Guarding here keeps the method contract independent of
/// the query string.
#[cfg(feature = "xlayer-verify")]
async fn guard_method(request: Request, next: Next) -> Response {
    // Matching on the dereferenced method keeps the arms free of reference
    // patterns; the `&`-prefixed form trips `clippy::match_ref_pats`.
    match *request.method() {
        Method::GET => next.run(request).await,
        Method::HEAD => method_not_allowed_without_body(),
        _ => method_not_allowed(),
    }
}

/// Exposes `GET /signer/get?refOrderId=<id>` for the asset-management callback.
/// Read-only: only reads the client's issued-ID cache via `has_ref_order_id`.
#[cfg(feature = "xlayer-verify")]
pub fn app(client: Arc<XLayerRemoteClient>) -> Router {
    Router::new()
        .route("/signer/get", any(get_handler))
        .route_layer(middleware::from_fn(guard_method))
        .with_state(client)
}

/// Starts the verify server on `addr`. Returns on serve error so the caller can
/// log it and continue.
#[cfg(feature = "xlayer-verify")]
pub async fn serve(
    addr: std::net::SocketAddr,
    client: Arc<XLayerRemoteClient>,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("refOrderId lookup endpoint listening on {addr}");
    axum::serve(listener, app(client)).await?;
    Ok(())
}

#[cfg(all(test, feature = "xlayer-verify"))]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Method, Request},
    };
    use tower::ServiceExt;

    use super::*;
    use crate::xlayer_remote_client::XLayerRemoteClient;

    const FIVE_FIELDS: [&str; 5] = ["status", "code", "msg", "detailMsg", "data"];

    /// Round-trips one request through the router and returns the status plus
    /// the decoded JSON body.
    async fn call(
        client: Arc<XLayerRemoteClient>,
        method: Method,
        uri: &str,
    ) -> (StatusCode, serde_json::Value) {
        let request = Request::builder().method(method).uri(uri).body(Body::empty()).unwrap();
        let response = app(client).oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let body = serde_json::from_slice(&bytes).expect("response body must be JSON");
        (status, body)
    }

    /// Asserts the response carries exactly the five documented fields with the
    /// expected values.
    fn assert_contract(body: &serde_json::Value, status: u16, code: i64, msg: &str) {
        let object = body.as_object().expect("body must be a JSON object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut expected = FIVE_FIELDS.to_vec();
        expected.sort_unstable();
        assert_eq!(keys, expected, "unexpected field set in {body}");
        assert_eq!(body["status"], status);
        assert_eq!(body["code"], code);
        assert_eq!(body["msg"], msg);
        assert_eq!(body["detailMsg"], "");
        assert_eq!(body["data"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn test_verify_found_returns_code_0() {
        let client = Arc::new(XLayerRemoteClient::test_client_with_capacity(100));
        let id = "PROPOSER_TZ_27_1000_a1b2c3d4";
        client.seed_ref_order_id(id).await;

        let (status, body) =
            call(client, Method::GET, &format!("/signer/get?refOrderId={id}")).await;

        assert_eq!(status, StatusCode::OK);
        assert_contract(&body, 200, 0, "success");
    }

    #[tokio::test]
    async fn test_verify_not_found_returns_code_1() {
        let client = Arc::new(XLayerRemoteClient::test_client_with_capacity(100));

        let (status, body) =
            call(client, Method::GET, "/signer/get?refOrderId=UNKNOWN_ID_12345").await;

        assert_eq!(status, StatusCode::OK);
        assert_contract(&body, 200, 1, "not found");
    }

    #[tokio::test]
    async fn test_verify_missing_param_returns_400() {
        let client = Arc::new(XLayerRemoteClient::test_client_with_capacity(100));

        let (status, body) = call(client, Method::GET, "/signer/get").await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_contract(&body, 400, 1, "refOrderId is required");
    }

    #[tokio::test]
    async fn test_verify_empty_param_returns_400() {
        let client = Arc::new(XLayerRemoteClient::test_client_with_capacity(100));

        let (status, body) = call(client, Method::GET, "/signer/get?refOrderId=").await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_contract(&body, 400, 1, "refOrderId is required");
    }

    #[tokio::test]
    async fn test_verify_post_method_returns_405() {
        let client = Arc::new(XLayerRemoteClient::test_client_with_capacity(100));

        let (status, body) = call(client, Method::POST, "/signer/get").await;

        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_contract(&body, 405, 1, "method not allowed");
    }

    /// A second non-GET, non-HEAD method, to pin the contract beyond POST.
    #[tokio::test]
    async fn test_verify_put_method_returns_405() {
        let client = Arc::new(XLayerRemoteClient::test_client_with_capacity(100));

        let (status, body) = call(client, Method::PUT, "/signer/get").await;

        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_contract(&body, 405, 1, "method not allowed");
    }

    /// `HEAD` must be rejected explicitly: routing it to the GET handler would
    /// answer with the lookup's own status. The 405 carries no body, because a
    /// HEAD response never does.
    #[tokio::test]
    async fn test_verify_head_method_returns_405_no_body() {
        let client = Arc::new(XLayerRemoteClient::test_client_with_capacity(100));
        client.seed_ref_order_id("PROPOSER_TZ_27_1000_a1b2c3d4").await;

        let request = Request::builder()
            .method(Method::HEAD)
            .uri("/signer/get?refOrderId=PROPOSER_TZ_27_1000_a1b2c3d4")
            .body(Body::empty())
            .unwrap();
        let response = app(client).oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        assert!(bytes.is_empty(), "HEAD response must have no body, got {bytes:?}");
    }

    /// A 405 has to advertise the methods the route serves.
    #[tokio::test]
    async fn test_verify_method_not_allowed_reports_allow_header() {
        let client = Arc::new(XLayerRemoteClient::test_client_with_capacity(100));

        let request =
            Request::builder().method(Method::POST).uri("/signer/get").body(Body::empty()).unwrap();
        let response = app(client).oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.headers().get(header::ALLOW).and_then(|value| value.to_str().ok()),
            Some("GET"),
            "a 405 must carry the methods the route serves"
        );
    }

    /// The method contract does not depend on the query string: a request whose
    /// query cannot be read is still answered by the method guard, not by the
    /// query extractor.
    #[tokio::test]
    async fn test_verify_head_with_unreadable_query_returns_405_without_body() {
        let client = Arc::new(XLayerRemoteClient::test_client_with_capacity(100));

        let request = Request::builder()
            .method(Method::HEAD)
            .uri("/signer/get?refOrderId=a&refOrderId=b")
            .body(Body::empty())
            .unwrap();
        let response = app(client).oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        assert!(bytes.is_empty(), "HEAD response must have no body, got {bytes:?}");
    }

    #[tokio::test]
    async fn test_verify_post_with_unreadable_query_returns_405_envelope() {
        let client = Arc::new(XLayerRemoteClient::test_client_with_capacity(100));

        let (status, body) =
            call(client, Method::POST, "/signer/get?refOrderId=a&refOrderId=b").await;

        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_contract(&body, 405, 1, "method not allowed");
    }

    /// An ID that was never issued must not be reported as found even when the
    /// cache is non-empty.
    #[tokio::test]
    async fn test_verify_five_field_contract_for_every_scenario() {
        let client = Arc::new(XLayerRemoteClient::test_client_with_capacity(100));
        client.seed_ref_order_id("PROPOSER_TZ_20_1_00000000").await;

        let (_, found) =
            call(client.clone(), Method::GET, "/signer/get?refOrderId=PROPOSER_TZ_20_1_00000000")
                .await;
        assert_contract(&found, 200, 0, "success");

        let (_, missing) = call(client.clone(), Method::GET, "/signer/get").await;
        assert_contract(&missing, 400, 1, "refOrderId is required");
    }

    /// Two clients do not share issued-order state.
    #[tokio::test]
    async fn test_verify_cross_client_isolation() {
        let client_a = Arc::new(XLayerRemoteClient::test_client_with_capacity(100));
        let client_b = Arc::new(XLayerRemoteClient::test_client_with_capacity(100));
        let id = "ISOLATION_TEST_42_5000_deadbeef";
        client_a.seed_ref_order_id(id).await;

        let (_, body_a) =
            call(client_a, Method::GET, &format!("/signer/get?refOrderId={id}")).await;
        assert_eq!(body_a["code"], 0);

        let (_, body_b) =
            call(client_b, Method::GET, &format!("/signer/get?refOrderId={id}")).await;
        assert_contract(&body_b, 200, 1, "not found");
    }

    /// Waits until the detached server accepts connections, bounded by a
    /// deadline — a readiness signal rather than a fixed sleep.
    async fn get_until_ready(url: &str) -> reqwest::Response {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match reqwest::get(url).await {
                Ok(response) => return response,
                Err(error) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "the detached server never became reachable: {error}"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// The documented endpoint is reachable over a real socket, and the task
    /// keeps serving after its join handle is dropped.
    #[tokio::test]
    async fn test_verify_detached_server_survives_handle_drop() {
        let client = Arc::new(XLayerRemoteClient::test_client_with_capacity(100));
        let id = "DETACHED_99_9999_ffffffff";
        client.seed_ref_order_id(id).await;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound_addr = listener.local_addr().unwrap();
        let server_client = client.clone();

        let handle = tokio::spawn(async move {
            axum::serve(listener, app(server_client)).await.unwrap();
        });
        // The server task must outlive the handle that started it.
        drop(handle);

        let found =
            get_until_ready(&format!("http://{bound_addr}/signer/get?refOrderId={id}")).await;
        assert_eq!(found.status(), 200);
        let found_body: serde_json::Value = found.json().await.unwrap();
        assert_contract(&found_body, 200, 0, "success");

        let unknown =
            get_until_ready(&format!("http://{bound_addr}/signer/get?refOrderId=nope")).await;
        assert_eq!(unknown.status(), 200);
        let unknown_body: serde_json::Value = unknown.json().await.unwrap();
        assert_contract(&unknown_body, 200, 1, "not found");
    }
}
