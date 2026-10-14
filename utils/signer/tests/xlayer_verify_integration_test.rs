//! End-to-end check of the contract between the signing path and the lookup
//! endpoint.
//!
//! One `XLayerRemoteClient` is shared between the lookup endpoint and a local
//! mock of the asset-management service. When the mock receives a signing
//! request it reads the `refOrderId` out of it, queries the lookup endpoint
//! *before* releasing its own response, and records what it observed. That is
//! the real ordering the callback depends on: an order must be answerable while
//! the signer is still waiting for its signature.
//!
//! Everything runs on the loopback interface. No order is issued to a real
//! service and no chain or funds are involved.

#![cfg(feature = "xlayer-verify")]

use std::{net::SocketAddr, sync::Arc};

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::Encodable2718;
use alloy_primitives::{address, Bytes, TxKind, U256};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use op_succinct_signer_utils::xlayer_remote_client::{XLayerConfig, XLayerRemoteClient};
use serde_json::{json, Value};
use tokio::sync::Mutex;

/// Prefix the client under test stamps on the ids it issues.
const REF_ORDER_PREFIX: &str = "LOOKUP_TEST_";

/// The path the lookup endpoint is queried on.
const LOOKUP_PATH: &str = "/signer/get";

/// What the mock observed when it queried the lookup endpoint from inside the
/// signing request.
#[derive(Clone, Debug)]
struct Observation {
    ref_order_id: String,
    http_status: u16,
    body: Value,
}

/// Shared state of the mock asset-management service.
struct Mock {
    /// Address of the lookup endpoint the client under test serves.
    lookup_addr: SocketAddr,
    /// Signed transaction the mock hands back once the lookup has been made.
    signed_tx_hex: String,
    /// Filled in by the signing handler before its response is released.
    observation: Mutex<Option<Observation>>,
}

type SharedMock = Arc<Mock>;

/// Handles the signing request: capture the issued id, ask the lookup endpoint
/// about it, record the answer, and only then release the sign response.
async fn sign_handler(State(mock): State<SharedMock>, body: String) -> impl IntoResponse {
    let request: Value =
        serde_json::from_str(&body).expect("signing request body must be a JSON object");
    let ref_order_id = request["refOrderId"]
        .as_str()
        .expect("signing request must carry a refOrderId")
        .to_string();

    let url = format!("http://{}{LOOKUP_PATH}?refOrderId={ref_order_id}", mock.lookup_addr);
    let response = reqwest::get(&url).await.expect("lookup request failed");
    let http_status = response.status().as_u16();
    let text = response.text().await.expect("lookup response body unreadable");
    let observed = Observation {
        ref_order_id,
        http_status,
        body: serde_json::from_str(&text).expect("lookup body must be JSON"),
    };

    if observed.http_status != 200 || observed.body["code"] != 0 {
        panic!(
            "the issued order was not answerable while its signature was still pending: \
             http_status={}, body={}",
            observed.http_status, observed.body
        );
    }

    *mock.observation.lock().await = Some(observed);

    (
        StatusCode::OK,
        Json(json!({
            "status": 200,
            "code": 0,
            "msg": "success",
            "detailMsg": "",
            "data": "MOCK_ORDER_ACK",
            "success": true,
        })),
    )
}

/// Hands back the signature the signer is waiting for.
async fn query_handler(State(mock): State<SharedMock>) -> impl IntoResponse {
    Json(json!({
        "status": 200,
        "code": 0,
        "msg": "success",
        "detailMsg": "",
        "data": mock.signed_tx_hex,
        "success": true,
    }))
}

/// Builds the transaction the proposer would hand to the signer, plus the
/// signature the mock returns for it.
fn build_transaction(signer: &PrivateKeySigner) -> (TransactionRequest, String) {
    const CHAIN_ID: u64 = 11_155_111;
    const NONCE: u64 = 7;
    const GAS_LIMIT: u64 = 200_000;
    const MAX_FEE_PER_GAS: u128 = 2_000_000_000;
    const MAX_PRIORITY_FEE_PER_GAS: u128 = 1_000_000_000;

    // `OPSuccinctFaultDisputeGame.resolve()` takes no arguments.
    let calldata = Bytes::from(hex::decode("2810e1d6").unwrap());
    let to = address!("1234567890123456789012345678901234567890");

    let mut request = TransactionRequest::default();
    request.from = Some(signer.address());
    request.to = Some(TxKind::Call(to));
    request.input = TransactionInput::new(calldata.clone());
    request.nonce = Some(NONCE);
    request.gas = Some(GAS_LIMIT);
    request.max_fee_per_gas = Some(MAX_FEE_PER_GAS);
    request.max_priority_fee_per_gas = Some(MAX_PRIORITY_FEE_PER_GAS);
    request.value = Some(U256::ZERO);
    request.chain_id = Some(CHAIN_ID);

    let envelope_tx = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce: NONCE,
        gas_limit: GAS_LIMIT,
        max_fee_per_gas: MAX_FEE_PER_GAS,
        max_priority_fee_per_gas: MAX_PRIORITY_FEE_PER_GAS,
        to: TxKind::Call(to),
        value: U256::ZERO,
        access_list: Default::default(),
        input: calldata,
    };
    let signature = signer.sign_hash_sync(&envelope_tx.signature_hash()).unwrap();
    let envelope = TxEnvelope::Eip1559(envelope_tx.into_signed(signature));

    (request, format!("0x{}", hex::encode(envelope.encoded_2718())))
}

/// The lookup endpoint answers for an order while the signer is still waiting
/// for that order's signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_transaction_callback_visible_before_post_returns() {
    let signer = PrivateKeySigner::random();
    let (transaction, signed_tx_hex) = build_transaction(&signer);

    // The mock asset-management service.
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_listener.local_addr().unwrap();

    // The lookup endpoint shares the very client that issues the orders.
    let lookup_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lookup_addr = lookup_listener.local_addr().unwrap();

    let config = XLayerConfig {
        endpoint: format!("http://{mock_addr}"),
        address: signer.address(),
        request_sign_uri: "/sign".to_string(),
        query_sign_uri: "/query".to_string(),
        ref_order_prefix: REF_ORDER_PREFIX.to_string(),
        ..XLayerConfig::default()
    };
    let client = Arc::new(XLayerRemoteClient::new(config));

    let lookup_client = Arc::clone(&client);
    tokio::spawn(async move {
        axum::serve(
            lookup_listener,
            op_succinct_signer_utils::xlayer_verify_server::app(lookup_client),
        )
        .await
        .unwrap();
    });

    let mock = Arc::new(Mock {
        lookup_addr,
        signed_tx_hex: signed_tx_hex.clone(),
        observation: Mutex::new(None),
    });
    let mock_app = Router::new()
        .route("/sign", post(sign_handler))
        .route("/query", get(query_handler))
        .with_state(Arc::clone(&mock));
    tokio::spawn(async move {
        axum::serve(mock_listener, mock_app).await.unwrap();
    });

    // Drive the real signing path — not a seeded cache entry.
    let signed = client.sign_transaction(&transaction).await.expect("signing must succeed");
    assert_eq!(hex::encode(signed.as_ref()), signed_tx_hex.trim_start_matches("0x"));

    let observation = mock
        .observation
        .lock()
        .await
        .clone()
        .expect("the mock must query the lookup endpoint before releasing its response");

    assert!(
        observation.ref_order_id.starts_with(REF_ORDER_PREFIX),
        "issued id must carry the configured prefix, got {}",
        observation.ref_order_id
    );
    assert_eq!(observation.http_status, 200);

    let body = observation.body.as_object().expect("lookup body must be a JSON object");
    let mut keys: Vec<&str> = body.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["code", "data", "detailMsg", "msg", "status"]);
    assert_eq!(body["status"], 200);
    assert_eq!(body["code"], 0);
    assert_eq!(body["msg"], "success");
    assert_eq!(body["detailMsg"], "");
    assert_eq!(body["data"], Value::Null);
}
