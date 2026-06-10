// Integration tests for the XLayer remote signer.
// Each test exercises the full sign + poll round-trip against a real remote
// service, so all are #[ignore]'d. The default endpoint is the asset-onchain
// test cluster; any field can be overridden via env vars.
//
// Run manually:
//   cargo test --package op-succinct-signer-utils \
//     --test xlayer_integration_test -- --ignored --nocapture
//
// Optional env (override hardcoded defaults below):
//   XLAYER_ENDPOINT, XLAYER_ADDRESS, XLAYER_USER_ID,
//   XLAYER_ACCESS_KEY, XLAYER_SECRET_KEY
//
// Note: auth is skipped entirely when XLAYER_ACCESS_KEY or XLAYER_SECRET_KEY
// is empty (matches Go's addAuth behavior).

#![cfg(test)]

use alloy_primitives::{address, Bytes, U256};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use op_succinct_signer_utils::xlayer_remote_client::{XLayerConfig, XLayerRemoteClient};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "http://asset-onchain.forked-contract-risk.svc.test2.local:7001";
const TEST_ADDRESS: alloy_primitives::Address =
    address!("d6dda5aa7749142b7fda3fe4662c9f346101b8a6");
const DEFAULT_USER_ID: i32 = 0;
const SYMBOL: i32 = 2882;
const PROJECT_SYMBOL: i32 = 3011;
const OPERATE_SYMBOL: i32 = 2;
const OPERATE_AMOUNT: &str = "0";
const SYS_FROM: i32 = 3;
const REQUEST_SIGN_URI: &str = "/priapi/v1/assetonchain/ecology/ecologyOperate";
const QUERY_SIGN_URI: &str = "/priapi/v1/assetonchain/ecology/querySignDataByOrderNo";
const TIMEOUT: Duration = Duration::from_secs(30);

const CHAIN_ID: u64 = 11155111; // Sepolia
const MAX_FEE_PER_GAS: u128 = 2_000_000_000;
const MAX_PRIORITY_FEE_PER_GAS: u128 = 1_000_000_000;

fn build_config() -> XLayerConfig {
    let endpoint =
        std::env::var("XLAYER_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
    let address = match std::env::var("XLAYER_ADDRESS") {
        Ok(s) => s.parse().expect("XLAYER_ADDRESS not a valid Ethereum address"),
        Err(_) => TEST_ADDRESS,
    };
    let user_id = std::env::var("XLAYER_USER_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_USER_ID);
    let access_key = std::env::var("XLAYER_ACCESS_KEY").unwrap_or_default();
    let secret_key = std::env::var("XLAYER_SECRET_KEY").unwrap_or_default();

    XLayerConfig {
        endpoint,
        address,
        user_id,
        symbol: SYMBOL,
        project_symbol: PROJECT_SYMBOL,
        operate_symbol: OPERATE_SYMBOL,
        operate_amount: OPERATE_AMOUNT.to_string(),
        sys_from: SYS_FROM,
        request_sign_uri: REQUEST_SIGN_URI.to_string(),
        query_sign_uri: QUERY_SIGN_URI.to_string(),
        access_key,
        secret_key,
        timeout: TIMEOUT,
    }
}

fn build_tx(
    to: alloy_primitives::Address,
    gas: u64,
    nonce: u64,
    data: Vec<u8>,
) -> TransactionRequest {
    let mut tx = TransactionRequest::default();
    tx.to = Some(alloy_primitives::TxKind::Call(to));
    tx.gas = Some(gas);
    tx.nonce = Some(nonce);
    tx.max_fee_per_gas = Some(MAX_FEE_PER_GAS);
    tx.max_priority_fee_per_gas = Some(MAX_PRIORITY_FEE_PER_GAS);
    tx.input = TransactionInput::new(Bytes::from(data));
    tx.value = Some(U256::ZERO);
    tx.chain_id = Some(CHAIN_ID);
    tx
}

async fn run_sign_flow(label: &str, tx: TransactionRequest) {
    let config = build_config();
    println!("[{label}] Target endpoint: {}", config.endpoint);

    let client = XLayerRemoteClient::new(config);

    let signed = client
        .sign_transaction(&tx)
        .await
        .unwrap_or_else(|e| panic!("[{label}] sign request failed: {e}"));

    println!("[{label}] Signed transaction: {} bytes", signed.len());
    assert!(!signed.is_empty(), "[{label}] signed payload should not be empty");
}

// 1. DisputeGameFactory.create — OperateType::Create = 20
#[tokio::test]
#[ignore]
async fn test_create() {
    let mut data = hex::decode("82ecf2f6").unwrap();
    // gameType = 1 (uint32 padded to 32 bytes)
    data.extend_from_slice(&[0u8; 28]);
    data.extend_from_slice(&[0, 0, 0, 1]);
    // rootClaim (bytes32)
    data.extend_from_slice(&[0x12u8; 32]);
    // extraData offset = 0x60
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0x60]);
    // extraData length = 8
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 8]);
    // extraData = L2 block number (8 bytes)
    data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x01, 0x00]);

    let tx = build_tx(TEST_ADDRESS, 1_000_000, 1, data);
    run_sign_flow("create", tx).await;
}

// 2. OPSuccinctFaultDisputeGame.resolve — OperateType::Resolve = 22
#[tokio::test]
#[ignore]
async fn test_resolve() {
    let data = hex::decode("2810e1d6").unwrap();
    let tx = build_tx(TEST_ADDRESS, 500_000, 3, data);
    run_sign_flow("resolve", tx).await;
}

// 3. OPSuccinctFaultDisputeGame.claimCredit — OperateType::ClaimCredit = 23
#[tokio::test]
#[ignore]
async fn test_claim_credit() {
    let mut data = hex::decode("60e27464").unwrap();
    // recipient address (20 bytes), padded to 32
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(&hex::decode("1234567890123456789012345678901234567890").unwrap());

    let tx = build_tx(TEST_ADDRESS, 500_000, 4, data);
    run_sign_flow("claimCredit", tx).await;
}

// 4. OPSuccinctFaultDisputeGame.prove(bytes) — OperateType::Prove = 27
#[tokio::test]
#[ignore]
async fn test_prove() {
    let mut data = hex::decode("375bfa5d").unwrap();
    // proofBytes offset = 0x20
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0x20]);
    // proofBytes length = 128
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0x80]);
    // proofBytes payload (128 dummy bytes)
    data.extend_from_slice(&[0xCDu8; 128]);

    let tx = build_tx(TEST_ADDRESS, 2_000_000, 5, data);
    run_sign_flow("prove", tx).await;
}

// 5. OPSuccinctFaultDisputeGame.challenge() — OperateType::Challenge = 28
#[tokio::test]
#[ignore]
async fn test_challenge() {
    let data = hex::decode("d2ef7398").unwrap();
    let tx = build_tx(TEST_ADDRESS, 500_000, 6, data);
    run_sign_flow("challenge", tx).await;
}
