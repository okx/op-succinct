// Integration tests for XLayer remote signer
// These tests require a real XLayer API endpoint and are skipped in CI
// To run manually: cargo test --package op-succinct-signer-utils --test xlayer_integration_test -- --ignored

#![cfg(test)]

use alloy_primitives::{address, Bytes, U256};
use alloy_rpc_types_eth::TransactionRequest;
use op_succinct_signer_utils::xlayer_remote_client::{XLayerConfig, XLayerRemoteClient};
use std::time::Duration;

/// Helper to create test config from environment variables
/// Set these in .env file:
/// - XLAYER_ENDPOINT
/// - XLAYER_ADDRESS
/// - XLAYER_USER_ID
/// - XLAYER_ACCESS_KEY
/// - XLAYER_SECRET_KEY
fn get_test_config() -> Option<XLayerConfig> {
    dotenv::dotenv().ok();

    let endpoint = std::env::var("XLAYER_ENDPOINT").ok()?;
    let address = std::env::var("XLAYER_ADDRESS").ok()?;
    let user_id = std::env::var("XLAYER_USER_ID").ok()?.parse().ok()?;
    let access_key = std::env::var("XLAYER_ACCESS_KEY").ok()?;
    let secret_key = std::env::var("XLAYER_SECRET_KEY").ok()?;

    Some(XLayerConfig {
        endpoint,
        address: address.parse().ok()?,
        user_id,
        symbol: 2882,
        project_symbol: 3011,
        operate_symbol: 2,
        operate_amount: "0".to_string(),
        sys_from: 3,
        request_sign_uri: "/priapi/v1/assetonchain/ecology/ecologyOperate".to_string(),
        query_sign_uri: "/priapi/v1/assetonchain/ecology/querySignDataByOrderNo".to_string(),
        access_key,
        secret_key,
        timeout: Duration::from_secs(30),
    })
}

#[tokio::test]
#[ignore] // Skip in CI, run manually with: cargo test -- --ignored
async fn test_proposer_create_full_flow() {
    let config = get_test_config().expect(
        "\n❌ XLayer configuration not found!\n\
         Please set the following environment variables:\n\
         - XLAYER_ENDPOINT\n\
         - XLAYER_ADDRESS\n\
         - XLAYER_USER_ID\n\
         - XLAYER_ACCESS_KEY\n\
         - XLAYER_SECRET_KEY\n\n\
         See INTEGRATION_TEST_GUIDE.md for details.\n"
    );

    let client = XLayerRemoteClient::new(config.clone());

    // DisputeGameFactory.create method signature
    let method_sig = hex::decode("82ecf2f6").unwrap();
    let mut data = method_sig.clone();

    // gameType = 1 (padded to 32 bytes)
    data.extend_from_slice(&[0u8; 28]);
    data.extend_from_slice(&[0, 0, 0, 1]);

    // rootClaim (32 bytes)
    data.extend_from_slice(&[0x12u8; 32]);

    // extraData offset = 96
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0x60]);

    // extraData length = 8
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 8]);

    // extraData = 8 bytes (L2 block number)
    data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x01, 0x00]);

    let mut tx = TransactionRequest::default();
    tx.to = Some(alloy_primitives::TxKind::Call(address!(
        "0000000000000000000000000000000000000001"
    )));
    tx.gas = Some(1000000);
    tx.nonce = Some(1);
    tx.max_fee_per_gas = Some(2000000000);
    tx.max_priority_fee_per_gas = Some(1000000000);
    tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
    tx.value = Some(U256::ZERO);
    tx.chain_id = Some(11155111); // Sepolia

    println!("Sending transaction to XLayer remote signer...");
    let result = client
        .sign_transaction(&tx, Bytes::new())
        .await;

    match result {
        Ok(signed_tx_bytes) => {
            println!("✅ Transaction signed successfully!");
            println!("Signed transaction length: {} bytes", signed_tx_bytes.len());
            assert!(!signed_tx_bytes.is_empty());
        }
        Err(e) => {
            println!("❌ Signing failed: {}", e);
            panic!("Integration test failed: {}", e);
        }
    }
}

#[tokio::test]
#[ignore]
async fn test_challenger_claim_credit_full_flow() {
    let config = get_test_config().expect(
        "\n❌ XLayer configuration not found!\n\
         Please set the required environment variables.\n\
         See INTEGRATION_TEST_GUIDE.md for details.\n"
    );

    let client = XLayerRemoteClient::new(config);

    // FaultDisputeGame.claimCredit method signature
    let method_sig = hex::decode("60e27464").unwrap();
    let mut data = method_sig.clone();

    // recipient address (padded to 32 bytes)
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(&hex::decode("1234567890123456789012345678901234567890").unwrap());

    let mut tx = TransactionRequest::default();
    tx.to = Some(alloy_primitives::TxKind::Call(address!(
        "0000000000000000000000000000000000000002"
    )));
    tx.gas = Some(500000);
    tx.nonce = Some(2);
    tx.max_fee_per_gas = Some(2000000000);
    tx.max_priority_fee_per_gas = Some(1000000000);
    tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
    tx.value = Some(U256::ZERO);
    tx.chain_id = Some(11155111);

    println!("Sending claimCredit transaction to XLayer remote signer...");
    let result = client
        .sign_transaction(&tx, Bytes::new())
        .await;

    match result {
        Ok(signed_tx_bytes) => {
            println!("✅ ClaimCredit transaction signed successfully!");
            println!("Signed transaction length: {} bytes", signed_tx_bytes.len());
            assert!(!signed_tx_bytes.is_empty());
        }
        Err(e) => {
            println!("❌ Signing failed: {}", e);
            panic!("Integration test failed: {}", e);
        }
    }
}

#[tokio::test]
#[ignore]
async fn test_challenger_prove_full_flow() {
    let config = get_test_config().expect(
        "\n❌ XLayer configuration not found!\n\
         Please set the required environment variables.\n\
         See INTEGRATION_TEST_GUIDE.md for details.\n"
    );

    let client = XLayerRemoteClient::new(config);

    // FaultDisputeGame.prove method signature: 0x0e5d7305
    let method_sig = hex::decode("0e5d7305").unwrap();
    let mut data = method_sig.clone();

    // Add dummy proofBytes (ABI-encoded bytes)
    // offset to proofBytes data (32 bytes)
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0x20]); // offset = 32

    // length of proofBytes (let's say 128 bytes)
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0x80]); // length = 128

    // actual proof data (128 bytes of dummy data)
    data.extend_from_slice(&[0xABu8; 128]);

    let mut tx = TransactionRequest::default();
    tx.to = Some(alloy_primitives::TxKind::Call(address!(
        "0000000000000000000000000000000000000003"
    )));
    tx.gas = Some(2000000);
    tx.nonce = Some(3);
    tx.max_fee_per_gas = Some(2000000000);
    tx.max_priority_fee_per_gas = Some(1000000000);
    tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
    tx.value = Some(U256::ZERO);
    tx.chain_id = Some(11155111);

    println!("Sending prove transaction to XLayer remote signer...");
    let result = client
        .sign_transaction(&tx, Bytes::new())
        .await;

    match result {
        Ok(signed_tx_bytes) => {
            println!("✅ Prove transaction signed successfully!");
            println!("Signed transaction length: {} bytes", signed_tx_bytes.len());
            assert!(!signed_tx_bytes.is_empty());
        }
        Err(e) => {
            println!("❌ Signing failed: {}", e);
            panic!("Integration test failed: {}", e);
        }
    }
}

#[tokio::test]
#[ignore]
async fn test_challenger_resolve_full_flow() {
    let config = get_test_config().expect(
        "\n❌ XLayer configuration not found!\n\
         Please set the required environment variables.\n\
         See INTEGRATION_TEST_GUIDE.md for details.\n"
    );

    let client = XLayerRemoteClient::new(config);

    // FaultDisputeGame.resolve method signature: 0x2810e1d6
    let method_sig = hex::decode("2810e1d6").unwrap();
    let data = method_sig; // No parameters for resolve()

    let mut tx = TransactionRequest::default();
    tx.to = Some(alloy_primitives::TxKind::Call(address!(
        "0000000000000000000000000000000000000004"
    )));
    tx.gas = Some(500000);
    tx.nonce = Some(4);
    tx.max_fee_per_gas = Some(2000000000);
    tx.max_priority_fee_per_gas = Some(1000000000);
    tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
    tx.value = Some(U256::ZERO);
    tx.chain_id = Some(11155111);

    println!("Sending resolve transaction to XLayer remote signer...");
    let result = client
        .sign_transaction(&tx, Bytes::new())
        .await;

    match result {
        Ok(signed_tx_bytes) => {
            println!("✅ Resolve transaction signed successfully!");
            println!("Signed transaction length: {} bytes", signed_tx_bytes.len());
            assert!(!signed_tx_bytes.is_empty());
        }
        Err(e) => {
            println!("❌ Signing failed: {}", e);
            panic!("Integration test failed: {}", e);
        }
    }
}

#[tokio::test]
#[ignore]
async fn test_challenger_challenge_full_flow() {
    let config = get_test_config().expect(
        "\n❌ XLayer configuration not found!\n\
         Please set the required environment variables.\n\
         See INTEGRATION_TEST_GUIDE.md for details.\n"
    );

    let client = XLayerRemoteClient::new(config);

    // FaultDisputeGame.challenge method signature: 0xd2ef7398
    let method_sig = hex::decode("d2ef7398").unwrap();
    let data = method_sig; // No parameters for challenge()

    let mut tx = TransactionRequest::default();
    tx.to = Some(alloy_primitives::TxKind::Call(address!(
        "0000000000000000000000000000000000000005"
    )));
    tx.gas = Some(500000);
    tx.nonce = Some(5);
    tx.max_fee_per_gas = Some(2000000000);
    tx.max_priority_fee_per_gas = Some(1000000000);
    tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
    tx.value = Some(U256::ZERO);
    tx.chain_id = Some(11155111);

    println!("Sending challenge transaction to XLayer remote signer...");
    let result = client
        .sign_transaction(&tx, Bytes::new())
        .await;

    match result {
        Ok(signed_tx_bytes) => {
            println!("✅ Challenge transaction signed successfully!");
            println!("Signed transaction length: {} bytes", signed_tx_bytes.len());
            assert!(!signed_tx_bytes.is_empty());
        }
        Err(e) => {
            println!("❌ Signing failed: {}", e);
            panic!("Integration test failed: {}", e);
        }
    }
}

#[test]
fn test_integration_test_setup_instructions() {
    println!("\n=== XLayer Integration Test Setup ===");
    println!("To run integration tests, set these environment variables:");
    println!("  XLAYER_ENDPOINT=http://your-xlayer-api-endpoint");
    println!("  XLAYER_ADDRESS=0x...");
    println!("  XLAYER_USER_ID=123");
    println!("  XLAYER_ACCESS_KEY=your-access-key");
    println!("  XLAYER_SECRET_KEY=your-secret-key");
    println!("\nThen run:");
    println!("  cargo test --package op-succinct-signer-utils --test xlayer_integration_test -- --ignored");
    println!("\nAvailable tests:");
    println!("  1. test_proposer_create_full_flow - DisputeGameFactory.create");
    println!("  2. test_challenger_prove_full_flow - FaultDisputeGame.prove");
    println!("  3. test_challenger_resolve_full_flow - FaultDisputeGame.resolve");
    println!("  4. test_challenger_claim_credit_full_flow - FaultDisputeGame.claimCredit");
    println!("  5. test_challenger_challenge_full_flow - FaultDisputeGame.challenge");
    println!("=====================================\n");
}

