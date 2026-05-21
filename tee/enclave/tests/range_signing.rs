//! End-to-end HTTP tests against the real handler.
//!
//! The handler calls `kona_client::run`, which requires a witness whose
//! `preimage_store` contains the full preimage chain (Local keys + L2 block
//! headers / state trie nodes / blobs etc.). Our synthetic fixture only
//! populates the 7 Local keys, so it triggers `InvalidWitness` at
//! `get_inputs_for_pipeline`.
//!
//! The full sign-then-ecrecover happy path is exercised by the unit test
//! [`crate::signing::tests::sign_then_recover_matches_enclave_address`];
//! a future integration test will use a recorded real witness blob.

mod common;

use rkyv::rancor::Error as RkyvError;
use xlayer_tee_enclave::keys::init_dev_keys;
use xlayer_tee_types::paths;

use common::witness_fixture::{synth_boot, synthetic_witness};

#[tokio::test]
async fn synthetic_witness_triggers_invalid_witness() {
    // A synthetic witness contains only the Local boot-info keys.
    // The real range program needs the L2 chain preimages too, so
    // `get_inputs_for_pipeline` fails with "Invalid preimage key" → InvalidWitness.
    init_dev_keys();
    let app = common::app();

    let boot = synth_boot([0x22; 32], [0x33; 32], [0x44; 32], 1800);
    let witness = synthetic_witness(&boot);
    let body = rkyv::to_bytes::<RkyvError>(&witness).expect("encode witness");

    let (status, resp_bytes) =
        common::call(&app, common::post(paths::TASKS_RANGE, body.to_vec())).await;
    assert_eq!(status, 400, "expected 400, body={:?}", resp_bytes);
    let json: serde_json::Value = serde_json::from_slice(&resp_bytes).expect("err is json");
    assert_eq!(json["error_kind"], "InvalidWitness");
    let msg = json["message"].as_str().unwrap_or_default();
    assert!(msg.contains("get_inputs_for_pipeline"), "expected message about pipeline: {msg}");
}

#[tokio::test]
async fn post_range_rejects_zero_claimed_block() {
    init_dev_keys();
    let app = common::app();

    let boot = synth_boot([0u8; 32], [0u8; 32], [0u8; 32], 0); // claimed_l2_block = 0
    let witness = synthetic_witness(&boot);
    let body = rkyv::to_bytes::<RkyvError>(&witness).expect("encode");

    let (status, resp_bytes) =
        common::call(&app, common::post(paths::TASKS_RANGE, body.to_vec())).await;
    assert_eq!(status, 400, "expected 400, body={:?}", resp_bytes);
    let json: serde_json::Value = serde_json::from_slice(&resp_bytes).expect("err is json");
    assert_eq!(json["error_kind"], "InvalidWitness");
}

#[tokio::test]
async fn post_range_rejects_garbage_body() {
    init_dev_keys();
    let app = common::app();
    let (status, resp_bytes) =
        common::call(&app, common::post(paths::TASKS_RANGE, b"not-rkyv-at-all".to_vec())).await;
    assert_eq!(status, 500);
    let json: serde_json::Value = serde_json::from_slice(&resp_bytes).expect("err is json");
    assert_eq!(json["error_kind"], "DeserializeRkyv");
}

// TODO(phase-2-real-fixture): once we record a real op-succinct witness blob
// (via `op-succinct/scripts/utils/bin/gen_sp1_test_artifacts.rs` or similar),
// add a test that posts the blob and verifies:
//   - status 200
//   - response.journal.l2_block_number matches recorded value
//   - ecrecover(signature) == enclave_address()
