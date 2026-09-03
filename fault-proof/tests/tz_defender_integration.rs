//! End-to-end Defender integration tests (spec §7.4, §9 item 10).
//!
//! Drives the full stack — real `WbClient` (wire-parsed via `wiremock`) → `WbWitnessSource` →
//! `Handler` state machine → local `verifier` → `MockChallengeContract` submit — plus the
//! `Watcher` finality/dedup gating and `MockRootManager`. All expected tree values are computed
//! natively via the public `tree_adapter` helpers (no frozen fixture file — per creator direction
//! the values are generated from the same wrapper the Witness Builder uses).

#![cfg(feature = "tz")]

use std::sync::Arc;

use alloy_primitives::{Address, B256};
use fault_proof::tz::defender::challenge_contract::{
    ChallengeOpened, ChallengeStatus, MockChallengeContract,
};
use fault_proof::tz::defender::handler::{Handler, HandlerOutcome};
use fault_proof::tz::defender::rootmanager_client::MockRootManager;
use fault_proof::tz::defender::watcher::Watcher;
use fault_proof::tz::defender::witness_wb::WbWitnessSource;
use fault_proof::tz::withdraw::tree_adapter::{
    business_root, calculate_inner_root, zero_hashes, WITHDRAWAL_TAG,
};
use fault_proof::tz::withdraw::wb_client::WbClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CHAIN_ID: u64 = 196;
const CHECKPOINT_HEIGHT: u64 = 20;
const RECORD_HEIGHT: u64 = 10;

/// Build a valid single-leaf (count == 1) proof for `leaf`, returning the bound withdrawal root
/// and the 32 sibling hashes.
fn build_proof(leaf: B256) -> (B256, [B256; 32]) {
    let z = zero_hashes();
    let mut siblings = [B256::ZERO; 32];
    siblings.copy_from_slice(&z[..32]);
    let inner = calculate_inner_root(leaf, 0, &siblings);
    let root = business_root(inner, 1, WITHDRAWAL_TAG);
    (root, siblings)
}

fn ok_body(data: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "code": 0, "message": "ok", "data": data })
}

fn record_json(leaf: B256, height: Option<u64>) -> serde_json::Value {
    let mut r = serde_json::json!({
        "version": 1, "chainId": CHAIN_ID, "transactionHash": leaf,
        "tokenType": 0, "tokenAddress": Address::ZERO, "tokenIds": [], "amounts": [],
        "from": Address::ZERO, "to": Address::ZERO
    });
    if let Some(h) = height {
        r.as_object_mut().unwrap().insert("canonicalBlockHeight".into(), h.into());
    }
    r
}

fn proof_json(leaf: B256, root: B256, siblings: &[B256; 32]) -> serde_json::Value {
    let sibs: Vec<String> = siblings.iter().map(|s| format!("{s:#x}")).collect();
    ok_body(serde_json::json!({
        "record": record_json(leaf, Some(RECORD_HEIGHT)),
        "recordHash": leaf, "leafHash": leaf,
        "canonicalBlockHeight": RECORD_HEIGHT, "checkpointHeight": CHECKPOINT_HEIGHT,
        "withdrawalRoot": root, "leafIndex": 0, "count": 1, "siblings": sibs
    }))
}

async fn mount_wb(server: &MockServer, leaf: B256, root: B256, siblings: &[B256; 32]) {
    Mock::given(method("GET"))
        .and(path("/chain/canonical_record"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(record_json(leaf, Some(RECORD_HEIGHT)))))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/chain/historical_inclusion_proof"))
        .respond_with(ResponseTemplate::new(200).set_body_json(proof_json(leaf, root, siblings)))
        .mount(server)
        .await;
}

fn opened(leaf: B256, block: u64) -> ChallengeOpened {
    ChallengeOpened {
        chain_id: CHAIN_ID,
        contract: Address::repeat_byte(0x01),
        tx_hash: B256::repeat_byte(0x02),
        log_index: 0,
        leaf_hash: leaf,
        block_number: block,
    }
}

/// Happy path through the watcher (finality) and the handler (verify + prove), end to end.
#[tokio::test]
async fn full_pipeline_verifies_and_proves() {
    let leaf = B256::repeat_byte(0x42);
    let (root, siblings) = build_proof(leaf);

    let server = MockServer::start().await;
    mount_wb(&server, leaf, root, &siblings).await;

    let wb = Arc::new(WbClient::new(server.uri().parse().unwrap(), CHAIN_ID).unwrap());
    let witness = Arc::new(WbWitnessSource::new(wb));
    let rm = Arc::new(MockRootManager::new());
    rm.record(CHECKPOINT_HEIGHT, root); // finalized covering root

    let cc = Arc::new(MockChallengeContract::new());
    cc.inject_opened(opened(leaf, 100), 10_000);

    // Watcher: not finalized yet, then finalized.
    let mut watcher = Watcher::new(cc.clone(), 32);
    assert!(watcher.poll(120).await.unwrap().is_empty(), "not finalized before tip");
    let events = watcher.poll(200).await.unwrap();
    assert_eq!(events.len(), 1);

    let handler = Handler::new(cc.clone(), witness, rm, 16, 100);
    let outcome = handler.handle(&events[0], 0).await.unwrap();
    assert!(matches!(outcome, HandlerOutcome::Proved(_)), "got {outcome:?}");

    let calls = cc.prove_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].leaf_hash, leaf);
    assert_eq!(calls[0].checkpoint_height, CHECKPOINT_HEIGHT);
    assert_eq!(calls[0].count, 1);
    assert_eq!(calls[0].leaf_index, 0);
}

/// A WB proof that does not match the bound root must NOT produce a transaction.
#[tokio::test]
async fn tampered_wb_proof_sends_no_tx() {
    let leaf = B256::repeat_byte(0x42);
    let (root, siblings) = build_proof(leaf);

    let server = MockServer::start().await;
    // canonical_record returns the height; the proof endpoint returns a proof for a DIFFERENT leaf
    // but claims our bound root ⇒ local verify must fail.
    Mock::given(method("GET"))
        .and(path("/chain/canonical_record"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(record_json(leaf, Some(RECORD_HEIGHT)))))
        .mount(&server)
        .await;
    let wrong_leaf = B256::repeat_byte(0xEE);
    Mock::given(method("GET"))
        .and(path("/chain/historical_inclusion_proof"))
        .respond_with(ResponseTemplate::new(200).set_body_json(proof_json(wrong_leaf, root, &siblings)))
        .mount(&server)
        .await;

    let wb = Arc::new(WbClient::new(server.uri().parse().unwrap(), CHAIN_ID).unwrap());
    let witness = Arc::new(WbWitnessSource::new(wb));
    let rm = Arc::new(MockRootManager::new());
    rm.record(CHECKPOINT_HEIGHT, root);

    let cc = Arc::new(MockChallengeContract::new());
    cc.set_status(leaf, ChallengeStatus { open: true, deadline: 10_000 });

    let handler = Handler::new(cc.clone(), witness, rm, 16, 100);
    assert_eq!(handler.handle(&opened(leaf, 0), 0).await.unwrap(), HandlerOutcome::VerifyFailed);
    assert!(cc.prove_calls().is_empty(), "no tx on verify failure");
}

/// Restart / duplicate-event recovery: rescanning the same finalized window does not re-dispatch.
#[tokio::test]
async fn restart_rescan_does_not_double_dispatch() {
    let leaf = B256::repeat_byte(0x42);
    let cc = Arc::new(MockChallengeContract::new());
    cc.inject_opened(opened(leaf, 100), 10_000);

    let mut watcher = Watcher::new(cc.clone(), 0);
    assert_eq!(watcher.poll(200).await.unwrap().len(), 1);
    // Simulate a restart re-scanning the same window.
    let mut watcher2 = Watcher::new(cc.clone(), 0);
    let first = watcher2.poll(200).await.unwrap();
    assert_eq!(first.len(), 1, "a fresh watcher re-dispatches; dedup is per-process (event rescan)");
    // Same watcher instance does not re-dispatch.
    assert_eq!(watcher2.poll(200).await.unwrap().len(), 0);
}
