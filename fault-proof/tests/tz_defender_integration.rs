//! End-to-end Defender integration tests.
//!
//! Drives the full stack — real `WbClient` (wire-parsed via `wiremock`) -> `WbWitnessSource` ->
//! `Handler` state machine / `Supervisor` -> local `verifier` -> `MockChallengeContract` submit —
//! plus the `Watcher` finality/dedup gating and `MockRootManager` latest-only roots. All expected
//! tree values are computed natively via the public `tree_adapter` helpers (no frozen fixture).

#![cfg(feature = "tz")]

use std::sync::Arc;

use alloy_primitives::{Address, B256, TxHash};
use fault_proof::tz::{
    defender::{
        challenge_contract::{
            ChallengeEventSource, ChallengeStatus, MockChallengeContract, TxStatus,
        },
        config::DefenderConfig,
        handler::{ChallengeState, Handler, WitnessSource},
        rootmanager_client::MockRootManager,
        supervisor::Supervisor,
        watcher::Watcher,
        witness_wb::WbWitnessSource,
    },
    withdraw::{
        tree_adapter::{business_root, root_from_frontier, zero_hashes, WITHDRAWAL_TAG},
        wb_client::WbClient,
    },
};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

const CHAIN_ID: u64 = 196;
const CHECKPOINT_HEIGHT: u64 = 20;
const SAFETY: u64 = 100;
const MAX_RESEND: u32 = 3;
const PROOF_ROUTE: &str = "/chain/witness/withdrawal-proof";

fn build_proof(leaf: B256) -> (B256, [B256; 32]) {
    // A count==1 tree places the leaf at index 0 with all-empty siblings; the single-leaf frontier
    // is [leaf], whose inner root matches what the verifier rebuilds along the zero-sibling path.
    let z = zero_hashes();
    let mut siblings = [B256::ZERO; 32];
    siblings.copy_from_slice(&z[..32]);
    let inner = root_from_frontier(&[leaf], 1).expect("single-leaf frontier inner root");
    let root = business_root(inner, 1, WITHDRAWAL_TAG);
    (root, siblings)
}

fn ok_body(data: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "code": 0, "message": "ok", "data": data })
}

fn record_json(leaf: B256) -> serde_json::Value {
    serde_json::json!({
        "version": 1, "chainId": CHAIN_ID, "transactionHash": leaf,
        "rawTradezoneWithdrawal": {
            "tokenType": 0, "tokenAddress": Address::ZERO, "tokenIds": [], "amounts": [],
            "from": Address::ZERO, "to": Address::ZERO
        }
    })
}

fn proof_json(leaf: B256, root: B256, siblings: &[B256; 32]) -> serde_json::Value {
    let sibs: Vec<String> = siblings.iter().map(|s| format!("{s:#x}")).collect();
    ok_body(serde_json::json!({
        "record": record_json(leaf), "recordHash": leaf, "leafHash": leaf,
        "canonicalBlockHeight": 10, "withdrawalRoot": root,
        "leafIndex": 0, "count": 1, "siblings": sibs
    }))
}

async fn mount_proof(server: &MockServer, leaf: B256, root: B256, siblings: &[B256; 32]) {
    Mock::given(method("GET"))
        .and(path(PROOF_ROUTE))
        .respond_with(ResponseTemplate::new(200).set_body_json(proof_json(leaf, root, siblings)))
        .mount(server)
        .await;
}

fn witness_for(server: &MockServer) -> Arc<dyn WitnessSource> {
    let wb = Arc::new(WbClient::new(server.uri().parse().unwrap(), CHAIN_ID).unwrap());
    Arc::new(WbWitnessSource::new(wb))
}

fn open_status(deadline: u64) -> ChallengeStatus {
    ChallengeStatus { open: true, deadline, chain_timestamp: 0 }
}

fn inject(cc: &MockChallengeContract, tx_seed: u8, leaf: B256, block: u64) -> fault_proof::tz::defender::ChallengeId {
    let id = cc.inject_opened_from(
        CHAIN_ID,
        Address::repeat_byte(0x01),
        B256::repeat_byte(tx_seed),
        0,
        leaf,
        block,
        10_000,
    );
    cc.set_status(id, open_status(10_000));
    id
}

/// Happy path: finality gating, real WB proof fetch + local verify, optimistic submit, then a
/// receipt+status-confirmed Proved. Broadcast alone is only Submitted.
#[tokio::test]
async fn full_pipeline_submits_then_confirms_proved() {
    let leaf = B256::repeat_byte(0x42);
    let (root, siblings) = build_proof(leaf);
    let server = MockServer::start().await;
    mount_proof(&server, leaf, root, &siblings).await;

    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, root);
    let cc = Arc::new(MockChallengeContract::new());
    let id = inject(&cc, 0x02, leaf, 100);

    // Watcher: not finalized before the tip, finalized after.
    let mut watcher = Watcher::new(cc.clone(), 32);
    assert!(watcher.poll(120).await.unwrap().is_empty(), "not finalized before tip");
    let events = watcher.poll(200).await.unwrap();
    assert_eq!(events.len(), 1);

    let handler =
        Handler::new(cc.clone(), cc.clone(), witness_for(&server), rm, 16, SAFETY, MAX_RESEND);
    let mut state = ChallengeState::Discovered;
    handler.drive(&events[0], &mut state).await.unwrap();
    assert!(matches!(state, ChallengeState::Submitted(_)), "broadcast is Submitted, not Proved");

    let calls = cc.prove_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].challenge_id, id);
    assert_eq!(calls[0].checkpoint_height, CHECKPOINT_HEIGHT);
    assert_eq!(calls[0].count, 1);
    assert_eq!(calls[0].leaf_index, 0);

    // Confirmation requires a successful receipt AND a resolved status.
    cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Success);
    cc.mark_resolved_in_our_favor(id);
    handler.drive(&events[0], &mut state).await.unwrap();
    assert!(matches!(state, ChallengeState::Proved(_)));
}

/// An uncertain (pending) receipt reconciles on the next tick rather than resending.
#[tokio::test]
async fn pending_receipt_reconciles_not_resends() {
    let leaf = B256::repeat_byte(0x42);
    let (root, siblings) = build_proof(leaf);
    let server = MockServer::start().await;
    mount_proof(&server, leaf, root, &siblings).await;
    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, root);
    let cc = Arc::new(MockChallengeContract::new());
    let _id = inject(&cc, 0x02, leaf, 100);
    let handler =
        Handler::new(cc.clone(), cc.clone(), witness_for(&server), rm, 16, SAFETY, MAX_RESEND);

    // No scripted receipt ⇒ confirm returns Pending.
    let mut state = ChallengeState::Submitted(TxHash::repeat_byte(0x99));
    handler.drive(&opened(&cc, leaf, 100), &mut state).await.unwrap();
    assert!(matches!(state, ChallengeState::Submitted(_)));
    assert!(cc.prove_calls().is_empty(), "no resend on a pending receipt");
}

/// A WB proof that does not match the bound root must NOT produce a transaction.
#[tokio::test]
async fn tampered_wb_proof_sends_no_tx() {
    let leaf = B256::repeat_byte(0x42);
    let (root, siblings) = build_proof(leaf);
    let wrong_leaf = B256::repeat_byte(0xEE);
    let server = MockServer::start().await;
    // Proof for a DIFFERENT leaf but claiming our bound root ⇒ local verify must fail.
    mount_proof(&server, wrong_leaf, root, &siblings).await;
    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, root);
    let cc = Arc::new(MockChallengeContract::new());
    let _id = inject(&cc, 0x02, leaf, 100);
    let handler =
        Handler::new(cc.clone(), cc.clone(), witness_for(&server), rm, 16, SAFETY, MAX_RESEND);
    let mut state = ChallengeState::Discovered;
    handler.drive(&opened(&cc, leaf, 100), &mut state).await.unwrap();
    assert!(matches!(state, ChallengeState::PermanentFailure));
    assert!(cc.prove_calls().is_empty(), "no tx on verify failure");
}

/// End-to-end RootNotFound classification: a proof-endpoint 404 with code 11009 is a bounded wait;
/// an unknown/plain 404 fails closed. Neither sends a transaction.
#[tokio::test]
async fn root_not_found_11009_waits_and_unknown_404_fails_closed() {
    let leaf = B256::repeat_byte(0x42);
    let (root, _sibs) = build_proof(leaf);

    // 404 + 11009 ⇒ WaitingWitness.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(PROOF_ROUTE))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "code": 11009, "name": "RootNotFound", "message": "root not indexed"
        })))
        .mount(&server)
        .await;
    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, root);
    let cc = Arc::new(MockChallengeContract::new());
    let _id = inject(&cc, 0x02, leaf, 100);
    let handler =
        Handler::new(cc.clone(), cc.clone(), witness_for(&server), rm, 16, SAFETY, MAX_RESEND);
    let mut state = ChallengeState::Discovered;
    handler.drive(&opened(&cc, leaf, 100), &mut state).await.unwrap();
    assert!(matches!(state, ChallengeState::WaitingWitness), "index lag ⇒ wait");
    assert!(cc.prove_calls().is_empty());

    // Unknown/plain 404 ⇒ fail closed.
    let server2 = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(PROOF_ROUTE))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server2)
        .await;
    let rm2 = Arc::new(MockRootManager::new());
    rm2.set_latest(CHECKPOINT_HEIGHT, root);
    let cc2 = Arc::new(MockChallengeContract::new());
    let _id2 = inject(&cc2, 0x02, leaf, 100);
    let handler2 =
        Handler::new(cc2.clone(), cc2.clone(), witness_for(&server2), rm2, 16, SAFETY, MAX_RESEND);
    let mut state2 = ChallengeState::Discovered;
    handler2.drive(&opened(&cc2, leaf, 100), &mut state2).await.unwrap();
    assert!(matches!(state2, ChallengeState::PermanentFailure), "unknown 404 ⇒ fail closed");
    assert!(cc2.prove_calls().is_empty());
}

/// The supervisor re-drives pending work across ticks and gates on the L2 tip's finality. This is
/// the tip-source regression: the tip is the L2 provider's height (never the L1 settlement one).
#[tokio::test]
async fn supervisor_finality_gating_and_redrive() {
    let leaf = B256::repeat_byte(0x42);
    let (root, siblings) = build_proof(leaf);
    let server = MockServer::start().await;
    mount_proof(&server, leaf, root, &siblings).await;
    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, root);
    let cc = Arc::new(MockChallengeContract::new());
    let _id = inject(&cc, 0x02, leaf, 100);
    let handler =
        Handler::new(cc.clone(), cc.clone(), witness_for(&server), rm, 16, SAFETY, MAX_RESEND);
    let mut sup = Supervisor::new(Watcher::new(cc.clone(), 32), handler, cc.clone());

    // Tip below finality ⇒ nothing discovered.
    sup.tick(120).await.unwrap();
    assert_eq!(sup.pending_len(), 0, "not finalized ⇒ not dispatched");
    // Tip past finality ⇒ discovered and driven to Submitted.
    cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Success);
    sup.tick(200).await.unwrap();
    assert_eq!(sup.pending_len(), 1);
    assert_eq!(cc.prove_calls().len(), 1, "submitted once");
}

/// No events ⇒ no pending work and no transactions.
#[tokio::test]
async fn no_event_is_a_noop() {
    let server = MockServer::start().await;
    let leaf = B256::repeat_byte(0x42);
    let (root, siblings) = build_proof(leaf);
    mount_proof(&server, leaf, root, &siblings).await;
    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, root);
    let cc = Arc::new(MockChallengeContract::new());
    let handler =
        Handler::new(cc.clone(), cc.clone(), witness_for(&server), rm, 16, SAFETY, MAX_RESEND);
    let mut sup = Supervisor::new(Watcher::new(cc.clone(), 0), handler, cc.clone());
    sup.tick(1_000).await.unwrap();
    assert_eq!(sup.pending_len(), 0);
    assert!(cc.prove_calls().is_empty());
}

/// The same leaf challenged twice yields two distinct challenge ids, both tracked independently.
#[tokio::test]
async fn same_leaf_two_challenges_are_distinct_and_tracked() {
    let leaf = B256::repeat_byte(0x42);
    let cc = Arc::new(MockChallengeContract::new());
    let a = inject(&cc, 0x02, leaf, 100);
    let b = cc.inject_opened_from(
        CHAIN_ID,
        Address::repeat_byte(0x01),
        B256::repeat_byte(0x03),
        0,
        leaf,
        100,
        10_000,
    );
    assert_ne!(a, b);
    let mut watcher = Watcher::new(cc.clone(), 0);
    let events = watcher.poll(200).await.unwrap();
    assert_eq!(events.len(), 2, "two distinct challenges for one leaf");
    // A rescan does not re-dispatch either.
    assert!(watcher.poll(200).await.unwrap().is_empty());
}

/// Restart recovery uses current status only: a still-open challenge is re-enqueued (best effort),
/// a closed one is skipped. No prior transaction receipt is queried.
#[tokio::test]
async fn restart_rescan_reconciles_status_only() {
    let leaf = B256::repeat_byte(0x42);
    let (root, siblings) = build_proof(leaf);
    let server = MockServer::start().await;
    mount_proof(&server, leaf, root, &siblings).await;
    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, root);
    let cc = Arc::new(MockChallengeContract::new());
    let open_id = inject(&cc, 0x10, leaf, 100);
    let closed_id = cc.inject_opened_from(
        CHAIN_ID,
        Address::repeat_byte(0x01),
        B256::repeat_byte(0x11),
        0,
        leaf,
        100,
        10_000,
    );
    cc.set_status(closed_id, ChallengeStatus { open: false, deadline: 10_000, chain_timestamp: 0 });

    let handler =
        Handler::new(cc.clone(), cc.clone(), witness_for(&server), rm, 16, SAFETY, MAX_RESEND);
    let mut sup = Supervisor::new(Watcher::new(cc.clone(), 0), handler, cc.clone());
    let rediscovered = ChallengeEventSource::watch_opened(&*cc).await.unwrap();
    sup.reconcile_on_startup(&rediscovered).await.unwrap();
    assert!(sup.is_pending(open_id), "still-open ⇒ best-effort re-drive");
    assert!(!sup.is_pending(closed_id), "closed ⇒ skipped (no old-receipt lookup)");
}

/// The startup lookback lower bound is derived in L2 blocks (period converted via the minimum
/// block interval, plus finality depth and reorg margin), never by adding seconds to blocks; a
/// still-open challenge within the window is rediscovered.
#[tokio::test]
async fn lookback_bound_is_blocks_and_still_open_is_rediscovered() {
    let cfg = defender_config();
    let lb = cfg.startup_lookback_blocks(7200, 2); // period 7200s / 2s ⇒ 3600 blocks + margins
    assert!(lb >= 3600 + cfg.finality_blocks);
    assert_ne!(lb, 7200 + cfg.finality_blocks, "seconds and blocks are never added directly");

    let leaf = B256::repeat_byte(0x42);
    let (root, siblings) = build_proof(leaf);
    let server = MockServer::start().await;
    mount_proof(&server, leaf, root, &siblings).await;
    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, root);
    let cc = Arc::new(MockChallengeContract::new());
    let id = inject(&cc, 0x02, leaf, 100);
    let handler =
        Handler::new(cc.clone(), cc.clone(), witness_for(&server), rm, 16, SAFETY, MAX_RESEND);
    let mut sup = Supervisor::new(Watcher::new(cc.clone(), 0), handler, cc.clone());
    let rediscovered = ChallengeEventSource::watch_opened(&*cc).await.unwrap();
    sup.reconcile_on_startup(&rediscovered).await.unwrap();
    assert!(sup.is_pending(id), "a still-open challenge in the window is rediscovered");
}

fn defender_config() -> DefenderConfig {
    use std::collections::HashMap;
    let mut m = HashMap::new();
    m.insert("DEFENDER_CHALLENGE_CONTRACT", format!("{:#x}", Address::repeat_byte(0x01)));
    m.insert("DEFENDER_ROOT_MANAGER", format!("{:#x}", Address::repeat_byte(0x02)));
    m.insert("DEFENDER_WB_ENDPOINT", "http://wb:8545".to_string());
    m.insert("DEFENDER_TZ_CHAIN_ID", "196".to_string());
    m.insert("DEFENDER_SIGNER_SECRET", "kms-ref".to_string());
    DefenderConfig::parse_from(|k| m.get(k).cloned()).unwrap()
}

fn opened(cc: &MockChallengeContract, leaf: B256, block: u64) -> fault_proof::tz::defender::ChallengeOpened {
    // Reconstruct the event with the same coordinates used by `inject` so its id matches.
    let _ = cc;
    fault_proof::tz::defender::ChallengeOpened::new(
        CHAIN_ID,
        Address::repeat_byte(0x01),
        B256::repeat_byte(0x02),
        0,
        leaf,
        block,
    )
}
