//! End-to-end Defender acceptance tests.
//!
//! Drives the full stack — real `WbClient` (wire-parsed via `wiremock`) → `WbWitnessSource` →
//! `Handler` state machine / `Supervisor` → local leaf-bound `verifier` → `MockChallengeContract`
//! submit — plus `Watcher` window/dedup gating and `MockRootManager` latest-only roots. All
//! expected tree values are computed natively via the public `tree_adapter` helpers (no frozen
//! fixture), and every challenged leaf is the tz-witness-recomputed record hash so leaf-bound
//! verification passes.
//!
//! The state-machine internals (counted resend, in-flight gate, nearest-deadline, ReconcileUnknown,
//! failure isolation) are exhaustively covered by the crate's unit tests; this suite asserts the
//! END-TO-END wire behavior: real WB numeric-code classification, the covering-root gate, leaf
//! binding, single-finality scanning, dedup/rescan, restart reconciliation, and Submitted≠Proved.

#![cfg(feature = "tz")]

use std::sync::Arc;

use alloy_primitives::{Address, TxHash, B256, U256};
use fault_proof::tz::{
    defender::{
        challenge_contract::{
            ChallengeEventSource, ChallengeOpened, ChallengeStatus, MockChallengeContract,
            ScanWindow, TxStatus,
        },
        handler::{ChallengeState, Handler, InFlightGate, WitnessSource},
        rootmanager_client::MockRootManager,
        supervisor::Supervisor,
        verifier::record_leaf_hash,
        watcher::Watcher,
        witness_wb::WbWitnessSource,
        ChallengeId,
    },
    withdraw::{
        tree_adapter::{business_root, root_from_frontier, zero_hashes, WITHDRAWAL_TAG},
        types::WithdrawRecord,
        wb_client::WbClient,
    },
};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

const CHAIN_ID: u64 = 196;
const CHECKPOINT_HEIGHT: u64 = 20;
const RECORD_HEIGHT: u64 = 10;
const SAFETY: u64 = 100;
const MAX_RESEND: u32 = 3;
const CONTRACT: u8 = 0x01;
const PROOF_ROUTE: &str = "/chain/witness/withdrawal-proof";

/// A valid canonical Erc20 record; `seed` varies its fields so distinct seeds give distinct leaves.
fn valid_record(seed: u8) -> WithdrawRecord {
    WithdrawRecord {
        version: 1,
        chain_id: CHAIN_ID,
        transaction_hash: B256::repeat_byte(seed),
        token_type: 0,
        token_address: Address::repeat_byte(0xAA),
        token_ids: vec![U256::ZERO],
        amounts: vec![U256::from(seed as u64 + 1)],
        from: Address::repeat_byte(0x01),
        to: Address::repeat_byte(0x02),
    }
}

/// The tz-witness-recomputed leaf hash of a record (== recordHash for V1).
fn leaf_of(r: &WithdrawRecord) -> B256 {
    record_leaf_hash(r).expect("valid record hashes")
}

/// A valid count==1 proof `(root, siblings)` for `leaf`, via the public tree_adapter helpers only
/// (integration tests cannot see `#[cfg(test)]` fixtures).
fn build_proof(leaf: B256) -> (B256, [B256; 32]) {
    let z = zero_hashes();
    let mut siblings = [B256::ZERO; 32];
    siblings.copy_from_slice(&z[..32]);
    let inner = root_from_frontier(&[leaf], 1).expect("single-leaf inner root");
    let root = business_root(inner, 1, WITHDRAWAL_TAG);
    (root, siblings)
}

fn ok_body(data: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "code": 0, "message": "ok", "data": data })
}

/// The WB record JSON mirroring `r` (nested under `rawTradezoneWithdrawal`, no `name` field).
fn record_json(r: &WithdrawRecord) -> serde_json::Value {
    serde_json::json!({
        "version": r.version, "chainId": r.chain_id, "transactionHash": r.transaction_hash,
        "rawTradezoneWithdrawal": {
            "tokenType": r.token_type, "tokenAddress": r.token_address,
            "tokenIds": r.token_ids, "amounts": r.amounts,
            "from": r.from, "to": r.to
        }
    })
}

fn proof_json(
    r: &WithdrawRecord,
    leaf: B256,
    root: B256,
    siblings: &[B256; 32],
) -> serde_json::Value {
    let sibs: Vec<String> = siblings.iter().map(|s| format!("{s:#x}")).collect();
    ok_body(serde_json::json!({
        "record": record_json(r), "recordHash": leaf, "leafHash": leaf,
        "canonicalBlockHeight": RECORD_HEIGHT, "withdrawalRoot": root,
        "leafIndex": 0, "count": 1, "siblings": sibs
    }))
}

/// Mount the canonical-record endpoint so the covering-root gate's `canonical_record_height` reads
/// `record_height` for `leaf`.
async fn mount_record(server: &MockServer, r: &WithdrawRecord, leaf: B256, record_height: u64) {
    Mock::given(method("GET"))
        .and(path(format!("/chain/witness/withdrawals/{leaf:#x}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(serde_json::json!({
            "canonicalBlockHeight": record_height, "record": record_json(r)
        }))))
        .mount(server)
        .await;
}

async fn mount_proof(
    server: &MockServer,
    r: &WithdrawRecord,
    leaf: B256,
    root: B256,
    siblings: &[B256; 32],
) {
    Mock::given(method("GET"))
        .and(path(PROOF_ROUTE))
        .respond_with(ResponseTemplate::new(200).set_body_json(proof_json(r, leaf, root, siblings)))
        .mount(server)
        .await;
}

fn witness_for(server: &MockServer) -> Arc<dyn WitnessSource> {
    let wb = Arc::new(WbClient::new(server.uri().parse().unwrap(), CHAIN_ID).unwrap());
    Arc::new(WbWitnessSource::new(wb))
}

fn handler(
    server: &MockServer,
    rm: Arc<MockRootManager>,
    cc: Arc<MockChallengeContract>,
) -> Handler {
    Handler::new(cc.clone(), cc, witness_for(server), rm, CHAIN_ID, 16, SAFETY, MAX_RESEND)
}

fn opened(tx_seed: u8, leaf: B256, block: u64) -> ChallengeOpened {
    ChallengeOpened::new(
        CHAIN_ID,
        Address::repeat_byte(CONTRACT),
        B256::repeat_byte(tx_seed),
        0,
        leaf,
        block,
    )
}

fn inject(
    cc: &MockChallengeContract,
    tx_seed: u8,
    leaf: B256,
    block: u64,
    deadline: u64,
) -> ChallengeId {
    let ev = opened(tx_seed, leaf, block);
    let id = ev.challenge_id;
    cc.inject_opened(ev, deadline);
    cc.set_status(id, ChallengeStatus { open: true, deadline, chain_timestamp: 0 });
    id
}

/// Happy path: covering-root gate, real WB record + proof fetch, leaf-bound verify, optimistic
/// submit (Submitted, NOT Proved), then a receipt+status-confirmed Proved.
#[tokio::test]
async fn full_pipeline_covering_gate_submits_then_proved() {
    let r = valid_record(0x42);
    let leaf = leaf_of(&r);
    let (root, siblings) = build_proof(leaf);
    let server = MockServer::start().await;
    mount_record(&server, &r, leaf, RECORD_HEIGHT).await;
    mount_proof(&server, &r, leaf, root, &siblings).await;

    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, root); // 20 >= record_height 10 ⇒ covered
    let cc = Arc::new(MockChallengeContract::new());
    let id = inject(&cc, 0x02, leaf, 100, 10_000);
    let h = handler(&server, rm, cc.clone());
    let gate = InFlightGate::new();
    let ev = opened(0x02, leaf, 100);

    let mut state = ChallengeState::Discovered;
    h.drive(&ev, &mut state, &gate).await.unwrap();
    assert!(
        matches!(state, ChallengeState::Submitted { .. }),
        "broadcast is Submitted, not Proved"
    );
    assert_eq!(gate.holder(), Some(id), "holds the in-flight gate");

    let calls = cc.prove_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].challenge_id, id);
    assert_eq!(calls[0].checkpoint_height, CHECKPOINT_HEIGHT);
    assert_eq!(calls[0].count, 1);
    assert_eq!(calls[0].leaf_index, 0);

    cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Success);
    cc.mark_resolved_in_our_favor(id);
    h.drive(&ev, &mut state, &gate).await.unwrap();
    assert!(matches!(state, ChallengeState::Proved(_)));
    assert_eq!(gate.holder(), None, "gate released on Proved");
}

/// The covering-root gate waits (no proof request) until the latest checkpoint covers the record
/// height (end-to-end).
#[tokio::test]
async fn covering_gate_waits_when_checkpoint_behind_record() {
    let r = valid_record(0x42);
    let leaf = leaf_of(&r);
    let (root, siblings) = build_proof(leaf);
    let server = MockServer::start().await;
    // record_height = 30, but the latest checkpoint is only 20 ⇒ wait, no proof.
    mount_record(&server, &r, leaf, 30).await;
    mount_proof(&server, &r, leaf, root, &siblings).await;
    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, root); // 20 < 30
    let cc = Arc::new(MockChallengeContract::new());
    inject(&cc, 0x02, leaf, 100, 10_000);
    let h = handler(&server, rm.clone(), cc.clone());
    let gate = InFlightGate::new();
    let ev = opened(0x02, leaf, 100);

    let mut state = ChallengeState::Discovered;
    h.drive(&ev, &mut state, &gate).await.unwrap();
    assert!(
        matches!(state, ChallengeState::WaitingWitness { .. }),
        "checkpoint behind record ⇒ wait"
    );
    assert!(cc.prove_calls().is_empty(), "no tx while the checkpoint is behind the record");

    // Once the checkpoint catches up (>= 30), the proof is fetched, verified, and submitted.
    rm.set_latest(30, root);
    h.drive(&ev, &mut state, &gate).await.unwrap();
    assert!(matches!(state, ChallengeState::Submitted { .. }));
    assert_eq!(cc.prove_calls().len(), 1);
}

/// A WB proof for a DIFFERENT leaf than the challenge's is rejected by leaf binding; no tx.
#[tokio::test]
async fn leaf_binding_rejects_proof_of_other_leaf() {
    let challenged = valid_record(0x42);
    let leaf = leaf_of(&challenged);
    let other = valid_record(0x11);
    let other_leaf = leaf_of(&other);
    let (root, siblings) = build_proof(other_leaf); // valid proof, but for the OTHER leaf
    let server = MockServer::start().await;
    // The record endpoint answers for the challenged leaf (covering gate passes)...
    mount_record(&server, &challenged, leaf, RECORD_HEIGHT).await;
    // ...but the proof endpoint returns a (self-consistent) proof for `other_leaf`.
    mount_proof(&server, &other, other_leaf, root, &siblings).await;
    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, root);
    let cc = Arc::new(MockChallengeContract::new());
    inject(&cc, 0x02, leaf, 100, 10_000);
    let h = handler(&server, rm, cc.clone());
    let gate = InFlightGate::new();

    let mut state = ChallengeState::Discovered;
    h.drive(&opened(0x02, leaf, 100), &mut state, &gate).await.unwrap();
    assert!(matches!(state, ChallengeState::PermanentFailure), "leaf-binding mismatch ⇒ no tx");
    assert!(cc.prove_calls().is_empty());
    assert_eq!(gate.holder(), None);
}

/// Real WB numeric-code classification on the proof endpoint: 11009 (authoritative root) is a
/// bounded wait; a plain/unknown 404 fails closed. Neither sends a tx.
#[tokio::test]
async fn wb_root_not_found_11009_waits_and_plain_404_fails_closed() {
    let r = valid_record(0x42);
    let leaf = leaf_of(&r);
    let (root, _sibs) = build_proof(leaf);

    // 404 + real envelope {code:11009,...} (NO name) ⇒ WaitingWitness.
    let server = MockServer::start().await;
    mount_record(&server, &r, leaf, RECORD_HEIGHT).await;
    Mock::given(method("GET"))
        .and(path(PROOF_ROUTE))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!(
            {"code": 11009, "message": "RootNotFound: 0x33", "data": null})))
        .mount(&server)
        .await;
    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, root);
    let cc = Arc::new(MockChallengeContract::new());
    inject(&cc, 0x02, leaf, 100, 10_000);
    let h = handler(&server, rm, cc.clone());
    let gate = InFlightGate::new();
    let mut state = ChallengeState::Discovered;
    h.drive(&opened(0x02, leaf, 100), &mut state, &gate).await.unwrap();
    assert!(matches!(state, ChallengeState::WaitingWitness { .. }), "11009 authoritative ⇒ wait");
    assert!(cc.prove_calls().is_empty());

    // Unknown/plain 404 ⇒ Protocol fail-closed ⇒ PermanentFailure, no tx.
    let server2 = MockServer::start().await;
    mount_record(&server2, &r, leaf, RECORD_HEIGHT).await;
    Mock::given(method("GET"))
        .and(path(PROOF_ROUTE))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server2)
        .await;
    let rm2 = Arc::new(MockRootManager::new());
    rm2.set_latest(CHECKPOINT_HEIGHT, root);
    let cc2 = Arc::new(MockChallengeContract::new());
    inject(&cc2, 0x02, leaf, 100, 10_000);
    let h2 = handler(&server2, rm2, cc2.clone());
    let gate2 = InFlightGate::new();
    let mut state2 = ChallengeState::Discovered;
    h2.drive(&opened(0x02, leaf, 100), &mut state2, &gate2).await.unwrap();
    assert!(matches!(state2, ChallengeState::PermanentFailure), "plain 404 ⇒ fail closed");
    assert!(cc2.prove_calls().is_empty());
}

/// 11006 NotReady arrives as HTTP 409 and is a wait (not mapped to InvalidRequest by status); a
/// checkpoint-only code (11003) on the proof endpoint is a joint-tuple violation ⇒ fail closed.
#[tokio::test]
async fn wb_not_ready_409_waits_and_joint_tuple_fails_closed() {
    let r = valid_record(0x42);
    let leaf = leaf_of(&r);
    let (root, _sibs) = build_proof(leaf);

    let server = MockServer::start().await;
    mount_record(&server, &r, leaf, RECORD_HEIGHT).await;
    Mock::given(method("GET"))
        .and(path(PROOF_ROUTE))
        .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!(
            {"code": 11006, "message": "NotReady: rebuilding", "data": null})))
        .mount(&server)
        .await;
    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, root);
    let cc = Arc::new(MockChallengeContract::new());
    inject(&cc, 0x02, leaf, 100, 10_000);
    let h = handler(&server, rm, cc.clone());
    let gate = InFlightGate::new();
    let mut state = ChallengeState::Discovered;
    h.drive(&opened(0x02, leaf, 100), &mut state, &gate).await.unwrap();
    assert!(matches!(state, ChallengeState::WaitingWitness { .. }), "11006/409 ⇒ NotReady wait");
    assert!(cc.prove_calls().is_empty());

    // 11003 (a checkpoint code) on the proof endpoint ⇒ Protocol ⇒ fail closed.
    let server2 = MockServer::start().await;
    mount_record(&server2, &r, leaf, RECORD_HEIGHT).await;
    Mock::given(method("GET"))
        .and(path(PROOF_ROUTE))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!(
            {"code": 11003, "message": "CheckpointNotFound: 9", "data": null})))
        .mount(&server2)
        .await;
    let rm2 = Arc::new(MockRootManager::new());
    rm2.set_latest(CHECKPOINT_HEIGHT, root);
    let cc2 = Arc::new(MockChallengeContract::new());
    inject(&cc2, 0x02, leaf, 100, 10_000);
    let h2 = handler(&server2, rm2, cc2.clone());
    let gate2 = InFlightGate::new();
    let mut state2 = ChallengeState::Discovered;
    h2.drive(&opened(0x02, leaf, 100), &mut state2, &gate2).await.unwrap();
    assert!(
        matches!(state2, ChallengeState::PermanentFailure),
        "11003-on-proof ⇒ Protocol fail closed"
    );
    assert!(cc2.prove_calls().is_empty());
}

/// An uncertain (pending) receipt reconciles on the next tick rather than resending.
#[tokio::test]
async fn pending_receipt_reconciles_not_resends() {
    let r = valid_record(0x42);
    let leaf = leaf_of(&r);
    let (root, siblings) = build_proof(leaf);
    let server = MockServer::start().await;
    mount_record(&server, &r, leaf, RECORD_HEIGHT).await;
    mount_proof(&server, &r, leaf, root, &siblings).await;
    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, root);
    let cc = Arc::new(MockChallengeContract::new());
    inject(&cc, 0x02, leaf, 100, 10_000);
    let h = handler(&server, rm, cc.clone());
    let gate = InFlightGate::new();
    let ev = opened(0x02, leaf, 100);

    // No scripted receipt ⇒ confirm returns Pending.
    let mut state = ChallengeState::Submitted { tx: TxHash::repeat_byte(0x99), attempts: 0, root };
    h.drive(&ev, &mut state, &gate).await.unwrap();
    assert!(matches!(state, ChallengeState::Submitted { .. }), "pending ⇒ reconcile, not resend");
    assert!(cc.prove_calls().is_empty(), "no resend on a pending receipt");
}

/// The supervisor applies finality exactly once (Model A) — the scan window's `to_block` is
/// `H - finality_blocks` — and drives a discovered challenge to Submitted; the scan tip is the L2
/// head passed in, not an L1 provider.
#[tokio::test]
async fn supervisor_single_finality_scan_and_redrive() {
    let r = valid_record(0x42);
    let leaf = leaf_of(&r);
    let (root, siblings) = build_proof(leaf);
    let server = MockServer::start().await;
    mount_record(&server, &r, leaf, RECORD_HEIGHT).await;
    mount_proof(&server, &r, leaf, root, &siblings).await;
    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, root);
    let cc = Arc::new(MockChallengeContract::new());
    inject(&cc, 0x02, leaf, 100, 10_000); // event at block 100
    cc.set_tx_status(TxHash::repeat_byte(0x99), TxStatus::Success);
    let h = handler(&server, rm, cc.clone());
    // finality_blocks = 32, startup_lookback = 1000.
    let mut sup =
        Supervisor::new(Watcher::new(cc.clone()), h, cc.clone(), InFlightGate::new(), 32, 1_000);

    // Head 120 ⇒ actionable_to = 88 (< block 100) ⇒ not yet actionable, nothing dispatched.
    sup.tick(120).await.unwrap();
    let w = cc.last_scan_window().unwrap();
    assert_eq!(w.to_block, 120 - 32, "finality subtracted exactly once");
    assert_eq!(sup.pending_len(), 0, "event above the actionable window is not dispatched");

    // Head 200 ⇒ actionable_to = 168 (>= 100) ⇒ discovered and driven to Submitted.
    sup.tick(200).await.unwrap();
    assert_eq!(sup.pending_len(), 1);
    assert_eq!(cc.prove_calls().len(), 1, "submitted once");
}

/// No events ⇒ no pending work and no transactions.
#[tokio::test]
async fn no_event_is_a_noop() {
    let server = MockServer::start().await;
    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, B256::repeat_byte(0x33));
    let cc = Arc::new(MockChallengeContract::new());
    let h = handler(&server, rm, cc.clone());
    let mut sup =
        Supervisor::new(Watcher::new(cc.clone()), h, cc.clone(), InFlightGate::new(), 0, 1_000);
    sup.tick(1_000).await.unwrap();
    assert_eq!(sup.pending_len(), 0);
    assert!(cc.prove_calls().is_empty());
}

/// The same leaf challenged twice yields two distinct challenge ids, both dispatched once; a rescan
/// of the same window does not re-dispatch either (dedup by ChallengeId).
#[tokio::test]
async fn same_leaf_two_challenges_distinct_and_dedup() {
    let leaf = leaf_of(&valid_record(0x42));
    let cc = Arc::new(MockChallengeContract::new());
    let a = inject(&cc, 0x02, leaf, 100, 10_000);
    let b = inject(&cc, 0x03, leaf, 100, 10_000);
    assert_ne!(a, b, "same leaf, different event coords ⇒ distinct ChallengeId");
    let mut watcher = Watcher::new(cc.clone());
    let window = ScanWindow { from_block: 0, to_block: 200 };
    assert_eq!(watcher.poll(window).await.unwrap().len(), 2);
    assert!(watcher.poll(window).await.unwrap().is_empty(), "rescan does not re-dispatch");
}

/// Restart recovery uses current status only: a still-open challenge is re-enqueued (best effort),
/// a closed one is skipped. No prior transaction receipt is queried.
#[tokio::test]
async fn restart_rescan_reconciles_status_only() {
    let leaf = leaf_of(&valid_record(0x42));
    let server = MockServer::start().await;
    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, B256::repeat_byte(0x33));
    let cc = Arc::new(MockChallengeContract::new());
    let open_id = inject(&cc, 0x10, leaf, 100, 10_000);
    let closed_id = inject(&cc, 0x11, leaf, 100, 10_000);
    cc.set_status(closed_id, ChallengeStatus { open: false, deadline: 10_000, chain_timestamp: 0 });

    let h = handler(&server, rm, cc.clone());
    let mut sup =
        Supervisor::new(Watcher::new(cc.clone()), h, cc.clone(), InFlightGate::new(), 0, 1_000);
    let rediscovered =
        ChallengeEventSource::watch_opened(&*cc, ScanWindow { from_block: 0, to_block: 10_000 })
            .await
            .unwrap();
    sup.reconcile_on_startup(&rediscovered).await.unwrap();
    assert!(sup.is_pending(open_id), "still-open ⇒ best-effort re-drive");
    assert!(!sup.is_pending(closed_id), "closed ⇒ skipped (no old-receipt lookup)");
}
