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
            ChallengeEventSource, ChallengeOpened, ChallengeStatus, ConfirmOutcome,
            MockChallengeContract, ScanWindow,
        },
        challenge_manager::{ChallengeManagerContract, ChallengeType, RawChallengeEvent},
        handler::{ChallengeState, Handler, InFlightGate, WitnessSource},
        rootmanager_client::MockRootManager,
        supervisor::Supervisor,
        verifier::record_leaf_hash,
        watcher::Watcher,
        witness_wb::WbWitnessSource,
        ChallengeId, CompatibilityDeclaration, DeclarationProvenance, DeploymentTarget,
        DirectLeafLocator, LeafEncodingGate,
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

/// The expected encoding identity this test deployment is bound to (arbitrary fixed values; the
/// matching declaration below reproduces all of them).
fn gate_target() -> DeploymentTarget {
    DeploymentTarget {
        address: Address::repeat_byte(CONTRACT),
        chain_id: CHAIN_ID,
        expected_encoding_version: 1,
        expected_canonical_encoding_hash: B256::repeat_byte(0xcc),
        expected_witness_builder_id: B256::repeat_byte(0xdd),
    }
}

/// A gate that is `Proven` for this test deployment (a declaration matching every criterion), so
/// the proof-path tests exercise the full flow.
fn proven_gate() -> Arc<LeafEncodingGate> {
    let target = gate_target();
    let declaration = CompatibilityDeclaration {
        address: target.address,
        chain_id: target.chain_id,
        encoding_version: target.expected_encoding_version,
        canonical_encoding_hash: target.expected_canonical_encoding_hash,
        witness_builder_id: target.expected_witness_builder_id,
        provenance: DeclarationProvenance::AuthenticatedImmutable,
    };
    Arc::new(LeafEncodingGate::new(target, Some(declaration)))
}

/// A gate with no compatibility declaration ⇒ `LeafEncodingMismatch` for this test deployment.
fn mismatch_gate() -> Arc<LeafEncodingGate> {
    Arc::new(LeafEncodingGate::new(gate_target(), None))
}

fn handler_with_gate(
    server: &MockServer,
    rm: Arc<MockRootManager>,
    cc: Arc<MockChallengeContract>,
    gate: Arc<LeafEncodingGate>,
) -> Handler {
    Handler::new(cc.clone(), cc, witness_for(server), rm, gate, CHAIN_ID, 16, SAFETY, MAX_RESEND)
}

fn handler(
    server: &MockServer,
    rm: Arc<MockRootManager>,
    cc: Arc<MockChallengeContract>,
) -> Handler {
    handler_with_gate(server, rm, cc, proven_gate())
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
    assert_eq!(calls[0].count, 1);
    assert_eq!(calls[0].leaf_index, 0);

    cc.set_confirm_outcome(
        TxHash::repeat_byte(0x99),
        ConfirmOutcome::Succeeded { resolved_challenge_ids: vec![id] },
    );
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
    cc.set_confirm_outcome(
        TxHash::repeat_byte(0x99),
        ConfirmOutcome::Succeeded { resolved_challenge_ids: vec![] },
    );
    let h = handler(&server, rm, cc.clone());
    // finality_blocks = 32, startup_lookback = 1000.
    let mut sup = Supervisor::new(
        Watcher::new(cc.clone()),
        h,
        cc.clone(),
        InFlightGate::new(),
        32,
        1_000,
        16,
    );

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
        Supervisor::new(Watcher::new(cc.clone()), h, cc.clone(), InFlightGate::new(), 0, 1_000, 16);
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
        Supervisor::new(Watcher::new(cc.clone()), h, cc.clone(), InFlightGate::new(), 0, 1_000, 16);
    let rediscovered =
        ChallengeEventSource::watch_opened(&*cc, ScanWindow { from_block: 0, to_block: 10_000 })
            .await
            .unwrap();
    sup.reconcile_on_startup(&rediscovered).await.unwrap();
    assert!(sup.is_pending(open_id), "still-open ⇒ best-effort re-drive");
    assert!(!sup.is_pending(closed_id), "closed ⇒ skipped (no old-receipt lookup)");
}

/// A decoded challenge event for the real adapter's scripted/offline event source.
fn raw_event(
    onchain_id: U256,
    challenge_type: ChallengeType,
    leaf: B256,
    tx_seed: u8,
    log_index: u64,
) -> RawChallengeEvent {
    RawChallengeEvent {
        onchain_challenge_id: onchain_id,
        challenge_type,
        // Keep tz_tx_hash distinct from leaf so a field-order/mapping bug cannot pass by
        // coincidence.
        tz_tx_hash: B256::repeat_byte(0xF0 | tx_seed),
        leaf,
        affected_bridge: Address::repeat_byte(0xB0),
        response_deadline: 10_000,
        block_number: 100,
        chain_id: CHAIN_ID,
        contract: Address::repeat_byte(CONTRACT),
        tx_hash: B256::repeat_byte(tx_seed),
        log_index,
    }
}

/// End-to-end with the REAL `ChallengeManagerContract`: a mixed-type batch in one scan window is
/// filtered to exactly the `WithdrawNotInRoot` challenge, driven through the real `WbClient`
/// (wiremock) → `WbWitnessSource` → `Handler`, and the resulting submit carries the WB proof's four
/// fields verbatim. This exercises the real adapter across the whole stack (not the mock seam).
#[tokio::test]
async fn end_to_end_real_adapter_answers_only_withdraw_not_in_root() {
    let r = valid_record(0x42);
    let leaf = leaf_of(&r);
    let (root, siblings) = build_proof(leaf);
    let server = MockServer::start().await;
    mount_record(&server, &r, leaf, RECORD_HEIGHT).await;
    mount_proof(&server, &r, leaf, root, &siblings).await;

    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, root);

    // One WithdrawNotInRoot (identifier == leaf, via DirectLeafLocator) interleaved with other
    // types that must be ignored — no event emitted, no witness query, no transaction for them.
    let onchain_id = U256::from(4242u64);
    let raws = vec![
        raw_event(onchain_id, ChallengeType::WithdrawNotInRoot, leaf, 0xAA, 1),
        raw_event(U256::from(7u64), ChallengeType::Other(3), B256::repeat_byte(0x02), 0xBB, 2),
        raw_event(U256::from(9u64), ChallengeType::Other(8), B256::repeat_byte(0x03), 0xCC, 3),
        // A force-transaction challenge carrying a zero leaf: dropped by the type filter, never a
        // zero-leaf proof attempt.
        raw_event(U256::from(11u64), ChallengeType::Other(2), B256::ZERO, 0xDD, 4),
    ];
    let adapter = Arc::new(ChallengeManagerContract::from_raw_events(
        raws,
        DirectLeafLocator,
        CHAIN_ID,
        Address::repeat_byte(CONTRACT),
    ));

    let opened = ChallengeEventSource::watch_opened(
        &*adapter,
        ScanWindow { from_block: 0, to_block: 10_000 },
    )
    .await
    .unwrap();
    assert_eq!(
        opened.len(),
        1,
        "only the WithdrawNotInRoot challenge is emitted from the mixed batch"
    );
    let ev = opened[0].clone();
    adapter.script_status(ev.challenge_id, true, 10_000, 0);

    let witness = witness_for(&server);
    let h = Handler::new(
        adapter.clone(),
        adapter.clone(),
        witness,
        rm,
        proven_gate(),
        CHAIN_ID,
        16,
        SAFETY,
        MAX_RESEND,
    );
    let gate = InFlightGate::new();
    let mut state = ChallengeState::Discovered;
    h.drive(&ev, &mut state, &gate).await.unwrap();
    assert!(
        matches!(state, ChallengeState::Submitted { .. }),
        "the WithdrawNotInRoot challenge is answered, got {state:?}"
    );

    // The recorded submit carries the WB proof's four fields, verbatim.
    let call = adapter.last_submit_call().expect("a submit was recorded");
    assert_eq!(call.challenge_id, onchain_id, "on-chain challengeId passed through verbatim");
    assert_eq!(call.leaf_index, 0);
    assert_eq!(call.leaf_count, 1);
    assert_eq!(call.proof, siblings);
}

/// End-to-end with a MISMATCHED leaf-encoding gate: a `WithdrawNotInRoot` challenge driven through
/// the real adapter lands in `Blocked` with ZERO Witness-Builder calls and ZERO submit calls. No
/// record/proof endpoints are mounted, so the absence of any wiremock endpoint proves the proof
/// flow was never entered. A force-transaction challenge (zero leaf) in the same batch is dropped
/// by the type filter before it could reach any proof path.
#[tokio::test]
async fn end_to_end_blocked_leaf_encoding_mismatch_makes_zero_wb_and_zero_sender_calls() {
    let r = valid_record(0x42);
    let leaf = leaf_of(&r);
    // Deliberately mount NO record/proof endpoints: a mismatched gate must block BEFORE any WB
    // call, so the absence of endpoints is itself the zero-WB-call proof.
    let server = MockServer::start().await;
    let rm = Arc::new(MockRootManager::new());
    rm.set_latest(CHECKPOINT_HEIGHT, B256::repeat_byte(0x33));

    let onchain_id = U256::from(4242u64);
    let raws = vec![
        raw_event(onchain_id, ChallengeType::WithdrawNotInRoot, leaf, 0xAA, 1),
        // A force-transaction challenge with a zero leaf: dropped by the type filter.
        raw_event(U256::from(7u64), ChallengeType::Other(2), B256::ZERO, 0xDD, 2),
    ];
    let adapter = Arc::new(ChallengeManagerContract::from_raw_events(
        raws,
        DirectLeafLocator,
        CHAIN_ID,
        Address::repeat_byte(CONTRACT),
    ));

    let opened = ChallengeEventSource::watch_opened(
        &*adapter,
        ScanWindow { from_block: 0, to_block: 10_000 },
    )
    .await
    .unwrap();
    assert_eq!(opened.len(), 1, "the zero-leaf force-tx challenge is dropped by the type filter");
    let ev = opened[0].clone();
    assert_eq!(ev.leaf_hash, leaf, "the emitted leaf_hash is the event's leaf");
    adapter.script_status(ev.challenge_id, true, 10_000, 0);

    let h = Handler::new(
        adapter.clone(),
        adapter.clone(),
        witness_for(&server),
        rm,
        mismatch_gate(),
        CHAIN_ID,
        16,
        SAFETY,
        MAX_RESEND,
    );
    let gate = InFlightGate::new();
    let mut state = ChallengeState::Discovered;
    h.drive(&ev, &mut state, &gate).await.unwrap();
    assert!(
        matches!(state, ChallengeState::Blocked(_)),
        "a mismatched leaf-encoding gate blocks the challenge, got {state:?}"
    );
    assert!(
        adapter.last_submit_call().is_none(),
        "no submitWithdrawProof calldata is built while blocked"
    );
    assert_eq!(gate.holder(), None, "no in-flight gate is held while blocked");
}

/// The refOrderId lookup contract exposed by the Defender's signer, driven through the same
/// construction the binary performs.
///
/// Gated on `xlayer-verify-test-utils`: the cache-seeding bridge these cases use exists only in
/// test builds, mirroring the binary's own gate on `XLAYER_SIGNER_ENABLED` — a release build
/// carries neither.
#[cfg(feature = "xlayer-verify-test-utils")]
mod reforder_lookup_contract {
    use alloy_primitives::{Address, B256, U256};
    use fault_proof::tz::defender::{
        challenge_manager::{ChallengeType, RawChallengeEvent},
        leaf_encoding_gate::LeafEncodingDecision,
        leaf_locator::LeafLocator,
        make_defender_context, DefenderConfig,
    };
    use op_succinct_signer_utils::{Signer, SignerLock, XLayerConfig, XLayerRemoteClient};

    use super::raw_event;

    const CONTRACT: Address = Address::repeat_byte(0x0c);

    fn env_value(key: &str) -> Option<String> {
        match key {
            "DEFENDER_CHALLENGE_CONTRACT" => Some(format!("{CONTRACT:#x}")),
            "DEFENDER_ROOT_MANAGER" => Some(format!("{:#x}", Address::repeat_byte(0x0d))),
            "DEFENDER_WB_ENDPOINT" => Some("http://127.0.0.1:18546".to_string()),
            "DEFENDER_TZ_CHAIN_ID" => Some("2882".to_string()),
            "DEFENDER_FINALITY_BLOCKS" => Some("0".to_string()),
            _ => None,
        }
    }

    fn config() -> DefenderConfig {
        DefenderConfig::parse_from(env_value).expect("the injected environment is complete")
    }

    /// T7a — a signer that is not an XLayer remote signer never resolves a lookup target, so the
    /// binary has nothing to bind.
    #[test]
    fn non_xlayer_signer_has_no_lookup_target() {
        let url = "http://127.0.0.1:8545".parse().expect("a literal URL parses");
        let signer = Signer::new_web3_signer(url, Address::repeat_byte(0x01));
        let target =
            signer.xlayer_verify_target().expect("a web3 signer never fails the address check");
        assert!(target.is_none(), "a non-XLayer signer must not serve the lookup endpoint");
    }

    /// T7b — an XLayer signer whose lookup address is empty serves nothing, and asking it to spawn
    /// the endpoint is a successful no-op rather than an error.
    #[tokio::test]
    async fn empty_lookup_address_serves_nothing() {
        let cfg = XLayerConfig { verify_addr: String::new(), ..XLayerConfig::default() };
        let signer = Signer::new_xlayer_remote_signer(cfg);
        assert!(
            signer.xlayer_verify_target().expect("an empty address is not a parse error").is_none(),
            "an empty lookup address must resolve to no target"
        );
        SignerLock::new(signer)
            .maybe_spawn_xlayer_verify_server()
            .await
            .expect("spawning without a target is a no-op");
    }

    /// T7c — the default configuration carries no lookup address at all.
    #[test]
    fn default_config_has_empty_lookup_address() {
        assert_eq!(XLayerConfig::default().verify_addr, "");
    }

    /// A configured but unparsable lookup address must stop startup instead of silently running
    /// without the endpoint the asset-management callback depends on.
    #[test]
    fn malformed_lookup_address_is_rejected() {
        let cfg = XLayerConfig {
            verify_addr: "not-a-socket-addr".to_string(),
            ..XLayerConfig::default()
        };
        let signer = Signer::new_xlayer_remote_signer(cfg);
        assert!(signer.xlayer_verify_target().is_err(), "a malformed address must be fatal");
    }

    /// T7d — an ID registered on the client is confirmed by the same lookup the endpoint serves.
    #[tokio::test]
    async fn seeded_id_is_confirmed() {
        let client = XLayerRemoteClient::new(XLayerConfig::default());
        client.seed_ref_order_id("DEFENDER_LOCAL_PROBE_20_1_00000000").await;
        assert!(
            client.has_ref_order_id("DEFENDER_LOCAL_PROBE_20_1_00000000").await,
            "a seeded ID must be confirmed"
        );
    }

    /// T7e — an ID that was never registered is not confirmed, and probing for it evicts nothing.
    #[tokio::test]
    async fn unseeded_id_is_not_confirmed() {
        let client = XLayerRemoteClient::new(XLayerConfig::default());
        client.seed_ref_order_id("DEFENDER_LOCAL_PROBE_20_2_00000000").await;
        assert!(
            !client.has_ref_order_id("DEFENDER_LOCAL_PROBE_20_3_00000000").await,
            "an unseeded ID must not be confirmed"
        );
        assert!(
            client.has_ref_order_id("DEFENDER_LOCAL_PROBE_20_2_00000000").await,
            "a miss must not evict a real entry"
        );
    }

    /// T7f — the cache is per client instance, so one process cannot confirm another's IDs.
    #[tokio::test]
    async fn second_client_does_not_confirm_first_clients_ids() {
        let first = XLayerRemoteClient::new(XLayerConfig::default());
        let second = XLayerRemoteClient::new(XLayerConfig::default());
        first.seed_ref_order_id("DEFENDER_LOCAL_PROBE_20_4_00000000").await;
        assert!(first.has_ref_order_id("DEFENDER_LOCAL_PROBE_20_4_00000000").await);
        assert!(
            !second.has_ref_order_id("DEFENDER_LOCAL_PROBE_20_4_00000000").await,
            "a second instance must not see IDs registered on the first"
        );
    }

    /// T7g — the challenge-side context is built by the same function the binary calls, so these
    /// cases exercise production wiring: the direct event-leaf locator and the fail-closed gate.
    #[tokio::test]
    async fn challenge_context_mirrors_binary_construction() {
        let cfg = config();
        let ctx = make_defender_context(&cfg);
        assert!(
            matches!(
                ctx.leaf_encoding_gate.decision(),
                LeafEncodingDecision::LeafEncodingMismatch(_)
            ),
            "with no compatibility declaration the gate must stay closed"
        );

        let ev = raw_event(
            U256::from(1u64),
            ChallengeType::WithdrawNotInRoot,
            B256::repeat_byte(0xbb),
            0xAA,
            0,
        );
        let leaf = ctx.locator.locate(&ev).await.expect("the direct locator never fails");
        assert_eq!(leaf, ev.leaf, "the wired locator returns the event's leaf field");
        assert_ne!(leaf, ev.tz_tx_hash, "the wired locator must not return the tzTxHash");
    }

    /// The event builder and the configuration above are wired consistently: the challenge address
    /// the context gates on is the one the configuration carries.
    #[test]
    fn challenge_context_uses_configured_deployment() {
        let cfg = config();
        assert_eq!(cfg.challenge_contract, CONTRACT);
        assert_eq!(cfg.chain_id, 2882);
        // A challenge event on that deployment decodes into the shape the context consumes.
        let ev = RawChallengeEvent {
            contract: CONTRACT,
            chain_id: cfg.chain_id,
            ..raw_event(
                U256::from(2u64),
                ChallengeType::WithdrawNotInRoot,
                B256::repeat_byte(0xcc),
                0xBB,
                1,
            )
        };
        assert_eq!(ev.contract, cfg.challenge_contract);
    }
}

/// Signer wiring through the shared startup path.
///
/// Gated on `xlayer-verify-test-utils`: the seed bridge and the `get_signer` accessor exist only in
/// test builds, so a release build compiles none of this.
///
/// The point of these cases is mutation sensitivity. `shared_construction_ptr_equality` never calls
/// `set_signer` by hand — it goes through the same function the binary calls. If the wiring step is
/// dropped from that function, the adapter holds no signer, `get_signer()` answers `None`, and the
/// test fails at runtime instead of silently passing on a differently wired adapter.
#[cfg(all(feature = "tz", feature = "xlayer-verify-test-utils"))]
mod defender_reverse_lookup {
    use super::*;
    use fault_proof::tz::defender::signer::{build_defender_signer, wire_defender_signer};
    use op_succinct_signer_utils::XLayerConfig;
    use op_succinct_signer_utils::XLayerRemoteClient;

    /// Serializes the cases that mutate the process environment: the environment is shared by the
    /// whole test binary, so two of these running at once would read each other's variables.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Sets the signer environment the Defender startup path reads. Rust 2024 makes environment
    /// mutation unsafe because it is process-wide; every caller holds [`ENV_LOCK`] for the whole
    /// case so no other case observes a half-written environment.
    fn set_signer_env(verify_addr: &str) {
        unsafe {
            std::env::set_var("XLAYER_SIGNER_ENABLED", "true");
            std::env::set_var("XLAYER_SIGNER_REF_ORDER_PREFIX", "TEST_DEFENDER");
            std::env::set_var("XLAYER_SIGNER_VERIFY_ADDR", verify_addr);
            std::env::set_var("XLAYER_SIGNER_ENDPOINT", "https://signer.example.com");
            std::env::set_var(
                "XLAYER_SIGNER_ADDRESS",
                "0x1111111111111111111111111111111111111111",
            );
            std::env::set_var("XLAYER_ACCESS_KEY", "test-key");
            std::env::set_var("XLAYER_SECRET_KEY", "test-secret");
        }
    }

    fn clear_signer_env() {
        unsafe {
            for key in [
                "XLAYER_SIGNER_ENABLED",
                "XLAYER_SIGNER_REF_ORDER_PREFIX",
                "XLAYER_SIGNER_VERIFY_ADDR",
                "XLAYER_SIGNER_ENDPOINT",
                "XLAYER_SIGNER_ADDRESS",
                "XLAYER_ACCESS_KEY",
                "XLAYER_SECRET_KEY",
            ] {
                std::env::remove_var(key);
            }
        }
    }

    fn scripted_adapter() -> Arc<ChallengeManagerContract<DirectLeafLocator>> {
        Arc::new(ChallengeManagerContract::from_raw_events(
            vec![],
            DirectLeafLocator,
            CHAIN_ID,
            Address::repeat_byte(CONTRACT),
        ))
    }

    /// One client serves both the signer and the lookup endpoint, through the shared wiring.
    #[tokio::test]
    async fn shared_construction_ptr_equality() {
        let _guard = ENV_LOCK.lock().await;
        set_signer_env("127.0.0.1:19976");
        let adapter = scripted_adapter();

        // The shared startup path — the same call the binary makes. Not `set_signer` by hand.
        let listener_client = wire_defender_signer(&adapter)
            .await
            .expect("the shared wiring succeeds")
            .expect("a fully configured signer resolves a lookup target");

        let wired = adapter.get_signer().expect("the wiring step attached the signer");
        let (_addr, wired_client) = wired
            .xlayer_verify_target()
            .await
            .expect("the wired signer resolves its lookup target")
            .expect("a configured address yields a target");

        assert!(
            Arc::ptr_eq(&listener_client, &wired_client),
            "one client instance must serve both the signer and the lookup endpoint"
        );

        clear_signer_env();
    }

    /// The startup path yields no signer at all when the gate is off.
    #[tokio::test]
    async fn disabled_gate_wires_no_signer() {
        let _guard = ENV_LOCK.lock().await;
        clear_signer_env();
        let (lock, client) = build_defender_signer().await.expect("the gate check cannot fail");
        assert!(lock.is_none(), "a disabled gate must construct no signer");
        assert!(client.is_none(), "a disabled gate must resolve no lookup client");

        let adapter = scripted_adapter();
        wire_defender_signer(&adapter).await.expect("wiring without a signer is a no-op");
        assert!(adapter.get_signer().is_none(), "a disabled gate must leave the adapter unwired");
    }

    /// A seeded ID does not leak into a second client.
    #[tokio::test]
    async fn second_instance_does_not_see_seeded_id() {
        let c1 = Arc::new(XLayerRemoteClient::new(XLayerConfig::default()));
        let c2 = Arc::new(XLayerRemoteClient::new(XLayerConfig::default()));
        c1.seed_ref_order_id("instance-1-only").await;
        assert!(c1.has_ref_order_id("instance-1-only").await);
        assert!(
            !c2.has_ref_order_id("instance-1-only").await,
            "a second instance must not see IDs seeded in the first"
        );
    }
}
