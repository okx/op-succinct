//! Real ChallengeManager adapter: the concrete implementation of the Defender's three seams
//! ([`ChallengeEventSource`], [`ChallengeReader`], [`ChallengeSender`]) that talks to the on-chain
//! ChallengeManager via an L2 provider.
//!
//! This module is the ABI-aware layer that slots in exactly where `MockChallengeContract` does; the
//! watcher, handler state machine, verifier, and supervisor are unchanged. It:
//! - decodes the `ChallengeCreated` event ([`decode_challenge_created`]),
//! - responds ONLY to the `WithdrawNotInRoot` challenge type — every other type is dropped silently
//!   (no event emitted, no error, no witness query, no transaction),
//! - turns the event into a Witness-Builder leaf key via a swappable [`LeafLocator`], and
//! - submits `submitWithdrawProof(challengeId, leafIndex, leafCount, proof)` with the four fields
//!   passed through verbatim.

use std::collections::HashMap;
use std::sync::Mutex;

use alloy_primitives::{Address, TxHash, B256, U256};
use alloy_provider::{DynProvider, Provider};
use alloy_rpc_types_eth::Filter;
use alloy_sol_types::{sol, SolEvent};
use anyhow::Context;
use async_trait::async_trait;

use super::challenge_contract::{
    ChallengeEventSource, ChallengeId, ChallengeOpened, ChallengeReader, ChallengeSender,
    ChallengeStatus, ScanWindow, SenderError, SubmitOutcome, TxStatus,
};
use super::leaf_locator::LeafLocator;

/// The kind of challenge carried by a `ChallengeCreated` event. Only [`ChallengeType::WithdrawNotInRoot`]
/// is acted upon; every other on-chain discriminant is represented as [`ChallengeType::Other`] so an
/// unknown type is always representable and never panics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeType {
    /// The withdraw-not-in-root challenge the Defender answers.
    WithdrawNotInRoot,
    /// Any other on-chain challenge type, kept as its raw discriminant so it can be logged/ignored.
    Other(u8),
}

/// The on-chain discriminant of the withdraw-not-in-root challenge type.
///
/// This value maps the contract's `ChallengeType` enum onto [`ChallengeType::WithdrawNotInRoot`].
/// It is the single point to adjust if the deployed enum orders its members differently; the event
/// decoder and its unit test both reference this constant, so they stay consistent. Confirm it
/// against the deployed contract's enum before production wiring.
pub const WITHDRAW_NOT_IN_ROOT_DISCRIMINANT: u8 = 0;

impl ChallengeType {
    /// Map an on-chain `uint8` challenge-type discriminant into a [`ChallengeType`].
    pub fn from_discriminant(raw: u8) -> Self {
        if raw == WITHDRAW_NOT_IN_ROOT_DISCRIMINANT {
            ChallengeType::WithdrawNotInRoot
        } else {
            ChallengeType::Other(raw)
        }
    }
}

sol! {
    // The ChallengeManager `ChallengeCreated` event. The challenge-type enum is ABI-encoded as its
    // underlying `uint8`; the identifier slot carries the transaction-scoped withdraw identifier
    // (a `bytes32`), not a leaf hash — the leaf key is resolved separately by a `LeafLocator`.
    #[allow(missing_docs)]
    event ChallengeCreated(
        uint256 indexed challengeId,
        uint8 indexed challengeType,
        address indexed target,
        address affectedBridge,
        bytes32 identifier,
        address challenger,
        uint64 responseDeadline
    );
}

/// A decoded-but-unfiltered `ChallengeCreated` event. `identifier` is the event's transaction-scoped
/// withdraw identifier (a `bytes32`); resolving it to a Witness-Builder leaf key is the job of a
/// [`LeafLocator`], never of the state machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawChallengeEvent {
    pub onchain_challenge_id: U256,
    pub challenge_type: ChallengeType,
    pub identifier: B256,
    pub response_deadline: u64,
    pub block_number: u64,
    pub chain_id: u64,
    pub contract: Address,
    pub tx_hash: B256,
    pub log_index: u64,
}

/// Decode a `ChallengeCreated` log into a [`RawChallengeEvent`]. Pure and chain-free: the event data
/// comes from the log topics/data and the event coordinates from the log envelope, so it is unit
/// testable without a live provider. Fails closed if the log is missing block/tx/log-index
/// coordinates or does not decode as `ChallengeCreated`.
pub fn decode_challenge_created(
    log: &alloy_rpc_types_eth::Log,
    chain_id: u64,
) -> anyhow::Result<RawChallengeEvent> {
    let decoded = ChallengeCreated::decode_log(&log.inner)
        .map_err(|e| anyhow::anyhow!("failed to decode ChallengeCreated log: {e}"))?;
    let block_number = log.block_number.context("ChallengeCreated log missing block_number")?;
    let tx_hash = log.transaction_hash.context("ChallengeCreated log missing transaction_hash")?;
    let log_index = log.log_index.context("ChallengeCreated log missing log_index")?;
    Ok(RawChallengeEvent {
        onchain_challenge_id: decoded.data.challengeId,
        challenge_type: ChallengeType::from_discriminant(decoded.data.challengeType),
        identifier: decoded.data.identifier,
        response_deadline: decoded.data.responseDeadline,
        block_number,
        chain_id,
        contract: log.inner.address,
        tx_hash,
        log_index,
    })
}

/// Mutable adapter state shared by the live and scripted paths.
#[derive(Default)]
struct AdapterState {
    /// Opaque [`ChallengeId`] → on-chain `challengeId`, populated as challenges are discovered so
    /// later status/submit calls can recover the on-chain id.
    id_map: HashMap<ChallengeId, U256>,
    /// On-chain `challengeId` → `responseDeadline` captured at discovery time.
    deadlines: HashMap<U256, u64>,
    /// Pre-decoded events for the scripted (test) path; `None` on the live path.
    scripted_events: Option<Vec<RawChallengeEvent>>,
    /// Scripted per-challenge status for the test path.
    scripted_status: HashMap<ChallengeId, ChallengeStatus>,
    /// Scripted receipt statuses (by tx hash) for the test path.
    scripted_tx_status: HashMap<TxHash, TxStatus>,
    /// The most recent `submitWithdrawProof` calldata built (verbatim four fields; one slot, so a
    /// long-running adapter does not accumulate). Observability for tests and operators.
    last_submit: Option<SubmitWithdrawProofCall>,
}

/// The exact `submitWithdrawProof(challengeId, leafIndex, leafCount, proof)` calldata the adapter
/// builds. It carries ONLY the four contract fields — the seam's legacy `checkpoint_height` is not
/// part of the call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitWithdrawProofCall {
    pub challenge_id: U256,
    pub leaf_index: u32,
    pub leaf_count: u32,
    pub proof: [B256; 32],
}

/// Real ChallengeManager adapter implementing the three Defender seams. It is generic ONLY over the
/// [`LeafLocator`]; the L2 provider is type-erased ([`DynProvider`]) and optional so the scripted
/// test path needs no provider. Non-`WithdrawNotInRoot` challenges are dropped in `watch_opened`
/// before any `ChallengeOpened` is built, so the state machine only ever sees the type it answers.
pub struct ChallengeManagerContract<L: LeafLocator> {
    chain_id: u64,
    contract: Address,
    locator: L,
    /// The L2 provider (live path). `None` on the scripted test path.
    provider: Option<DynProvider>,
    state: Mutex<AdapterState>,
}

impl<L: LeafLocator> ChallengeManagerContract<L> {
    /// Build a live adapter over an L2 provider. The provider is type-erased so the adapter carries
    /// no network generic.
    pub fn new(
        provider: impl Provider + 'static,
        contract: Address,
        chain_id: u64,
        locator: L,
    ) -> Self {
        Self {
            chain_id,
            contract,
            locator,
            provider: Some(provider.erased()),
            state: Mutex::new(AdapterState::default()),
        }
    }

    /// Scripted/offline constructor: feed an already-decoded batch of events through the same
    /// filter → locate → build pipeline as the live path, with no provider. Used by tests
    /// (including cross-crate integration tests); hidden from the public docs.
    #[doc(hidden)]
    pub fn from_raw_events(
        events: Vec<RawChallengeEvent>,
        locator: L,
        chain_id: u64,
        contract: Address,
    ) -> Self {
        Self {
            chain_id,
            contract,
            locator,
            provider: None,
            state: Mutex::new(AdapterState {
                scripted_events: Some(events),
                ..AdapterState::default()
            }),
        }
    }

    /// Gather the decoded-but-unfiltered events in `window`: the scripted batch when present, else a
    /// live `get_logs` scan for the `ChallengeCreated` topic decoded via [`decode_challenge_created`].
    async fn collect_raw_events(&self, window: ScanWindow) -> anyhow::Result<Vec<RawChallengeEvent>> {
        if let Some(events) = self.state.lock().unwrap().scripted_events.clone() {
            return Ok(events
                .into_iter()
                .filter(|e| e.block_number >= window.from_block && e.block_number <= window.to_block)
                .collect());
        }
        let provider =
            self.provider.as_ref().context("challenge adapter has neither provider nor scripted events")?;
        let filter = Filter::new()
            .address(self.contract)
            .event_signature(ChallengeCreated::SIGNATURE_HASH)
            .from_block(window.from_block)
            .to_block(window.to_block);
        let logs = provider.get_logs(&filter).await.context("get_logs for ChallengeCreated failed")?;
        let mut raws = Vec::with_capacity(logs.len());
        for log in &logs {
            match decode_challenge_created(log, self.chain_id) {
                Ok(r) => raws.push(r),
                Err(e) => tracing::warn!(error = %e, "skipping undecodable ChallengeCreated log"),
            }
        }
        Ok(raws)
    }

    /// Filter to `WithdrawNotInRoot`, resolve the leaf via the locator, build a [`ChallengeOpened`],
    /// and record the opaque-id → on-chain-id mapping and deadline. A locator error for a single
    /// event is logged and that event skipped (witness-wait semantics), never a scan failure. Every
    /// other challenge type is dropped silently — no event, no error, no witness query.
    async fn process_raw_events(&self, raws: Vec<RawChallengeEvent>) -> Vec<ChallengeOpened> {
        let mut opened = Vec::new();
        for raw in raws {
            // Respond only to WithdrawNotInRoot; drop every other type silently.
            if raw.challenge_type != ChallengeType::WithdrawNotInRoot {
                continue;
            }
            // Resolve the leaf via the (swappable) locator. A per-event lookup failure is a
            // witness-wait: log and skip this one event, never fail the whole scan.
            let leaf = match self.locator.locate(&raw).await {
                Ok(leaf) => leaf,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        onchain_challenge_id = %raw.onchain_challenge_id,
                        "leaf-locator could not resolve a challenge; skipping (witness-wait)"
                    );
                    continue;
                }
            };
            let ev = ChallengeOpened::new(
                raw.chain_id,
                raw.contract,
                raw.tx_hash,
                raw.log_index,
                leaf,
                raw.block_number,
            );
            {
                let mut state = self.state.lock().unwrap();
                state.id_map.insert(ev.challenge_id, raw.onchain_challenge_id);
                state.deadlines.insert(raw.onchain_challenge_id, raw.response_deadline);
            }
            opened.push(ev);
        }
        opened
    }

    /// The on-chain `challengeId` recorded for an opaque [`ChallengeId`], if discovered.
    #[cfg(test)]
    pub fn onchain_id_for(&self, id: ChallengeId) -> Option<U256> {
        self.state.lock().unwrap().id_map.get(&id).copied()
    }

    /// Scripted/offline seam: set the status returned by `get_challenge` for a (discovered)
    /// challenge id. Used by tests (including cross-crate integration tests); hidden from docs.
    #[doc(hidden)]
    pub fn script_status(
        &self,
        id: ChallengeId,
        open: bool,
        deadline: u64,
        chain_timestamp: u64,
        resolved_by_us: bool,
    ) {
        self.state
            .lock()
            .unwrap()
            .scripted_status
            .insert(id, ChallengeStatus { open, deadline, chain_timestamp, resolved_by_us });
    }

    /// The last `submitWithdrawProof` calldata this adapter built, if any (introspection).
    pub fn last_submit_call(&self) -> Option<SubmitWithdrawProofCall> {
        self.state.lock().unwrap().last_submit.clone()
    }

    /// Whether any built `submitWithdrawProof` calldata carried the seam's legacy
    /// `checkpoint_height`. It never does — the call is exactly the four contract fields — so this
    /// is a standing invariant, not runtime state.
    pub fn submitted_any_checkpoint_height(&self) -> bool {
        false
    }
}

#[async_trait]
impl<L: LeafLocator> ChallengeSender for ChallengeManagerContract<L> {
    async fn prove_challenge(
        &self,
        id: ChallengeId,
        checkpoint_height: u64,
        leaf_index: u32,
        count: u32,
        siblings: [B256; 32],
    ) -> Result<SubmitOutcome, SenderError> {
        // Recover the on-chain id; an id this adapter never decoded is a safe pre-broadcast retry
        // (never a panic), so a restart with an empty map re-discovers rather than crashing.
        let onchain_id = match self.state.lock().unwrap().id_map.get(&id).copied() {
            Some(v) => v,
            None => {
                tracing::warn!(?id, "prove_challenge for an unknown challenge id; safe to retry");
                return Err(SenderError::SafeToRetryPreBroadcast);
            }
        };
        // Build the submitWithdrawProof calldata: the four contract fields, verbatim. The seam's
        // legacy `checkpoint_height` is NOT a contract parameter and is intentionally dropped.
        let _ = checkpoint_height;
        self.state.lock().unwrap().last_submit = Some(SubmitWithdrawProofCall {
            challenge_id: onchain_id,
            leaf_index,
            leaf_count: count,
            proof: siblings,
        });
        // Scripted path: mirror the mock — an accepted broadcast.
        if self.provider.is_none() {
            return Ok(SubmitOutcome::Submitted(TxHash::repeat_byte(0x99)));
        }
        // Live path: the four fields above are the verbatim submitWithdrawProof mapping, but
        // broadcasting needs a transaction signer that is not wired in this stage. This provably
        // never broadcasts, so it is the safe-to-retry class (the handler stays Ready and re-drives
        // without sending) rather than an ambiguous outcome.
        tracing::warn!(
            on_chain_challenge_id = %onchain_id,
            leaf_index,
            leaf_count = count,
            "submitWithdrawProof calldata built (verbatim four fields); no transaction signer is \
             wired, not broadcasting"
        );
        Err(SenderError::SafeToRetryPreBroadcast)
    }

    async fn confirm(&self, tx: TxHash) -> anyhow::Result<TxStatus> {
        // Scripted path: mirror the mock — scripted status, defaulting to Pending.
        if self.provider.is_none() {
            return Ok(self
                .state
                .lock()
                .unwrap()
                .scripted_tx_status
                .get(&tx)
                .copied()
                .unwrap_or(TxStatus::Pending));
        }
        // Live path: no transaction is broadcast this stage, so there is no receipt to confirm.
        anyhow::bail!("live confirm is not wired (no transaction is broadcast until a signer lands)")
    }
}

#[async_trait]
impl<L: LeafLocator> ChallengeEventSource for ChallengeManagerContract<L> {
    async fn watch_opened(&self, window: ScanWindow) -> anyhow::Result<Vec<ChallengeOpened>> {
        let raws = self.collect_raw_events(window).await?;
        Ok(self.process_raw_events(raws).await)
    }
}

#[async_trait]
impl<L: LeafLocator> ChallengeReader for ChallengeManagerContract<L> {
    async fn get_challenge(&self, id: ChallengeId) -> anyhow::Result<ChallengeStatus> {
        // Recover the on-chain id; an id this adapter never decoded (e.g. after a restart with an
        // empty map) is a typed error routed to a safe retry — never an unwrap panic.
        let onchain_id = self
            .state
            .lock()
            .unwrap()
            .id_map
            .get(&id)
            .copied()
            .with_context(|| format!("get_challenge for an unknown challenge id {id:?}"))?;
        // Scripted (test) status when present.
        if let Some(status) = self.state.lock().unwrap().scripted_status.get(&id).copied() {
            return Ok(status);
        }
        // Live path: reading the on-chain challenge status needs the verified ChallengeManager
        // status-view ABI, which is not yet available. Fail closed with a clear message rather than
        // fabricating a call.
        if self.provider.is_some() {
            anyhow::bail!(
                "live challenge status read is not yet wired (blocked on the verified \
                 ChallengeManager status-view ABI); on-chain challengeId {onchain_id}"
            );
        }
        // A scripted adapter with no status for a known id defaults to closed (mirrors the mock).
        Ok(ChallengeStatus { open: false, deadline: 0, chain_timestamp: 0, resolved_by_us: false })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `ChallengeCreated` log fixture from the generated event type.
    fn challenge_created_log_fixture(
        challenge_id: U256,
        challenge_type: u8,
        identifier: B256,
        response_deadline: u64,
    ) -> alloy_rpc_types_eth::Log {
        let ev = ChallengeCreated {
            challengeId: challenge_id,
            challengeType: challenge_type,
            target: Address::repeat_byte(0x0a),
            affectedBridge: Address::repeat_byte(0x0b),
            identifier,
            challenger: Address::repeat_byte(0x0c),
            responseDeadline: response_deadline,
        };
        let inner =
            alloy_primitives::Log { address: Address::repeat_byte(0x01), data: ev.encode_log_data() };
        alloy_rpc_types_eth::Log {
            inner,
            block_number: Some(100),
            transaction_hash: Some(B256::repeat_byte(0x02)),
            log_index: Some(0),
            ..Default::default()
        }
    }

    #[test]
    fn decodes_challenge_created_fields_from_real_abi() {
        let id = U256::from(42u64);
        let ident = B256::repeat_byte(0x7c);
        let log = challenge_created_log_fixture(
            id,
            WITHDRAW_NOT_IN_ROOT_DISCRIMINANT,
            ident,
            1_700u64,
        );
        let ev = decode_challenge_created(&log, 196).unwrap();
        assert_eq!(ev.onchain_challenge_id, id);
        assert_eq!(ev.challenge_type, ChallengeType::WithdrawNotInRoot);
        assert_eq!(ev.identifier, ident);
        assert_eq!(ev.response_deadline, 1_700);
        assert_eq!(ev.chain_id, 196);
        assert_eq!(ev.block_number, 100);
        assert_eq!(ev.log_index, 0);
    }

    #[test]
    fn maps_non_withdraw_types_to_other() {
        assert_eq!(ChallengeType::from_discriminant(WITHDRAW_NOT_IN_ROOT_DISCRIMINANT), ChallengeType::WithdrawNotInRoot);
        let other = WITHDRAW_NOT_IN_ROOT_DISCRIMINANT.wrapping_add(1);
        assert_eq!(ChallengeType::from_discriminant(other), ChallengeType::Other(other));
    }

    // ── Real adapter: WithdrawNotInRoot filter + leaf-locator replaceability ──

    use crate::tz::defender::leaf_locator::{DirectLeafLocator, ReverseLookupLeafLocator};
    use crate::tz::withdraw::wb_client::test_doubles::MockTzTxToLeaf;

    const CONTRACT_ADDR: Address = Address::repeat_byte(0x01);

    fn window() -> ScanWindow {
        ScanWindow { from_block: 0, to_block: 1_000 }
    }

    /// A decoded event with a distinct tx hash per `log_index` (so distinct ChallengeIds), inside
    /// the default window.
    fn raw(challenge_type: ChallengeType, identifier: B256, log_index: u64) -> RawChallengeEvent {
        RawChallengeEvent {
            onchain_challenge_id: U256::from(log_index + 1),
            challenge_type,
            identifier,
            response_deadline: 10_000,
            block_number: 10,
            chain_id: 196,
            contract: CONTRACT_ADDR,
            tx_hash: B256::repeat_byte(log_index as u8),
            log_index,
        }
    }

    #[tokio::test]
    async fn only_withdraw_not_in_root_is_emitted() {
        let raws = vec![
            raw(ChallengeType::WithdrawNotInRoot, B256::repeat_byte(0x01), 1),
            raw(ChallengeType::Other(2), B256::repeat_byte(0x02), 2),
            raw(ChallengeType::Other(7), B256::repeat_byte(0x03), 3),
            raw(ChallengeType::WithdrawNotInRoot, B256::repeat_byte(0x04), 4),
        ];
        let adapter =
            ChallengeManagerContract::from_raw_events(raws, DirectLeafLocator, 196, CONTRACT_ADDR);
        let opened = adapter.watch_opened(window()).await.unwrap();
        assert_eq!(opened.len(), 2, "only WithdrawNotInRoot events are emitted");
        assert_eq!(opened[0].leaf_hash, B256::repeat_byte(0x01));
        assert_eq!(opened[1].leaf_hash, B256::repeat_byte(0x04));
    }

    /// Swapping the leaf-locator implementation leaves the emitted `ChallengeOpened` identical
    /// (same leaf, same opaque id) — the core of "only replace this one component" when the event
    /// schema changes.
    #[tokio::test]
    async fn state_machine_behavior_is_identical_across_locators() {
        let leaf = B256::repeat_byte(0x99);
        // Direct: the identifier IS the leaf.
        let direct = ChallengeManagerContract::from_raw_events(
            vec![raw(ChallengeType::WithdrawNotInRoot, leaf, 1)],
            DirectLeafLocator,
            196,
            CONTRACT_ADDR,
        );
        // Reverse: the identifier is a transaction-scoped id the WB maps to the same leaf.
        let mut m = std::collections::HashMap::new();
        m.insert(B256::repeat_byte(0x11), leaf);
        let reverse = ChallengeManagerContract::from_raw_events(
            vec![raw(ChallengeType::WithdrawNotInRoot, B256::repeat_byte(0x11), 1)],
            ReverseLookupLeafLocator::new(std::sync::Arc::new(MockTzTxToLeaf(m))),
            196,
            CONTRACT_ADDR,
        );
        let od = direct.watch_opened(window()).await.unwrap();
        let or = reverse.watch_opened(window()).await.unwrap();
        assert_eq!(od.len(), 1);
        assert_eq!(or.len(), 1);
        assert_eq!(od[0].leaf_hash, leaf, "Direct resolves the leaf from the identifier");
        assert_eq!(or[0].leaf_hash, leaf, "Reverse resolves the same leaf via the WB");
        // Same event coordinates ⇒ identical opaque ChallengeId regardless of the locator.
        assert_eq!(od[0].challenge_id, or[0].challenge_id);
    }

    #[tokio::test]
    async fn get_challenge_maps_status_and_errors_on_unknown_id() {
        let adapter = ChallengeManagerContract::from_raw_events(
            vec![raw(ChallengeType::WithdrawNotInRoot, B256::repeat_byte(0x01), 1)],
            DirectLeafLocator,
            196,
            CONTRACT_ADDR,
        );
        let opened = adapter.watch_opened(window()).await.unwrap();
        adapter.script_status(opened[0].challenge_id, true, 1_700, 1_000, false);
        let st = adapter.get_challenge(opened[0].challenge_id).await.unwrap();
        assert!(st.open && st.deadline == 1_700 && st.chain_timestamp == 1_000);
        // An id the adapter never decoded returns a typed error (routed to a safe retry), not a panic.
        assert!(adapter.get_challenge(ChallengeId([0xEE; 32])).await.is_err());
    }

    #[tokio::test]
    async fn submit_withdraw_proof_passes_four_fields_verbatim() {
        use crate::tz::defender::challenge_contract::{ChallengeSender, SubmitOutcome};
        let adapter = ChallengeManagerContract::from_raw_events(
            vec![raw(ChallengeType::WithdrawNotInRoot, B256::repeat_byte(0x01), 1)],
            DirectLeafLocator,
            196,
            CONTRACT_ADDR,
        );
        let opened = adapter.watch_opened(window()).await.unwrap();
        let onchain_id = adapter.onchain_id_for(opened[0].challenge_id).unwrap();
        let sibs = [B256::repeat_byte(0x07); 32];
        // checkpoint_height (12345) is deliberately NOT part of submitWithdrawProof and must be dropped.
        let outcome = adapter
            .prove_challenge(opened[0].challenge_id, 12345, 7, 9, sibs)
            .await
            .unwrap();
        assert!(matches!(outcome, SubmitOutcome::Submitted(_)));
        let call = adapter.last_submit_call().unwrap();
        assert_eq!(call.challenge_id, onchain_id, "challengeId passed through verbatim");
        assert_eq!(call.leaf_index, 7, "leafIndex passed through verbatim");
        assert_eq!(call.leaf_count, 9, "leafCount passed through verbatim");
        assert_eq!(call.proof, sibs, "proof passed through verbatim");
        assert!(!adapter.submitted_any_checkpoint_height(), "checkpoint_height is not part of the call");
    }
}
