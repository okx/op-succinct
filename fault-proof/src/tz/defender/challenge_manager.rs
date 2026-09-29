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

use std::{collections::HashMap, sync::Mutex};

use alloy_primitives::{Address, TxHash, B256, U256};
use alloy_provider::{DynProvider, Provider};
use alloy_rpc_types_eth::Filter;
use alloy_sol_types::{sol, SolEvent};
use anyhow::Context;
use async_trait::async_trait;

use super::{
    challenge_contract::{
        ChallengeEventSource, ChallengeId, ChallengeOpened, ChallengeReader, ChallengeSender,
        ChallengeStatus, ConfirmOutcome, ScanWindow, SenderError, SubmitOutcome,
    },
    leaf_locator::LeafLocator,
};

/// The kind of challenge carried by a `ChallengeCreated` event. Only
/// [`ChallengeType::WithdrawNotInRoot`] is acted upon; every other on-chain discriminant is
/// represented as [`ChallengeType::Other`] so an unknown type is always representable and never
/// panics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeType {
    /// The withdraw-not-in-root challenge the Defender answers.
    WithdrawNotInRoot,
    /// Any other on-chain challenge type, kept as its raw discriminant so it can be
    /// logged/ignored.
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
    // underlying `uint8`. The event carries two independent `bytes32` values: `tzTxHash`, the
    // transaction-scoped withdraw identifier retained for observability, and `leaf`, the Merkle leaf
    // the proof path consumes directly. Withdraw challenge types emit the withdraw-hash leaf; a
    // force-transaction challenge emits a zero leaf.
    #[allow(missing_docs)]
    event ChallengeCreated(
        uint256 indexed challengeId,
        uint8 indexed challengeType,
        address indexed target,
        address affectedBridge,
        bytes32 tzTxHash,
        bytes32 leaf,
        address challenger,
        uint64 responseDeadline
    );
}

sol! {
    // The ChallengeManager view + failure event that back the live status read and resolution
    // attribution. `activeWithdrawChallenge` returns the challengeId currently occupying a bridge's
    // active withdraw-challenge slot (zero when none). `ChallengeFailed` carries the resolved
    // `challengeId` plus the contract's `bondRecipient` address; matching the `challengeId` against our
    // own confirmed proof receipt is how resolution is attributed. Both shapes MUST be re-confirmed
    // against the deployed contract before LIVE responses are relied upon.
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IChallengeManager {
        function activeWithdrawChallenge(address bridge) external view returns (uint256);
    }

    // The contract event has TWO parameters, BOTH `indexed`: `challengeId` is carried in topics[1]
    // and `bondRecipient` in topics[2], and the log `data` section is empty. topic0 is derived from
    // the complete ordered type list `(uint256,address)` —
    // `keccak256("ChallengeFailed(uint256,address)")` — and is unaffected by indexed-ness. Declaring
    // both fields `indexed` makes the generated `decode_log` read them from the topics. The decode
    // stays fail-closed: a wrong-topic0 / arity- or layout-mismatched / non-decoding log — including
    // the earlier non-indexed-data shape that carried the address in `data`, and the retired
    // one-parameter signature — is skipped rather than mis-parsed, keeping an unresolved challenge
    // in-flight instead of mis-attributing it.
    #[allow(missing_docs)]
    event ChallengeFailed(uint256 indexed challengeId, address indexed bondRecipient);
}

/// A decoded-but-unfiltered `ChallengeCreated` event. `tz_tx_hash` is the transaction-scoped
/// withdraw identifier, retained for observability and a future fallback path; `leaf` is the Merkle
/// leaf the proof path consumes directly via a [`LeafLocator`]. The two are independent decoded
/// fields and must never be conflated. `affected_bridge` is the bridge whose active-challenge slot
/// this challenge occupies, used by the live status read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawChallengeEvent {
    pub onchain_challenge_id: U256,
    pub challenge_type: ChallengeType,
    pub tz_tx_hash: B256,
    pub leaf: B256,
    pub affected_bridge: Address,
    pub response_deadline: u64,
    pub block_number: u64,
    pub chain_id: u64,
    pub contract: Address,
    pub tx_hash: B256,
    pub log_index: u64,
}

/// Decode a `ChallengeCreated` log into a [`RawChallengeEvent`]. Pure and chain-free: the event
/// data comes from the log topics/data and the event coordinates from the log envelope, so it is
/// unit testable without a live provider. Fails closed if the log is missing block/tx/log-index
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
        tz_tx_hash: decoded.data.tzTxHash,
        leaf: decoded.data.leaf,
        affected_bridge: decoded.data.affectedBridge,
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
    /// On-chain `challengeId` → `affectedBridge` captured at discovery time, consumed by the live
    /// status read.
    affected_bridge: HashMap<U256, Address>,
    /// Pre-decoded events for the scripted (test) path; `None` on the live path.
    scripted_events: Option<Vec<RawChallengeEvent>>,
    /// Scripted per-challenge status for the test path.
    scripted_status: HashMap<ChallengeId, ChallengeStatus>,
    /// Scripted live-status inputs `(active_withdraw_challenge_id, chain_timestamp)` for the test
    /// path, driving the same exact-equality open/closed derivation the live path uses without a
    /// provider.
    scripted_active: HashMap<ChallengeId, (U256, u64)>,
    /// Scripted confirm outcomes (by tx hash) for the test path.
    scripted_confirm: HashMap<TxHash, ConfirmOutcome>,
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

    /// Gather the decoded-but-unfiltered events in `window`: the scripted batch when present, else
    /// a live `get_logs` scan for the `ChallengeCreated` topic decoded via
    /// [`decode_challenge_created`].
    async fn collect_raw_events(
        &self,
        window: ScanWindow,
    ) -> anyhow::Result<Vec<RawChallengeEvent>> {
        if let Some(events) = self.state.lock().unwrap().scripted_events.clone() {
            return Ok(events
                .into_iter()
                .filter(|e| {
                    e.block_number >= window.from_block && e.block_number <= window.to_block
                })
                .collect());
        }
        let provider = self
            .provider
            .as_ref()
            .context("challenge adapter has neither provider nor scripted events")?;
        let filter = Filter::new()
            .address(self.contract)
            .event_signature(ChallengeCreated::SIGNATURE_HASH)
            .from_block(window.from_block)
            .to_block(window.to_block);
        let logs =
            provider.get_logs(&filter).await.context("get_logs for ChallengeCreated failed")?;
        let mut raws = Vec::with_capacity(logs.len());
        for log in &logs {
            match decode_challenge_created(log, self.chain_id) {
                Ok(r) => raws.push(r),
                Err(e) => tracing::warn!(error = %e, "skipping undecodable ChallengeCreated log"),
            }
        }
        Ok(raws)
    }

    /// Filter to `WithdrawNotInRoot`, resolve the leaf via the locator, build a
    /// [`ChallengeOpened`], and record the opaque-id → on-chain-id mapping and deadline. A
    /// locator error for a single event is logged and that event skipped (witness-wait
    /// semantics), never a scan failure. Every other challenge type is dropped silently — no
    /// event, no error, no witness query.
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
                state.affected_bridge.insert(raw.onchain_challenge_id, raw.affected_bridge);
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

    /// The `affectedBridge` cached for an on-chain `challengeId`, if discovered (introspection).
    #[cfg(test)]
    pub fn affected_bridge_for(&self, onchain_id: U256) -> Option<Address> {
        self.state.lock().unwrap().affected_bridge.get(&onchain_id).copied()
    }

    /// Scripted/offline seam: set the status returned by `get_challenge` for a (discovered)
    /// challenge id. Used by tests (including cross-crate integration tests); hidden from docs.
    #[doc(hidden)]
    pub fn script_status(&self, id: ChallengeId, open: bool, deadline: u64, chain_timestamp: u64) {
        self.state
            .lock()
            .unwrap()
            .scripted_status
            .insert(id, ChallengeStatus { open, deadline, chain_timestamp });
    }

    /// Scripted/offline seam: feed the `(active_withdraw_challenge_id, chain_timestamp)` the live
    /// derivation would read for a (discovered) challenge, exercising the same exact-equality
    /// open/closed rule without a provider. Used by tests; hidden from docs.
    #[doc(hidden)]
    pub fn script_active(&self, id: ChallengeId, active: U256, chain_timestamp: u64) {
        self.state.lock().unwrap().scripted_active.insert(id, (active, chain_timestamp));
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

    /// Scripted/offline seam: set the [`ConfirmOutcome`] returned by `confirm` for a tx hash. Used
    /// by tests; hidden from docs.
    #[doc(hidden)]
    pub fn script_confirm(&self, tx: TxHash, outcome: ConfirmOutcome) {
        self.state.lock().unwrap().scripted_confirm.insert(tx, outcome);
    }

    /// Map the `ChallengeFailed` logs in a transaction receipt to the opaque challenge ids this
    /// adapter has discovered. On-chain ids the adapter never decoded are ignored — a challenge we
    /// are not tracking is not ours to credit.
    fn resolved_ids_from_logs(&self, logs: &[alloy_rpc_types_eth::Log]) -> Vec<ChallengeId> {
        let state = self.state.lock().unwrap();
        let mut resolved = Vec::new();
        for log in logs {
            // Attribution comes only from OUR challenge manager's events: ignore any log emitted by
            // a different contract in the receipt (matches the live status read, which binds
            // self.contract), so a colliding ChallengeFailed from elsewhere cannot be miscredited.
            if log.inner.address != self.contract {
                continue;
            }
            let Ok(decoded) = ChallengeFailed::decode_log(&log.inner) else {
                continue;
            };
            for (opaque, onchain) in state.id_map.iter() {
                if *onchain == decoded.data.challengeId && !resolved.contains(opaque) {
                    resolved.push(*opaque);
                }
            }
        }
        resolved
    }
}

#[async_trait]
impl<L: LeafLocator> ChallengeSender for ChallengeManagerContract<L> {
    async fn prove_challenge(
        &self,
        id: ChallengeId,
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
        // Build the submitWithdrawProof calldata: exactly the four contract fields, verbatim.
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

    async fn confirm(&self, tx: TxHash) -> anyhow::Result<ConfirmOutcome> {
        // Live path: fetch the receipt and, on success, attribute resolution by parsing the
        // receipt's ChallengeFailed logs into the opaque challenge ids our own transaction
        // resolved. No transaction is broadcast until a signer lands, so this path is exercised
        // only once the sender is wired.
        if let Some(provider) = self.provider.as_ref() {
            let receipt = provider
                .get_transaction_receipt(tx)
                .await
                .context("failed to fetch prove transaction receipt")?;
            let Some(receipt) = receipt else {
                return Ok(ConfirmOutcome::Pending);
            };
            if !receipt.status() {
                return Ok(ConfirmOutcome::Reverted);
            }
            let logs = receipt.inner.logs().to_vec();
            let resolved_challenge_ids = self.resolved_ids_from_logs(&logs);
            return Ok(ConfirmOutcome::Succeeded { resolved_challenge_ids });
        }
        // Scripted path: the scripted outcome, defaulting to Pending.
        Ok(self
            .state
            .lock()
            .unwrap()
            .scripted_confirm
            .get(&tx)
            .cloned()
            .unwrap_or(ConfirmOutcome::Pending))
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
        // Recover the on-chain id and cached facts; an id this adapter never decoded (e.g. after a
        // restart with an empty map) is a typed error routed to a safe retry — never an unwrap
        // panic.
        let (onchain_id, affected_bridge, deadline) = {
            let state = self.state.lock().unwrap();
            let onchain_id = state
                .id_map
                .get(&id)
                .copied()
                .with_context(|| format!("get_challenge for an unknown challenge id {id:?}"))?;
            let affected_bridge = state.affected_bridge.get(&onchain_id).copied();
            let deadline = state.deadlines.get(&onchain_id).copied().unwrap_or(0);
            (onchain_id, affected_bridge, deadline)
        };
        // Scripted (test) status when present.
        if let Some(status) = self.state.lock().unwrap().scripted_status.get(&id).copied() {
            return Ok(status);
        }
        // Scripted live-status inputs: drive the exact-equality open/closed derivation offline.
        if let Some((active, chain_timestamp)) =
            self.state.lock().unwrap().scripted_active.get(&id).copied()
        {
            return Ok(ChallengeStatus { open: active == onchain_id, deadline, chain_timestamp });
        }
        // Live path: read the bridge's active withdraw-challenge id and the latest L2 block
        // timestamp through the provider, then derive open/closed by EXACT equality (a different or
        // zero active id means this challenge no longer holds the slot). Resolution attribution is
        // NOT read here — it comes only from our own confirmed prove receipt.
        if let Some(provider) = self.provider.as_ref() {
            let bridge = affected_bridge.with_context(|| {
                format!("no affectedBridge cached for challenge id {id:?}; cannot read live status")
            })?;
            let manager = IChallengeManager::new(self.contract, provider.clone());
            let active = manager
                .activeWithdrawChallenge(bridge)
                .call()
                .await
                .context("failed to read activeWithdrawChallenge")?;
            let block = provider
                .get_block_by_number(alloy_eips::BlockNumberOrTag::Latest)
                .await
                .context("failed to read latest L2 block for challenge status")?
                .context("latest L2 block is missing")?;
            return Ok(ChallengeStatus {
                open: active == onchain_id,
                deadline,
                chain_timestamp: block.header.timestamp,
            });
        }
        // A scripted adapter with no status for a known id defaults to closed (mirrors the mock).
        Ok(ChallengeStatus { open: false, deadline: 0, chain_timestamp: 0 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `ChallengeCreated` log fixture from the generated event type. The event carries
    /// independent `tzTxHash` and `leaf` fields plus `affectedBridge`.
    fn challenge_created_log_fixture(
        challenge_id: U256,
        challenge_type: u8,
        tz_tx_hash: B256,
        leaf: B256,
        affected_bridge: Address,
        response_deadline: u64,
    ) -> alloy_rpc_types_eth::Log {
        let ev = ChallengeCreated {
            challengeId: challenge_id,
            challengeType: challenge_type,
            target: Address::repeat_byte(0x0a),
            affectedBridge: affected_bridge,
            tzTxHash: tz_tx_hash,
            leaf,
            challenger: Address::repeat_byte(0x0c),
            responseDeadline: response_deadline,
        };
        let inner = alloy_primitives::Log {
            address: Address::repeat_byte(0x01),
            data: ev.encode_log_data(),
        };
        alloy_rpc_types_eth::Log {
            inner,
            block_number: Some(100),
            transaction_hash: Some(B256::repeat_byte(0x02)),
            log_index: Some(0),
            ..Default::default()
        }
    }

    /// The retired event shape carrying a single transaction-scoped `identifier` and no `leaf`,
    /// used only to prove the current decoder rejects a log carrying the old event signature.
    mod retired_abi {
        alloy_sol_types::sol! {
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
    }

    #[test]
    fn decodes_new_challenge_created_abi_with_distinct_tztxhash_and_leaf() {
        let id = U256::from(42u64);
        let tz_tx = B256::repeat_byte(0x7c);
        let leaf = B256::repeat_byte(0x5e);
        let bridge = Address::repeat_byte(0x2b);
        assert_ne!(tz_tx, leaf, "the fixture must use distinct tzTxHash and leaf values");
        let log = challenge_created_log_fixture(
            id,
            WITHDRAW_NOT_IN_ROOT_DISCRIMINANT,
            tz_tx,
            leaf,
            bridge,
            1_700u64,
        );
        let ev = decode_challenge_created(&log, 196).unwrap();
        assert_eq!(ev.onchain_challenge_id, id);
        assert_eq!(ev.challenge_type, ChallengeType::WithdrawNotInRoot);
        assert_eq!(ev.tz_tx_hash, tz_tx, "tzTxHash decodes into its own field");
        assert_eq!(ev.leaf, leaf, "leaf decodes into its own field");
        assert_ne!(ev.tz_tx_hash, ev.leaf, "tzTxHash and leaf are decoded independently");
        assert_eq!(ev.affected_bridge, bridge, "affectedBridge decodes into its own field");
        assert_eq!(ev.response_deadline, 1_700);
        assert_eq!(ev.chain_id, 196);
        assert_eq!(ev.block_number, 100);
        assert_eq!(ev.log_index, 0);
    }

    #[test]
    fn old_signature_log_does_not_decode() {
        // Adding the leaf field changes the event signature, so the previous event's topic0 differs
        // and a log carrying it must fail closed rather than be mis-parsed as the current event.
        assert_ne!(
            retired_abi::ChallengeCreated::SIGNATURE_HASH,
            ChallengeCreated::SIGNATURE_HASH,
            "the extra leaf field changes the event signature (topic0)"
        );
        let old = retired_abi::ChallengeCreated {
            challengeId: U256::from(1u64),
            challengeType: WITHDRAW_NOT_IN_ROOT_DISCRIMINANT,
            target: Address::repeat_byte(0x0a),
            affectedBridge: Address::repeat_byte(0x0b),
            identifier: B256::repeat_byte(0x7c),
            challenger: Address::repeat_byte(0x0c),
            responseDeadline: 1_700,
        };
        let inner = alloy_primitives::Log {
            address: Address::repeat_byte(0x01),
            data: old.encode_log_data(),
        };
        let log = alloy_rpc_types_eth::Log {
            inner,
            block_number: Some(100),
            transaction_hash: Some(B256::repeat_byte(0x02)),
            log_index: Some(0),
            ..Default::default()
        };
        assert!(
            decode_challenge_created(&log, 196).is_err(),
            "a log with the retired signature fails closed under the current decoder"
        );
    }

    #[test]
    fn truncated_log_fails_closed() {
        // A log whose ABI data payload is too short to hold the event's non-indexed fields must
        // decode to an error, never a partially-filled event.
        let mut log = challenge_created_log_fixture(
            U256::from(1u64),
            WITHDRAW_NOT_IN_ROOT_DISCRIMINANT,
            B256::repeat_byte(0x7c),
            B256::repeat_byte(0x5e),
            Address::repeat_byte(0x2b),
            1_700,
        );
        log.inner.data.data = alloy_primitives::Bytes::from_static(&[0x00, 0x01, 0x02]);
        assert!(
            decode_challenge_created(&log, 196).is_err(),
            "a truncated data payload fails closed"
        );
    }

    #[test]
    fn maps_non_withdraw_types_to_other() {
        assert_eq!(
            ChallengeType::from_discriminant(WITHDRAW_NOT_IN_ROOT_DISCRIMINANT),
            ChallengeType::WithdrawNotInRoot
        );
        let other = WITHDRAW_NOT_IN_ROOT_DISCRIMINANT.wrapping_add(1);
        assert_eq!(ChallengeType::from_discriminant(other), ChallengeType::Other(other));
    }

    // ── Real adapter: WithdrawNotInRoot filter + leaf-locator replaceability ──

    use crate::tz::{
        defender::leaf_locator::{DirectLeafLocator, ReverseLookupLeafLocator},
        withdraw::wb_client::test_doubles::MockTzTxToLeaf,
    };

    const CONTRACT_ADDR: Address = Address::repeat_byte(0x01);

    fn window() -> ScanWindow {
        ScanWindow { from_block: 0, to_block: 1_000 }
    }

    /// A decoded event with a distinct tx hash per `log_index` (so distinct ChallengeIds), inside
    /// the default window. `tz_tx_hash` is derived to stay distinct from `leaf` so a
    /// field-order/mapping bug cannot pass by coincidence.
    fn raw(challenge_type: ChallengeType, leaf: B256, log_index: u64) -> RawChallengeEvent {
        RawChallengeEvent {
            onchain_challenge_id: U256::from(log_index + 1),
            challenge_type,
            tz_tx_hash: B256::repeat_byte(0xF0 | (log_index as u8)),
            leaf,
            affected_bridge: Address::repeat_byte(0xB0),
            response_deadline: 10_000,
            block_number: 10,
            chain_id: 196,
            contract: CONTRACT_ADDR,
            tx_hash: B256::repeat_byte(log_index as u8),
            log_index,
        }
    }

    /// A challenge-type discriminant that is not the withdraw type (models a force-transaction
    /// challenge, which carries a zero leaf).
    const FORCE_TX_DISCRIMINANT: u8 = 2;

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
        // The emitted leaf_hash is the event's leaf field, never its (distinct) tz_tx_hash.
        assert_eq!(opened[0].leaf_hash, B256::repeat_byte(0x01));
        assert_ne!(
            opened[0].leaf_hash,
            B256::repeat_byte(0xF1),
            "leaf_hash is the leaf, not tzTxHash"
        );
        assert_eq!(opened[1].leaf_hash, B256::repeat_byte(0x04));
        assert_ne!(
            opened[1].leaf_hash,
            B256::repeat_byte(0xF4),
            "leaf_hash is the leaf, not tzTxHash"
        );
    }

    #[tokio::test]
    async fn force_tx_zero_leaf_is_dropped_by_type_filter() {
        // A force-transaction challenge carries a zero leaf and a non-withdraw type; it must be
        // dropped by the type filter BEFORE any leaf-locate/proof path, so no zero-leaf challenge
        // is ever emitted.
        let mut force = raw(ChallengeType::Other(FORCE_TX_DISCRIMINANT), B256::ZERO, 1);
        force.leaf = B256::ZERO;
        let adapter = ChallengeManagerContract::from_raw_events(
            vec![force],
            DirectLeafLocator,
            196,
            CONTRACT_ADDR,
        );
        let opened = adapter.watch_opened(window()).await.unwrap();
        assert!(
            opened.is_empty(),
            "a non-withdraw (zero-leaf) challenge produces no ChallengeOpened"
        );
    }

    #[tokio::test]
    async fn affected_bridge_is_cached_per_challenge() {
        let ev = raw(ChallengeType::WithdrawNotInRoot, B256::repeat_byte(0x01), 1);
        let onchain_id = ev.onchain_challenge_id;
        let bridge = ev.affected_bridge;
        let adapter = ChallengeManagerContract::from_raw_events(
            vec![ev],
            DirectLeafLocator,
            196,
            CONTRACT_ADDR,
        );
        let opened = adapter.watch_opened(window()).await.unwrap();
        assert_eq!(opened.len(), 1);
        assert_eq!(
            adapter.affected_bridge_for(onchain_id),
            Some(bridge),
            "the event's affectedBridge is cached by on-chain challenge id"
        );
    }

    /// Swapping the leaf-locator implementation leaves the emitted `ChallengeOpened` identical
    /// (same leaf, same opaque id) — the core of "only replace this one component" when the event
    /// schema changes.
    #[tokio::test]
    async fn state_machine_behavior_is_identical_across_locators() {
        let leaf = B256::repeat_byte(0x99);
        let tz_tx = B256::repeat_byte(0x11);
        assert_ne!(
            tz_tx, leaf,
            "tzTxHash and leaf must differ so the two locators are distinguished"
        );
        // Direct: the event's explicit `leaf` field is the leaf; its tzTxHash is unrelated.
        let mut direct_ev = raw(ChallengeType::WithdrawNotInRoot, leaf, 1);
        direct_ev.tz_tx_hash = tz_tx;
        let direct = ChallengeManagerContract::from_raw_events(
            vec![direct_ev],
            DirectLeafLocator,
            196,
            CONTRACT_ADDR,
        );
        // Reverse: the WB maps the event's tzTxHash to the same leaf; its own leaf field is unused.
        let mut reverse_ev = raw(ChallengeType::WithdrawNotInRoot, B256::repeat_byte(0x77), 1);
        reverse_ev.tz_tx_hash = tz_tx;
        let mut m = std::collections::HashMap::new();
        m.insert(tz_tx, leaf);
        let reverse = ChallengeManagerContract::from_raw_events(
            vec![reverse_ev],
            ReverseLookupLeafLocator::new(std::sync::Arc::new(MockTzTxToLeaf(m))),
            196,
            CONTRACT_ADDR,
        );
        let od = direct.watch_opened(window()).await.unwrap();
        let or = reverse.watch_opened(window()).await.unwrap();
        assert_eq!(od.len(), 1);
        assert_eq!(or.len(), 1);
        assert_eq!(od[0].leaf_hash, leaf, "Direct resolves the leaf from the event's leaf field");
        assert_eq!(or[0].leaf_hash, leaf, "Reverse resolves the same leaf via the WB by tzTxHash");
        // Same event coordinates ⇒ identical opaque ChallengeId regardless of the locator.
        assert_eq!(od[0].challenge_id, or[0].challenge_id);
    }

    #[tokio::test]
    async fn live_get_challenge_open_closed_by_active_id() {
        let adapter = ChallengeManagerContract::from_raw_events(
            vec![raw(ChallengeType::WithdrawNotInRoot, B256::repeat_byte(0x01), 1)],
            DirectLeafLocator,
            196,
            CONTRACT_ADDR,
        );
        let opened = adapter.watch_opened(window()).await.unwrap();
        let id = opened[0].challenge_id;
        let onchain_id = adapter.onchain_id_for(id).unwrap();
        // active-withdraw-challenge id EXACTLY equals our on-chain id ⇒ open; the deadline comes
        // from the cached event and the chain timestamp from the (scripted) block read.
        adapter.script_active(id, onchain_id, 4_200);
        let st = adapter.get_challenge(id).await.unwrap();
        assert!(st.open, "active == our on-chain id ⇒ open");
        assert_eq!(st.chain_timestamp, 4_200);
        assert_eq!(st.deadline, 10_000, "deadline is the cached event's response deadline");
        // A DIFFERENT active id ⇒ closed (exact equality; not merely non-zero).
        adapter.script_active(id, onchain_id + U256::from(1u64), 4_200);
        assert!(!adapter.get_challenge(id).await.unwrap().open, "a different active id ⇒ closed");
        // A zero active id ⇒ closed.
        adapter.script_active(id, U256::ZERO, 4_200);
        assert!(!adapter.get_challenge(id).await.unwrap().open, "a zero active id ⇒ closed");
    }

    /// Build a `ChallengeFailed` receipt log from the RAW on-chain topic/data layout — NOT the Rust
    /// binding's own `encode_log_data()`. Self-encoding round-trips whatever layout the binding
    /// declares, so it cannot surface a topic-vs-data layout error; building the log from the
    /// pinned raw layout (topic0 + indexed topics + data section) is what makes the decode
    /// observable.
    fn challenge_failed_log_raw(
        address: Address,
        topics: Vec<B256>,
        data: alloy_primitives::Bytes,
    ) -> alloy_rpc_types_eth::Log {
        alloy_rpc_types_eth::Log {
            inner: alloy_primitives::Log {
                address,
                data: alloy_primitives::LogData::new_unchecked(topics, data),
            },
            ..Default::default()
        }
    }

    /// The pinned on-chain `ChallengeFailed` topic0, computed from the canonical signature string
    /// so the fixtures never borrow it from the binding under test. `indexed`-ness never
    /// affects topic0.
    fn challenge_failed_topic0() -> B256 {
        alloy_primitives::keccak256("ChallengeFailed(uint256,address)")
    }

    /// A `uint256` value as a 32-byte big-endian topic word (an indexed `challengeId`).
    fn u256_topic(v: U256) -> B256 {
        B256::from(v.to_be_bytes::<32>())
    }

    #[tokio::test]
    async fn confirm_success_with_real_dual_indexed_challenge_failed_maps_to_proved() {
        let adapter = ChallengeManagerContract::from_raw_events(
            vec![raw(ChallengeType::WithdrawNotInRoot, B256::repeat_byte(0x01), 1)],
            DirectLeafLocator,
            196,
            CONTRACT_ADDR,
        );
        let opened = adapter.watch_opened(window()).await.unwrap();
        let id = opened[0].challenge_id;
        let onchain_id = adapter.onchain_id_for(id).unwrap();
        // A REAL dual-indexed ChallengeFailed(uint256 indexed challengeId, address indexed
        // bondRecipient) receipt log, built from the pinned raw layout: challengeId in topics[1],
        // bondRecipient in topics[2], and an EMPTY data section. bondRecipient is populated and
        // distinct from challengeId so a field-order/mapping slip cannot pass by coincidence. Built
        // raw (not encode_log_data()) so the topic-vs-data layout is exercised for real.
        let bond_recipient = Address::repeat_byte(0x7a);
        let log = challenge_failed_log_raw(
            CONTRACT_ADDR,
            vec![challenge_failed_topic0(), u256_topic(onchain_id), bond_recipient.into_word()],
            alloy_primitives::Bytes::new(),
        );
        // resolved_ids_from_logs decodes challengeId from topics[1] and maps it to the opaque id.
        // The handler transitions a challenge to Proved iff its id is in resolved_challenge_ids
        // (covered by the handler's confirm mapping and the end-to-end integration test); this is
        // the id that mapping keys off.
        assert_eq!(
            adapter.resolved_ids_from_logs(std::slice::from_ref(&log)),
            vec![id],
            "a real dual-indexed ChallengeFailed (challengeId in topics[1]) maps to the opaque \
             ChallengeId the handler proves"
        );
        // A dual-indexed ChallengeFailed for an id this adapter never decoded is ignored.
        let unknown_log = challenge_failed_log_raw(
            CONTRACT_ADDR,
            vec![
                challenge_failed_topic0(),
                u256_topic(U256::from(9_999u64)),
                bond_recipient.into_word(),
            ],
            alloy_primitives::Bytes::new(),
        );
        assert!(
            adapter.resolved_ids_from_logs(std::slice::from_ref(&unknown_log)).is_empty(),
            "an unknown on-chain id is ignored"
        );
    }

    #[tokio::test]
    async fn challenge_failed_negatives_are_skipped_fail_closed() {
        let adapter = ChallengeManagerContract::from_raw_events(
            vec![raw(ChallengeType::WithdrawNotInRoot, B256::repeat_byte(0x01), 1)],
            DirectLeafLocator,
            196,
            CONTRACT_ADDR,
        );
        let opened = adapter.watch_opened(window()).await.unwrap();
        let onchain_id = adapter.onchain_id_for(opened[0].challenge_id).unwrap();
        let bond_recipient = Address::repeat_byte(0x7a);

        // (i) OLD non-indexed-`data` layout — the prior (wrong) shape: correct topic0 and
        // challengeId in topics[1], but the address in the DATA section with NO topics[2].
        // Against the dual-indexed binding this is an arity/layout mismatch, so decode_log
        // skips it fail-closed. This guards against reintroducing that prior-binding regression.
        let old_layout_log = challenge_failed_log_raw(
            CONTRACT_ADDR,
            vec![challenge_failed_topic0(), u256_topic(onchain_id)],
            alloy_primitives::Bytes::from(bond_recipient.into_word().as_slice().to_vec()),
        );
        assert!(
            adapter.resolved_ids_from_logs(std::slice::from_ref(&old_layout_log)).is_empty(),
            "the old non-indexed-data ChallengeFailed layout is skipped fail-closed, not resolved"
        );

        // (ii) RETIRED one-parameter signature — its topic0 differs from the corrected filter, so a
        // log carrying it is never matched. The retired topic0 is derived from a nested binding
        // (the retired_abi idiom) and the log built raw.
        mod retired_cf {
            alloy_sol_types::sol! {
                #[allow(missing_docs)]
                event ChallengeFailed(uint256 indexed challengeId);
            }
        }
        assert_ne!(
            retired_cf::ChallengeFailed::SIGNATURE_HASH,
            challenge_failed_topic0(),
            "the retired one-parameter ChallengeFailed has a different topic0"
        );
        let retired_log = challenge_failed_log_raw(
            CONTRACT_ADDR,
            vec![retired_cf::ChallengeFailed::SIGNATURE_HASH, u256_topic(onchain_id)],
            alloy_primitives::Bytes::new(),
        );
        assert!(
            adapter.resolved_ids_from_logs(std::slice::from_ref(&retired_log)).is_empty(),
            "a retired one-parameter ChallengeFailed topic0 is not matched (fail-closed)"
        );

        // (iii) FOREIGN contract — a correctly-shaped dual-indexed ChallengeFailed carrying OUR
        // on-chain id but emitted by a DIFFERENT contract address is ignored by the
        // own-contract-only filter: resolution is attributed only from our own challenge
        // manager's events.
        let foreign_log = challenge_failed_log_raw(
            Address::repeat_byte(0xFE),
            vec![challenge_failed_topic0(), u256_topic(onchain_id), bond_recipient.into_word()],
            alloy_primitives::Bytes::new(),
        );
        assert!(
            adapter.resolved_ids_from_logs(std::slice::from_ref(&foreign_log)).is_empty(),
            "a ChallengeFailed emitted by another contract is not credited to us"
        );
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
        adapter.script_status(opened[0].challenge_id, true, 1_700, 1_000);
        let st = adapter.get_challenge(opened[0].challenge_id).await.unwrap();
        assert!(st.open && st.deadline == 1_700 && st.chain_timestamp == 1_000);
        // An id the adapter never decoded returns a typed error (routed to a safe retry), not a
        // panic.
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
        let outcome = adapter.prove_challenge(opened[0].challenge_id, 7, 9, sibs).await.unwrap();
        assert!(matches!(outcome, SubmitOutcome::Submitted(_)));
        let call = adapter.last_submit_call().unwrap();
        assert_eq!(call.challenge_id, onchain_id, "challengeId passed through verbatim");
        assert_eq!(call.leaf_index, 7, "leafIndex passed through verbatim");
        assert_eq!(call.leaf_count, 9, "leafCount passed through verbatim");
        assert_eq!(call.proof, sibs, "proof passed through verbatim");
        assert!(
            !adapter.submitted_any_checkpoint_height(),
            "checkpoint_height is not part of the call"
        );
    }
}
