//! Real Withdraw-challenge contract adapter — ABI bindings + pure, I/O-free decode/filter/mapping.
//!
//! ABI source: tradezone-bridge `pre_master_deBridge` @ `6fd850d0311958d91ea7ac1c482054ef4b175f5c`,
//! `contracts/ChallengeManager.sol` (read-only reference; a newer tip `fdafdee5…` exists ahead and
//! changes none of the bound fields). Only the `WithdrawNotInRoot` challenge type is handled
//! downstream; the other two types are silently ignored (no response, no error).
//!
//! This module keeps the ABI-dependent decoding a set of pure, fixture-testable functions
//! (`decode_challenge_created`, the type filter, the id mapping) separate from any RPC/HTTP, so the
//! parse/filter/map surface is unit-testable without a live provider. The event's indexed enum is
//! ABI-encoded as `uint8`, so the binding declares `uint8 indexed challengeType`, which yields the
//! identical event signature as the Solidity `ChallengeType` enum.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{Address, TxHash, B256, U256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::Filter;
use alloy_sol_types::{sol, SolEvent};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use thiserror::Error;

use super::challenge_contract::{
    ChallengeEventSource, ChallengeId, ChallengeOpened, ChallengeReader, ChallengeSender,
    ChallengeStatus, ScanWindow, SenderError, SubmitOutcome, TxStatus,
};
use crate::tz::withdraw::{error::WbError, wb_client::WbClient};

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ChallengeManager {
        event ChallengeCreated(
            uint256 indexed challengeId,
            uint8   indexed challengeType,
            address indexed target,
            address affectedBridge,
            bytes32 tzTxHash,
            address challenger,
            uint64  responseDeadline
        );
        function submitWithdrawProof(uint256 challengeId, uint32 leafIndex, uint32 leafCount, bytes32[32] proof) external;
        function activeWithdrawChallenge(address bridge) external view returns (uint256);
    }
}

/// The three challenge types, in the exact ordinal order of the Solidity `enum ChallengeType`.
/// Only `WithdrawNotInRoot` is answered by the Defender.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeType {
    WithdrawNotInRoot,
    WithdrawMissingInBridge,
    ForceTxNotInRoot,
}

/// A failure decoding a `ChallengeCreated` log into [`ParsedChallengeCreated`].
#[derive(Debug, Error)]
pub enum ChallengeDecodeError {
    /// The log is not a `ChallengeCreated` event (wrong `topic0`) or is otherwise malformed.
    #[error("log is not a ChallengeCreated event or is malformed: {0}")]
    Abi(String),
    /// The `challengeType` ordinal is outside the known enum range.
    #[error("unknown challengeType ordinal {0}")]
    UnknownType(u8),
}

/// The bound fields of a `ChallengeCreated` event, decoded from a log. `target`/`affected_bridge`
/// and the event coordinates are retained for the reader's derivations and for observability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedChallengeCreated {
    pub challenge_id: U256,
    pub challenge_type: ChallengeType,
    pub target: Address,
    pub affected_bridge: Address,
    pub tz_tx_hash: B256,
    pub response_deadline: u64,
    pub block_number: u64,
    pub tx_hash: B256,
    pub log_index: u64,
}

/// Map the contract's authoritative `uint256 challengeId` to the opaque [`ChallengeId`] the state
/// machine keys on, **big-endian** (canonical, reversible for a 256-bit id). The real adapter uses
/// this instead of `derive_challenge_id` (which stays only for the mock).
pub fn challenge_id_to_bytes(id: U256) -> ChallengeId {
    ChallengeId(id.to_be_bytes::<32>())
}

/// Inverse of [`challenge_id_to_bytes`]: recover the `uint256 challengeId` for on-chain reads/calls.
pub fn challenge_id_from_bytes(id: ChallengeId) -> U256 {
    U256::from_be_bytes(id.0)
}

/// Whether a challenge type is the only one the Defender answers.
pub fn is_withdraw_not_in_root(t: ChallengeType) -> bool {
    matches!(t, ChallengeType::WithdrawNotInRoot)
}

fn challenge_type_from_ordinal(o: u8) -> Result<ChallengeType, ChallengeDecodeError> {
    match o {
        0 => Ok(ChallengeType::WithdrawNotInRoot),
        1 => Ok(ChallengeType::WithdrawMissingInBridge),
        2 => Ok(ChallengeType::ForceTxNotInRoot),
        other => Err(ChallengeDecodeError::UnknownType(other)),
    }
}

/// Pure decode: an `alloy` RPC log → [`ParsedChallengeCreated`]. No I/O; fixture-tested. A log that
/// is not a `ChallengeCreated` event (wrong `topic0`) or is truncated fails as
/// [`ChallengeDecodeError::Abi`] rather than mis-parsing into a bogus challenge.
pub fn decode_challenge_created(
    log: &alloy_rpc_types_eth::Log,
) -> Result<ParsedChallengeCreated, ChallengeDecodeError> {
    let decoded = ChallengeManager::ChallengeCreated::decode_log(&log.inner)
        .map_err(|e| ChallengeDecodeError::Abi(e.to_string()))?;
    Ok(ParsedChallengeCreated {
        challenge_id: decoded.challengeId,
        challenge_type: challenge_type_from_ordinal(decoded.challengeType)?,
        target: decoded.target,
        affected_bridge: decoded.affectedBridge,
        tz_tx_hash: decoded.tzTxHash,
        response_deadline: decoded.responseDeadline,
        block_number: log.block_number.unwrap_or_default(),
        tx_hash: log.transaction_hash.unwrap_or_default(),
        log_index: log.log_index.unwrap_or_default(),
    })
}

/// Resolves a challenge's `tzTxHash` to its withdrawal `leafHash`. Injected into the adapter so the
/// watch path is unit-testable without HTTP; the production impl is backed by the WB client.
#[async_trait]
pub trait TxToLeafResolver: Send + Sync {
    async fn leaf_for_tx(&self, tz_tx_hash: B256) -> Result<B256, WbError>;
}

/// Production resolver over the real [`WbClient`] reverse-lookup. The `leaf_hash` is used only for
/// the Defender's own local verification/logging — it never enters prove calldata.
pub struct WbTxToLeafResolver(pub Arc<WbClient>);

#[async_trait]
impl TxToLeafResolver for WbTxToLeafResolver {
    async fn leaf_for_tx(&self, tz_tx_hash: B256) -> Result<B256, WbError> {
        Ok(self.0.get_withdrawal_by_tx(tz_tx_hash).await?.leaf_hash)
    }
}

/// Internal seam: the L2 log query for `ChallengeCreated` over a finality-bounded window. Split out
/// so the adapter's parse/filter/reverse-lookup/construct path is unit-testable without a node.
#[async_trait]
pub trait EventLogSource: Send + Sync {
    async fn challenge_logs(&self, window: ScanWindow) -> Result<Vec<alloy_rpc_types_eth::Log>>;
}

/// Internal seam: the two on-chain state reads the reader needs — the public
/// `activeWithdrawChallenge(bridge)` mapping and the current L2 block timestamp.
#[async_trait]
pub trait ActiveChallengeReader: Send + Sync {
    async fn active_withdraw_challenge(&self, bridge: Address) -> Result<U256>;
    async fn chain_timestamp(&self) -> Result<u64>;
}

/// Internal seam: broadcast a `submitWithdrawProof` and read a receipt. The four fields are passed
/// through verbatim by the adapter; this seam only handles the wire submit/confirm.
#[async_trait]
pub trait ProveSender: Send + Sync {
    async fn send_prove(
        &self,
        challenge_id: U256,
        leaf_index: u32,
        leaf_count: u32,
        proof: [B256; 32],
    ) -> Result<SubmitOutcome, SenderError>;
    async fn confirm(&self, tx: TxHash) -> Result<TxStatus>;
}

/// Real [`EventLogSource`] over an `alloy` provider: a `ChallengeCreated`-filtered `get_logs`.
pub struct ProviderEventLogSource<P> {
    provider: P,
    contract: Address,
}

#[async_trait]
impl<P: Provider + Clone + Send + Sync + 'static> EventLogSource for ProviderEventLogSource<P> {
    async fn challenge_logs(&self, window: ScanWindow) -> Result<Vec<alloy_rpc_types_eth::Log>> {
        // The window already encodes finality (the supervisor set `to_block = actionable_to`); this
        // seam does not re-apply it.
        let filter = Filter::new()
            .address(self.contract)
            .event_signature(ChallengeManager::ChallengeCreated::SIGNATURE_HASH)
            .from_block(window.from_block)
            .to_block(window.to_block);
        Ok(self.provider.get_logs(&filter).await?)
    }
}

/// Real [`ActiveChallengeReader`] over an `alloy` provider: the public mapping getter + latest block
/// timestamp.
pub struct ProviderChainReader<P> {
    provider: P,
    contract: Address,
}

#[async_trait]
impl<P: Provider + Clone + Send + Sync + 'static> ActiveChallengeReader for ProviderChainReader<P> {
    async fn active_withdraw_challenge(&self, bridge: Address) -> Result<U256> {
        // Single-return call: alloy returns the bare `uint256`.
        Ok(ChallengeManager::new(self.contract, self.provider.clone())
            .activeWithdrawChallenge(bridge)
            .call()
            .await?)
    }

    async fn chain_timestamp(&self) -> Result<u64> {
        let block = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await?
            .ok_or_else(|| anyhow!("no latest L2 block available for chain timestamp"))?;
        Ok(block.header.timestamp)
    }
}

/// Real [`ProveSender`] over an `alloy` provider: build and broadcast `submitWithdrawProof`, then
/// read a receipt.
///
/// NOTE: real end-to-end submission is pending upstream items (a wallet/signer and the WB reverse
/// endpoint), so this path is compiled but not exercised end-to-end. A broadcast error is
/// conservatively mapped to [`SenderError::UnknownBroadcastOutcome`] (hold the in-flight gate and
/// reconcile via receipt) rather than inferring a safe pre-broadcast retry.
pub struct ProviderProveSender<P> {
    provider: P,
    contract: Address,
}

#[async_trait]
impl<P: Provider + Clone + Send + Sync + 'static> ProveSender for ProviderProveSender<P> {
    async fn send_prove(
        &self,
        challenge_id: U256,
        leaf_index: u32,
        leaf_count: u32,
        proof: [B256; 32],
    ) -> Result<SubmitOutcome, SenderError> {
        // Bind the contract instance to a local so the call builder (which borrows it) does not
        // outlive a temporary.
        let contract = ChallengeManager::new(self.contract, self.provider.clone());
        let call = contract.submitWithdrawProof(challenge_id, leaf_index, leaf_count, proof);
        match call.send().await {
            Ok(pending) => Ok(SubmitOutcome::Submitted(*pending.tx_hash())),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "submitWithdrawProof broadcast returned an error; treating as unknown outcome"
                );
                Err(SenderError::UnknownBroadcastOutcome { tx_hash: None })
            }
        }
    }

    async fn confirm(&self, tx: TxHash) -> Result<TxStatus> {
        match self.provider.get_transaction_receipt(tx).await? {
            Some(receipt) => {
                Ok(if receipt.status() { TxStatus::Success } else { TxStatus::Reverted })
            }
            None => Ok(TxStatus::Pending),
        }
    }
}

/// Per-challenge facts cached from the `ChallengeCreated` event so the reader can derive status
/// without a per-challenge on-chain getter (the contract exposes none).
#[derive(Clone, Copy)]
struct EventFacts {
    response_deadline: u64,
    affected_bridge: Address,
}

/// Real `ChallengeManager` adapter implementing the three ABI-agnostic seams
/// ([`ChallengeEventSource`] / [`ChallengeReader`] / [`ChallengeSender`]) over the L2 provider,
/// plus an injected [`TxToLeafResolver`]. Only `WithdrawNotInRoot` challenges are surfaced; the
/// other two types are silently ignored. The watcher / handler / supervisor / verifier / cache are
/// unchanged — this only binds them to the real contract.
pub struct ChallengeManagerClient {
    events: Arc<dyn EventLogSource>,
    chain: Arc<dyn ActiveChallengeReader>,
    sender: Arc<dyn ProveSender>,
    resolver: Arc<dyn TxToLeafResolver>,
    chain_id: u64,
    contract: Address,
    /// `(response_deadline, affected_bridge)` per challenge id, cached from `ChallengeCreated`.
    facts: Mutex<HashMap<ChallengeId, EventFacts>>,
}

impl ChallengeManagerClient {
    /// Build the real adapter over an `alloy` L2 provider and a WB-backed reverse-lookup resolver.
    pub fn new<P: Provider + Clone + Send + Sync + 'static>(
        provider: P,
        contract: Address,
        resolver: Arc<dyn TxToLeafResolver>,
        chain_id: u64,
    ) -> Self {
        Self {
            events: Arc::new(ProviderEventLogSource { provider: provider.clone(), contract }),
            chain: Arc::new(ProviderChainReader { provider: provider.clone(), contract }),
            sender: Arc::new(ProviderProveSender { provider, contract }),
            resolver,
            chain_id,
            contract,
            facts: Mutex::new(HashMap::new()),
        }
    }

    fn cache_facts(&self, id: ChallengeId, facts: EventFacts) {
        self.facts.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(id, facts);
    }

    fn facts_for(&self, id: ChallengeId) -> Option<EventFacts> {
        self.facts.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&id).copied()
    }
}

#[async_trait]
impl ChallengeEventSource for ChallengeManagerClient {
    async fn watch_opened(&self, window: ScanWindow) -> Result<Vec<ChallengeOpened>> {
        // A whole-scan RPC failure propagates (the supervisor isolates it); a per-event decode or
        // reverse-lookup failure is logged and skipped, never aborting the scan.
        let logs = self.events.challenge_logs(window).await?;
        let mut out = Vec::new();
        for log in &logs {
            let parsed = match decode_challenge_created(log) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, "skipping undecodable ChallengeManager log");
                    continue;
                }
            };
            // Only WithdrawNotInRoot is answered; the other two types are silently ignored.
            if !is_withdraw_not_in_root(parsed.challenge_type) {
                continue;
            }
            // Reverse-lookup the leaf from tzTxHash. A retryable/permanent failure means the event
            // is simply not surfaced this scan; a retryable one is re-observed on a later scan
            // (dedup by ChallengeId keeps rescans idempotent — the watcher marks an event seen only
            // once it is returned here).
            let leaf_hash = match self.resolver.leaf_for_tx(parsed.tz_tx_hash).await {
                Ok(leaf) => leaf,
                Err(e) if e.is_retryable() => {
                    tracing::debug!(error = %e, "reverse-lookup not ready; will re-observe");
                    continue;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "reverse-lookup failed; skipping this scan");
                    continue;
                }
            };
            let id = challenge_id_to_bytes(parsed.challenge_id);
            self.cache_facts(
                id,
                EventFacts {
                    response_deadline: parsed.response_deadline,
                    affected_bridge: parsed.affected_bridge,
                },
            );
            // Construct ChallengeOpened directly from the authoritative id + reverse-looked-up leaf;
            // `ChallengeOpened::new`/`derive_challenge_id` are NOT used by the real adapter.
            out.push(ChallengeOpened {
                challenge_id: id,
                leaf_hash,
                block_number: parsed.block_number,
                chain_id: self.chain_id,
                contract: self.contract,
                tx_hash: parsed.tx_hash,
                log_index: parsed.log_index,
            });
        }
        Ok(out)
    }
}

#[async_trait]
impl ChallengeReader for ChallengeManagerClient {
    async fn get_challenge(&self, id: ChallengeId) -> Result<ChallengeStatus> {
        let facts = self
            .facts_for(id)
            .ok_or_else(|| anyhow!("no cached ChallengeCreated facts for the requested challenge"))?;
        // `open` is an EXACT equality against the cached challenge id: a bridge holds at most one
        // active withdraw-type challenge in this slot, so `activeWithdrawChallenge[bridge]` equals
        // this id iff it is still open (a different or zero id ⇒ closed).
        let active = self.chain.active_withdraw_challenge(facts.affected_bridge).await?;
        let chain_timestamp = self.chain.chain_timestamp().await?;
        Ok(ChallengeStatus {
            open: active == challenge_id_from_bytes(id),
            deadline: facts.response_deadline,
            chain_timestamp,
            // Attribution is established by the existing confirm_submitted receipt flow: a success
            // receipt that leaves the challenge no-longer-open is our resolution; a non-us
            // resolution surfaces as a revert or a still-open-past-deadline status, never a success
            // receipt. So the reader reports `resolved_by_us = true` and the handler's success
            // branch stays correct unchanged.
            resolved_by_us: true,
        })
    }
}

#[async_trait]
impl ChallengeSender for ChallengeManagerClient {
    async fn prove_challenge(
        &self,
        id: ChallengeId,
        leaf_index: u32,
        count: u32,
        siblings: [B256; 32],
    ) -> Result<SubmitOutcome, SenderError> {
        // Four-field passthrough: the mapped uint256 challengeId + the proof's leaf_index/count/
        // siblings, verbatim — no business transformation.
        self.sender.send_prove(challenge_id_from_bytes(id), leaf_index, count, siblings).await
    }

    async fn confirm(&self, tx: TxHash) -> Result<TxStatus> {
        self.sender.confirm(tx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, LogData, B256, U256};

    #[test]
    fn challenge_id_roundtrip_big_endian() {
        for v in [U256::ZERO, U256::from(1u64), U256::from(u64::MAX), U256::MAX - U256::from(3u64)] {
            assert_eq!(challenge_id_from_bytes(challenge_id_to_bytes(v)), v);
        }
        // Big-endian layout: the low byte of `1` is the LAST byte.
        let one = challenge_id_to_bytes(U256::from(1u64));
        assert_eq!(one.0[31], 1);
        assert!(one.0[..31].iter().all(|b| *b == 0));
    }

    /// Build a REAL ABI-encoded `ChallengeCreated` log via the `sol!`-generated event, then decode
    /// it — a fixture that is byte-consistent with the pinned ABI.
    fn encode_created(id: U256, ty: u8, tz: B256, deadline: u64) -> alloy_rpc_types_eth::Log {
        let ev = ChallengeManager::ChallengeCreated {
            challengeId: id,
            challengeType: ty,
            target: Address::repeat_byte(0xAA),
            affectedBridge: Address::repeat_byte(0xBB),
            tzTxHash: tz,
            challenger: Address::repeat_byte(0xDD),
            responseDeadline: deadline,
        };
        let data: LogData = ev.encode_log_data();
        let inner = alloy_primitives::Log { address: Address::repeat_byte(0xEE), data };
        alloy_rpc_types_eth::Log {
            inner,
            block_number: Some(1234),
            transaction_hash: Some(B256::repeat_byte(0x77)),
            log_index: Some(5),
            ..Default::default()
        }
    }

    #[test]
    fn decode_parses_all_bound_fields() {
        let tz = B256::repeat_byte(0xCC);
        let log = encode_created(U256::from(42u64), 0 /* WithdrawNotInRoot */, tz, 1_700_000_000);
        let p = decode_challenge_created(&log).unwrap();
        assert_eq!(p.challenge_id, U256::from(42u64));
        assert_eq!(p.challenge_type, ChallengeType::WithdrawNotInRoot);
        assert_eq!(p.tz_tx_hash, tz);
        assert_eq!(p.response_deadline, 1_700_000_000);
        assert_eq!(p.target, Address::repeat_byte(0xAA));
        assert_eq!(p.affected_bridge, Address::repeat_byte(0xBB));
        assert_eq!(p.block_number, 1234);
        assert_eq!(p.tx_hash, B256::repeat_byte(0x77));
        assert_eq!(p.log_index, 5);
    }

    #[test]
    fn decode_maps_each_challenge_type_ordinal() {
        for (ty, want) in [
            (0u8, ChallengeType::WithdrawNotInRoot),
            (1u8, ChallengeType::WithdrawMissingInBridge),
            (2u8, ChallengeType::ForceTxNotInRoot),
        ] {
            let log = encode_created(U256::from(1u64), ty, B256::ZERO, 1);
            assert_eq!(decode_challenge_created(&log).unwrap().challenge_type, want);
        }
    }

    #[test]
    fn decode_rejects_unknown_challenge_type_ordinal() {
        // An out-of-range ordinal (3) is a decode error, never a silently-mapped type.
        let log = encode_created(U256::from(1u64), 3, B256::ZERO, 1);
        assert!(matches!(
            decode_challenge_created(&log),
            Err(ChallengeDecodeError::UnknownType(3))
        ));
    }

    #[test]
    fn filter_keeps_only_withdraw_not_in_root() {
        assert!(is_withdraw_not_in_root(ChallengeType::WithdrawNotInRoot));
        assert!(!is_withdraw_not_in_root(ChallengeType::WithdrawMissingInBridge));
        assert!(!is_withdraw_not_in_root(ChallengeType::ForceTxNotInRoot));
    }

    #[test]
    fn decode_rejects_wrong_signature_and_truncated_log() {
        // Wrong topic0 (not ChallengeCreated) ⇒ clean decode error, never a panic or bogus parse.
        let inner = alloy_primitives::Log {
            address: Address::repeat_byte(0xEE),
            data: LogData::new_unchecked(vec![B256::repeat_byte(0x12)], Default::default()),
        };
        let bad = alloy_rpc_types_eth::Log { inner, ..Default::default() };
        assert!(matches!(decode_challenge_created(&bad), Err(ChallengeDecodeError::Abi(_))));
    }

    // ── Task 4: real-adapter seams driven by in-test stubs (no live node / HTTP). The `created_log`
    //    helper builds real ABI-encoded ChallengeCreated logs, so the parse/filter/reverse-lookup/
    //    construct + open-derivation + four-field passthrough surface is exercised end-to-end. ──

    #[allow(clippy::too_many_arguments)]
    fn created_log(
        id: U256,
        ty: u8,
        tz: B256,
        affected_bridge: Address,
        block: u64,
        log_index: u64,
        deadline: u64,
    ) -> alloy_rpc_types_eth::Log {
        let ev = ChallengeManager::ChallengeCreated {
            challengeId: id,
            challengeType: ty,
            target: Address::repeat_byte(0xAA),
            affectedBridge: affected_bridge,
            tzTxHash: tz,
            challenger: Address::repeat_byte(0xDD),
            responseDeadline: deadline,
        };
        let data: LogData = ev.encode_log_data();
        let inner = alloy_primitives::Log { address: Address::repeat_byte(0xEE), data };
        alloy_rpc_types_eth::Log {
            inner,
            block_number: Some(block),
            transaction_hash: Some(B256::repeat_byte(0x77)),
            log_index: Some(log_index),
            ..Default::default()
        }
    }

    /// Construct the adapter directly over in-test seams (the child module may name the private
    /// fields of its parent's struct).
    fn client_for_test(
        events: Arc<dyn EventLogSource>,
        chain: Arc<dyn ActiveChallengeReader>,
        sender: Arc<dyn ProveSender>,
        resolver: Arc<dyn TxToLeafResolver>,
        chain_id: u64,
        contract: Address,
    ) -> ChallengeManagerClient {
        ChallengeManagerClient {
            events,
            chain,
            sender,
            resolver,
            chain_id,
            contract,
            facts: Mutex::new(HashMap::new()),
        }
    }

    struct StubLogs(Vec<alloy_rpc_types_eth::Log>);
    #[async_trait]
    impl EventLogSource for StubLogs {
        async fn challenge_logs(&self, _w: ScanWindow) -> Result<Vec<alloy_rpc_types_eth::Log>> {
            Ok(self.0.clone())
        }
    }

    #[derive(Default)]
    struct StubActive {
        map: HashMap<Address, U256>,
        timestamp: u64,
    }
    impl StubActive {
        fn with(pairs: &[(Address, U256)]) -> Self {
            Self { map: pairs.iter().copied().collect(), timestamp: 0 }
        }
    }
    #[async_trait]
    impl ActiveChallengeReader for StubActive {
        async fn active_withdraw_challenge(&self, bridge: Address) -> Result<U256> {
            Ok(self.map.get(&bridge).copied().unwrap_or(U256::ZERO))
        }
        async fn chain_timestamp(&self) -> Result<u64> {
            Ok(self.timestamp)
        }
    }

    struct NoopSender;
    #[async_trait]
    impl ProveSender for NoopSender {
        async fn send_prove(
            &self,
            _id: U256,
            _leaf_index: u32,
            _leaf_count: u32,
            _proof: [B256; 32],
        ) -> Result<SubmitOutcome, SenderError> {
            Ok(SubmitOutcome::Submitted(TxHash::repeat_byte(0x99)))
        }
        async fn confirm(&self, _tx: TxHash) -> Result<TxStatus> {
            Ok(TxStatus::Pending)
        }
    }

    #[derive(Clone)]
    struct RecordedProve {
        challenge_id: U256,
        leaf_index: u32,
        leaf_count: u32,
        proof: [B256; 32],
    }
    #[derive(Default, Clone)]
    struct RecordingSender {
        calls: Arc<Mutex<Vec<RecordedProve>>>,
    }
    impl RecordingSender {
        fn last(&self) -> RecordedProve {
            self.calls.lock().unwrap().last().cloned().expect("a recorded prove call")
        }
    }
    #[async_trait]
    impl ProveSender for RecordingSender {
        async fn send_prove(
            &self,
            challenge_id: U256,
            leaf_index: u32,
            leaf_count: u32,
            proof: [B256; 32],
        ) -> Result<SubmitOutcome, SenderError> {
            self.calls.lock().unwrap().push(RecordedProve {
                challenge_id,
                leaf_index,
                leaf_count,
                proof,
            });
            Ok(SubmitOutcome::Submitted(TxHash::repeat_byte(0x99)))
        }
        async fn confirm(&self, _tx: TxHash) -> Result<TxStatus> {
            Ok(TxStatus::Pending)
        }
    }

    #[derive(Default)]
    struct MockResolver {
        map: HashMap<B256, B256>,
        not_ready: std::collections::HashSet<B256>,
    }
    impl MockResolver {
        fn with(pairs: &[(B256, B256)]) -> Self {
            Self { map: pairs.iter().copied().collect(), not_ready: Default::default() }
        }
        fn not_ready(txs: &[B256]) -> Self {
            Self { map: HashMap::new(), not_ready: txs.iter().copied().collect() }
        }
        fn empty() -> Self {
            Self::default()
        }
    }
    #[async_trait]
    impl TxToLeafResolver for MockResolver {
        async fn leaf_for_tx(&self, tz: B256) -> Result<B256, WbError> {
            if self.not_ready.contains(&tz) {
                return Err(WbError::NotReady);
            }
            self.map.get(&tz).copied().ok_or(WbError::WithdrawalNotFound)
        }
    }

    #[tokio::test]
    async fn watch_opened_keeps_only_withdraw_not_in_root_and_reverse_looks_up_leaf() {
        let bridge = Address::repeat_byte(0xBB);
        let tz0 = B256::repeat_byte(0xC0);
        // Three logs of types 0/1/2; only the type-0 (WithdrawNotInRoot) event survives.
        let logs = vec![
            created_log(U256::from(10u64), 0, tz0, bridge, 111, 7, 5_000),
            created_log(U256::from(11u64), 1, B256::repeat_byte(0xC1), bridge, 112, 8, 5_000),
            created_log(U256::from(12u64), 2, B256::repeat_byte(0xC2), bridge, 113, 9, 5_000),
        ];
        let resolver = Arc::new(MockResolver::with(&[(tz0, B256::repeat_byte(0xAA))]));
        let client = client_for_test(
            Arc::new(StubLogs(logs)),
            Arc::new(StubActive::default()),
            Arc::new(NoopSender),
            resolver,
            196,
            Address::repeat_byte(0xEE),
        );
        let opened =
            client.watch_opened(ScanWindow { from_block: 0, to_block: 1000 }).await.unwrap();
        assert_eq!(opened.len(), 1, "only the WithdrawNotInRoot event is surfaced");
        assert_eq!(
            opened[0].challenge_id,
            challenge_id_to_bytes(U256::from(10u64)),
            "id comes from the contract's uint256, mapped big-endian"
        );
        assert_eq!(opened[0].leaf_hash, B256::repeat_byte(0xAA), "leaf is reverse-looked-up");
        assert_eq!(opened[0].block_number, 111);
        assert_eq!(opened[0].chain_id, 196);
        assert_eq!(opened[0].contract, Address::repeat_byte(0xEE));
    }

    #[tokio::test]
    async fn watch_opened_skips_events_whose_reverse_lookup_is_not_ready() {
        let bridge = Address::repeat_byte(0xBB);
        let tz0 = B256::repeat_byte(0xC0);
        let logs = vec![created_log(U256::from(10u64), 0, tz0, bridge, 111, 7, 5_000)];
        let resolver = Arc::new(MockResolver::not_ready(&[tz0]));
        let client = client_for_test(
            Arc::new(StubLogs(logs)),
            Arc::new(StubActive::default()),
            Arc::new(NoopSender),
            resolver,
            196,
            Address::repeat_byte(0xEE),
        );
        // Not-ready ⇒ the event is NOT surfaced this scan and does not abort it; it is naturally
        // re-observed later (dedup by ChallengeId keeps rescans idempotent).
        assert_eq!(
            client.watch_opened(ScanWindow { from_block: 0, to_block: 1000 }).await.unwrap().len(),
            0
        );
    }

    #[tokio::test]
    async fn open_derivation_is_exact_equality() {
        let bridge = Address::repeat_byte(0xBB); // matches created_log's affectedBridge
        let id = U256::from(77u64);
        let tz = B256::repeat_byte(0xC0);

        // active[bridge] == 77 ⇒ open; deadline comes from the cached event.
        let client = client_for_test(
            Arc::new(StubLogs(vec![created_log(id, 0, tz, bridge, 5, 0, 5_000)])),
            Arc::new(StubActive::with(&[(bridge, id)])),
            Arc::new(NoopSender),
            Arc::new(MockResolver::with(&[(tz, B256::repeat_byte(0xAA))])),
            196,
            Address::repeat_byte(0xEE),
        );
        let _ = client.watch_opened(ScanWindow { from_block: 0, to_block: 10 }).await.unwrap();
        let status = client.get_challenge(challenge_id_to_bytes(id)).await.unwrap();
        assert!(status.open, "slot holds this exact id ⇒ open");
        assert_eq!(status.deadline, 5_000, "deadline is the cached responseDeadline");

        // A DIFFERENT id in the slot ⇒ closed (not merely 'any non-zero').
        let client2 = client_for_test(
            Arc::new(StubLogs(vec![created_log(id, 0, tz, bridge, 5, 0, 5_000)])),
            Arc::new(StubActive::with(&[(bridge, U256::from(1u64))])),
            Arc::new(NoopSender),
            Arc::new(MockResolver::with(&[(tz, B256::repeat_byte(0xAA))])),
            196,
            Address::repeat_byte(0xEE),
        );
        let _ = client2.watch_opened(ScanWindow { from_block: 0, to_block: 10 }).await.unwrap();
        assert!(!client2.get_challenge(challenge_id_to_bytes(id)).await.unwrap().open);

        // A ZERO id in the slot (empty mapping) ⇒ closed.
        let client3 = client_for_test(
            Arc::new(StubLogs(vec![created_log(id, 0, tz, bridge, 5, 0, 5_000)])),
            Arc::new(StubActive::default()),
            Arc::new(NoopSender),
            Arc::new(MockResolver::with(&[(tz, B256::repeat_byte(0xAA))])),
            196,
            Address::repeat_byte(0xEE),
        );
        let _ = client3.watch_opened(ScanWindow { from_block: 0, to_block: 10 }).await.unwrap();
        assert!(!client3.get_challenge(challenge_id_to_bytes(id)).await.unwrap().open);
    }

    #[tokio::test]
    async fn prove_challenge_passes_the_four_fields_verbatim() {
        let sender = RecordingSender::default();
        let client = client_for_test(
            Arc::new(StubLogs(vec![])),
            Arc::new(StubActive::default()),
            Arc::new(sender.clone()),
            Arc::new(MockResolver::empty()),
            196,
            Address::repeat_byte(0xEE),
        );
        let sibs = [B256::repeat_byte(0x07); 32];
        client.prove_challenge(challenge_id_to_bytes(U256::from(9u64)), 3, 5, sibs).await.unwrap();
        let call = sender.last();
        assert_eq!(call.challenge_id, U256::from(9u64), "ChallengeId mapped back to the uint256");
        assert_eq!(call.leaf_index, 3);
        assert_eq!(call.leaf_count, 5);
        assert_eq!(call.proof, sibs);
    }
}
