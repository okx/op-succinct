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

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{sol, SolEvent};
use anyhow::Context;

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
}
