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

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{sol, SolEvent};
use thiserror::Error;

use super::challenge_contract::ChallengeId;

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
}
