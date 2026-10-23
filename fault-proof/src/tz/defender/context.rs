//! Challenge-side wiring of the Defender, built from configuration in one place.
//!
//! The binary and the integration tests both call [`make_defender_context`], so a test drives the
//! same locator and the same leaf-encoding gate that production runs, rather than a parallel
//! construction in the test file that could silently drift from the binary.

use std::sync::Arc;

use alloy_primitives::B256;

use super::{
    config::DefenderConfig,
    leaf_encoding_gate::{DeploymentTarget, LeafEncodingGate},
    leaf_locator::DirectLeafLocator,
};

/// The challenge-side components the Defender derives from its configuration.
pub struct DefenderChallengeContext {
    /// Turns a decoded challenge event into the Witness-Builder leaf key. The actor never consumes
    /// a reverse lookup to find leaves, so nothing about a lookup service gates the
    /// challenge-listening chain.
    pub locator: DirectLeafLocator,
    /// Deployment-bound leaf-encoding compatibility gate guarding the proof flow.
    pub leaf_encoding_gate: Arc<LeafEncodingGate>,
}

/// Builds the challenge-side wiring for `config`.
///
/// The gate is constructed without a compatibility declaration: none is published yet and none is
/// constructible from local config/env/flags, so it stays mismatched and every proof path is
/// withheld with an observable Blocked status — there is no local re-encode shim to mask it. The
/// expected encoding version / canonical hash / Witness-Builder identity are placeholders for the
/// same reason: with no declaration to match, they are never compared. Lifting fail-closed is a
/// separate contract/Witness-Builder prerequisite (publish an authenticated, immutable declaration
/// and wire an authenticated read).
pub fn make_defender_context(config: &DefenderConfig) -> DefenderChallengeContext {
    DefenderChallengeContext {
        locator: DirectLeafLocator,
        leaf_encoding_gate: Arc::new(LeafEncodingGate::new(
            DeploymentTarget {
                address: config.challenge_contract,
                chain_id: config.chain_id,
                expected_encoding_version: 0,
                expected_canonical_encoding_hash: B256::ZERO,
                expected_witness_builder_id: B256::ZERO,
            },
            None,
        )),
    }
}
