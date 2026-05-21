//! EIP712 domain constants for `KonaTeeVerifier`.
//!
//! ## ⚠️ Locked at v0.1
//!
//! `NAME` and `VERSION` are encoded into the EIP712 domain separator. Changing
//! them after the verifier contract is deployed invalidates **all** previously
//! signed proofs. Coordinate with the contract team before touching.

use alloy_primitives::{Address, address, U256};
use alloy_sol_types::Eip712Domain;

/// EIP712 domain name. Must match the value passed to the verifier contract's
/// `EIP712("XLayerKonaTeeVerifier", "1")` constructor.
pub const NAME: &str = "XLayerKonaTeeVerifier";

/// EIP712 domain version. Bump only on breaking journal layout changes
/// (and redeploy the verifier).
pub const VERSION: &str = "1";

/// Build an `Eip712Domain` for the given L1 chain and verifier address.
///
/// `chain_id` is the L1 chain where `KonaTeeVerifier` lives (e.g. 1 for mainnet,
/// 11155111 for sepolia). `verifying_contract` is the deployed verifier address;
/// pass `PLACEHOLDER_VERIFYING_CONTRACT` while the contract is not yet deployed.
pub fn domain(chain_id: u64, verifying_contract: Address) -> Eip712Domain {
    Eip712Domain {
        name: Some(NAME.into()),
        version: Some(VERSION.into()),
        chain_id: Some(U256::from(chain_id)),
        verifying_contract: Some(verifying_contract),
        salt: None,
    }
}

/// Placeholder verifier address for use before the real contract is deployed.
/// **Do not** sign production proofs against this — they will not verify.
pub const PLACEHOLDER_VERIFYING_CONTRACT: Address =
    address!("0000000000000000000000000000000000000000");
