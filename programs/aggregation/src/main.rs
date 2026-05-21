//! A program that aggregates the proofs of the range program.
//!
//! Each range can be proven by either:
//! - **SP1 ZK proof** of the range program (legacy path), verified via
//!   `sp1_lib::verify::verify_sp1_proof` recursion; or
//! - **TEE EIP712 signature** over the `RangeJournal`, verified inline in
//!   this zkVM via ecrecover against a hardcoded approved-enclaves set.
//!
//! The choice is per-range, signalled by the `RangeProof` enum in
//! `AggregationInputs.range_proofs[i]`. On-chain downstream sees only the
//! aggregated `AggregationOutputs` and the SP1 proof — it cannot tell which
//! ranges were SP1 vs TEE, so the trust model is identical from the
//! verifier-contract perspective.
//!
//! ## TEE verification is closed at vkey-bake time
//!
//! The approved enclave set ([`APPROVED_TEE_ENCLAVES`]) and the EIP712 domain
//! ([`tee_eip712_domain`]) are compiled into the program → into the SP1
//! aggregation vkey → into the on-chain SP1 verifier deployment. Rotating
//! the approved set therefore requires:
//!   1. Editing the constants below.
//!   2. Rebuilding the aggregation program and getting a new vkey hash.
//!   3. Updating the vkey hash in the on-chain SP1 verifier.

#![cfg_attr(target_os = "zkvm", no_main)]
#[cfg(target_os = "zkvm")]
sp1_zkvm::entrypoint!(main);

use alloy_consensus::Header;
use alloy_primitives::{address, b256, keccak256, Address, B256, U256};
use alloy_sol_types::{sol, Eip712Domain, SolStruct, SolValue};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use op_succinct_client_utils::{
    boot::BootInfoStruct,
    types::{u32_to_u8, AggregationInputs, AggregationOutputs, RangeProof},
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ============================================================================
// TEE verification — vkey-baked constants
// ============================================================================

/// EIP712 domain name. Must equal `xlayer-tee-types::eip712::NAME` on the
/// enclave side. Any divergence → typeHash mismatch → all signatures fail.
const TEE_EIP712_DOMAIN_NAME: &str = "XLayerKonaTeeVerifier";

/// EIP712 domain version. Bump only on a breaking journal layout change
/// and re-deploy the verifier in lockstep.
const TEE_EIP712_DOMAIN_VERSION: &str = "1";

/// EIP712 domain `chainId`. Set to the L1 chainId where the aggregation
/// proof gets posted (the L1 that hosts the L2OutputOracle / SP1 verifier).
/// `1` = mainnet, `11155111` = sepolia, `195` = X Layer devnet L1.
/// **Adjust per deployment**.
const TEE_EIP712_CHAIN_ID: u64 = 1;

/// EIP712 domain `verifyingContract`. With on-chain TEE registration
/// removed, the verifier address has no natural value. We use the zero
/// address as a sentinel so the domain stays well-formed; the security
/// boundary now lives in the SP1 vkey, not in this field.
const TEE_EIP712_VERIFYING_CONTRACT: Address =
    address!("0000000000000000000000000000000000000000");

/// Approved `(pcr0, signer_address)` pairs. Signatures whose recovered
/// signer + journal-embedded PCR0 do not match any entry are rejected.
///
/// `pcr0` is `keccak256(NSM 48-byte SHA-384 PCR0)` (see
/// `xlayer-tee-enclave::main` for the compression scheme).
///
/// Entries here are **placeholders for the dev enclave** (Anvil acct #0
/// signer + all-zero PCR0). Replace before any production deployment, and
/// follow the rotation playbook in the design doc.
const APPROVED_TEE_ENCLAVES: &[(B256, Address)] = &[
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000000"),
        address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
    ),
];

// ============================================================================
// Mirror of `xlayer-tee-types::journal::RangeJournal`
//
// Field order **must** match the enclave's definition exactly — EIP712
// typeHash is computed from field order. Defined inline here (rather than
// importing the `tee-types` crate) to keep the aggregation program's
// dependency surface minimal and to make the zkvm build self-contained.
// ============================================================================

sol! {
    struct RangeJournal {
        bytes32 pcr0;
        bytes32 configHash;
        bytes32 l1OriginHash;
        uint64  l2BlockNumber;
        bytes32 prevOutputRoot;
        bytes32 outputRoot;
    }
}

// ============================================================================
// Main
// ============================================================================

pub fn main() {
    // Read in the public values corresponding to each range proof.
    let agg_inputs = sp1_zkvm::io::read::<AggregationInputs>();
    // Note: The headers are in order from start to end. We use serde_cbor as bincode serialization
    // causes issues with the zkVM.
    let headers_bytes = sp1_zkvm::io::read_vec();
    let headers: Vec<Header> = serde_cbor::from_slice(&headers_bytes).unwrap();
    assert!(!agg_inputs.boot_infos.is_empty());
    assert_eq!(
        agg_inputs.boot_infos.len(),
        agg_inputs.range_proofs.len(),
        "boot_infos and range_proofs must be parallel-indexed",
    );

    // Confirm that the boot infos are sequential.
    agg_inputs.boot_infos.windows(2).for_each(|pair| {
        let (prev_boot_info, boot_info) = (&pair[0], &pair[1]);

        // The claimed block of the previous boot info must be the L2 output root of the current
        // boot.
        assert_eq!(prev_boot_info.l2PostRoot, boot_info.l2PreRoot);

        // The rollup config must be the same for all the boot infos, to ensure they're
        // from the same chain and span batch range.
        assert_eq!(prev_boot_info.rollupConfigHash, boot_info.rollupConfigHash);
    });

    // Verify each range program proof — dispatched on the RangeProof variant.
    let tee_domain = tee_eip712_domain();
    for (boot_info, range_proof) in
        agg_inputs.boot_infos.iter().zip(agg_inputs.range_proofs.iter())
    {
        match range_proof {
            RangeProof::Sp1 => {
                // Legacy path: SP1 recursion asserts a pre-loaded proof of the range program
                // committed to this boot_info.
                let serialized_boot_info = bincode::serialize(boot_info).unwrap();
                let pv_digest = Sha256::digest(serialized_boot_info);
                sp1_lib::verify::verify_sp1_proof(
                    &agg_inputs.multi_block_vkey,
                    &pv_digest.into(),
                );
            }
            RangeProof::Tee { pcr0, signature } => {
                verify_tee_range_proof(boot_info, pcr0, signature, &tee_domain);
            }
        }
    }

    // Create a map of each l1 head in the [`BootInfoStruct`]'s to booleans
    let mut l1_heads_map: HashMap<B256, bool> =
        agg_inputs.boot_infos.iter().map(|boot_info| (boot_info.l1Head, false)).collect();

    // Iterate through the headers in reverse order. The headers should be sequentially linked and
    // include the l1 head of each boot info.
    let mut current_hash = agg_inputs.latest_l1_checkpoint_head;
    for header in headers.iter().rev() {
        assert_eq!(current_hash, header.hash_slow());

        // Mark the l1 head as found if it's in our map.
        if let Some(found) = l1_heads_map.get_mut(&current_hash) {
            *found = true;
        }

        current_hash = header.parent_hash;
    }

    // Check if all l1 heads were found in the chain.
    for (l1_head, found) in l1_heads_map.iter() {
        assert!(*found, "l1 head {l1_head:?} not found in the provided header chain");
    }

    let first_boot_info = &agg_inputs.boot_infos[0];
    let last_boot_info = &agg_inputs.boot_infos[agg_inputs.boot_infos.len() - 1];
    // Consolidate the boot info into a single BootInfo struct that represents the range proven.
    let final_boot_info = BootInfoStruct {
        // The first boot info's L2 output root is the L2 output root of the range.
        l2PreRoot: first_boot_info.l2PreRoot,
        l2BlockNumber: last_boot_info.l2BlockNumber,
        l2PostRoot: last_boot_info.l2PostRoot,
        l1Head: agg_inputs.latest_l1_checkpoint_head,
        rollupConfigHash: last_boot_info.rollupConfigHash,
    };

    // Convert the range vkey to a B256.
    let multi_block_vkey_b256 = B256::from(u32_to_u8(agg_inputs.multi_block_vkey));

    let agg_outputs = AggregationOutputs {
        l1Head: final_boot_info.l1Head,
        l2PreRoot: final_boot_info.l2PreRoot,
        l2PostRoot: final_boot_info.l2PostRoot,
        l2BlockNumber: final_boot_info.l2BlockNumber,
        rollupConfigHash: final_boot_info.rollupConfigHash,
        multiBlockVKey: multi_block_vkey_b256,
        proverAddress: agg_inputs.prover_address,
    };

    // Commit to the aggregated [`AggregationOutputs`].
    sp1_zkvm::io::commit_slice(&agg_outputs.abi_encode());
}

// ============================================================================
// TEE verification helpers
// ============================================================================

/// Build the EIP712 domain used for in-zkVM verification. Constructed every
/// call (rather than `lazy_static`) to keep the program no_std-friendly;
/// allocations are tiny.
fn tee_eip712_domain() -> Eip712Domain {
    Eip712Domain {
        name: Some(TEE_EIP712_DOMAIN_NAME.into()),
        version: Some(TEE_EIP712_DOMAIN_VERSION.into()),
        chain_id: Some(U256::from(TEE_EIP712_CHAIN_ID)),
        verifying_contract: Some(TEE_EIP712_VERIFYING_CONTRACT),
        salt: None,
    }
}

/// Verify one TEE-signed range proof.
///
/// 1. Reconstruct the `RangeJournal` the enclave signed: 5 fields from the
///    parallel `BootInfoStruct`, plus `pcr0` from the proof itself.
/// 2. Compute the EIP712 signing hash.
/// 3. ecrecover the secp256k1 signature → 20-byte signer address.
/// 4. Assert `(pcr0, signer)` is in [`APPROVED_TEE_ENCLAVES`].
///
/// Panics on any mismatch (SP1 turns the panic into proof-generation
/// failure, which the host scheduler surfaces as a retryable error).
fn verify_tee_range_proof(
    boot_info: &BootInfoStruct,
    pcr0: &B256,
    signature: &[u8],
    domain: &Eip712Domain,
) {
    assert_eq!(
        signature.len(),
        65,
        "TEE signature must be exactly 65 bytes (r ‖ s ‖ v), got {}",
        signature.len()
    );
    // (1) Reconstruct the journal the enclave signed.
    let journal = RangeJournal {
        pcr0: *pcr0,
        configHash: boot_info.rollupConfigHash,
        l1OriginHash: boot_info.l1Head,
        l2BlockNumber: boot_info.l2BlockNumber,
        prevOutputRoot: boot_info.l2PreRoot,
        outputRoot: boot_info.l2PostRoot,
    };

    // (2) EIP712 signing hash. `eip712_signing_hash` produces:
    //   keccak256("\x19\x01" ‖ domainSeparator ‖ structHash)
    let digest: B256 = journal.eip712_signing_hash(domain);

    // (3) secp256k1 ecrecover. Inside SP1 this routes through the
    // secp256k1 precompile via the SP1-patched k256 crate.
    let signer = ecrecover(&digest, signature);

    // (4) Approved-set membership check.
    let approved =
        APPROVED_TEE_ENCLAVES.iter().any(|(p, s)| p == pcr0 && *s == signer);
    assert!(
        approved,
        "TEE enclave not in approved set: pcr0={:?} signer={:?}",
        pcr0, signer,
    );
}

/// secp256k1 ECDSA `ecrecover` over a prehash. Matches the on-chain
/// `ecrecover(hash, v, r, s)` semantics: returns the 20-byte address
/// derived from `keccak256(uncompressed_pubkey[1..])[12..]`.
///
/// Caller must ensure `sig_65.len() == 65`; `verify_tee_range_proof`
/// asserts this before calling.
fn ecrecover(digest: &B256, sig_65: &[u8]) -> Address {
    debug_assert_eq!(sig_65.len(), 65);
    let sig = Signature::from_slice(&sig_65[..64]).expect("malformed (r,s) signature");
    // v in {27, 28} → RecoveryId {0, 1}. The enclave normalizes to 27/28
    // (see `xlayer-tee-enclave::signing::V_OFFSET`); reject anything else.
    let rec_id_byte = sig_65[64]
        .checked_sub(27)
        .expect("signature v must be 27 or 28");
    let rec_id = RecoveryId::try_from(rec_id_byte).expect("invalid recovery id");

    let vk = VerifyingKey::recover_from_prehash(digest.as_slice(), &sig, rec_id)
        .expect("ecrecover: could not recover verifying key");

    // Address = keccak256(uncompressed_pubkey[1..])[12..]. The leading 0x04
    // SEC1 prefix is stripped before hashing — same convention as
    // Ethereum's address derivation.
    let encoded = vk.to_encoded_point(false);
    let pubkey_bytes = encoded.as_bytes();
    debug_assert_eq!(pubkey_bytes.len(), 65, "uncompressed SEC1 must be 65 bytes");
    let hash = keccak256(&pubkey_bytes[1..]);
    Address::from_slice(&hash[12..])
}
