//! AWS Nitro Enclave attestation verification, in-zkVM.
//!
//! Single entry: [`verify_attestation`]. Pass raw `COSE_Sign1` bytes plus
//! the trust anchors (PCR0 hash + AWS Nitro Root-G1 pubkey); panics on any
//! failure (SP1 turns this into proof-generation failure).

mod cose;
mod doc;
mod x509;

use alloy_primitives::{keccak256, Address, B256};
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};

/// Trust anchors baked into the guest's vkey. Changing either rebuilds the
/// ELF and forces an on-chain vkey upgrade — by design.
pub struct TrustAnchors {
    /// `keccak256(raw 48-byte NSM PCR0)` — same 32-byte form the enclave
    /// signs into `RangeJournal.pcr0`.
    pub expected_pcr0_hash: B256,
    /// AWS Nitro Root-G1 P-384 public key, SEC1 uncompressed X ‖ Y (no `0x04`
    /// prefix). Public information; safe to commit.
    pub aws_root_pubkey: [u8; 96],
}

/// Minimum the aggregation guest needs to bind subsequent `RangeProof::Tee`
/// leaves to this attestation.
pub struct VerifiedSession {
    /// Ethereum-style address from the attestation's `public_key` field
    /// (`keccak256(SEC1_uncompressed[1..])[12..]`).
    pub signer: Address,
}

/// Verify one AWS Nitro Enclave attestation document end-to-end. Panics on
/// any failure; deterministic and side-effect-free.
///
/// 1. Parse COSE_Sign1 + attestation document payload.
/// 2. M-02 content checks.
/// 3. Parse cert chain + M-01 content + expiry + per-cert P-384 sigs.
/// 4. Root SPKI == `anchors.aws_root_pubkey`.
/// 5. COSE_Sign1 signature verified by leaf cert pubkey.
/// 6. `keccak256(attestation.pcrs[0]) == anchors.expected_pcr0_hash`.
/// 7. Signer address derived from attestation's `public_key`.
pub fn verify_attestation(bytes: &[u8], anchors: &TrustAnchors) -> VerifiedSession {
    let envelope = cose::CoseSign1::parse(bytes);
    let document = doc::AttestationDoc::parse(&envelope.payload);
    doc::validate_content(&document);

    // The cert parser borrows from the underlying DER bytes; hold the slice
    // view here for the chain's lifetime.
    let cabundle_refs: Vec<&[u8]> = document.cabundle.iter().map(|b| b.as_ref()).collect();
    let chain = x509::CertChain::parse(&cabundle_refs, document.certificate.as_ref());
    chain.validate_each_cert();
    chain.check_expiry(document.timestamp);
    chain.verify_signatures();
    chain.assert_root_pubkey(&anchors.aws_root_pubkey);

    verify_cose_signature(chain.leaf_public_key(), &envelope);

    // PCR0 check: enclave stores `keccak256(raw 48-byte NSM PCR0)` in the
    // RangeJournal, so we anchor against that 32-byte form directly.
    let pcr0_hash = keccak256(document.pcr0());
    assert_eq!(
        pcr0_hash, anchors.expected_pcr0_hash,
        "attestation: PCR0 hash mismatch"
    );

    let pk = document.public_key.as_ref().expect("attestation: public_key missing");
    let signer = address_from_pubkey(pk.as_ref());

    VerifiedSession { signer }
}

/// Verify the COSE_Sign1 signature using the leaf cert's P-384 public key.
/// `p384`'s ECDSA `verify()` hashes the message with SHA-384 internally;
/// we pass the full `Sig_structure1` blob.
fn verify_cose_signature(leaf_pubkey: &[u8], envelope: &cose::CoseSign1) {
    let vkey = VerifyingKey::from_sec1_bytes(leaf_pubkey)
        .unwrap_or_else(|e| panic!("attestation: leaf pubkey not a valid SEC1 P-384 point: {e}"));
    let sig = Signature::from_slice(&envelope.signature)
        .unwrap_or_else(|e| panic!("attestation: COSE signature not valid raw ES384: {e}"));
    let sig_structure = envelope.sig_structure();
    vkey.verify(&sig_structure, &sig)
        .unwrap_or_else(|e| panic!("attestation: COSE_Sign1 signature invalid: {e}"));
}

/// Ethereum-style address from a SEC1 uncompressed public key.
fn address_from_pubkey(pk_sec1: &[u8]) -> Address {
    assert_eq!(
        pk_sec1.len(),
        65,
        "attestation: public_key must be 65-byte SEC1 uncompressed (got {})",
        pk_sec1.len()
    );
    assert_eq!(pk_sec1[0], 0x04, "attestation: public_key missing SEC1 0x04 prefix");
    let hash = keccak256(&pk_sec1[1..]);
    Address::from_slice(&hash[12..])
}
