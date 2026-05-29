//! AWS Nitro Enclave attestation verification, in-zkVM.
//!
//! Single entry: [`verify_attestation`]; panics on failure.

mod cose;
mod doc;
mod x509;

use alloy_primitives::{keccak256, Address, B256};
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};

/// Trust anchors baked into the guest's vkey. PCR0 is *not* anchored here —
/// it is surfaced through [`VerifiedSession::pcr0_hash`] for the on-chain
/// approved-PCR0 check, so rotating the image doesn't need a vkey upgrade.
pub struct TrustAnchors {
    /// AWS Nitro Root-G1 P-384 pubkey, SEC1 X ‖ Y (96 bytes, no prefix).
    pub aws_root_pubkey: [u8; 96],
}

pub struct VerifiedSession {
    /// TEE leaves must ecrecover to this signer.
    pub signer: Address,
    /// `keccak256(raw 48-byte NSM PCR0)` — same form the enclave signs into
    /// `RangeJournal.pcr0` and that gets committed publicly.
    pub pcr0_hash: B256,
}

/// Verify one AWS Nitro attestation end-to-end and extract signer + PCR0.
///
/// Checks: COSE_Sign1 envelope, AttestationDoc field sanity, cert chain
/// (per-cert content + expiry + P-384 sigs + root SPKI ==
/// `anchors.aws_root_pubkey`), and the COSE signature with the leaf cert.
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

    // PCR0 returned to the caller; the on-chain verifier decides whether
    // this measurement is approved.
    let pcr0_hash = keccak256(document.pcr0());

    let pk = document.public_key.as_ref().expect("attestation: public_key missing");
    let signer = address_from_pubkey(pk.as_ref());

    VerifiedSession { signer, pcr0_hash }
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
