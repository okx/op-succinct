pub mod attestation;
pub mod cert_chain;
pub mod crypto;
pub mod types;

use alloy_primitives::{keccak256, B256};
use types::{TrustAnchors, VerifiedSession};

pub use crypto::verify_tee_range_proof;

pub fn verify_attestation(bytes: &[u8], anchors: &TrustAnchors) -> VerifiedSession {
    let cose = types::CoseSign1::parse(bytes);
    let doc = types::AttestationDoc::parse(&cose.payload);
    doc.validate_content();

    let chain = cert_chain::CertChain::parse(&doc.cabundle, &doc.certificate);
    chain.validate_each_cert();
    chain.check_expiry(doc.timestamp);
    chain.verify_signatures();
    chain.assert_root_pubkey(anchors);
    chain.verify_cose_signature(&cose);

    let pcr0 = doc.pcrs.get(&0).expect("PCR0 missing");
    let pcr0_hash = keccak256(pcr0);
    let signer = crypto::address_from_pubkey(&doc.public_key);

    VerifiedSession { signer, pcr0_hash: B256::from(pcr0_hash) }
}
