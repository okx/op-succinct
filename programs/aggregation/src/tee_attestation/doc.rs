//! AWS Nitro Enclave attestation document — CBOR payload parsing and content
//! validation. Schema: <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>
//!
//! Only the fields the aggregation guest consumes are deserialized:
//! `timestamp`, `digest`, `pcrs`, `certificate`, `cabundle`, `public_key`.
//! `module_id`, `user_data`, `nonce` are ignored.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_bytes::{ByteArray, ByteBuf};

/// PCR measurement length (SHA-384 output).
pub const PCR_LEN: usize = 48;

/// Parsed AWS Nitro attestation document.
///
/// Extra unknown keys are tolerated by CBOR map deserialization.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AttestationDoc {
    /// Attestation timestamp, ms since Unix epoch.
    pub timestamp: u64,
    /// Always `"SHA384"` for AWS Nitro; enforced in [`validate_content`].
    pub digest: String,
    /// PCR table. AWS Nitro produces ~16 entries; each value is 48 bytes
    /// (SHA-384). We only read PCR0; the rest are ignored.
    pub pcrs: BTreeMap<u8, ByteArray<PCR_LEN>>,
    /// DER-encoded leaf certificate that signs `COSE_Sign1`.
    pub certificate: ByteBuf,
    /// DER-encoded chain root → ... → last intermediate (leaf not included).
    pub cabundle: Vec<ByteBuf>,
    /// SEC1-encoded uncompressed enclave public key (65 bytes for secp256k1).
    /// The enclave hands this to NSM; NSM binds it via the COSE signature.
    #[serde(default)]
    pub public_key: Option<ByteBuf>,
}

impl AttestationDoc {
    /// Parse the CBOR payload from inside a `COSE_Sign1` envelope.
    pub fn parse(payload: &[u8]) -> Self {
        ciborium::de::from_reader(payload).expect("AttestationDoc: malformed CBOR payload")
    }

    /// Return PCR0 (enclave image SHA-384). Panics if absent.
    pub fn pcr0(&self) -> [u8; PCR_LEN] {
        let pcr0 = self.pcrs.get(&0).expect("attestation doc: PCR0 missing");
        **pcr0
    }
}

/// Runtime sanity checks. Precondition to trusting downstream cert-chain
/// and signature verification.
pub fn validate_content(doc: &AttestationDoc) {
    assert!(doc.timestamp != 0, "attestation: timestamp is zero");
    assert_eq!(doc.digest, "SHA384", "attestation: digest must be SHA384");
    assert!(!doc.cabundle.is_empty(), "attestation: cabundle empty");
    assert!(doc.pcrs.contains_key(&0), "attestation: PCR0 missing");

    // public_key required: the aggregation guest's TEE binding hinges on
    // recovering the signer from this field. Reject present-but-empty too.
    let pk = doc.public_key.as_ref().expect("attestation: public_key missing");
    let len = pk.len();
    assert!(
        (1..=1024).contains(&len),
        "attestation: public_key length {len} out of range (1..=1024)"
    );
}
