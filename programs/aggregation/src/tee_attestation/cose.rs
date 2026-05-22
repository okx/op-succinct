//! COSE_Sign1 envelope parsing for AWS Nitro Enclave attestation documents.
//!
//! RFC 8152 §4.2 wrapper around the attestation document payload. AWS Nitro
//! always uses untagged COSE_Sign1 with `alg = ES384`; we reject any other
//! shape rather than try to be a general COSE library.

use ciborium::Value as CborValue;

/// Parsed COSE_Sign1 envelope. Fields are owned `Vec<u8>` — attestation
/// docs are ~5 KB, one copy is cheap compared to the P-384 verifications.
pub struct CoseSign1 {
    /// CBOR-encoded `body_protected`. AWS Nitro = `{1: -35}` (alg = ES384).
    pub protected: Vec<u8>,
    /// Raw attestation document bytes — CBOR payload parsed by [`super::doc`].
    pub payload: Vec<u8>,
    /// 96-byte raw ECDSA signature `r ‖ s` (each 48 bytes) over `Sig_structure1`.
    pub signature: Vec<u8>,
}

impl CoseSign1 {
    /// Parse a COSE_Sign1 envelope. Expects a CBOR array of 4 elements:
    /// `[protected, unprotected, payload, signature]`. Optional CBOR tag 18
    /// is stripped defensively even though AWS Nitro doesn't emit it.
    pub fn parse(bytes: &[u8]) -> Self {
        let value: CborValue =
            ciborium::de::from_reader(bytes).expect("COSE_Sign1: malformed CBOR");

        let array = match value {
            CborValue::Tag(18, inner) => match *inner {
                CborValue::Array(a) => a,
                _ => panic!("COSE_Sign1: tag 18 wraps a non-array"),
            },
            CborValue::Array(a) => a,
            _ => panic!("COSE_Sign1: top-level CBOR must be array or tag(18, array)"),
        };

        assert_eq!(array.len(), 4, "COSE_Sign1: expected 4 elements");

        let mut iter = array.into_iter();
        let protected = extract_bytes(iter.next().unwrap(), "protected");
        // Unprotected header — AWS Nitro doesn't populate anything we use.
        let _ = iter.next().unwrap();
        let payload = extract_bytes(iter.next().unwrap(), "payload");
        let signature = extract_bytes(iter.next().unwrap(), "signature");

        // ES384 signature is r ‖ s, each scalar 48 bytes.
        assert_eq!(
            signature.len(),
            96,
            "COSE_Sign1: ES384 signature must be 96 bytes, got {}",
            signature.len()
        );

        Self { protected, payload, signature }
    }

    /// CBOR encoding of the `Sig_structure1` that the signature covers
    /// (RFC 8152 §4.4): `[ "Signature1", body_protected, empty_aad, payload ]`.
    pub fn sig_structure(&self) -> Vec<u8> {
        let structure = CborValue::Array(vec![
            CborValue::Text("Signature1".to_string()),
            CborValue::Bytes(self.protected.clone()),
            CborValue::Bytes(Vec::new()),
            CborValue::Bytes(self.payload.clone()),
        ]);

        let mut buf = Vec::with_capacity(self.protected.len() + self.payload.len() + 32);
        ciborium::ser::into_writer(&structure, &mut buf)
            .expect("Sig_structure1: encode never fails for owned values");
        buf
    }
}

fn extract_bytes(value: CborValue, field: &'static str) -> Vec<u8> {
    match value {
        CborValue::Bytes(b) => b,
        _ => panic!("COSE_Sign1: field {field} must be a CBOR byte string"),
    }
}
