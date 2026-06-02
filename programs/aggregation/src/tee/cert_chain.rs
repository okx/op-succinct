use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use x509_parser::prelude::*;

use super::cose::CoseSign1;

// secp384r1 OID: 1.3.132.0.34 — not in oid-registry 0.7's default set
const OID_EC_P384_RAW: &[u64] = &[1, 3, 132, 0, 34];

pub struct CertChain {
    certs: Vec<Vec<u8>>,
}

/// Pure arithmetic: is timestamp_ms / 1000 within (not_before_secs, not_after_secs)?
pub fn covers(timestamp_ms: u64, not_before_secs: u64, not_after_secs: u64) -> bool {
    let ts_secs = timestamp_ms / 1000;
    not_before_secs < ts_secs && ts_secs < not_after_secs
}

impl CertChain {
    /// Parse certificate chain. cabundle is root -> intermediates (DER); leaf is separate DER.
    pub fn parse(cabundle: &[Vec<u8>], leaf_der: &[u8]) -> Self {
        let mut certs = cabundle.to_vec();
        certs.push(leaf_der.to_vec());
        CertChain { certs }
    }

    /// Validate each cert: sig algorithm, curve, basicConstraints, keyUsage.
    pub fn validate_each_cert(&self) {
        let len = self.certs.len();
        for (i, cert_der) in self.certs.iter().enumerate() {
            let (_, cert) =
                X509Certificate::from_der(cert_der).expect("failed to parse DER certificate");

            let sig_alg = &cert.signature_algorithm.algorithm;
            assert!(
                *sig_alg == oid_registry::OID_SIG_ECDSA_WITH_SHA384,
                "cert {i}: signature algorithm must be ecdsa-with-SHA384, got {sig_alg}"
            );

            let spki = cert.public_key();
            let key_alg = &spki.algorithm.algorithm;
            assert!(
                *key_alg == oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY,
                "cert {i}: public key algorithm must be EC, got {key_alg}"
            );

            if let Some(params) = &spki.algorithm.parameters {
                if let Ok(curve_oid) = params.as_oid() {
                    let is_p384 = curve_oid.iter().unwrap().collect::<Vec<_>>() == OID_EC_P384_RAW;
                    assert!(
                        is_p384,
                        "cert {i}: curve must be P-384 (1.3.132.0.34), got {curve_oid}"
                    );
                }
            }

            let is_leaf = i == len - 1;

            if let Ok(Some(bc)) = cert.basic_constraints() {
                if is_leaf {
                    assert!(!bc.value.ca, "leaf cert must not have cA=true");
                } else {
                    assert!(bc.value.ca, "cert {i}: CA cert must have cA=true");
                }
            } else if !is_leaf {
                panic!("cert {i}: CA cert must have basicConstraints with cA=true");
            }

            if let Ok(Some(ku)) = cert.key_usage() {
                if is_leaf {
                    assert!(
                        ku.value.digital_signature(),
                        "leaf cert must have digitalSignature keyUsage"
                    );
                } else {
                    assert!(
                        ku.value.key_cert_sign(),
                        "cert {i}: CA cert must have keyCertSign keyUsage"
                    );
                }
            }
        }
    }

    /// Check all certs are valid at the given millisecond timestamp.
    pub fn check_expiry(&self, timestamp_ms: u64) {
        for (i, cert_der) in self.certs.iter().enumerate() {
            let (_, cert) = X509Certificate::from_der(cert_der).expect("failed to parse cert");
            let validity = cert.validity();
            let not_before = validity.not_before.timestamp() as u64;
            let not_after = validity.not_after.timestamp() as u64;
            assert!(
                covers(timestamp_ms, not_before, not_after),
                "cert {i}: not valid at timestamp {timestamp_ms}ms (not_before={not_before}s, not_after={not_after}s)"
            );
        }
    }

    /// Verify signature chain (each non-root signed by parent).
    pub fn verify_signatures(&self) {
        for i in 1..self.certs.len() {
            let (_, child) =
                X509Certificate::from_der(&self.certs[i]).expect("failed to parse child cert");
            let (_, parent) =
                X509Certificate::from_der(&self.certs[i - 1]).expect("failed to parse parent cert");

            assert_eq!(
                child.issuer(),
                parent.subject(),
                "cert {i}: issuer does not match parent subject"
            );

            if let Ok(Some(bc)) = parent.basic_constraints() {
                if let Some(path_len) = bc.value.path_len_constraint {
                    let remaining_intermediates = (self.certs.len() - 2 - (i - 1)) as u32;
                    assert!(
                        remaining_intermediates <= path_len,
                        "cert {}: parent pathLenConstraint violated ({remaining_intermediates} > {path_len})",
                        i - 1
                    );
                }
            }

            let parent_spki = parent.public_key();
            let parent_key_bytes = parent_spki.subject_public_key.as_ref();
            let parent_vk = VerifyingKey::from_sec1_bytes(parent_key_bytes)
                .expect("failed to parse parent P-384 public key");

            let child_tbs = child.tbs_certificate.as_ref();
            let child_sig_bytes = child.signature_value.as_ref();
            let child_sig = Signature::from_der(child_sig_bytes)
                .expect("failed to parse child cert DER signature");

            parent_vk
                .verify(child_tbs, &child_sig)
                .expect("cert {i}: P-384 signature verification failed");
        }
    }

    /// Assert root cert public key matches the trust anchor.
    pub fn assert_root_pubkey(&self, expected: &[u8; 96]) {
        let (_, root) =
            X509Certificate::from_der(&self.certs[0]).expect("failed to parse root cert");
        let spki = root.public_key();
        let pubkey_bytes = spki.subject_public_key.as_ref();
        assert!(
            pubkey_bytes.len() == 97 && pubkey_bytes[0] == 0x04,
            "root cert public key must be 97 bytes (0x04 || X || Y)"
        );
        assert_eq!(
            &pubkey_bytes[1..],
            expected,
            "root cert public key does not match trust anchor"
        );
    }

    /// Return the leaf certificate's P-384 public key (uncompressed, 97 bytes).
    pub fn leaf_pubkey(&self) -> Vec<u8> {
        let (_, leaf) = X509Certificate::from_der(self.certs.last().expect("empty chain"))
            .expect("failed to parse leaf cert");
        leaf.public_key().subject_public_key.as_ref().to_vec()
    }

    /// Verify COSE envelope signature using the leaf cert's P-384 public key.
    pub fn verify_cose_signature(&self, envelope: &CoseSign1) {
        let leaf_pk_bytes = self.leaf_pubkey();
        let leaf_vk = VerifyingKey::from_sec1_bytes(&leaf_pk_bytes)
            .expect("failed to parse leaf P-384 public key");

        let sig_input = envelope.sig_structure();
        let sig =
            Signature::from_slice(&envelope.signature).expect("failed to parse ES384 signature");

        leaf_vk.verify(&sig_input, &sig).expect("COSE envelope signature verification failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_covers_within_range() {
        assert!(covers(1_500_000, 1_000, 2_000));
    }

    #[test]
    fn test_covers_expired() {
        assert!(!covers(3_000_000, 1_000, 2_000));
    }

    #[test]
    fn test_covers_not_yet_valid() {
        assert!(!covers(500_000, 1_000, 2_000));
    }

    #[test]
    fn test_covers_exact_not_before_boundary() {
        assert!(!covers(1_000_000, 1_000, 2_000));
    }

    #[test]
    fn test_covers_exact_not_after_boundary() {
        assert!(!covers(2_000_000, 1_000, 2_000));
    }
}
