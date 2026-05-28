//! X.509 certificate chain validation for AWS Nitro Enclave attestations.
//!
//! Checks:
//!   - Per-cert content (algorithm OID, EC curve, basicConstraints, keyUsage,
//!     issuer/subject chain, path length).
//!   - Validity period vs `AttestationDoc.timestamp`.
//!   - P-384 / ECDSA-SHA384 signature of every non-root cert by its parent.
//!     Root self-signature is **not** verified — root trust is asserted via
//!     [`CertChain::assert_root_pubkey`] against the vkey-baked AWS Nitro
//!     Root-G1 public key constant.

use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use x509_parser::{
    certificate::X509Certificate,
    oid_registry::{OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_SIG_ECDSA_WITH_SHA384},
    prelude::FromDer,
};

/// Parsed AWS Nitro PKI chain. Element 0 is the root; the last element is the
/// leaf cert that signed `COSE_Sign1`.
pub struct CertChain<'a> {
    certs: Vec<X509Certificate<'a>>,
}

impl<'a> CertChain<'a> {
    /// Parse `cabundle` (root-first) + the separately-carried leaf cert.
    pub fn parse(cabundle: &[&'a [u8]], leaf_der: &'a [u8]) -> Self {
        assert!(!cabundle.is_empty(), "cert chain: cabundle empty");

        let mut certs = Vec::with_capacity(cabundle.len() + 1);
        for (i, der) in cabundle.iter().enumerate() {
            let (rest, cert) = X509Certificate::from_der(der)
                .unwrap_or_else(|e| panic!("cert chain: cabundle[{i}] DER parse failed: {e}"));
            assert!(rest.is_empty(), "cert chain: cabundle[{i}] has trailing bytes");
            certs.push(cert);
        }
        let (rest, leaf) = X509Certificate::from_der(leaf_der)
            .unwrap_or_else(|e| panic!("cert chain: leaf DER parse failed: {e}"));
        assert!(rest.is_empty(), "cert chain: leaf has trailing bytes");
        certs.push(leaf);

        Self { certs }
    }

    /// Per-cert content checks on every certificate.
    pub fn validate_each_cert(&self) {
        let last = self.certs.len() - 1;
        for (i, cert) in self.certs.iter().enumerate() {
            let is_leaf = i == last && self.certs.len() > 1;
            validate_cert_content(cert, is_leaf, i);
        }
    }

    /// Every cert must cover `timestamp_ms / 1000`.
    pub fn check_expiry(&self, timestamp_ms: u64) {
        let ts_secs = timestamp_ms / 1000;
        for (i, cert) in self.certs.iter().enumerate() {
            let not_before = cert.validity().not_before.timestamp();
            let not_after = cert.validity().not_after.timestamp();
            let not_before_u = u64::try_from(not_before).unwrap_or_else(|_| {
                panic!("cert chain: cert {i} notBefore negative ({not_before})")
            });
            let not_after_u = u64::try_from(not_after)
                .unwrap_or_else(|_| panic!("cert chain: cert {i} notAfter negative ({not_after})"));
            assert!(
                not_before_u < ts_secs && ts_secs < not_after_u,
                "cert chain: cert {i} validity {not_before_u}..{not_after_u} doesn't cover \
                 attestation timestamp {ts_secs}"
            );
        }
    }

    /// Verify every non-root cert's signature against its parent's public key
    /// and enforce chain coherence (issuer/subject match, path length).
    /// Root self-signature is **not** verified here.
    pub fn verify_signatures(&self) {
        let n = self.certs.len();
        for i in 1..n {
            let parent = &self.certs[i - 1];
            let child = &self.certs[i];

            // Issuer chain consistency.
            assert_eq!(
                child.issuer(),
                parent.subject(),
                "cert chain: cert {i} issuer != parent subject"
            );

            // pathLenConstraint on the parent.
            if let Some(parent_bc) = parent
                .basic_constraints()
                .unwrap_or_else(|e| panic!("cert chain: cert {} basicConstraints: {e}", i - 1))
            {
                let remaining = (n - 1).saturating_sub(i);
                if let Some(max) = parent_bc.value.path_len_constraint {
                    assert!(
                        (remaining as u32) <= max,
                        "cert chain: cert {i} violates parent path_len_constraint \
                         (max={max}, remaining={remaining})"
                    );
                }
            }

            // P-384 / ECDSA-SHA384 signature verification.
            let parent_pk = parent.public_key().subject_public_key.data.as_ref();
            let vkey = VerifyingKey::from_sec1_bytes(parent_pk).unwrap_or_else(|e| {
                panic!("cert chain: cert {} pubkey not a valid SEC1 P-384 point: {e}", i - 1)
            });
            let sig = Signature::from_der(child.signature_value.data.as_ref()).unwrap_or_else(
                |e| panic!("cert chain: cert {i} signature not valid DER ECDSA: {e}"),
            );
            // Raw TBS DER from the cert — what the parent's signature covers.
            // Avoids re-encoding which is expensive in zkVM.
            let tbs = child.tbs_certificate.as_ref();
            vkey.verify(tbs, &sig)
                .unwrap_or_else(|e| panic!("cert chain: cert {i} signature invalid: {e}"));
        }
    }

    /// Anchor: root SubjectPublicKey must equal the expected AWS Nitro
    /// Root-G1 public key. `expected` is the 96-byte X ‖ Y (no SEC1 prefix).
    pub fn assert_root_pubkey(&self, expected: &[u8; 96]) {
        let root_spki = self.certs[0].public_key().subject_public_key.data.as_ref();
        // SEC1 uncompressed: 0x04 || X(48) || Y(48) = 97 bytes for P-384.
        assert_eq!(
            root_spki.len(),
            97,
            "cert chain: root SPKI not 97-byte SEC1 uncompressed P-384 ({} bytes)",
            root_spki.len()
        );
        assert_eq!(root_spki[0], 0x04, "cert chain: root SPKI missing SEC1 0x04 prefix");
        assert_eq!(
            &root_spki[1..],
            &expected[..],
            "cert chain: root pubkey does not match AWS Nitro Root-G1"
        );
    }

    /// SEC1-encoded uncompressed leaf public key (`0x04 || X || Y`, 97 bytes
    /// for P-384). Used by [`super::cose`] to verify the COSE signature.
    pub fn leaf_public_key(&self) -> &[u8] {
        self.certs.last().expect("cert chain: empty").public_key().subject_public_key.data.as_ref()
    }
}

/// Content checks for a single certificate.
fn validate_cert_content(cert: &X509Certificate<'_>, is_leaf: bool, idx: usize) {
    // (a) Signature algorithm must be ecdsa-with-SHA384.
    let sig_oid = cert.signature_algorithm.oid();
    assert!(
        *sig_oid == OID_SIG_ECDSA_WITH_SHA384,
        "cert {idx}: unsupported signature algorithm {sig_oid}"
    );

    // (b) Public key must be EC, curve must be P-384. Without the curve check,
    //     a P-256 cert could sneak through the EC algorithm check.
    let pk_algo = &cert.public_key().algorithm;
    assert!(
        pk_algo.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY,
        "cert {idx}: unsupported pubkey algorithm {}",
        pk_algo.algorithm
    );
    let curve_oid = pk_algo
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .unwrap_or_else(|| panic!("cert {idx}: EC pubkey missing curve OID"));
    assert!(curve_oid == OID_NIST_EC_P384, "cert {idx}: curve {curve_oid} not P-384");

    // (c) basicConstraints + keyUsage shape depending on role.
    let basic_constraints = cert
        .basic_constraints()
        .unwrap_or_else(|e| panic!("cert {idx}: basicConstraints parse: {e}"));
    let key_usage =
        cert.key_usage().unwrap_or_else(|e| panic!("cert {idx}: keyUsage parse: {e}"));

    if is_leaf {
        if let Some(bc) = basic_constraints {
            assert!(!bc.value.ca, "cert {idx} (leaf): basicConstraints cA=true");
        }
        if let Some(ku) = key_usage {
            assert!(
                ku.value.digital_signature(),
                "cert {idx} (leaf): keyUsage missing digitalSignature"
            );
        }
    } else {
        let bc = basic_constraints
            .unwrap_or_else(|| panic!("cert {idx} (CA): missing basicConstraints"));
        assert!(bc.value.ca, "cert {idx} (CA): basicConstraints cA=false");
        let ku = key_usage.unwrap_or_else(|| panic!("cert {idx} (CA): missing keyUsage"));
        assert!(ku.value.key_cert_sign(), "cert {idx} (CA): keyUsage missing keyCertSign");
    }
}
