use super::types::TrustAnchors;
use p384::ecdsa::{
    signature::Verifier, Signature as P384Signature, VerifyingKey as P384VerifyingKey,
};
use x509_parser::{der_parser::oid, prelude::*};

pub struct CertChain {
    certs: Vec<Vec<u8>>,
}

impl CertChain {
    pub fn parse(cabundle: &[Vec<u8>], leaf_cert_der: &[u8]) -> Self {
        let mut all_certs = cabundle.to_vec();
        all_certs.push(leaf_cert_der.to_vec());

        for cert_der in &all_certs {
            let (rest, _) =
                X509Certificate::from_der(cert_der).expect("failed to parse X.509 certificate DER");
            assert!(rest.is_empty(), "DER certificate has trailing bytes");
        }

        Self { certs: all_certs }
    }

    pub fn validate_each_cert(&self) {
        let ecdsa_sha384_oid = oid!(1.2.840 .10045 .4 .3 .3);
        let p384_oid = oid!(1.3.132 .0 .34);
        let len = self.certs.len();

        for (i, cert_der) in self.certs.iter().enumerate() {
            let (_, cert) = X509Certificate::from_der(cert_der).unwrap();
            let is_leaf = i == len - 1;

            assert!(
                cert.signature_algorithm.algorithm == ecdsa_sha384_oid,
                "cert[{i}]: signature algorithm must be ecdsa-with-SHA384"
            );

            let spki = cert.tbs_certificate.subject_pki.algorithm.clone();
            let curve_oid = spki
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .unwrap_or_else(|| panic!("cert[{i}]: missing EC curve OID"));
            assert!(curve_oid == p384_oid, "cert[{i}]: EC curve must be P-384 (secp384r1)");

            if is_leaf {
                if let Ok(Some(bc)) = cert.basic_constraints() {
                    assert!(!bc.value.ca, "leaf cert: basicConstraints.cA must be false");
                }
            } else {
                let bc = cert
                    .basic_constraints()
                    .expect("CA cert: basicConstraints parse error")
                    .expect("CA cert: basicConstraints extension required");
                assert!(bc.value.ca, "cert[{i}]: CA cert must have basicConstraints.cA == true");

                let ku = cert
                    .key_usage()
                    .expect("CA cert: keyUsage parse error")
                    .expect("cert[{i}]: CA cert must have keyUsage extension");
                assert!(
                    ku.value.key_cert_sign(),
                    "cert[{i}]: CA cert keyUsage must contain keyCertSign"
                );
            }
        }
    }

    pub fn check_expiry(&self, timestamp_ms: u64) {
        let ts_secs = timestamp_ms / 1000;

        for (i, cert_der) in self.certs.iter().enumerate() {
            let (_, cert) = X509Certificate::from_der(cert_der).unwrap();
            let validity = &cert.validity();

            let not_before = validity.not_before.timestamp();
            let not_after = validity.not_after.timestamp();

            let not_before_secs = u64::try_from(not_before)
                .unwrap_or_else(|_| panic!("cert[{i}]: notBefore is negative"));
            let not_after_secs = u64::try_from(not_after)
                .unwrap_or_else(|_| panic!("cert[{i}]: notAfter is negative"));

            assert!(
                ts_secs >= not_before_secs,
                "cert[{i}]: not yet valid (timestamp {ts_secs} < notBefore {not_before_secs})"
            );
            assert!(
                ts_secs <= not_after_secs,
                "cert[{i}]: expired (timestamp {ts_secs} > notAfter {not_after_secs})"
            );
        }
    }

    pub fn verify_signatures(&self) {
        for i in 1..self.certs.len() {
            let (_, child) = X509Certificate::from_der(&self.certs[i]).unwrap();
            let (_, parent) = X509Certificate::from_der(&self.certs[i - 1]).unwrap();

            assert!(
                child.issuer() == parent.subject(),
                "cert[{i}]: issuer does not match parent subject"
            );

            if let Ok(Some(bc)) = parent.basic_constraints() {
                if let Some(path_len) = bc.value.path_len_constraint {
                    let depth_below = (self.certs.len().saturating_sub(1).saturating_sub(i)) as u32;
                    assert!(
                        depth_below <= path_len,
                        "cert[{i}]: violates parent pathLenConstraint ({depth_below} > {path_len})"
                    );
                }
            }

            let parent_spki = &parent.tbs_certificate.subject_pki.subject_public_key.data;
            let parent_vk = P384VerifyingKey::from_sec1_bytes(parent_spki)
                .unwrap_or_else(|_| panic!("cert[{i}]: failed to parse parent P-384 public key"));

            let child_sig_bytes = &child.signature_value.data;
            let child_sig = P384Signature::from_der(child_sig_bytes)
                .unwrap_or_else(|_| panic!("cert[{i}]: failed to parse DER ECDSA signature"));

            let tbs = child.tbs_certificate.as_ref();
            parent_vk
                .verify(tbs, &child_sig)
                .unwrap_or_else(|_| panic!("cert[{i}]: signature verification failed"));
        }
    }

    pub fn assert_root_pubkey(&self, anchors: &TrustAnchors) {
        let (_, root) = X509Certificate::from_der(&self.certs[0]).unwrap();
        let spki_bytes = &root.tbs_certificate.subject_pki.subject_public_key.data;

        assert!(
            spki_bytes.len() == 97,
            "root cert SPKI must be 97 bytes (SEC1 0x04 || X || Y), got {}",
            spki_bytes.len()
        );
        assert!(spki_bytes[0] == 0x04, "root cert SPKI must start with 0x04");

        assert!(
            &spki_bytes[1..] == &anchors.aws_root_pubkey,
            "root cert public key does not match AWS Nitro root"
        );
    }

    pub fn verify_cose_signature(&self, cose: &super::types::CoseSign1) {
        let leaf_der = self.certs.last().expect("cert chain is empty");
        let (_, leaf) = X509Certificate::from_der(leaf_der).unwrap();
        let leaf_spki = &leaf.tbs_certificate.subject_pki.subject_public_key.data;
        let leaf_vk = P384VerifyingKey::from_sec1_bytes(leaf_spki)
            .expect("failed to parse leaf P-384 public key");

        let sig_struct = cose.build_sig_structure();

        let raw_sig = P384Signature::from_slice(&cose.signature)
            .expect("COSE signature: invalid raw ES384 bytes");

        leaf_vk.verify(&sig_struct, &raw_sig).expect("COSE Sig_structure1 verification failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

    fn generate_p384_cert_chain() -> (Vec<Vec<u8>>, Vec<u8>, [u8; 96]) {
        let root_kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let root_pubkey_sec1 = root_kp.public_key_raw();
        let mut anchor = [0u8; 96];
        assert!(root_pubkey_sec1.len() == 97 || root_pubkey_sec1.len() == 96);
        if root_pubkey_sec1.len() == 97 {
            anchor.copy_from_slice(&root_pubkey_sec1[1..]);
        } else {
            anchor.copy_from_slice(root_pubkey_sec1);
        }

        let mut root_params = CertificateParams::new(vec![]).unwrap();
        root_params.distinguished_name.push(DnType::CommonName, "Test Root CA");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];

        let root_cert = root_params.self_signed(&root_kp).unwrap();
        let root_der = root_cert.der().to_vec();

        let leaf_kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut leaf_params = CertificateParams::new(vec![]).unwrap();
        leaf_params.distinguished_name.push(DnType::CommonName, "Test Leaf");
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

        let leaf_cert = leaf_params.signed_by(&leaf_kp, &root_cert, &root_kp).unwrap();
        let leaf_der = leaf_cert.der().to_vec();

        (vec![root_der], leaf_der, anchor)
    }

    fn generate_ca_cert_no_key_usage() -> (Vec<u8>, KeyPair, rcgen::Certificate) {
        let root_kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut root_params = CertificateParams::new(vec![]).unwrap();
        root_params.distinguished_name.push(DnType::CommonName, "Bad CA");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![];
        let root_cert = root_params.self_signed(&root_kp).unwrap();
        let root_der = root_cert.der().to_vec();
        (root_der, root_kp, root_cert)
    }

    #[test]
    fn test_cert_chain_valid_fixture() {
        let (cabundle, leaf_der, anchor) = generate_p384_cert_chain();
        let anchors = TrustAnchors { aws_root_pubkey: anchor };
        let chain = CertChain::parse(&cabundle, &leaf_der);
        chain.validate_each_cert();
        chain.check_expiry(
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()
                as u64,
        );
        chain.verify_signatures();
        chain.assert_root_pubkey(&anchors);
    }

    #[test]
    #[should_panic(expected = "does not match AWS Nitro root")]
    fn test_cert_chain_root_pubkey_mismatch() {
        let (cabundle, leaf_der, _) = generate_p384_cert_chain();
        let wrong_anchor = TrustAnchors { aws_root_pubkey: [0xFF; 96] };
        let chain = CertChain::parse(&cabundle, &leaf_der);
        chain.assert_root_pubkey(&wrong_anchor);
    }

    #[test]
    #[should_panic(expected = "signature verification failed")]
    fn test_cert_chain_tampered_signature() {
        let (cabundle, leaf_der, _) = generate_p384_cert_chain();
        let mut tampered_leaf = leaf_der.clone();
        let len = tampered_leaf.len();
        tampered_leaf[len - 2] ^= 0xFF;

        let chain = CertChain::parse(&cabundle, &tampered_leaf);
        chain.verify_signatures();
    }

    #[test]
    #[should_panic]
    fn test_cert_chain_issuer_subject_mismatch() {
        let (cabundle, _, _) = generate_p384_cert_chain();
        let (_, unrelated_leaf, _) = generate_p384_cert_chain();

        let chain = CertChain::parse(&cabundle, &unrelated_leaf);
        chain.verify_signatures();
    }

    #[test]
    #[should_panic(expected = "trailing bytes")]
    fn test_cert_chain_trailing_der_bytes() {
        let (cabundle, leaf_der, _) = generate_p384_cert_chain();
        let mut extended = leaf_der.clone();
        extended.extend_from_slice(&[0xFF, 0xFF]);
        CertChain::parse(&cabundle, &extended);
    }

    // --- 8 new tests required by rework ---

    #[test]
    #[should_panic(expected = "signature algorithm must be ecdsa-with-SHA384")]
    fn test_cert_chain_p256_rejected() {
        let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.distinguished_name.push(DnType::CommonName, "P256 Leaf");
        params.is_ca = IsCa::NoCa;
        let cert = params.self_signed(&kp).unwrap();
        let chain = CertChain { certs: vec![cert.der().to_vec()] };
        chain.validate_each_cert();
    }

    #[test]
    #[should_panic(expected = "signature algorithm must be ecdsa-with-SHA384")]
    fn test_cert_chain_wrong_curve() {
        let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.distinguished_name.push(DnType::CommonName, "Wrong Curve Leaf");
        params.is_ca = IsCa::NoCa;
        let cert = params.self_signed(&kp).unwrap();
        let leaf_der = cert.der().to_vec();

        let chain = CertChain { certs: vec![leaf_der] };
        chain.validate_each_cert();
    }

    #[test]
    #[should_panic(expected = "CA cert must have keyUsage extension")]
    fn test_cert_chain_ca_missing_key_usage() {
        let (root_der, root_kp, root_cert) = generate_ca_cert_no_key_usage();

        let leaf_kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut leaf_params = CertificateParams::new(vec![]).unwrap();
        leaf_params.distinguished_name.push(DnType::CommonName, "Leaf");
        leaf_params.is_ca = IsCa::NoCa;
        let leaf_cert = leaf_params.signed_by(&leaf_kp, &root_cert, &root_kp).unwrap();
        let leaf_der = leaf_cert.der().to_vec();

        let chain = CertChain::parse(&[root_der], &leaf_der);
        chain.validate_each_cert();
    }

    #[test]
    #[should_panic(expected = "keyCertSign")]
    fn test_cert_chain_ca_missing_key_cert_sign() {
        let root_kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut root_params = CertificateParams::new(vec![]).unwrap();
        root_params.distinguished_name.push(DnType::CommonName, "Bad CA 2");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let root_cert = root_params.self_signed(&root_kp).unwrap();
        let root_der = root_cert.der().to_vec();

        let leaf_kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut leaf_params = CertificateParams::new(vec![]).unwrap();
        leaf_params.distinguished_name.push(DnType::CommonName, "Leaf 2");
        leaf_params.is_ca = IsCa::NoCa;
        let leaf_cert = leaf_params.signed_by(&leaf_kp, &root_cert, &root_kp).unwrap();
        let leaf_der = leaf_cert.der().to_vec();

        let chain = CertChain::parse(&[root_der], &leaf_der);
        chain.validate_each_cert();
    }

    #[test]
    fn test_cert_chain_pathlen_underflow() {
        let (cabundle, leaf_der, _) = generate_p384_cert_chain();
        let chain = CertChain::parse(&cabundle, &leaf_der);
        let depth = chain.certs.len().saturating_sub(1).saturating_sub(1);
        assert_eq!(depth, 0);
        chain.verify_signatures();
    }

    #[test]
    #[should_panic(expected = "expired")]
    fn test_expiry_covers_expired() {
        let (cabundle, leaf_der, _) = generate_p384_cert_chain();
        let chain = CertChain::parse(&cabundle, &leaf_der);
        let far_future_ms: u64 = 253_402_300_800_000;
        chain.check_expiry(far_future_ms);
    }

    #[test]
    #[should_panic(expected = "not yet valid")]
    fn test_expiry_covers_not_yet_valid() {
        let (cabundle, leaf_der, _) = generate_p384_cert_chain();
        let chain = CertChain::parse(&cabundle, &leaf_der);
        let past_ms: u64 = 1000;
        chain.check_expiry(past_ms);
    }
}
