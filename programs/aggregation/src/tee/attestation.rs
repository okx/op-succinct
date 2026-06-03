use alloy_primitives::{keccak256, B256};

use super::{
    cert_chain::CertChain, cose::CoseSign1, crypto::address_from_pubkey, TrustAnchors,
    VerifiedSession,
};

pub struct AttestationDoc {
    pub timestamp: u64,
    pub digest: String,
    pub pcrs: std::collections::BTreeMap<u64, Vec<u8>>,
    pub certificate: Vec<u8>,
    pub cabundle: Vec<Vec<u8>>,
    pub public_key: Vec<u8>,
}

impl AttestationDoc {
    /// Parse an AttestationDoc from CBOR bytes.
    pub fn parse(data: &[u8]) -> Self {
        let value: ciborium::Value =
            ciborium::from_reader(data).expect("AttestationDoc: invalid CBOR");

        let map = match value {
            ciborium::Value::Map(m) => m,
            _ => panic!("AttestationDoc: expected CBOR map"),
        };

        let mut timestamp = None;
        let mut digest = None;
        let mut pcrs = std::collections::BTreeMap::new();
        let mut certificate = None;
        let mut cabundle = None;
        let mut public_key = None;

        for (k, v) in map {
            let key_str = match &k {
                ciborium::Value::Text(s) => s.clone(),
                _ => continue,
            };
            match key_str.as_str() {
                "timestamp" => {
                    timestamp = match v {
                        ciborium::Value::Integer(i) => {
                            let val: i128 = i.into();
                            Some(val as u64)
                        }
                        _ => None,
                    };
                }
                "digest" => {
                    digest = match v {
                        ciborium::Value::Text(s) => Some(s),
                        _ => None,
                    };
                }
                "pcrs" => {
                    if let ciborium::Value::Map(pcr_map) = v {
                        for (pk, pv) in pcr_map {
                            if let (ciborium::Value::Integer(idx), ciborium::Value::Bytes(data)) =
                                (pk, pv)
                            {
                                let idx_val: i128 = idx.into();
                                pcrs.insert(idx_val as u64, data);
                            }
                        }
                    }
                }
                "certificate" => {
                    certificate = match v {
                        ciborium::Value::Bytes(b) => Some(b),
                        _ => None,
                    };
                }
                "cabundle" => {
                    if let ciborium::Value::Array(arr) = v {
                        let mut bundle = Vec::new();
                        for item in arr {
                            if let ciborium::Value::Bytes(b) = item {
                                bundle.push(b);
                            }
                        }
                        cabundle = Some(bundle);
                    }
                }
                "public_key" => {
                    public_key = match v {
                        ciborium::Value::Bytes(b) => Some(b),
                        _ => None,
                    };
                }
                _ => {}
            }
        }

        AttestationDoc {
            timestamp: timestamp.expect("AttestationDoc: missing timestamp"),
            digest: digest.expect("AttestationDoc: missing digest"),
            pcrs,
            certificate: certificate.expect("AttestationDoc: missing certificate"),
            cabundle: cabundle.expect("AttestationDoc: missing cabundle"),
            public_key: public_key.expect("AttestationDoc: missing public_key"),
        }
    }

    pub fn validate_content(&self) {
        assert!(self.timestamp != 0, "AttestationDoc: timestamp must be non-zero");
        assert!(
            self.digest == "SHA384",
            "AttestationDoc: digest must equal \"SHA384\", got \"{}\"",
            self.digest
        );
        assert!(!self.cabundle.is_empty(), "AttestationDoc: cabundle must be non-empty");

        let pcr0 = self.pcrs.get(&0).expect("AttestationDoc: pcrs must contain key 0");
        assert!(
            pcr0.len() == 48,
            "AttestationDoc: PCR0 must be exactly 48 bytes, got {}",
            pcr0.len()
        );

        assert!(
            !self.public_key.is_empty() && self.public_key.len() <= 1024,
            "AttestationDoc: public_key length must be in 1..=1024, got {}",
            self.public_key.len()
        );
    }
}

/// Top-level entry: verify a complete attestation document and return session identity.
pub fn verify_attestation(bytes: &[u8], anchors: &TrustAnchors) -> VerifiedSession {
    let envelope = CoseSign1::parse(bytes);
    let doc = AttestationDoc::parse(&envelope.payload);
    doc.validate_content();

    let chain = CertChain::parse(&doc.cabundle, &doc.certificate);
    chain.validate_each_cert();
    chain.check_expiry(doc.timestamp);
    chain.verify_signatures();
    chain.assert_root_pubkey(&anchors.aws_root_pubkey);

    chain.verify_cose_signature(&envelope);

    let pcr0_raw = doc.pcrs.get(&0).expect("PCR0 already validated");
    let pcr0_hash = keccak256(pcr0_raw);
    let signer = address_from_pubkey(&doc.public_key);

    VerifiedSession { signer, pcr0_hash: B256::from(pcr0_hash) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_doc(overrides: &[(&str, ciborium::Value)]) -> AttestationDoc {
        let cbor = build_doc_cbor(overrides);
        AttestationDoc::parse(&cbor)
    }

    fn build_doc_cbor(overrides: &[(&str, ciborium::Value)]) -> Vec<u8> {
        use ciborium::Value;

        let mut fields: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
        fields.insert("timestamp".into(), Value::Integer(1_700_000_000_000i64.into()));
        fields.insert("digest".into(), Value::Text("SHA384".into()));

        let pcr_map = vec![(Value::Integer(0.into()), Value::Bytes(vec![0xAA; 48]))];
        fields.insert("pcrs".into(), Value::Map(pcr_map));
        fields.insert("certificate".into(), Value::Bytes(vec![0x30; 10]));
        fields.insert("cabundle".into(), Value::Array(vec![Value::Bytes(vec![0x30; 10])]));
        fields.insert("public_key".into(), Value::Bytes(vec![0x04; 65]));

        for (key, val) in overrides {
            fields.insert((*key).to_string(), val.clone());
        }

        let map: Vec<(Value, Value)> =
            fields.into_iter().map(|(k, v)| (Value::Text(k), v)).collect();

        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut buf).unwrap();
        buf
    }

    #[test]
    fn test_parse_valid_attestation_doc() {
        let doc = build_doc(&[]);
        assert_eq!(doc.timestamp, 1_700_000_000_000);
        assert_eq!(doc.digest, "SHA384");
        assert_eq!(doc.pcrs.get(&0).unwrap().len(), 48);
        assert_eq!(doc.public_key.len(), 65);
    }

    #[test]
    #[should_panic(expected = "timestamp must be non-zero")]
    fn test_validate_content_zero_timestamp() {
        let doc = build_doc(&[("timestamp", ciborium::Value::Integer(0.into()))]);
        doc.validate_content();
    }

    #[test]
    #[should_panic(expected = "digest must equal")]
    fn test_validate_content_wrong_digest() {
        let doc = build_doc(&[("digest", ciborium::Value::Text("SHA256".into()))]);
        doc.validate_content();
    }

    #[test]
    #[should_panic(expected = "pcrs must contain key 0")]
    fn test_validate_content_missing_pcr0() {
        let doc = build_doc(&[("pcrs", ciborium::Value::Map(vec![]))]);
        doc.validate_content();
    }

    #[test]
    #[should_panic(expected = "PCR0 must be exactly 48 bytes")]
    fn test_validate_content_pcr0_wrong_length() {
        let pcr_map =
            vec![(ciborium::Value::Integer(0.into()), ciborium::Value::Bytes(vec![0u8; 32]))];
        let doc = build_doc(&[("pcrs", ciborium::Value::Map(pcr_map))]);
        doc.validate_content();
    }

    #[test]
    #[should_panic(expected = "public_key length must be in 1..=1024")]
    fn test_validate_content_pubkey_empty() {
        let doc = build_doc(&[("public_key", ciborium::Value::Bytes(vec![]))]);
        doc.validate_content();
    }

    #[test]
    #[should_panic(expected = "public_key length must be in 1..=1024")]
    fn test_validate_content_pubkey_too_long() {
        let doc = build_doc(&[("public_key", ciborium::Value::Bytes(vec![0u8; 1025]))]);
        doc.validate_content();
    }
}
