use super::types::{AttestationDoc, CoseSign1};
use std::collections::BTreeMap;

impl CoseSign1 {
    pub fn parse(bytes: &[u8]) -> Self {
        let value: ciborium::Value =
            ciborium::from_reader(bytes).expect("COSE_Sign1: invalid CBOR");

        let array = match value {
            ciborium::Value::Tag(18, inner) => match *inner {
                ciborium::Value::Array(arr) => arr,
                _ => panic!("COSE_Sign1: Tag(18) must wrap an Array"),
            },
            ciborium::Value::Array(arr) => arr,
            _ => panic!("COSE_Sign1: expected Array or Tag(18, Array)"),
        };

        assert!(array.len() == 4, "COSE_Sign1: exactly 4 elements required");

        let protected = match &array[0] {
            ciborium::Value::Bytes(b) => b.clone(),
            _ => panic!("COSE_Sign1: protected must be bstr"),
        };

        let payload = match &array[2] {
            ciborium::Value::Bytes(b) => b.clone(),
            _ => panic!("COSE_Sign1: payload must be bstr"),
        };

        let signature = match &array[3] {
            ciborium::Value::Bytes(b) => b.clone(),
            _ => panic!("COSE_Sign1: signature must be bstr"),
        };

        assert!(
            signature.len() == 96,
            "COSE_Sign1: signature must be 96 bytes (ES384), got {}",
            signature.len()
        );

        Self { protected, payload, signature }
    }

    pub fn build_sig_structure(&self) -> Vec<u8> {
        let sig_structure = ciborium::Value::Array(vec![
            ciborium::Value::Text("Signature1".to_string()),
            ciborium::Value::Bytes(self.protected.clone()),
            ciborium::Value::Bytes(vec![]),
            ciborium::Value::Bytes(self.payload.clone()),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&sig_structure, &mut buf).expect("CBOR serialization failed");
        buf
    }
}

impl AttestationDoc {
    pub fn parse(payload: &[u8]) -> Self {
        let value: ciborium::Value =
            ciborium::from_reader(payload).expect("AttestationDoc: invalid CBOR");

        let map = match value {
            ciborium::Value::Map(m) => m,
            _ => panic!("AttestationDoc: expected CBOR map"),
        };

        let mut timestamp = 0u64;
        let mut digest = String::new();
        let mut pcrs = BTreeMap::new();
        let mut certificate = Vec::new();
        let mut cabundle = Vec::new();
        let mut public_key = Vec::new();

        for (k, v) in map {
            let key = match k {
                ciborium::Value::Text(s) => s,
                _ => continue,
            };
            match key.as_str() {
                "timestamp" => {
                    timestamp = match v {
                        ciborium::Value::Integer(i) => {
                            let val: i128 = i.into();
                            u64::try_from(val).expect("timestamp must be a positive u64")
                        }
                        _ => panic!("timestamp must be an integer"),
                    };
                }
                "digest" => {
                    digest = match v {
                        ciborium::Value::Text(s) => s,
                        _ => panic!("digest must be a string"),
                    };
                }
                "pcrs" => {
                    let pcr_map = match v {
                        ciborium::Value::Map(m) => m,
                        _ => panic!("pcrs must be a map"),
                    };
                    for (pk, pv) in pcr_map {
                        let idx = match pk {
                            ciborium::Value::Integer(i) => {
                                let val: i128 = i.into();
                                u64::try_from(val).expect("PCR index must be a positive u64")
                            }
                            _ => continue,
                        };
                        let data = match pv {
                            ciborium::Value::Bytes(b) => b,
                            _ => continue,
                        };
                        pcrs.insert(idx, data);
                    }
                }
                "certificate" => {
                    certificate = match v {
                        ciborium::Value::Bytes(b) => b,
                        _ => panic!("certificate must be bytes"),
                    };
                }
                "cabundle" => {
                    let arr = match v {
                        ciborium::Value::Array(a) => a,
                        _ => panic!("cabundle must be an array"),
                    };
                    for item in arr {
                        match item {
                            ciborium::Value::Bytes(b) => cabundle.push(b),
                            _ => panic!("cabundle entries must be bytes"),
                        }
                    }
                }
                "public_key" => {
                    public_key = match v {
                        ciborium::Value::Bytes(b) => b,
                        _ => panic!("public_key must be bytes"),
                    };
                }
                _ => {}
            }
        }

        Self { timestamp, digest, pcrs, certificate, cabundle, public_key }
    }

    pub fn validate_content(&self) {
        assert!(self.timestamp != 0, "attestation timestamp must be nonzero");
        assert!(self.digest == "SHA384", "attestation digest must be SHA384, got {}", self.digest);
        assert!(!self.cabundle.is_empty(), "cabundle must be non-empty");

        let pcr0 = self.pcrs.get(&0).expect("PCR0 must exist in pcrs map");
        assert!(pcr0.len() == 48, "PCR0 must be exactly 48 bytes, got {}", pcr0.len());

        assert!(
            !self.public_key.is_empty() && self.public_key.len() <= 1024,
            "public_key length must be in 1..=1024, got {}",
            self.public_key.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_cose_bytes(tag: bool, sig_len: usize) -> Vec<u8> {
        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(vec![0xA0]),
            ciborium::Value::Map(vec![]),
            ciborium::Value::Bytes(vec![0xBB]),
            ciborium::Value::Bytes(vec![0u8; sig_len]),
        ]);
        let value = if tag { ciborium::Value::Tag(18, Box::new(array)) } else { array };
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).unwrap();
        buf
    }

    #[test]
    fn test_cose_parse_with_tag() {
        let bytes = build_cose_bytes(true, 96);
        let cose = CoseSign1::parse(&bytes);
        assert_eq!(cose.signature.len(), 96);
        assert_eq!(cose.protected, vec![0xA0]);
        assert_eq!(cose.payload, vec![0xBB]);
    }

    #[test]
    fn test_cose_parse_without_tag() {
        let bytes = build_cose_bytes(false, 96);
        let cose = CoseSign1::parse(&bytes);
        assert_eq!(cose.signature.len(), 96);
    }

    #[test]
    #[should_panic(expected = "96 bytes")]
    fn test_cose_parse_wrong_sig_length() {
        let bytes = build_cose_bytes(false, 64);
        CoseSign1::parse(&bytes);
    }

    #[test]
    fn test_cose_sig_structure() {
        let cose = CoseSign1 {
            protected: vec![0x01, 0x02],
            payload: vec![0x03, 0x04],
            signature: vec![0u8; 96],
        };
        let sig_struct = cose.build_sig_structure();
        let decoded: ciborium::Value = ciborium::from_reader(sig_struct.as_slice()).unwrap();
        match decoded {
            ciborium::Value::Array(arr) => {
                assert_eq!(arr.len(), 4);
                assert_eq!(arr[0], ciborium::Value::Text("Signature1".to_string()));
                assert_eq!(arr[1], ciborium::Value::Bytes(vec![0x01, 0x02]));
                assert_eq!(arr[2], ciborium::Value::Bytes(vec![]));
                assert_eq!(arr[3], ciborium::Value::Bytes(vec![0x03, 0x04]));
            }
            _ => panic!("expected array"),
        }
    }

    fn build_attestation_doc_cbor(
        timestamp: u64,
        digest: &str,
        pcr0: Option<Vec<u8>>,
        pubkey_len: usize,
        cabundle_empty: bool,
    ) -> Vec<u8> {
        let mut entries = vec![
            (
                ciborium::Value::Text("timestamp".to_string()),
                ciborium::Value::Integer(ciborium::value::Integer::from(timestamp as i64)),
            ),
            (
                ciborium::Value::Text("digest".to_string()),
                ciborium::Value::Text(digest.to_string()),
            ),
            (
                ciborium::Value::Text("certificate".to_string()),
                ciborium::Value::Bytes(vec![0xDE, 0xAD]),
            ),
            (
                ciborium::Value::Text("public_key".to_string()),
                ciborium::Value::Bytes(vec![0x04; pubkey_len]),
            ),
        ];

        let mut pcr_map = vec![];
        if let Some(pcr0_data) = pcr0 {
            pcr_map.push((
                ciborium::Value::Integer(ciborium::value::Integer::from(0)),
                ciborium::Value::Bytes(pcr0_data),
            ));
        }
        entries.push((ciborium::Value::Text("pcrs".to_string()), ciborium::Value::Map(pcr_map)));

        if cabundle_empty {
            entries.push((
                ciborium::Value::Text("cabundle".to_string()),
                ciborium::Value::Array(vec![]),
            ));
        } else {
            entries.push((
                ciborium::Value::Text("cabundle".to_string()),
                ciborium::Value::Array(vec![ciborium::Value::Bytes(vec![0xCA])]),
            ));
        }

        let value = ciborium::Value::Map(entries);
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).unwrap();
        buf
    }

    #[test]
    fn test_attestation_doc_parse_and_validate_happy() {
        let cbor =
            build_attestation_doc_cbor(1700000000000, "SHA384", Some(vec![0u8; 48]), 65, false);
        let doc = AttestationDoc::parse(&cbor);
        doc.validate_content();
        assert_eq!(doc.timestamp, 1700000000000);
        assert_eq!(doc.digest, "SHA384");
    }

    #[test]
    #[should_panic(expected = "timestamp must be nonzero")]
    fn test_attestation_doc_validate_zero_timestamp() {
        let cbor = build_attestation_doc_cbor(0, "SHA384", Some(vec![0u8; 48]), 65, false);
        let doc = AttestationDoc::parse(&cbor);
        doc.validate_content();
    }

    #[test]
    #[should_panic(expected = "SHA384")]
    fn test_attestation_doc_validate_wrong_digest() {
        let cbor = build_attestation_doc_cbor(1000, "SHA256", Some(vec![0u8; 48]), 65, false);
        let doc = AttestationDoc::parse(&cbor);
        doc.validate_content();
    }

    #[test]
    #[should_panic(expected = "PCR0 must exist")]
    fn test_attestation_doc_validate_pcr0_missing() {
        let cbor = build_attestation_doc_cbor(1000, "SHA384", None, 65, false);
        let doc = AttestationDoc::parse(&cbor);
        doc.validate_content();
    }

    #[test]
    #[should_panic(expected = "PCR0 must be exactly 48 bytes")]
    fn test_attestation_doc_validate_pcr0_wrong_length() {
        let cbor = build_attestation_doc_cbor(1000, "SHA384", Some(vec![0u8; 32]), 65, false);
        let doc = AttestationDoc::parse(&cbor);
        doc.validate_content();
    }

    #[test]
    #[should_panic(expected = "public_key length must be in 1..=1024")]
    fn test_attestation_doc_validate_pubkey_empty() {
        let cbor = build_attestation_doc_cbor(1000, "SHA384", Some(vec![0u8; 48]), 0, false);
        let doc = AttestationDoc::parse(&cbor);
        doc.validate_content();
    }

    #[test]
    #[should_panic(expected = "cabundle must be non-empty")]
    fn test_attestation_doc_validate_cabundle_empty() {
        let cbor = build_attestation_doc_cbor(1000, "SHA384", Some(vec![0u8; 48]), 65, true);
        let doc = AttestationDoc::parse(&cbor);
        doc.validate_content();
    }
}
