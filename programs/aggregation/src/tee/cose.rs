use ciborium::Value as CborValue;

pub struct CoseSign1 {
    pub protected: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl CoseSign1 {
    /// Parse COSE_Sign1 structure. Accepts both CBOR Tag(18, Array) and plain Array forms.
    pub fn parse(data: &[u8]) -> Self {
        let value: CborValue =
            ciborium::from_reader(data).expect("COSE_Sign1: invalid CBOR encoding");

        let array = match value {
            CborValue::Tag(18, inner) => match *inner {
                CborValue::Array(arr) => arr,
                _ => panic!("COSE_Sign1: Tag(18) must wrap an array"),
            },
            CborValue::Array(arr) => arr,
            _ => panic!("COSE_Sign1: expected Tag(18, Array) or plain Array"),
        };

        assert!(array.len() == 4, "COSE_Sign1 must be exactly 4-element array");

        let protected = match &array[0] {
            CborValue::Bytes(b) => b.clone(),
            _ => panic!("COSE_Sign1: protected must be bstr"),
        };

        let payload = match &array[2] {
            CborValue::Bytes(b) => b.clone(),
            _ => panic!("COSE_Sign1: payload must be bstr"),
        };

        let signature = match &array[3] {
            CborValue::Bytes(b) => b.clone(),
            _ => panic!("COSE_Sign1: signature must be bstr"),
        };

        assert!(
            signature.len() == 96,
            "COSE_Sign1: signature must be 96 bytes (raw ES384), got {}",
            signature.len()
        );

        CoseSign1 { protected, payload, signature }
    }

    /// Construct Sig_structure1 per RFC 8152 section 4.4:
    /// ["Signature1", body_protected, empty_aad, payload] as CBOR-encoded bytes.
    pub fn sig_structure(&self) -> Vec<u8> {
        let structure = CborValue::Array(vec![
            CborValue::Text("Signature1".to_string()),
            CborValue::Bytes(self.protected.clone()),
            CborValue::Bytes(vec![]),
            CborValue::Bytes(self.payload.clone()),
        ]);

        let mut buf = Vec::new();
        ciborium::into_writer(&structure, &mut buf).expect("failed to serialize Sig_structure1");
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_cose_array(protected: &[u8], payload: &[u8], sig_len: usize) -> Vec<u8> {
        let arr = CborValue::Array(vec![
            CborValue::Bytes(protected.to_vec()),
            CborValue::Map(vec![]),
            CborValue::Bytes(payload.to_vec()),
            CborValue::Bytes(vec![0u8; sig_len]),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&arr, &mut buf).unwrap();
        buf
    }

    fn build_cose_tagged(protected: &[u8], payload: &[u8], sig_len: usize) -> Vec<u8> {
        let arr = CborValue::Array(vec![
            CborValue::Bytes(protected.to_vec()),
            CborValue::Map(vec![]),
            CborValue::Bytes(payload.to_vec()),
            CborValue::Bytes(vec![0u8; sig_len]),
        ]);
        let tagged = CborValue::Tag(18, Box::new(arr));
        let mut buf = Vec::new();
        ciborium::into_writer(&tagged, &mut buf).unwrap();
        buf
    }

    #[test]
    fn test_parse_cose_with_tag18() {
        let protected = b"test_protected";
        let payload = b"test_payload";
        let data = build_cose_tagged(protected, payload, 96);

        let cose = CoseSign1::parse(&data);
        assert_eq!(cose.protected, protected);
        assert_eq!(cose.payload, payload);
        assert_eq!(cose.signature.len(), 96);
    }

    #[test]
    fn test_parse_cose_without_tag() {
        let protected = b"test_protected";
        let payload = b"test_payload";
        let data = build_cose_array(protected, payload, 96);

        let cose = CoseSign1::parse(&data);
        assert_eq!(cose.protected, protected);
        assert_eq!(cose.payload, payload);
        assert_eq!(cose.signature.len(), 96);
    }

    #[test]
    #[should_panic(expected = "signature must be 96 bytes")]
    fn test_parse_cose_rejects_non_96_signature() {
        let data = build_cose_array(b"p", b"pl", 70);
        CoseSign1::parse(&data);
    }

    #[test]
    #[should_panic(expected = "4-element array")]
    fn test_parse_cose_rejects_3_element_array() {
        let arr = CborValue::Array(vec![
            CborValue::Bytes(b"p".to_vec()),
            CborValue::Map(vec![]),
            CborValue::Bytes(b"pl".to_vec()),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&arr, &mut buf).unwrap();
        CoseSign1::parse(&buf);
    }

    #[test]
    fn test_sig_structure_format() {
        let cose = CoseSign1 {
            protected: b"P".to_vec(),
            payload: b"PL".to_vec(),
            signature: vec![0u8; 96],
        };

        let result = cose.sig_structure();
        let decoded: CborValue = ciborium::from_reader(result.as_slice()).unwrap();

        match decoded {
            CborValue::Array(arr) => {
                assert_eq!(arr.len(), 4);
                assert_eq!(arr[0], CborValue::Text("Signature1".to_string()));
                assert_eq!(arr[1], CborValue::Bytes(b"P".to_vec()));
                assert_eq!(arr[2], CborValue::Bytes(vec![]));
                assert_eq!(arr[3], CborValue::Bytes(b"PL".to_vec()));
            }
            _ => panic!("expected array"),
        }
    }
}
