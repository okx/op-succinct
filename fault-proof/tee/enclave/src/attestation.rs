use crate::error::Error;

pub const DEV_ATTESTATION_MARKER: &[u8] = b"\xffXLAYER-DEV-ATTESTATION-V1\xff";

#[cfg(not(all(target_os = "linux", feature = "vsock")))]
pub fn generate_attestation_doc(
    user_data: &[u8],
    nonce: &[u8],
    pub_key: &[u8],
) -> Result<Vec<u8>, Error> {
    use crate::keys::enclave_pubkey_uncompressed;
    if !nonce.is_empty() {
        return Err(Error::InvalidAttestationRequest("dev attestation requires empty nonce".into()));
    }

    let expected_pubkey = enclave_pubkey_uncompressed();
    if pub_key != expected_pubkey {
        return Err(Error::InvalidAttestationRequest(
            "pub_key does not match current enclave key".into(),
        ));
    }

    let user_data_len = user_data.len() as u16;
    let mut doc = Vec::with_capacity(DEV_ATTESTATION_MARKER.len() + 2 + user_data.len() + 65);
    doc.extend_from_slice(DEV_ATTESTATION_MARKER);
    doc.extend_from_slice(&user_data_len.to_be_bytes());
    doc.extend_from_slice(user_data);
    doc.extend_from_slice(&expected_pubkey);
    Ok(doc)
}

#[cfg(all(target_os = "linux", feature = "vsock"))]
pub fn generate_attestation_doc(
    user_data: &[u8],
    nonce: &[u8],
    pub_key: &[u8],
) -> Result<Vec<u8>, Error> {
    use aws_nitro_enclaves_nsm_api::{
        api::{Request, Response},
        driver,
    };

    let nsm_fd = driver::nsm_init();
    let request = Request::Attestation {
        user_data: if user_data.is_empty() {
            None
        } else {
            Some(serde_bytes::ByteBuf::from(user_data.to_vec()))
        },
        nonce: if nonce.is_empty() {
            None
        } else {
            Some(serde_bytes::ByteBuf::from(nonce.to_vec()))
        },
        public_key: if pub_key.is_empty() {
            None
        } else {
            Some(serde_bytes::ByteBuf::from(pub_key.to_vec()))
        },
    };

    let response = driver::nsm_process_request(nsm_fd, request);
    match response {
        Response::Attestation { document } => Ok(document),
        _ => Err(Error::Internal(anyhow::anyhow!("unexpected NSM response for attestation"))),
    }
}

#[cfg(all(target_os = "linux", feature = "vsock"))]
pub fn read_pcr0() -> Result<Vec<u8>, Error> {
    use aws_nitro_enclaves_nsm_api::{
        api::{Request, Response},
        driver,
    };

    let nsm_fd = driver::nsm_init();
    let request = Request::DescribePCR { index: 0 };
    let response = driver::nsm_process_request(nsm_fd, request);
    match response {
        Response::DescribePCR { lock: _, data } => Ok(data),
        _ => Err(Error::Internal(anyhow::anyhow!("unexpected NSM response for PCR0"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{enclave_pubkey_uncompressed, init_dev_keys};

    fn ensure_key_initialized() {
        init_dev_keys();
    }

    #[test]
    fn dev_attestation_with_valid_params() {
        ensure_key_initialized();
        let pubkey = enclave_pubkey_uncompressed();
        let user_data = b"test user data";

        let doc = generate_attestation_doc(user_data, &[], &pubkey).unwrap();

        assert!(doc.starts_with(DEV_ATTESTATION_MARKER), "should start with dev marker");

        let offset = DEV_ATTESTATION_MARKER.len();
        let user_data_len = u16::from_be_bytes([doc[offset], doc[offset + 1]]) as usize;
        assert_eq!(user_data_len, user_data.len());

        let ud_start = offset + 2;
        assert_eq!(&doc[ud_start..ud_start + user_data_len], user_data);

        let pk_start = ud_start + user_data_len;
        assert_eq!(&doc[pk_start..pk_start + 65], &pubkey[..]);
        assert_eq!(doc.len(), pk_start + 65);
    }

    #[test]
    fn dev_attestation_rejects_nonempty_nonce() {
        ensure_key_initialized();
        let pubkey = enclave_pubkey_uncompressed();

        let result = generate_attestation_doc(b"data", b"some-nonce", &pubkey);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, Error::InvalidAttestationRequest(_)),
            "expected InvalidAttestationRequest, got: {err}"
        );
    }

    #[test]
    fn dev_attestation_rejects_wrong_pubkey() {
        ensure_key_initialized();
        let wrong_key = [0xAA; 65];

        let result = generate_attestation_doc(b"data", &[], &wrong_key);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, Error::InvalidAttestationRequest(_)),
            "expected InvalidAttestationRequest, got: {err}"
        );
    }

    #[test]
    fn dev_attestation_empty_user_data() {
        ensure_key_initialized();
        let pubkey = enclave_pubkey_uncompressed();

        let doc = generate_attestation_doc(&[], &[], &pubkey).unwrap();
        assert!(doc.starts_with(DEV_ATTESTATION_MARKER));

        let offset = DEV_ATTESTATION_MARKER.len();
        let user_data_len = u16::from_be_bytes([doc[offset], doc[offset + 1]]);
        assert_eq!(user_data_len, 0);
    }
}
