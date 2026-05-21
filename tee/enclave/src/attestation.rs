//! Nitro NSM attestation.
//!
//! - **Default (dev)**: validates inputs and returns a hardcoded placeholder
//!   COSE byte string. This is **not** a real Nitro attestation; the host
//!   side will recognize the dev marker and skip CA-chain verification.
//! - **`vsock` feature**: calls `aws_nitro_enclaves_nsm_api` directly
//!   (`nsm_init → Request::Attestation → nsm_exit`) and returns the raw
//!   `COSE_Sign1` document bytes. Matches the pattern used by
//!   `tradezone/bin/enclave/lib.rs` (see design doc §4.2.7.4).

#[cfg(not(all(target_os = "linux", feature = "vsock")))]
mod dev {
    use crate::{error::{Error, Result}, keys::enclave_pubkey_uncompressed};

    /// Marker bytes prepended to the placeholder attestation document so the
    /// host side can distinguish dev attestations from real Nitro `COSE_Sign1`.
    /// Real Nitro docs begin with CBOR major type 6 tag (0xd2 0x84). We pick
    /// a clearly synthetic prefix instead.
    pub const DEV_ATTESTATION_MARKER: &[u8] = b"\xffXLAYER-DEV-ATTESTATION-V1\xff";

    /// Validate inputs and return a placeholder attestation document.
    ///
    /// Validation:
    /// - `pub_key` must equal the enclave's current uncompressed pubkey
    ///   (defends against the host querying after pubkey rotation).
    /// - `nonce` must be empty in dev (we do not roll the nonce).
    /// - `user_data` is opaque; we accept anything and echo it back inside
    ///   the returned doc so the host can correlate the request.
    pub fn generate_attestation_doc(
        user_data: &[u8],
        nonce: &[u8],
        pub_key: &[u8],
    ) -> Result<Vec<u8>> {
        if !nonce.is_empty() {
            return Err(Error::InvalidAttestationRequest("nonce must be empty in dev mode"));
        }
        let expected_pubkey = enclave_pubkey_uncompressed();
        if pub_key != expected_pubkey.as_slice() {
            return Err(Error::InvalidAttestationRequest(
                "pub_key does not match enclave's current key",
            ));
        }

        // Layout: marker || user_data_len(u16 BE) || user_data || pubkey(65).
        // Host-side dev verifier just checks the marker and extracts pubkey.
        let mut out = Vec::with_capacity(
            DEV_ATTESTATION_MARKER.len() + 2 + user_data.len() + expected_pubkey.len(),
        );
        out.extend_from_slice(DEV_ATTESTATION_MARKER);
        let len_be = (user_data.len() as u16).to_be_bytes();
        out.extend_from_slice(&len_be);
        out.extend_from_slice(user_data);
        out.extend_from_slice(&expected_pubkey);
        Ok(out)
    }
}

#[cfg(not(all(target_os = "linux", feature = "vsock")))]
pub use dev::{DEV_ATTESTATION_MARKER, generate_attestation_doc};

#[cfg(all(target_os = "linux", feature = "vsock"))]
mod prod {
    use aws_nitro_enclaves_nsm_api::api::{Request as NsmRequest, Response as NsmResponse};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
    use serde_bytes::ByteBuf;

    use crate::error::{Error, Result};

    /// Call NSM to produce a real `COSE_Sign1` attestation document binding
    /// `pub_key` (and optionally `user_data`/`nonce`) to PCR0. Returns the
    /// raw document bytes — the same form the host expects per the
    /// `application/octet-stream` contract on `GET /attestation`.
    pub fn generate_attestation_doc(
        user_data: &[u8],
        nonce: &[u8],
        pub_key: &[u8],
    ) -> Result<Vec<u8>> {
        let fd = nsm_init();
        if fd < 0 {
            return Err(Error::Internal("failed to initialize NSM driver".into()));
        }

        let request = NsmRequest::Attestation {
            user_data: (!user_data.is_empty()).then(|| ByteBuf::from(user_data.to_vec())),
            nonce: (!nonce.is_empty()).then(|| ByteBuf::from(nonce.to_vec())),
            public_key: (!pub_key.is_empty()).then(|| ByteBuf::from(pub_key.to_vec())),
        };

        let response = nsm_process_request(fd, request);
        nsm_exit(fd);

        match response {
            NsmResponse::Attestation { document } => Ok(document),
            NsmResponse::Error(err) => {
                Err(Error::Internal(format!("NSM attestation error: {err:?}")))
            }
            other => Err(Error::Internal(format!(
                "unexpected NSM response: {other:?}"
            ))),
        }
    }

    /// Read PCR0 from NSM. NSM returns the raw SHA-384 measurement (48 bytes).
    ///
    /// The on-chain `approvedEnclaves` schema stores PCR0 as `bytes32`, so the
    /// caller (`main.rs`) compresses this to 32 bytes; see the call site for
    /// the chosen compression and the open question for the contract team.
    pub fn read_pcr0() -> Result<Vec<u8>> {
        let fd = nsm_init();
        if fd < 0 {
            return Err(Error::Internal("failed to initialize NSM driver".into()));
        }

        let response = nsm_process_request(fd, NsmRequest::DescribePCR { index: 0 });
        nsm_exit(fd);

        match response {
            NsmResponse::DescribePCR { data, .. } => Ok(data),
            NsmResponse::Error(err) => {
                Err(Error::Internal(format!("NSM DescribePCR error: {err:?}")))
            }
            other => Err(Error::Internal(format!(
                "unexpected NSM response: {other:?}"
            ))),
        }
    }
}

#[cfg(all(target_os = "linux", feature = "vsock"))]
pub use prod::{generate_attestation_doc, read_pcr0};

#[cfg(all(test, not(all(target_os = "linux", feature = "vsock"))))]
mod tests {
    use super::*;

    use crate::keys::{enclave_pubkey_uncompressed, init_dev_keys};

    #[test]
    fn rejects_non_empty_nonce() {
        init_dev_keys();
        let pubkey = enclave_pubkey_uncompressed();
        let err = generate_attestation_doc(b"hi", b"some-nonce", &pubkey).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::InvalidAttestationRequest(_)
        ));
    }

    #[test]
    fn rejects_pubkey_mismatch() {
        init_dev_keys();
        let bad = [0xaau8; 65];
        let err = generate_attestation_doc(b"hi", b"", &bad).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::InvalidAttestationRequest(_)
        ));
    }

    #[test]
    fn happy_path_returns_marker_prefixed_doc() {
        init_dev_keys();
        let pubkey = enclave_pubkey_uncompressed();
        let doc = generate_attestation_doc(b"hello", b"", &pubkey).expect("ok");
        assert!(doc.starts_with(DEV_ATTESTATION_MARKER));
        // Tail of doc embeds the pubkey for host-side extraction.
        assert!(doc.ends_with(&pubkey));
    }
}
