//! In-tree stub of the OKG-internal `ok-kms-rust` SDK.
//!
//! The stub mirrors exactly the public surface `op-succinct-signer-utils`
//! compiles against so a workspace path dependency substitutes for the real
//! SDK without touching the committed manifest. `KmsClient::new` succeeds so
//! init paths stay exercised, but every secret lookup fails carrying
//! `STUB_MARKER` — a binary accidentally built `--features kms` against the
//! stub fails loudly on first use instead of authenticating with a bogus
//! credential. Swap for the real SDK with `just kms-crate`.

/// Marker embedded in every stub lookup error and thus in a stub-linked
/// binary's read-only data. `grep -ac OK_KMS_STUB <binary>` is > 0 for a
/// stub-linked build and 0 for a real-SDK build.
pub const STUB_MARKER: &str = "OK_KMS_STUB";

/// Mirrors the real SDK's error type surface that the signer references.
#[derive(Debug)]
pub enum KmsError {
    /// The SDK reported KMS disabled at client construction.
    Disabled,
    /// Stub-specific: any lookup against the stub. Carries `STUB_MARKER`.
    Stub(String),
}

impl std::fmt::Display for KmsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KmsError::Disabled => write!(f, "ok-kms-rust stub: KMS disabled"),
            KmsError::Stub(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for KmsError {}

/// Mirrors the real `ok-kms-rust` client surface used by the signer.
pub struct KmsClient;

impl KmsClient {
    /// Infallible construction so callers' init paths stay exercised.
    pub fn new() -> Result<KmsClient, KmsError> {
        Ok(KmsClient)
    }

    /// Always fails, embedding `STUB_MARKER` so a stub-linked `--features kms`
    /// binary fails loudly on first use.
    pub fn get_all_secrets(&self) -> Result<String, KmsError> {
        Err(KmsError::Stub(format!(
            "{STUB_MARKER}: built against the in-tree ok-kms-rust stub; run \
             `just kms-crate` with a real SDK checkout for production KMS resolution"
        )))
    }
}
