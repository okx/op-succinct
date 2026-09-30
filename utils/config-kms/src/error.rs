//! Normalized error taxonomy for startup config-secret resolution.
//!
//! Redaction invariant: an error's `Display` (and therefore any log built from it)
//! carries only the config-item name and a fixed error-class string. It never
//! contains the raw config value, the reference, the secret key, the resolved
//! plaintext, or the underlying provider/SDK error text.

use std::fmt;

/// The set of ways startup config-secret resolution can fail.
///
/// Item-specific variants carry the offending config item's name (a static
/// string from the protected set). Process-level variants carry no item because
/// they are not tied to a single item.
#[derive(Debug)]
pub enum KmsConfigError {
    /// The value used the reference prefix but the key part was empty.
    InvalidReferenceFormat { item: &'static str },
    /// Fetching the secret for a syntactically valid reference failed.
    SecretFetchError { item: &'static str },
    /// The referenced secret key does not exist.
    SecretNotFound { item: &'static str },
    /// The provider returned an empty value for the reference.
    EmptySecretValue { item: &'static str },
    /// The secret backend could not be initialized (missing/invalid runtime
    /// configuration or backend access). Not tied to a single item.
    KmsInitError,
    /// The current platform is outside the supported set. Not tied to a single item.
    UnsupportedPlatform,
}

impl KmsConfigError {
    /// The fixed, non-sensitive class label for this error.
    fn class(&self) -> &'static str {
        match self {
            KmsConfigError::InvalidReferenceFormat { .. } => "invalid reference format",
            KmsConfigError::SecretFetchError { .. } => "secret fetch error",
            KmsConfigError::SecretNotFound { .. } => "secret not found",
            KmsConfigError::EmptySecretValue { .. } => "empty secret value",
            KmsConfigError::KmsInitError => "initialization error",
            KmsConfigError::UnsupportedPlatform => "unsupported platform",
        }
    }

    /// The config item this error refers to, if it is item-specific.
    fn item(&self) -> Option<&'static str> {
        match self {
            KmsConfigError::InvalidReferenceFormat { item } |
            KmsConfigError::SecretFetchError { item } |
            KmsConfigError::SecretNotFound { item } |
            KmsConfigError::EmptySecretValue { item } => Some(item),
            KmsConfigError::KmsInitError | KmsConfigError::UnsupportedPlatform => None,
        }
    }
}

impl fmt::Display for KmsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only the item name (when applicable) and the fixed class ever appear.
        match self.item() {
            Some(item) => write!(f, "config secret error for {item}: {}", self.class()),
            None => write!(f, "config secret error: {}", self.class()),
        }
    }
}

impl std::error::Error for KmsConfigError {}
