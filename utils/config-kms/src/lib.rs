//! Startup-time secret resolution for a fixed set of sensitive config items.
//!
//! Each protected item may be supplied either as a plaintext value (unchanged
//! behavior) or as a strict lowercase `kms:<key>` reference. When a reference is
//! present, its plaintext is resolved once at process startup through a mockable
//! [`KmsSecretProvider`] boundary and written back into the environment, so all
//! existing read sites transparently observe plaintext. Any resolution problem is
//! fail-closed: the resolver returns an error and the process must refuse to start.
//!
//! Diagnostics carry only the config-item name and a fixed error class — never the
//! raw value, the reference, the key, the plaintext, or backend error text.

mod classify;
mod error;
mod provider;
mod resolve;

pub use error::KmsConfigError;
pub use provider::{init_provider, KmsProviderError, KmsSecretProvider, OkKmsProvider};
pub use resolve::resolve_protected_config_env;

/// The exhaustive, hard-coded set of protected config item names, in the fixed
/// order they are processed. No item outside this set is ever inspected.
pub const PROTECTED_KEYS: [&str; 6] = [
    "NETWORK_PRIVATE_KEY",
    "XLAYER_ACCESS_KEY",
    "XLAYER_SECRET_KEY",
    "SP1_GATEWAY_TOKEN",
    "SP1_GATEWAY_S3_TOKEN",
    "CLI_REDIS_NODES",
];
