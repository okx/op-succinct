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

mod error;
mod provider;

pub use error::KmsConfigError;
pub use provider::{init_provider, KmsProviderError, KmsSecretProvider, OkKmsProvider};
