//! ENCLAVE_KEY management.
//!
//! Two modes selected at compile time:
//! - **Default (dev)**: hardcoded `DEV_KEY_HEX` is loaded into `ENCLAVE_KEY`
//!   at startup. Predictable, no NSM required, suitable for unit tests and
//!   local smoke tests.
//! - **`vsock` feature (production, linux only)**: fresh per-instance key
//!   generated via `k256::SecretKey::random(&mut rand::rngs::OsRng)`. Inside
//!   a Nitro Enclave the Linux kernel CSPRNG (`/dev/urandom`) is seeded from
//!   NSM hardware entropy, so `OsRng` here is effectively NSM-backed without
//!   needing a separate `NsmRng` wrapper.
//!
//! The dev key is intentionally checked into source — anyone reading this
//! repository can sign as the dev enclave, which is the whole point of dev
//! mode. **Do not enable production deployment paths from a default build.**

use std::sync::OnceLock;

use alloy_primitives::{Address, keccak256};
use k256::ecdsa::SigningKey;

/// Hardcoded 32-byte secp256k1 secret key for dev builds (hex without `0x`).
///
/// ⚠️ Public test key — Anvil account #0. Only loaded by builds without
/// `--features vsock`. Never ship a default build to production.
pub const DEV_KEY_HEX: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Length in bytes of an uncompressed SEC1 secp256k1 public key
/// (`0x04 || X(32) || Y(32)`).
pub const UNCOMPRESSED_PUBKEY_LEN: usize = 65;

/// The enclave's signing key, initialized exactly once at startup.
static ENCLAVE_KEY: OnceLock<SigningKey> = OnceLock::new();

/// Initialize the enclave signing key from the hardcoded dev value.
///
/// Idempotent: subsequent calls are no-ops.
#[cfg(not(all(target_os = "linux", feature = "vsock")))]
pub fn init_dev_keys() {
    let _ = ENCLAVE_KEY.get_or_init(|| {
        let bytes =
            hex::decode(DEV_KEY_HEX).expect("DEV_KEY_HEX is a compile-time constant — must decode");
        SigningKey::from_slice(&bytes).expect("DEV_KEY_HEX must be a valid 32-byte secp256k1 key")
    });
}

/// Initialize the enclave signing key from `OsRng` (NSM-seeded inside the
/// Nitro VM). Idempotent: subsequent calls are no-ops.
#[cfg(all(target_os = "linux", feature = "vsock"))]
pub fn init_dev_keys() {
    let _ = ENCLAVE_KEY.get_or_init(|| {
        let secret = k256::SecretKey::random(&mut rand::rngs::OsRng);
        SigningKey::from(secret)
    });
}

/// Borrow the enclave signing key. Panics if `init_dev_keys()` (or its
/// vsock equivalent) has not been called yet.
pub fn enclave_signing_key() -> &'static SigningKey {
    ENCLAVE_KEY.get().expect("ENCLAVE_KEY uninitialized — call init_dev_keys() first")
}

/// Return the enclave's uncompressed SEC1 public key (`0x04 || X || Y`, 65 bytes).
pub fn enclave_pubkey_uncompressed() -> [u8; UNCOMPRESSED_PUBKEY_LEN] {
    let verifying_key = enclave_signing_key().verifying_key();
    let encoded = verifying_key.to_encoded_point(false /* compressed = false */);
    let bytes = encoded.as_bytes();
    assert_eq!(bytes.len(), UNCOMPRESSED_PUBKEY_LEN, "k256 uncompressed encoding must be 65 bytes");
    let mut out = [0u8; UNCOMPRESSED_PUBKEY_LEN];
    out.copy_from_slice(bytes);
    out
}

/// Return the enclave's Ethereum address — `keccak256(pubkey[1..])[12..]`.
pub fn enclave_address() -> Address {
    let pubkey = enclave_pubkey_uncompressed();
    // Skip the 0x04 SEC1 prefix; hash the X || Y bytes.
    let hash = keccak256(&pubkey[1..]);
    Address::from_slice(&hash[12..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_key_hex_decodes() {
        let bytes = hex::decode(DEV_KEY_HEX).expect("hex decodes");
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn init_is_idempotent() {
        init_dev_keys();
        init_dev_keys();
        let addr1 = enclave_address();
        init_dev_keys();
        let addr2 = enclave_address();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn pubkey_is_65_bytes_uncompressed_sec1() {
        init_dev_keys();
        let pubkey = enclave_pubkey_uncompressed();
        assert_eq!(pubkey.len(), UNCOMPRESSED_PUBKEY_LEN);
        assert_eq!(pubkey[0], 0x04, "SEC1 uncompressed prefix");
    }

    #[test]
    fn address_matches_known_dev_key() {
        // DEV_KEY_HEX above is the Anvil account #0 secret key:
        //   0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
        // Its derived address is 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
        init_dev_keys();
        let expected: Address =
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".parse().expect("known address");
        assert_eq!(enclave_address(), expected);
    }
}
