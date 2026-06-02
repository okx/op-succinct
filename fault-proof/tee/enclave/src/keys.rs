use alloy_primitives::Address;
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use std::sync::OnceLock;

static ENCLAVE_KEY: OnceLock<SigningKey> = OnceLock::new();

#[cfg(any(not(target_os = "linux"), not(feature = "vsock"), test))]
const DEV_KEY_HEX: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[cfg(not(all(target_os = "linux", feature = "vsock")))]
pub fn init_dev_keys() {
    let key_bytes = hex::decode(DEV_KEY_HEX).expect("invalid dev key hex");
    let signing_key = SigningKey::from_slice(&key_bytes).expect("invalid dev signing key");
    ENCLAVE_KEY.get_or_init(|| signing_key);
}

#[cfg(all(target_os = "linux", feature = "vsock"))]
pub fn init_dev_keys() {
    use k256::elliptic_curve::rand_core::OsRng;
    let signing_key = SigningKey::random(&mut OsRng);
    ENCLAVE_KEY.get_or_init(|| signing_key);
}

pub fn enclave_signing_key() -> &'static SigningKey {
    ENCLAVE_KEY.get().expect("ENCLAVE_KEY not initialized")
}

pub fn enclave_pubkey_uncompressed() -> [u8; 65] {
    use k256::ecdsa::VerifyingKey;
    let verifying_key = VerifyingKey::from(enclave_signing_key());
    let encoded = verifying_key.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    let mut out = [0u8; 65];
    out.copy_from_slice(bytes);
    out
}

pub fn enclave_address() -> Address {
    let pubkey = enclave_pubkey_uncompressed();
    let hash = Keccak256::digest(&pubkey[1..]);
    Address::from_slice(&hash[12..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_key_initialized() {
        #[cfg(not(all(target_os = "linux", feature = "vsock")))]
        init_dev_keys();
    }

    #[test]
    fn dev_key_initializes_deterministically() {
        ensure_key_initialized();
        let key = enclave_signing_key();
        let key_bytes = key.to_bytes();
        let expected = hex::decode(DEV_KEY_HEX).unwrap();
        assert_eq!(&key_bytes[..], expected.as_slice());
    }

    #[test]
    fn pubkey_is_65_bytes_uncompressed() {
        ensure_key_initialized();
        let pubkey = enclave_pubkey_uncompressed();
        assert_eq!(pubkey.len(), 65);
        assert_eq!(pubkey[0], 0x04, "uncompressed SEC1 prefix");
    }

    #[test]
    fn address_is_20_bytes_from_pubkey_hash() {
        ensure_key_initialized();
        let addr = enclave_address();
        assert_eq!(addr.as_slice().len(), 20);
        // Anvil #0 expected address
        let expected = hex::decode("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
            .unwrap_or_else(|_| hex::decode("f39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap());
        assert_eq!(addr.as_slice(), expected.as_slice(), "dev key should produce Anvil #0 address");
    }
}
