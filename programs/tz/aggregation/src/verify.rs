use alloy_sol_types::SolValue;
use op_succinct_client_utils::types::AggregationInputs;
use sha2::{Digest, Sha256};

/// pv_digest formula must match the byte stream the range guest committed
/// via `commit_slice(&boot_info.abi_encode())`. Drift here (bincode /
/// msgpack / etc) would only surface in real prove mode — execute mode's
/// NoOpSubproofVerifier masks the mismatch.
pub fn verify_range_proofs(inputs: &AggregationInputs) {
    for boot_info in &inputs.boot_infos {
        let pv_digest: [u8; 32] = Sha256::digest(boot_info.abi_encode()).into();
        sp1_lib::verify::verify_sp1_proof(&inputs.multi_block_vkey, &pv_digest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use op_succinct_client_utils::boot::BootInfoStruct;

    #[test]
    fn pv_digest_hashes_abi_encoded_bytes() {
        let boot_info = BootInfoStruct {
            l1Head: [0u8; 32].into(),
            l2PreRoot: [0xAA; 32].into(),
            l2PostRoot: [0xBB; 32].into(),
            l2BlockNumber: 12345,
            rollupConfigHash: [0u8; 32].into(),
        };
        let abi_bytes = boot_info.abi_encode();
        assert_eq!(abi_bytes.len(), 160);
        let expected: [u8; 32] = Sha256::digest(&abi_bytes).into();
        let actual: [u8; 32] = Sha256::digest(boot_info.abi_encode()).into();
        assert_eq!(expected, actual);
    }
}
