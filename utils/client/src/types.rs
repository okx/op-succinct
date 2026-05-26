use alloy_primitives::{Address, B256};
use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};

use crate::boot::BootInfoStruct;

/// How an individual range was proven.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RangeProof {
    /// SP1 ZK proof of the range program.
    Sp1,
    /// TEE-signed range journal. 65-byte secp256k1 ECDSA signature `r ‖ s ‖ v`
    /// (v ∈ {27, 28}) over `keccak256` of the packed [`RangeJournal`] bytes
    /// (defined in `xlayer-tee-types::journal`).
    Tee {
        signature: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationInputs {
    pub boot_infos: Vec<BootInfoStruct>,
    /// Index-aligned with `boot_infos`.
    pub range_proofs: Vec<RangeProof>,
    pub latest_l1_checkpoint_head: B256,
    pub multi_block_vkey: [u32; 8],
    pub prover_address: Address,
    /// L2 chain id mixed into every TEE leaf's signed digest. Ignored on
    /// pure-SP1 aggregations.
    pub tee_chain_id: u64,
}

sol! {
    #[derive(Debug, Serialize, Deserialize)]
    struct AggregationOutputs {
        bytes32 l1Head;
        bytes32 l2PreRoot;
        bytes32 l2PostRoot;
        uint64 l2BlockNumber;
        bytes32 rollupConfigHash;
        bytes32 multiBlockVKey;
        address proverAddress;
    }
}

/// Convert a u32 array to a u8 array. Useful for converting the range vkey to a B256.
pub fn u32_to_u8(input: [u32; 8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for (i, &value) in input.iter().enumerate() {
        let bytes = value.to_be_bytes();
        output[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }
    output
}
