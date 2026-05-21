use alloy_primitives::{Address, B256};
use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};

use crate::boot::BootInfoStruct;

/// How an individual range was proven. The aggregation program dispatches
/// per-range on this enum: `Sp1` keeps the existing `verify_sp1_proof`
/// recursion path; `Tee` triggers in-zkVM EIP712 ecrecover against a
/// hardcoded approved-enclaves set.
///
/// `range_proofs[i]` corresponds to `boot_infos[i]` (parallel vectors).
///
/// The wire-level signature here mirrors `xlayer-tee-types::RangeJournalWire`
/// (signed inside the enclave) — only `signature` and `pcr0` are explicitly
/// transported; the other five `RangeJournal` fields are reconstructed from
/// the parallel `BootInfoStruct` since they're identical by design.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RangeProof {
    /// SP1 ZK proof of the range program. The proof itself is loaded into
    /// SP1 SDK's recursion buffer out-of-band; the zkVM just asserts a proof
    /// matching the boot info digest exists.
    Sp1,
    /// TEE-signed range journal. `signature` is the 65-byte secp256k1
    /// ECDSA signature (r ‖ s ‖ v, v in {27, 28}) over the EIP712 digest of
    /// the `RangeJournal { pcr0, configHash, l1OriginHash, l2BlockNumber,
    /// prevOutputRoot, outputRoot }` struct.
    Tee {
        /// `keccak256(NSM PCR0)` — the enclave's image hash as committed in
        /// the signed journal. The aggregation program checks the
        /// `(pcr0, recovered_signer)` pair against its hardcoded approved
        /// enclaves set.
        pcr0: B256,
        /// 65-byte secp256k1 ECDSA signature (r ‖ s ‖ v, v in {27, 28}).
        /// Stored as `Vec<u8>` for serde compatibility — the aggregation
        /// program asserts `.len() == 65` before consuming.
        signature: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationInputs {
    pub boot_infos: Vec<BootInfoStruct>,
    /// One entry per `boot_infos`. Index-aligned. SP1-only deployments pass
    /// `vec![RangeProof::Sp1; boot_infos.len()]` to keep the legacy behavior.
    pub range_proofs: Vec<RangeProof>,
    pub latest_l1_checkpoint_head: B256,
    pub multi_block_vkey: [u32; 8],
    pub prover_address: Address,
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
