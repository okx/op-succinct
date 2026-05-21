//! Build a synthetic [`Witness`] (= `DefaultWitnessData`) from a hand-crafted
//! [`BootInfo`] by writing the 7 `Local` `PreimageKey` entries that
//! `kona_proof::BootInfo::load` expects.
//!
//! Production witnesses also carry global preimages (state trie nodes /
//! receipts / blob); this fixture omits them, which is enough to exercise
//! the wire and error paths but causes kona derivation to fail at
//! `get_inputs_for_pipeline`.

use alloy_primitives::U256;
use kona_genesis::{L1ChainConfig, RollupConfig};
use kona_preimage::PreimageKey;
use kona_proof::{
    BootInfo,
    boot::{
        L1_CONFIG_KEY, L1_HEAD_KEY, L2_CHAIN_ID_KEY, L2_CLAIM_BLOCK_NUMBER_KEY, L2_CLAIM_KEY,
        L2_OUTPUT_ROOT_KEY, L2_ROLLUP_CONFIG_KEY,
    },
};
use op_succinct_client_utils::witness::{
    BlobData, DefaultWitnessData as Witness, preimage_store::PreimageStore,
};

/// Build a synthetic [`Witness`] whose `preimage_store` contains the Local
/// keys for the given `BootInfo`. `blob_data` is empty.
///
/// Important: we deliberately use a `chain_id` that is **not** present in
/// `kona_registry::ROLLUP_CONFIGS` so that `BootInfo::load` falls through to
/// the oracle (`L2_ROLLUP_CONFIG_KEY`) and round-trips our supplied
/// `rollup_config`. Same for `l1_config`.
pub fn synthetic_witness(boot: &BootInfo) -> Witness {
    let mut store = PreimageStore::default();

    save_local(&mut store, L1_HEAD_KEY, boot.l1_head.0.to_vec());
    save_local(&mut store, L2_OUTPUT_ROOT_KEY, boot.agreed_l2_output_root.0.to_vec());
    save_local(&mut store, L2_CLAIM_KEY, boot.claimed_l2_output_root.0.to_vec());
    save_local(
        &mut store,
        L2_CLAIM_BLOCK_NUMBER_KEY,
        boot.claimed_l2_block_number.to_be_bytes().to_vec(),
    );
    save_local(&mut store, L2_CHAIN_ID_KEY, boot.chain_id.to_be_bytes().to_vec());
    save_local(
        &mut store,
        L2_ROLLUP_CONFIG_KEY,
        serde_json::to_vec(&boot.rollup_config).expect("rollup_config serializes"),
    );
    save_local(
        &mut store,
        L1_CONFIG_KEY,
        serde_json::to_vec(&boot.l1_config).expect("l1_config serializes"),
    );

    Witness { preimage_store: store, blob_data: BlobData::default() }
}

fn save_local(store: &mut PreimageStore, key: U256, value: Vec<u8>) {
    let local_key = PreimageKey::new_local(key.to());
    store.save_preimage(local_key, value).expect("save_preimage cannot fail for Local keys");
}

/// Build a `BootInfo` for tests. `chain_id = 999_999` ensures registry miss
/// so the loader falls through to oracle-provided configs.
pub fn synth_boot(
    l1_head: [u8; 32],
    agreed: [u8; 32],
    claimed: [u8; 32],
    claimed_block: u64,
) -> BootInfo {
    BootInfo {
        l1_head: l1_head.into(),
        agreed_l2_output_root: agreed.into(),
        claimed_l2_output_root: claimed.into(),
        claimed_l2_block_number: claimed_block,
        chain_id: 999_999,
        rollup_config: RollupConfig::default(),
        l1_config: L1ChainConfig::default(),
    }
}
