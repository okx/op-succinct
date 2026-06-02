---
name: "common-tools"
description: "Reusable components, traits, and macros across op-succinct crates"
---
# Common Tools and Reusable Components

[Reuse] `Signer` enum (`utils/signer/src/lib.rs`) — flexible signing backend; construct via `Signer::from_env()`; do not re-implement transaction signing.

[Reuse] `SignerLock` (`utils/signer/src/lib.rs`) — `Arc<Mutex<Signer>>` wrapper to serialize sends; required for multi-threaded use.

[Reuse] `XLayerRemoteClient` (`utils/signer/src/xlayer_remote_client.rs`) — full implementation of the asset-onchain HTTP signer protocol; do not duplicate.

[Reuse] `OPSuccinctDataFetcher` (`utils/host/src/fetcher.rs`) — L1/L2/beacon RPC client + rollup config loader. Share via `Arc` across services. Handles Isthmus pre/post withdrawal-root logic.

[Reuse] `WitnessGenerator` trait (`utils/host/src/witness_generation/traits.rs`) — async orchestration template for DA-specific witness generation; override only `get_executor()` and `get_sp1_stdin()`.

[Reuse] `PreimageWitnessCollector` / `OnlineBlobStore` (`utils/host/src/witness_generation/*`) — interceptor wrappers that auto-save preimages / blobs during execution.

[Reuse] `BootInfoStruct` (`utils/client/src/boot.rs`) — public-input struct serialised for on-chain verification; reuse for both range and aggregation outputs.

[Reuse] `AggregationInputs` (`utils/client/src/types.rs`) — multi-block aggregation input bundle; written to `SP1Stdin`. Includes `range_proofs: Vec<RangeProof>` parallel-indexed with `boot_infos`.

[Reuse] `RangeProof` (`utils/client/src/types.rs`) — per-range proof variant enum: `Sp1` (unit) for ZK range proofs, `Tee { signature: Vec<u8> }` for TEE-signed ranges (65-byte secp256k1 ECDSA). Extend this enum when adding new proof types; do not create parallel type hierarchies.

[Reuse] `ClusterProofConfig` / `ClusterProofHandle` (`utils/proof/src/lib.rs`) — encapsulate cluster prover state; persist `ClusterProofHandle` JSON across restarts.

[Reuse] `cluster_setup_keys()` (`utils/proof`) — range + aggregation vkey setup for cluster mode; call only in blocking context.

[Reuse] `get_range_elf_embedded()` (`utils/proof`) — feature-gated ELF selection; abstracts the three DA variants.

[Reuse] `setup_logger()` (`utils/host/src/logger.rs`) — tracing + OpenTelemetry init; call once per binary.

[Reuse] `OPSuccinctHost` trait (`utils/host`) — DA-agnostic host abstraction (`fetch_args`, `calculate_safe_l1_head`, `get_finalized_l2_block_number`); each DA implements once.

[Reuse] `BlobStore::from(BlobData)` (`utils/client/src/oracle/blob_provider.rs`) — in-guest blob verifier; verifies KZG batch and panics on failure (correct behavior).

[Reuse] `bindings/*` contract Instances — `DisputeGameFactoryInstance`, `OPSuccinctL2OOContract`, `OPSuccinctFaultDisputeGame`, `AnchorStateRegistry`, `AccessManager`; never hand-write Solidity-call code.

[Reuse] `scripts/utils/src/lib.rs::HostExecutorArgs` — CLI argument parser with `effective_batch_size()`; reuse across script binaries to keep batching consistent.

[Reuse] `scripts/utils/src/config_common.rs::get_shared_config_data()` — populates vkey hashes + verifier address for contract config; reuse in any contract-config generator script.

[Reuse] `validity/src/db/client.rs::DriverDBClient` — Postgres connection + migration runner singleton; never open ad-hoc `PgPool::connect` in service code.

[Convention] When adding new functionality that overlaps any of the above, extend the reusable component rather than duplicate. Code review should reject diffs that re-implement signer dispatch, witness collection, or proof polling.
