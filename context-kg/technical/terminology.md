---
name: "terminology"
description: "Domain term glossary for op-succinct — unified terminology across backend skills"
---
# Domain Terminology

| Term | Description | References |
|------|-------------|------------|
| Aggregation proof | SP1 proof that combines multiple range proofs into a single L1-verifiable proof (synonym: composite proof). | `programs/aggregation/src/main.rs`, `utils/client/src/types.rs` |
| AggregationInputs | zkVM-guest input bundle: `boot_infos[]`, latest L1 checkpoint head, multi-block vkey (u32×8), prover address. | `utils/client/src/types.rs` |
| Anchor Game | Latest finalized dispute game from `AnchorStateRegistry`; canonical head computed from it. | `fault-proof/src/proposer.rs:186-192` |
| BatchSize | Block count per range proof execution; resolved by `effective_batch_size` (default 10). | `scripts/utils/src/lib.rs` |
| BlobProvider | `kona-proof` trait for DA blob retrieval; per-DA impl wraps it (Ethereum uses `OracleBlobProvider`). | `utils/{ethereum,celestia,eigenda}/client/src/*` |
| BlobStore | In-guest blob verifier — converts `BlobData` → `Vec<(VersionedHash, Blob)>` and verifies KZG batch. | `utils/client/src/oracle/blob_provider.rs` |
| BootInfoStruct | ABI struct: `l1Head`, `l2PreRoot`, `l2PostRoot`, `l2BlockNumber`, `rollupConfigHash`. | `utils/client/src/boot.rs` |
| Canonical Head | Proposer's best-known game (parent slot for the next proposal). | `fault-proof/src/proposer.rs:186-192` |
| ClusterProofConfig | Cluster prover RPC + artifact store config (Redis/S3) + cached gRPC client. | `utils/proof/src/lib.rs` |
| ClusterProofHandle | Persisted JSON handle: `proof_id`, `proof_output_id`, `consecutive_poll_failures`. | `utils/proof/src/lib.rs`, `validity/migrations/04_*` |
| DAM | Data Availability Mode — Cargo feature flag selecting Ethereum / Celestia / EigenDA. | `utils/proof/src/lib.rs`, workspace `Cargo.toml` |
| DGF | DisputeGameFactory — L1 factory contract that creates per-output `FaultDisputeGame` instances. | `fault-proof/src/contract.rs` |
| DisputeGame | On-chain game contract for a specific output-root claim; supports prove/challenge/resolve/claimCredit. | `fault-proof/src/contract.rs` |
| DriverDBClient | Pooled `sqlx` Postgres wrapper for the validity proposer; runs migrations on init. | `validity/src/db/client.rs:14-24` |
| FDG | FaultDisputeGame — the per-game L1 contract implementing the dispute protocol. | `fault-proof/src/contract.rs` |
| Game | Cached dispute game record (index, address, parent_index, l2_block, status, deadlines, ownership flags). | `fault-proof/src/proposer.rs:145-175` |
| GameStatus | Terminal state on-chain: `IN_PROGRESS` / `DEFENDER_WINS` / `CHALLENGER_WINS`. | `fault-proof/src/contract.rs:156-162` |
| L2OO | OPSuccinctL2OutputOracle — validity-mode L1 oracle contract receiving aggregated proofs. | `validity/src/contract.rs` |
| OnlineBlobStore | Host-side blob fetcher that collects KZG commitments/proofs during witness generation. | `utils/host/src/witness_generation/online_blob_store.rs` |
| OPSuccinctDataFetcher | L1/L2/beacon RPC client + rollup config loader; `Arc`-shared across services. | `utils/host/src/fetcher.rs` |
| OPSuccinctHost | DA-agnostic host trait: `fetch_args`, `calculate_safe_l1_head`, `get_finalized_l2_block_number`. | `utils/host/src/lib.rs` |
| OPSuccinctRequest | Validity proposer DB row: block range, status, timing, commitments, proof bytes. | `validity/src/db/types.rs:78-114` |
| OracleL1ChainProvider | `kona-proof` L1 chain data oracle backed by the preimage server. | `utils/client/src/oracle/*` |
| OracleL2ChainProvider | `kona-proof` L2 chain data oracle backed by the preimage server. | `utils/client/src/oracle/*` |
| Output Root | L2 block state commitment computed via `compute_output_root_at_block`. | `fault-proof/src/lib.rs:51,86-113` |
| PreimageStore | In-guest oracle client wrapping `CommsClient`; implements `FlushableCache`. | `utils/client/src/witness/preimage_store.rs` |
| PreimageWitnessCollector | Host-side oracle proxy intercepting `get`/`get_exact`/`write` and persisting preimages. | `utils/host/src/witness_generation/preimage_witness_collector.rs` |
| ProgramConfig | Validity's cryptographic key bundle: range/agg vkeys + proving keys + commitment hashes. | `validity/src/config.rs:27-44` |
| ProposalStatus | FaultDisputeGame internal claim state: `Unchallenged` / `Challenged` / `*ValidProofProvided` / `Resolved`. | `fault-proof/src/contract.rs:165-177` |
| ProposerIdentity | Version metadata (vkey hashes + rollup config hash) checked on-chain at game creation. | `fault-proof/src/proposer.rs:88-143` |
| Range proof | SP1 proof for executing a sequential range of L2 blocks; produced by the range zkVM program. | `programs/range/{eth,celestia,eigenda}/src/main.rs` |
| RequesterConfig | Validity service runtime config: chain IDs, contracts, gas/cycle/concurrency limits, timeouts. | `validity/src/config.rs:47-147` |
| RequestMode | `Real` (SP1 network) or `Mock` (local mock prover). | `validity/src/db/types.rs:59-76` |
| RequestStatus | Proof lifecycle state: Unrequested → WitnessGeneration → Execution → Prove → Complete → Relayed (or Failed/Cancelled). | `validity/src/db/types.rs:9-38` |
| RequestType | `Range = 0` (block range) or `Aggregation = 1` (combine range proofs). | `validity/src/db/types.rs:40-57` |
| RPC | Remote-procedure-call provider (alloy L1/L2 provider). | `fault-proof/src/proposer.rs:249-251` |
| SafeDB | L1 head timestamp-based fallback when block estimator can't see ahead; `--safe_db_fallback`. | `utils/ethereum/host/src/host.rs` |
| Signer | Enum dispatch over `Web3Signer`, `LocalSigner`, `CloudHsmSigner` (GCP-KMS), `XLayerRemoteSigner`. | `utils/signer/src/lib.rs` |
| SignerLock | `Arc<Mutex<Signer>>` wrapper; serializes tx submission to avoid nonce conflicts. | `utils/signer/src/lib.rs` |
| WitnessExecutor | Async trait composing oracle + blob provider into a DA-specific derivation pipeline. | `utils/host/src/witness_generation/traits.rs`, `utils/{eth,celestia,eigenda}/host/*` |
| WitnessGenerator | Async trait orchestrating witness collection from oracle + blob streams. | `utils/host/src/witness_generation/traits.rs` |
| XLayerRemoteClient | HTTP signer client — POST sign, GET polling; AES-ECB + HMAC auth; routes by `OperateType`. | `utils/signer/src/xlayer_remote_client.rs` |
| tz | TradeZone L2 chain — custom OP-Stack-incompatible L2 with REST `/chain/confirmed_block_info` endpoint and `keccak256(blockHash ‖ stateHash)` rootClaim formula. Activated by Cargo feature `tz` (orthogonal to DA features). | `fault-proof/src/tz/`, `fault-proof/Cargo.toml` |
| TeeDisputeGame | tz dispute-game contract; default game type ID `1961`. Reuses `OPSuccinctFaultDisputeGame` ABI; `extraData` is 36 bytes `(U256 l2SeqNum, u32 parentIdx)` (same as xlayer). | `fault-proof/src/tz/config.rs::DEFAULT_TZ_GAME_TYPE` |
| TzChainClient | tz REST client + sync `Mutex<HashMap<u64, TzBlockInfo>>` checkpoint cache; multi-endpoint failover; `evict_below(anchor)` strict-`<` eviction. | `fault-proof/src/tz/chain_client.rs` |
| TzBlockInfo | tz checkpoint payload: `height: u64`, `block_hash: B256`, `state_hash: B256`. Returned by `GET /chain/confirmed_block_info`. | `fault-proof/src/tz/chain_client.rs:16-23` |
| TzL2Provider | tz `L2ProviderTrait` impl: `compute_output_root_at_block` does cache lookup keyed by L2 block number; `get_l2_block_by_number` and `get_l2_storage_root` return `unsupported`. | `fault-proof/src/tz/l2_provider.rs` |
| TzConfig | tz env-driven config: `rpc_urls: Vec<String>` (from comma-separated `L2_RPC`), `game_type: u32` (from `GAME_TYPE`, default `1961`). No `rollup_config_hash` field — it is read from L1 at construction. | `fault-proof/src/tz/config.rs` |
| TzCacheMissError | `thiserror` enum (`Missing(u64)`); raised when `compute_output_root_at_block` cannot find the requested height in the checkpoint cache. | `fault-proof/src/tz/chain_client.rs` |
| compute_tz_root_claim | tz rootClaim formula: `keccak256([block_hash, state_hash].concat())` — order-sensitive 64-byte input, distinct from xlayer's `OutputRoot::abi_encode()` formula. | `fault-proof/src/tz/l2_provider.rs:32-37` |
