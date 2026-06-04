---
name: "terminology"
description: "Domain term glossary for op-succinct — unified terminology across backend skills"
---
# Domain Terminology

| Term | Description | References |
|------|-------------|------------|
| Aggregation proof | SP1 proof that combines multiple range proofs (SP1 or TEE) into a single L1-verifiable proof; batch must be homogeneous (all-SP1 or all-TEE). | `programs/aggregation/src/main.rs`, `utils/client/src/types.rs` |
| AggregationInputs | zkVM-guest input bundle: `boot_infos[]`, `range_proofs[]` (parallel-indexed), latest L1 checkpoint head, multi-block vkey (u32×8), prover address. | `utils/client/src/types.rs` |
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
| OPSuccinctHost | DA-agnostic host trait: `fetch_args`, `calculate_safe_l1_head`, `get_finalized_l2_block_number`. **Not to be confused with xlayer-tee-host.** | `utils/host/src/lib.rs` |
| xlayer-tee-host | TEE proof coordination layer between proposer and Nitro Enclave. Northbound JSON REST, southbound rkyv-over-HTTP. Distinct from `OPSuccinctHost` (witness generation host trait). | `fault-proof/tee/host/` |
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
| RangeProof | Enum discriminator for per-leaf proof type in aggregation: `Sp1` (recursive ZK verification) or `Tee { signature: Vec<u8> }` (65-byte secp256k1 ECDSA signature). | `utils/client/src/types.rs` |
| VerifiedSession | Attestation-derived TEE session identity: `signer: Address` + `pcr0_hash: B256`. Constructed once per TEE batch from the attestation document. | `programs/aggregation/src/tee/types.rs` |
| TrustAnchors | Container for the AWS Nitro Root-G1 P-384 public key (96 bytes X‖Y); the single trust root baked into the aggregation guest. | `programs/aggregation/src/tee/types.rs` |
| pack_range_journal | 168-byte commitment packing function: pcr0[0..32], configHash[32..64], l1OriginHash[64..96], l2BlockNumber[96..104] BE, prevOutputRoot[104..136], outputRoot[136..168]. Must match enclave signing side. | `programs/aggregation/src/tee/crypto.rs` |
| WitnessExecutor | Async trait composing oracle + blob provider into a DA-specific derivation pipeline. | `utils/host/src/witness_generation/traits.rs`, `utils/{eth,celestia,eigenda}/host/*` |
| WitnessGenerator | Async trait orchestrating witness collection from oracle + blob streams. | `utils/host/src/witness_generation/traits.rs` |
| XLayerRemoteClient | HTTP signer client — POST sign, GET polling; AES-ECB + HMAC auth; routes by `OperateType`. | `utils/signer/src/xlayer_remote_client.rs` |
