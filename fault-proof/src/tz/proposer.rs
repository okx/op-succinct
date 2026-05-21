// TZ-specific implementations of `OPSuccinctProposer` methods whose logic diverges
// substantially from the xlayer path.
//
// Declared as a child module of `proposer` (via `#[path]`), so `use super::*` gives access to
// all types and private fields from proposer.rs without changing their visibility.

use super::*;
// for tz: Phase 2 — cluster artifact-ID proof submission and polling
use crate::tz::chain_client::WitnessStatus;
use op_succinct_client_utils::types::AggregationInputs;
use op_succinct_proof_utils::{
    cluster_poll_proof, cluster_submit_by_artifact_ids, cluster_upload_elf, tz_cluster_agg_proof,
};
use sp1_cluster_utils::ProofRequestResults;
use sp1_sdk::{
    blocking::{CpuProver, Prover as BlockingProver},
    SP1Proof, SP1ProofMode, SP1Stdin,
};

impl<P, H> OPSuccinctProposer<P, H>
where
    P: Provider + Clone + Send + Sync + 'static,
    H: OPSuccinctHost + Clone + Send + Sync + 'static,
{
    /// Handles the creation of a new game if conditions are met.
    #[tracing::instrument(name = "[[Proposing]]", skip(self))]
    pub async fn handle_game_creation(
        &self,
        next_l2_block_number_for_proposal: U256,
        parent_game_index: u32,
    ) -> Result<()> {
        let output_root = self
            .l2_provider
            .compute_output_root_at_block(next_l2_block_number_for_proposal)
            .await?;
        let extra_data = (next_l2_block_number_for_proposal, parent_game_index).abi_encode_packed();
        let maybe_existing_game = self
            .factory
            .games(self.config.game_type, output_root, extra_data.clone().into())
            .call()
            .await?
            .proxy;

        // tz: one-shot check — confirmed_height maps to exactly one rootClaim;
        // incrementing block number would not change rootClaim, so skip and wait for next
        // checkpoint.
        if maybe_existing_game != Address::ZERO {
            tracing::info!(
                l2_block_number = %next_l2_block_number_for_proposal,
                "tz: game already exists for this checkpoint, skipping"
            );
            return Ok(());
        }

        tracing::info!(
            l2_block_number = %next_l2_block_number_for_proposal,
            parent_game_index = %parent_game_index,
            output_root = ?output_root,
            "Creating game"
        );

        self.create_game(output_root, extra_data).await?;

        Ok(())
    }

    pub(super) async fn should_create_game(&self) -> Result<(bool, U256, u32)> {
        if self.config.fast_finality_mode {
            anyhow::bail!("tz: fast_finality_mode is not supported");
        }
        let respected_game_type = self.anchor_state_registry.respectedGameType().call().await?;
        if self.config.game_type != respected_game_type {
            tracing::warn!(
                proposer_game_type = self.config.game_type,
                ?respected_game_type,
                "Skipping game creation, game type does not match respected type"
            );
            return Ok((false, U256::ZERO, u32::MAX));
        }

        let (canonical_head_l2_block, parent_game_index) = {
            let state = self.state.read().await;

            let Some(canonical_head_l2_block) = state.canonical_head_l2_block else {
                tracing::info!("No canonical head; skipping game creation");
                return Ok((false, U256::ZERO, u32::MAX));
            };

            let anchor_index = state.anchor_game.as_ref().map(|a| a.index);
            let parent_game_index = state
                .canonical_head_index
                .filter(|&idx| anchor_index != Some(idx))
                .map(|index| index.to::<u32>())
                .unwrap_or(u32::MAX);

            (canonical_head_l2_block, parent_game_index)
        };

        // tz: use confirmed checkpoint height instead of eth_getBlockByNumber("finalized")
        match self
            .l2_provider
            .get_next_proposal_block(
                canonical_head_l2_block,
                self.config.proposal_interval_in_blocks,
            )
            .await?
        {
            Some(target) => Ok((true, target, parent_game_index)),
            None => Ok((false, U256::ZERO, u32::MAX)),
        }
    }

    /// Creates a new proposer with an injected L2 provider and range ELF.
    /// Avoids optimism_rollupConfig RPC and allows a custom L2 data source.
    /// Reads rollup_config_hash from the on-chain game implementation.
    pub async fn new_with_l2_provider(
        config: ProposerConfig,
        signer: SignerLock,
        anchor_state_registry: AnchorStateRegistryInstance<P>,
        factory: DisputeGameFactoryInstance<P>,
        fetcher: Arc<OPSuccinctDataFetcher>,
        host: Arc<H>,
        l2_provider: Arc<dyn L2ProviderTrait + Send + Sync>,
        range_elf: Vec<u8>,
        // for tz: Phase 2 — Witness Builder + L2 client (shared with l2_provider construction)
        tz_chain_client: Arc<crate::tz::chain_client::TzChainClient>,
        // for tz: Phase 2 — tz range ELF artifact ID (uploaded from range_elf at startup)
        tz_elf_artifact_id: String,
        // for tz: Phase 2 — tz aggregation ELF (distinct from op-succinct AGGREGATION_ELF)
        tz_agg_elf: Vec<u8>,
    ) -> Result<Self> {
        // tz: read all identity fields from the deployed game implementation so is_owned()
        // matches on-chain games regardless of which local ELF is loaded.
        let game_impl = factory.game_impl(config.game_type).await?;
        let rollup_config_hash = B256::from(game_impl.rollupConfigHash().call().await?.0);
        let on_chain_agg_vkey = B256::from(game_impl.aggregationVkey().call().await?.0);
        let on_chain_range_vkey = B256::from(game_impl.rangeVkeyCommitment().call().await?.0);
        tracing::info!(
            ?rollup_config_hash,
            ?on_chain_agg_vkey,
            ?on_chain_range_vkey,
            "tz: loaded identity from on-chain game implementation"
        );

        let is_cluster = is_cluster_mode();

        anyhow::ensure!(
            !(is_cluster && config.mock_mode),
            "mock and cluster modes are mutually exclusive"
        );

        // for tz: Phase 2 — build ClusterProofConfig once when in cluster mode
        let cluster_config =
            if is_cluster { Some(Arc::new(ClusterProofConfig::from_env().await?)) } else { None };

        tracing::info!("tz: deriving VKs from loaded ELF binaries (this may take a moment)");
        let (range_pk, range_vk, agg_pk, agg_vk, network_prover, network_mode) = if is_cluster {
            // tz: derive VKs from the actual tz ELFs loaded from disk (not xlayer's embedded ELFs)
            // so that multi_block_vkey and write_proof use the correct tz range VK.
            let range_elf_arc: std::sync::Arc<[u8]> = range_elf.into();
            let agg_elf_arc: std::sync::Arc<[u8]> = tz_agg_elf.clone().into();
            let (range_pk, range_vk, agg_pk, agg_vk) = tokio::task::spawn_blocking(move || {
                let cpu_prover = CpuProver::new();
                let range_pk = cpu_prover
                    .setup(Elf::Dynamic(range_elf_arc))
                    .context("tz range ELF setup failed")?;
                let range_vk = range_pk.verifying_key().clone();
                let agg_pk = cpu_prover
                    .setup(Elf::Dynamic(agg_elf_arc))
                    .context("tz agg ELF setup failed")?;
                let agg_vk = agg_pk.verifying_key().clone();
                anyhow::Ok((range_pk, range_vk, agg_pk, agg_vk))
            })
            .await??;
            (range_pk, range_vk, agg_pk, agg_vk, None, None)
        } else {
            let network_signer = get_network_signer(config.use_kms_requester).await?;
            let nm = determine_network_mode(
                config.proof_provider.range_proof_strategy,
                config.proof_provider.agg_proof_strategy,
            )?;
            let np = Arc::new(
                ProverClient::builder().network_for(nm).signer(network_signer).build().await,
            );
            // tz: in mock mode with an empty range ELF, substitute AGGREGATION_ELF so key
            // derivation succeeds without a real compiled ELF.
            let effective_range_elf: Elf = if config.mock_mode && range_elf.is_empty() {
                Elf::Static(AGGREGATION_ELF)
            } else {
                range_elf.into()
            };
            let range_pk = np.setup(effective_range_elf).await?;
            let range_vk = range_pk.verifying_key().clone();
            let agg_pk = np.setup(tz_agg_elf.clone().into()).await?;
            let agg_vk = agg_pk.verifying_key().clone();
            (range_pk, range_vk, agg_pk, agg_vk, Some(np), Some(nm))
        };

        // Compute local VK commitment values from the derived keys (mirrors xlayer proposer).
        let local_range_commitment = B256::from(range_vk.hash_bytes());
        let local_agg_vkey = B256::from(agg_vk.bytes32_raw());
        tracing::info!(
            local_range_commitment = ?local_range_commitment,
            local_agg_vkey = ?local_agg_vkey,
            "tz: VKs derived from local ELF binaries"
        );

        // Compare local VKs against on-chain VKs (skip in mock mode — ELF is a placeholder).
        if !config.mock_mode {
            let range_match = local_range_commitment == on_chain_range_vkey;
            let agg_match = local_agg_vkey == on_chain_agg_vkey;
            if range_match && agg_match {
                tracing::info!("tz: local VKs match on-chain VKs");
            } else {
                if !range_match {
                    tracing::warn!(
                        local = ?local_range_commitment,
                        on_chain = ?on_chain_range_vkey,
                        "tz: range VK mismatch — local ELF does not match on-chain rangeVkeyCommitment"
                    );
                }
                if !agg_match {
                    tracing::warn!(
                        local = ?local_agg_vkey,
                        on_chain = ?on_chain_agg_vkey,
                        "tz: agg VK mismatch — local ELF does not match on-chain aggregationVkey"
                    );
                }
            }
        }

        // Use locally-derived VKs as identity (mirrors xlayer) so on_chain_vkeys_match() performs
        // a real comparison between local and on-chain values on every game-creation cycle.
        let identity =
            ProposerIdentity::new(local_agg_vkey, local_range_commitment, rollup_config_hash);
        identity.log_startup_info();

        let keys = ProofKeys {
            range_pk: Arc::new(range_pk),
            range_vk: Arc::new(range_vk),
            agg_pk: Arc::new(agg_pk),
            agg_vk: Arc::new(agg_vk),
        };

        let prover = if is_cluster {
            ProofProvider::Cluster(ClusterProofProvider::new(
                keys.clone(),
                config.proof_provider.clone(),
            ))
        } else if config.mock_mode {
            ProofProvider::Mock(MockProofProvider::new(
                network_prover
                    .ok_or_else(|| anyhow::anyhow!("network_prover required in mock mode"))?,
                keys.clone(),
                config.proof_provider.clone(),
                AGGREGATION_ELF,
            ))
        } else {
            ProofProvider::Network(NetworkProofProvider::new(
                network_prover
                    .ok_or_else(|| anyhow::anyhow!("network_prover required in network mode"))?,
                keys.clone(),
                config.proof_provider.clone(),
                network_mode
                    .ok_or_else(|| anyhow::anyhow!("network_mode required in network mode"))?,
            ))
        };

        let l1_provider = ProviderBuilder::default().connect_http(config.l1_rpc.clone());
        let initial_state = ProposerState::default();

        Ok(Self {
            config: config.clone(),
            contract_params: OnceLock::new(),
            signer,
            l1_provider,
            l2_provider,
            anchor_state_registry: Arc::new(anchor_state_registry),
            factory: Arc::new(factory),
            init_bond: OnceLock::new(),
            safe_db_fallback: config.safe_db_fallback,
            prover,
            fetcher,
            host,
            tasks: Arc::new(Mutex::new(HashMap::new())),
            next_task_id: Arc::new(AtomicU64::new(1)),
            state: Arc::new(RwLock::new(initial_state)),
            backup_semaphore: Arc::new(Semaphore::new(1)),
            identity,
            // for tz: Phase 2
            cluster_config,
            tz_chain_client: Some(tz_chain_client),
            tz_elf_artifact_id,
            tz_agg_elf,
        })
    }

    /// TZ-specific game proving.
    ///
    /// Mock mode: SP1MockVerifier only checks `proofBytes.length == 0`, so we pass empty bytes.
    ///
    /// Real mode (mirrors xlayer flow):
    ///   1. Split [start_block, end_block] into sub-ranges.
    ///   2. For each sub-range in parallel: Witness Builder → SP1 cluster range proof (Compressed).
    ///   3. Aggregate range proofs via standard agg proof pipeline.
    ///   4. Submit agg proof bytes to L1.
    #[tracing::instrument(name = "[[Proving]]", skip(self), fields(game_address = ?game_address))]
    pub async fn prove_game(
        &self,
        game_address: Address,
        start_block: u64,
        end_block: u64,
    ) -> Result<(TxHash, u64, u64)> {
        // --- Phase 1 mock path (preserved) ---
        if self.config.mock_mode {
            let game = OPSuccinctFaultDisputeGame::new(game_address, self.l1_provider.clone());
            let tx = game.prove(alloy_primitives::Bytes::new()).into_transaction_request();
            tracing::info!(game_address = ?game_address, "tz: submitting mock proof (empty bytes)");
            let receipt = self
                .signer
                .send_transaction_request_with_timeout(
                    self.config.l1_rpc.clone(),
                    tx,
                    self.config.tx_confirmation_timeout,
                )
                .await?;
            if !receipt.status() {
                anyhow::bail!("{} {:?}", TX_REVERTED_PREFIX, receipt);
            }
            tracing::info!(
                game_address = ?game_address,
                tx_hash = ?receipt.transaction_hash,
                "tz: mock proof submitted"
            );
            return Ok((receipt.transaction_hash, 0, 0));
        }

        // --- Phase 2 real proof path ---
        let cluster_config = self
            .cluster_config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("tz: SP1_PROVER=cluster required for real proving"))?;
        let tz_client = self
            .tz_chain_client
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("tz: chain client not initialized"))?;

        // Fetch game metadata: deadline (for liveness) and L1 head (for agg proof, like xlayer)
        let game = OPSuccinctFaultDisputeGame::new(game_address, self.l1_provider.clone());
        let claim_data = game.claimData().call().await.context("tz: failed to fetch claimData")?;
        let game_deadline = claim_data.deadline;
        check_deadline(game_deadline, "pre-witness-submit")?;

        // Split range into sub-ranges (mirrors xlayer range_split_count logic)
        let ranges = self
            .config
            .range_split_count
            .split(start_block, end_block)
            .context("tz: failed to split range")?;
        let num_ranges = ranges.len();
        tracing::info!(game_address = ?game_address, num_ranges, "tz: proving over {num_ranges} sub-ranges");

        // Capture timeout_secs so closures can compute effective_deadline at submission time
        // (after witness polling completes) rather than once before witnesses start.
        let timeout_secs = self.config.proof_provider.timeout;

        let elf_artifact_id = self.tz_elf_artifact_id.clone();

        // Step 1+2: parallel per-sub-range: Witness Builder → range proof (Compressed)
        let tasks = ranges.into_iter().enumerate().map(|(idx, (sub_start, sub_end))| {
            let tz_client = tz_client.clone();
            let cluster_config = cluster_config.clone();
            let elf_artifact_id = elf_artifact_id.clone();
            async move {
                // 1a. Create witness task
                let artifact_id =
                    tz_client.create_witness_task(sub_start, sub_end).await.with_context(|| {
                        format!("tz: witness task failed for [{sub_start},{sub_end}]")
                    })?;
                tracing::info!(%artifact_id, sub_start, sub_end, "tz: witness task created");

                // 1b. Poll until Finished
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    match tz_client.poll_witness_task(&artifact_id).await? {
                        WitnessStatus::Finished { .. } => break,
                        WitnessStatus::Failed { reason, .. } => {
                            anyhow::bail!(
                                "tz: witness failed for [{sub_start},{sub_end}]: {reason}"
                            )
                        }
                        WitnessStatus::Running { process_percentage, .. } => {
                            tracing::debug!(
                                %artifact_id,
                                process_percentage,
                                "tz: witness running"
                            );
                        }
                        WitnessStatus::Pending => {
                            tracing::debug!(%artifact_id, "tz: witness pending");
                        }
                    }
                    check_deadline(game_deadline, "witness-poll")?;
                }
                tracing::info!(%artifact_id, sub_start, sub_end, "tz: witness ready");

                // 2a. Submit range proof (Compressed — required as input to agg proof)
                // Recompute effective_deadline at submission time so witness duration does
                // not eat into the budget: effective = min(now + timeout, game_deadline).
                let submit_deadline = {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs();
                    now.saturating_add(timeout_secs).min(game_deadline)
                };
                let proof_request = cluster_submit_by_artifact_ids(
                    &cluster_config,
                    submit_deadline,
                    elf_artifact_id,
                    artifact_id,
                    SP1ProofMode::Compressed,
                )
                .await
                .context("tz: SP1 cluster range proof submit failed")?;
                tracing::info!(
                    proof_id = %proof_request.proof_id,
                    sub_start,
                    sub_end,
                    "tz: range proof submitted to cluster"
                );

                // 2b. Poll until range proof is ready
                let range_proof: SP1ProofWithPublicValues = loop {
                    tokio::time::sleep(std::time::Duration::from_secs(
                        crate::prover::PROOF_STATUS_POLL_INTERVAL,
                    ))
                    .await;
                    match cluster_poll_proof(&cluster_config, proof_request.clone()).await? {
                        Some(ProofRequestResults { proof, .. }) => {
                            break SP1ProofWithPublicValues::from(proof);
                        }
                        None => {
                            check_deadline(game_deadline, "range-proof-poll")?;
                        }
                    }
                };

                Ok::<_, anyhow::Error>((idx, range_proof))
            }
        });

        let max_concurrent = self.config.max_concurrent_range_proofs.get().min(num_ranges);
        let mut results: Vec<(usize, SP1ProofWithPublicValues)> =
            stream::iter(tasks).buffer_unordered(max_concurrent).try_collect().await?;
        // Restore original range order for agg proof stdin construction
        results.sort_unstable_by_key(|(idx, _)| *idx);

        // Step 3: extract proof objects and boot infos (mirrors xlayer)
        let mut proofs = Vec::with_capacity(results.len());
        let mut boot_infos = Vec::with_capacity(results.len());
        for (_, range_proof) in results {
            let proof = range_proof.proof.clone();
            let mut pv = range_proof.public_values.clone();
            let boot_info: BootInfoStruct = pv.read();
            proofs.push(proof);
            boot_infos.push(boot_info);
        }

        // Step 3b: build tz agg proof stdin — no L1 headers (R8.7: tz has no L1 derivation)
        tracing::info!(game_address = ?game_address, "tz: preparing agg proof stdin");
        let range_vk = self.prover.keys().range_vk.clone();
        let mut agg_stdin = SP1Stdin::new();
        for proof in proofs {
            let SP1Proof::Compressed(compressed) = proof else {
                anyhow::bail!("tz: non-Compressed range proof fed to aggregation");
            };
            agg_stdin.write_proof(*compressed, range_vk.vk.clone());
        }
        agg_stdin.write(&AggregationInputs {
            boot_infos,
            // tz: no L1 derivation — L1 checkpoint head is always zero (R8.7)
            latest_l1_checkpoint_head: B256::ZERO,
            multi_block_vkey: range_vk.hash_u32(),
            prover_address: self.signer.address(),
        });
        // NOTE: no write_vec(headers_bytes) — tz omits the L1 header chain (R8.7)

        // Step 4: tz aggregation proof using tz-specific ELF (not op-succinct AGGREGATION_ELF)
        check_deadline(game_deadline, "pre-agg-proof")?;
        // Cap agg timeout at remaining time to game_deadline so the cluster job cannot
        // be issued with a deadline that exceeds the on-chain game deadline.
        let agg_timeout = {
            let now_for_agg =
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
            game_deadline.saturating_sub(now_for_agg).min(self.config.proof_provider.timeout)
        };
        let agg_proof = tz_cluster_agg_proof(
            agg_timeout,
            self.config.proof_provider.agg_proof_mode,
            &self.tz_agg_elf,
            agg_stdin,
        )
        .await?;

        // Step 5: submit agg proof to L1
        let tx = game.prove(agg_proof.bytes().into()).into_transaction_request();
        let receipt = self
            .signer
            .send_transaction_request_with_timeout(
                self.config.l1_rpc.clone(),
                tx,
                self.config.tx_confirmation_timeout,
            )
            .await?;
        if !receipt.status() {
            anyhow::bail!("{} {:?}", TX_REVERTED_PREFIX, receipt);
        }
        tracing::info!(
            game_address = ?game_address,
            tx_hash = ?receipt.transaction_hash,
            "tz: agg proof submitted to L1"
        );
        Ok((receipt.transaction_hash, 0, 0))
    }
}

/// Check that the current time is strictly before `game_deadline` (absolute Unix seconds).
/// Module-level so it can be called from async task closures without capturing `self`.
fn check_deadline(game_deadline: u64, checkpoint: &str) -> Result<()> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    if now >= game_deadline {
        anyhow::bail!("tz: past game deadline at {checkpoint}: now={now} deadline={game_deadline}");
    }
    Ok(())
}
