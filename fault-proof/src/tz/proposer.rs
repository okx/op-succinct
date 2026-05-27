// TZ-specific implementations of `OPSuccinctProposer` methods whose logic diverges
// substantially from the xlayer path.
//
// Declared as a child module of `proposer` (via `#[path]`), so `use super::*` gives access to
// all types and private fields from proposer.rs without changing their visibility.

use super::*;
use op_succinct_client_utils::types::AggregationInputs;
use sp1_sdk::{SP1Proof, SP1VerifyingKey};

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

        let game_address = self.create_game(output_root, extra_data).await?;

        // Mirror xlayer: record the created game so backup/restore keeps the duplicate-creation
        // guard state consistent even though tz's should_create_game uses a one-shot checkpoint
        // check instead of the pinned-cache guard.
        self.last_created_game_l2_block
            .store(next_l2_block_number_for_proposal.to::<u64>(), Ordering::Relaxed);
        *self.last_created_game_address.lock().await = game_address;

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

    /// Creates a new proposer with an injected L2 provider.
    /// Avoids optimism_rollupConfig RPC and allows a custom L2 data source.
    /// Reads rollup_config_hash from the on-chain game implementation.
    /// Range / aggregation ELFs are selected by the `tz` cargo feature
    /// (see `op_succinct_proof_utils::{get_range_elf_embedded, AGGREGATION_ELF}`).
    pub async fn new_with_l2_provider(
        config: ProposerConfig,
        signer: SignerLock,
        anchor_state_registry: AnchorStateRegistryInstance<P>,
        factory: DisputeGameFactoryInstance<P>,
        fetcher: Arc<OPSuccinctDataFetcher>,
        host: Arc<H>,
        l2_provider: Arc<dyn L2ProviderTrait + Send + Sync>,
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
            "mock and cluster modes are mutually exclusive — set only one of SP1_PROVER=cluster or mock_mode=true"
        );

        let (range_pk, range_vk, agg_pk, agg_vk, network_prover, network_mode) = if is_cluster {
            let (range_pk, range_vk, agg_pk, agg_vk) = cluster_setup_keys().await?;
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
            let range_pk = np.setup(Elf::Static(get_range_elf_embedded())).await?;
            let range_vk = range_pk.verifying_key().clone();
            let agg_pk = np.setup(Elf::Static(AGGREGATION_ELF)).await?;
            let agg_vk = agg_pk.verifying_key().clone();
            (range_pk, range_vk, agg_pk, agg_vk, Some(np), Some(nm))
        };

        let local_range_vk_hash = B256::from(op_succinct_client_utils::types::u32_to_u8(
            range_vk.hash_u32(),
        ));
        let local_agg_vk_hash = B256::from(agg_vk.bytes32_raw());
        tracing::info!(
            ?local_range_vk_hash,
            on_chain_range_vkey = ?on_chain_range_vkey,
            ?local_agg_vk_hash,
            on_chain_agg_vkey = ?on_chain_agg_vkey,
            "tz: local-computed vkeys (from get_range_elf_embedded / AGGREGATION_ELF) vs on-chain"
        );

        let identity =
            ProposerIdentity::new(on_chain_agg_vkey, on_chain_range_vkey, rollup_config_hash);
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
            last_synced_l1_block: Arc::new(AtomicU64::new(0)),
            last_created_game_l2_block: Arc::new(AtomicU64::new(0)),
            last_created_game_address: Arc::new(Mutex::new(Address::ZERO)),
            identity,
        })
    }

    /// TZ-specific game proving.
    ///
    /// Mock mode: SP1MockVerifier only checks `proofBytes.length == 0`, so submit empty bytes.
    ///
    /// Real mode: fetch DexState snapshot + Vec<Block> from the tz chain HTTP endpoints
    /// (single segment), generate a compressed range proof, then wrap into a groth16 aggregation
    /// proof. Submit the groth16 proof bytes to OPSuccinctFaultDisputeGame.prove.
    #[tracing::instrument(name = "[[Proving]]", skip(self), fields(game_address = ?game_address))]
    pub async fn prove_game(
        &self,
        game_address: Address,
        start_block: u64,
        end_block: u64,
    ) -> Result<(TxHash, u64, u64)> {
        let game = OPSuccinctFaultDisputeGame::new(game_address, self.l1_provider.clone());

        let proof_bytes = if self.config.mock_mode {
            tracing::info!(game_address = ?game_address, "tz: submitting mock proof (empty bytes)");
            alloy_primitives::Bytes::new()
        } else {
            self.tz_prove(start_block, end_block).await?
        };

        let transaction_request = game.prove(proof_bytes).into_transaction_request();
        let receipt = self
            .signer
            .send_transaction_request_with_timeout(
                self.config.l1_rpc.clone(),
                transaction_request,
                self.config.tx_confirmation_timeout,
            )
            .await?;

        if !receipt.status() {
            anyhow::bail!("{} {:?}", TX_REVERTED_PREFIX, receipt);
        }

        tracing::info!(
            game_address = ?game_address,
            tx_hash = ?receipt.transaction_hash,
            "tz: proof submitted"
        );
        Ok((receipt.transaction_hash, 0, 0))
    }

    /// Run the twin-layer prove pipeline (single segment): range proof → aggregation proof.
    /// Returns groth16-wrapped proof bytes ready for OPSuccinctFaultDisputeGame.prove.
    async fn tz_prove(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> Result<alloy_primitives::Bytes> {
        tracing::info!(
            start_block,
            end_block,
            "tz: fetching witness (snapshot + blocks) from tz chain"
        );
        let snapshot = self.l2_provider.fetch_dex_state_snapshot(start_block).await?;

        let tz_blocks_per_fetch: u64 = std::env::var("TZ_BLOCKS_PER_FETCH")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&n: &u64| n > 0)
            .unwrap_or(1000);
        // snapshot is the post-state of block `start_block`; the blocks to replay are
        // (start_block, end_block] — i.e. starting from start_block + 1.
        let first_block = start_block.saturating_add(1);
        let total_blocks = end_block.saturating_sub(start_block);
        let chunk_count: u32 = total_blocks
            .div_ceil(tz_blocks_per_fetch)
            .try_into()
            .context("chunk_count overflows u32")?;

        let mut range_stdin = SP1Stdin::new();
        range_stdin.write_vec(snapshot);
        range_stdin.write(&chunk_count);

        let mut cur = first_block;
        for _ in 0..chunk_count {
            let chunk_end = cur.saturating_add(tz_blocks_per_fetch - 1).min(end_block);
            let chunk = self.l2_provider.fetch_blocks_range(cur, chunk_end).await?;
            range_stdin.write_vec(chunk);
            cur = chunk_end.saturating_add(1);
        }

        if std::env::var("TZ_LOCAL_EXECUTE").ok().as_deref() == Some("1") {
            tracing::info!("tz: TZ_LOCAL_EXECUTE=1 — running range guest on local CPU first");
            let cpu = sp1_sdk::ProverClient::builder().cpu().build().await;
            match cpu
                .execute(Elf::Static(get_range_elf_embedded()), range_stdin.clone())
                .await
            {
                Ok((pv, report)) => tracing::info!(
                    pv_len = pv.as_slice().len(),
                    cycles = ?report.total_instruction_count(),
                    "tz: local execute OK"
                ),
                Err(e) => {
                    tracing::error!("tz: local execute FAILED: {e:?}");
                    return Err(anyhow::anyhow!("tz: local execute failed: {e}"));
                }
            }
        }

        tracing::info!("tz: generating range proof");
        let (range_proof, _cycles, _gas) = self.prover.generate_range_proof(range_stdin).await?;
        let pv_bytes = range_proof.public_values.as_slice();
        tracing::info!(
            pv_len = pv_bytes.len(),
            pv_head = %hex::encode(&pv_bytes[..pv_bytes.len().min(32)]),
            "tz: range proof public_values"
        );
        let boot_info = BootInfoStruct::abi_decode(pv_bytes).map_err(|e| {
            anyhow::anyhow!(
                "tz: failed to abi_decode range BootInfoStruct (pv_len={}): {e}",
                pv_bytes.len()
            )
        })?;

        let agg_inputs = AggregationInputs {
            boot_infos: vec![boot_info],
            // tz has no L1 derivation; the on-chain verifier expects ZERO.
            latest_l1_checkpoint_head: B256::ZERO,
            multi_block_vkey: self.prover.keys().range_vk.hash_u32(),
            prover_address: self.signer.address(),
        };
        let agg_stdin = aggregation_stdin(
            vec![range_proof.proof.clone()],
            &self.prover.keys().range_vk,
            &agg_inputs,
        )?;

        tracing::info!("tz: generating aggregation proof");
        let agg_proof = self.prover.generate_agg_proof(agg_stdin).await?;
        Ok(agg_proof.bytes().into())
    }
}

/// Build the SP1Stdin for the tz aggregation guest: write each compressed range
/// proof + its vkey, then the `AggregationInputs` body.
fn aggregation_stdin(
    compressed_proofs: Vec<SP1Proof>,
    range_vk: &SP1VerifyingKey,
    agg_inputs: &AggregationInputs,
) -> Result<SP1Stdin> {
    let mut stdin = SP1Stdin::new();
    for proof in compressed_proofs {
        let SP1Proof::Compressed(compressed) = proof else {
            return Err(anyhow::anyhow!(
                "aggregation_stdin: range proofs must be Compressed variant"
            ));
        };
        stdin.write_proof(*compressed, range_vk.vk.clone());
    }
    stdin.write(agg_inputs);
    Ok(stdin)
}
