// TZ-specific implementations of `OPSuccinctProposer` methods whose logic diverges
// substantially from the xlayer path.
//
// Declared as a child module of `proposer` (via `#[path]`), so `use super::*` gives access to
// all types and private fields from proposer.rs without changing their visibility.

use super::*;

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
        range_elf: &'static [u8],
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
            // tz: range_elf is a placeholder (0 bytes) until Phase 2; in mock mode substitute
            // AGGREGATION_ELF so key derivation succeeds.
            let effective_range_elf = if config.mock_mode && range_elf.is_empty() {
                AGGREGATION_ELF
            } else {
                range_elf
            };
            let range_pk = np.setup(Elf::Static(effective_range_elf)).await?;
            let range_vk = range_pk.verifying_key().clone();
            let agg_pk = np.setup(Elf::Static(AGGREGATION_ELF)).await?;
            let agg_vk = agg_pk.verifying_key().clone();
            (range_pk, range_vk, agg_pk, agg_vk, Some(np), Some(nm))
        };

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
    /// Mock mode: SP1MockVerifier only checks `proofBytes.length == 0`, so we pass empty bytes.
    ///
    /// Real mode: not yet implemented (Phase 2).
    #[tracing::instrument(name = "[[Proving]]", skip(self), fields(game_address = ?game_address))]
    pub async fn prove_game(
        &self,
        game_address: Address,
        _start_block: u64,
        _end_block: u64,
    ) -> Result<(TxHash, u64, u64)> {
        if !self.config.mock_mode {
            anyhow::bail!("TZ real proving is not yet implemented; set MOCK_MODE=true");
        }

        let game = OPSuccinctFaultDisputeGame::new(game_address, self.l1_provider.clone());
        let transaction_request =
            game.prove(alloy_primitives::Bytes::new()).into_transaction_request();

        tracing::info!(game_address = ?game_address, "tz: submitting mock proof (empty bytes)");

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
            "tz: mock proof submitted"
        );
        Ok((receipt.transaction_hash, 0, 0))
    }
}
