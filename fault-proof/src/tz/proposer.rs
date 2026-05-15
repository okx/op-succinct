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

    pub(super) async fn fetch_proposer_metrics(&self) -> Result<()> {
        let (canonical_head_l2_block, anchor_game) = {
            let state = self.state.read().await;
            (state.canonical_head_l2_block, state.anchor_game.clone())
        };

        if let Some(canonical_head_l2_block) = canonical_head_l2_block {
            ProposerGauge::LatestGameL2BlockNumber.set(canonical_head_l2_block.to::<u64>() as f64);
            // tz: skipped get_finalized_l2_block_number (requires eth_getBlockByNumber("finalized"))

            if let Some(anchor_game) = anchor_game {
                ProposerGauge::AnchorGameL2BlockNumber.set(anchor_game.l2_block.to::<u64>() as f64);
            } else {
                ProposerGauge::AnchorGameL2BlockNumber.set(0.0);
            }
        } else {
            tracing::warn!("canonical_head_l2_block is None; skipping metrics update");
        }

        let active_proving = self.count_active_proving_tasks().await;
        ProposerGauge::ActiveProvingTasks.set(active_proving as f64);

        Ok(())
    }

    pub(super) async fn should_create_game(&self) -> Result<(bool, U256, u32)> {
        if self.config.fast_finality_mode {
            let mut active_proving = self.count_active_proving_tasks().await;

            if active_proving < self.config.fast_finality_proving_limit {
                let signer_address = self.signer.address();

                let unproven_games = {
                    let state = self.state.read().await;
                    let tasks = self.tasks.lock().await;

                    let candidates = state
                        .games
                        .values()
                        .filter(|game| game.status == GameStatus::IN_PROGRESS)
                        .filter(|game| game.proposal_status == ProposalStatus::Unchallenged)
                        .map(|game| (game.index, game.address, game.deadline))
                        .collect::<Vec<_>>();

                    let proving_set = tasks
                        .values()
                        .filter_map(|(_, info)| match info {
                            TaskInfo::GameProving { game_address, .. } => Some(*game_address),
                            _ => None,
                        })
                        .collect::<HashSet<_>>();

                    candidates
                        .into_iter()
                        .filter(|(_, address, _)| !proving_set.contains(address))
                        .collect::<Vec<_>>()
                };

                let mut spawned_count = 0;

                for (index, game_address, deadline) in unproven_games {
                    if active_proving >= self.config.fast_finality_proving_limit {
                        tracing::debug!(
                            "Reached fast finality proving capacity ({}/{}) while resuming games",
                            active_proving,
                            self.config.fast_finality_proving_limit
                        );
                        break;
                    }

                    let contract =
                        OPSuccinctFaultDisputeGame::new(game_address, self.l1_provider.clone());
                    let creator = match contract.gameCreator().call().await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!(
                                ?game_address,
                                ?e,
                                "Failed to check game creator, skipping"
                            );
                            continue;
                        }
                    };

                    if creator != signer_address {
                        continue;
                    }

                    match self.spawn_game_proving_task(game_address, false, Some(deadline)).await {
                        Ok(true) => {
                            tracing::info!(
                                game_address = ?game_address,
                                game_index = %index,
                                "Resumed fast finality proving for existing game"
                            );
                            spawned_count += 1;
                            active_proving += 1;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            tracing::warn!(
                                ?game_address,
                                ?e,
                                "Failed to spawn proving task, continuing"
                            );
                        }
                    }
                }

                if spawned_count > 0 {
                    tracing::info!(
                        "Resumed proving for {} existing game(s), now at {}/{} capacity",
                        spawned_count,
                        active_proving,
                        self.config.fast_finality_proving_limit
                    );
                }
            }

            if active_proving >= self.config.fast_finality_proving_limit {
                tracing::info!(
                    "Skipping game creation: at proving capacity ({}/{})",
                    active_proving,
                    self.config.fast_finality_proving_limit
                );
                return Ok((false, U256::ZERO, u32::MAX));
            }
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

        if !self.on_chain_vkeys_match().await? {
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

    /// Creates a new proposer with an injected L2 provider, rollup config hash, and range ELF.
    /// Avoids optimism_rollupConfig RPC and allows a custom L2 data source.
    pub async fn new_with_l2_provider(
        config: ProposerConfig,
        signer: SignerLock,
        anchor_state_registry: AnchorStateRegistryInstance<P>,
        factory: DisputeGameFactoryInstance<P>,
        fetcher: Arc<OPSuccinctDataFetcher>,
        host: Arc<H>,
        l2_provider: Arc<dyn L2ProviderTrait + Send + Sync>,
        rollup_config_hash: B256,
        range_elf: &'static [u8],
    ) -> Result<Self> {
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
            let range_pk = np.setup(Elf::Static(range_elf)).await?;
            let range_vk = range_pk.verifying_key().clone();
            let agg_pk = np.setup(Elf::Static(AGGREGATION_ELF)).await?;
            let agg_vk = agg_pk.verifying_key().clone();
            (range_pk, range_vk, agg_pk, agg_vk, Some(np), Some(nm))
        };

        let aggregation_vkey = B256::from(agg_vk.bytes32_raw());
        let range_vkey_commitment = B256::from(range_vk.hash_bytes());
        let identity =
            ProposerIdentity::new(aggregation_vkey, range_vkey_commitment, rollup_config_hash);
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
        })
    }
}
