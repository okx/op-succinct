// TZ-specific implementations of `OPSuccinctProposer` methods.
//
// Declared as a child module of `proposer` (via `#[path]`), so `use super::*` gives access to
// all types and private fields from proposer.rs without changing their visibility.

use super::*;

use crate::tz_chain_client::TzCacheMissError;

impl<P, H> OPSuccinctProposer<P, H>
where
    P: Provider + Clone + Send + Sync + 'static,
    H: OPSuccinctHost + Clone + Send + Sync + 'static,
{
    pub(super) async fn startup_validations(&self) -> Result<(U256, U256, ContractParams)> {
        Self::validate_anchor_state_registry(
            &self.anchor_state_registry,
            &self.factory,
            self.config.game_type,
        )
        .await?;

        let anchor_l2_block = self.anchor_state_registry.getAnchorRoot().call().await?._1;
        // for tz: skipped validate_anchor_l2_block (requires eth_getBlockByNumber("finalized"))

        let init_bond = self.factory.fetch_init_bond(self.config.game_type).await?;

        let game_impl = self.factory.game_impl(self.config.game_type).await?;
        let max_challenge_duration = game_impl.maxChallengeDuration().call().await?.to::<u64>();
        let max_prove_duration = game_impl.maxProveDuration().call().await?;
        let contract_params = ContractParams { max_challenge_duration, max_prove_duration };

        Ok((anchor_l2_block, init_bond, contract_params))
    }

    pub async fn sync_state(&self) -> Result<()> {
        self.sync_games().await?;
        self.sync_anchor_game().await?;
        self.compute_canonical_head().await;

        // for tz: evict history cache entries below anchor_height after each sync cycle
        let anchor_height = self
            .state
            .read()
            .await
            .anchor_game
            .as_ref()
            .map(|g| g.l2_block.to::<u64>())
            .unwrap_or(0);
        if anchor_height > 0 {
            self.l2_provider.evict_cache_below(anchor_height);
        }

        Ok(())
    }

    pub async fn fetch_game(&self, index: U256) -> Result<GameFetchResult> {
        {
            let state = self.state.read().await;
            if state.games.contains_key(&index) {
                return Ok(GameFetchResult::AlreadyExists);
            }
        }

        let game = self.factory.gameAtIndex(index).call().await?;
        let game_address = game.proxy;
        let game_type = game.gameType;

        if game_type != self.config.game_type {
            tracing::warn!(
                game_index = %index,
                ?game_address,
                game_type,
                expected_game_type = self.config.game_type,
                "Unsupported game type"
            );
            return Ok(GameFetchResult::UnsupportedType { game_address });
        }

        let contract = OPSuccinctFaultDisputeGame::new(game_address, self.l1_provider.clone());

        let game_asr = contract.anchorStateRegistry().call().await?;
        if game_asr != *self.anchor_state_registry.address() {
            tracing::warn!(
                game_index = %index,
                ?game_address,
                ?game_asr,
                expected = ?self.anchor_state_registry.address(),
                "Skipping game with different anchor state registry"
            );
            return Ok(GameFetchResult::UnsupportedAnchorStateRegistry { game_address });
        }

        let l2_block = contract.l2BlockNumber().call().await?;

        // for tz: cache miss — own games skip rootClaim validation; foreign games also enter
        // state.games to preserve canonical head tracking in multi-proposer deployments.
        // If tz supports querying stateHash by block number in the future, this special handling
        // can be removed and unified with xlayer.
        let maybe_output_root: Option<FixedBytes<32>> = match self
            .l2_provider
            .compute_output_root_at_block(l2_block)
            .await
        {
            Ok(root) => Some(root),
            Err(e) if e.downcast_ref::<TzCacheMissError>().is_some() => {
                let creator = contract.gameCreator().call().await?;
                if creator == self.signer.address() {
                    tracing::debug!(
                        game_index = %index,
                        l2_block_number = %l2_block,
                        "tz: cache miss — own game, skipping rootClaim validation"
                    );
                } else {
                    tracing::warn!(
                        game_index = %index,
                        l2_block_number = %l2_block,
                        %creator,
                        "tz: cache miss — foreign game, adding to state without rootClaim validation"
                    );
                }
                None
            }
            Err(e) => return Err(e),
        };

        let claim = contract.rootClaim().call().await?;
        let was_respected = contract.wasRespectedGameTypeWhenCreated().call().await?;
        let status = contract.status().call().await?;
        let claim_data = contract.claimData().call().await?;

        let (parent_index, proposal_status, deadline) = (
            claim_data.parentIndex,
            claim_data.status,
            U256::from(claim_data.deadline).to::<u64>(),
        );

        let aggregation_vkey = B256::from(contract.aggregationVkey().call().await?.0);
        let range_vkey_commitment = B256::from(contract.rangeVkeyCommitment().call().await?.0);
        let rollup_config_hash = B256::from(contract.rollupConfigHash().call().await?.0);

        if !was_respected {
            tracing::warn!(
                game_index = %index,
                ?game_address,
                game_type,
                expected_game_type = self.config.game_type,
                "Invalid game: game type was not respected when created"
            );
            return Ok(GameFetchResult::InvalidGame { index });
        }

        // for tz: skip rootClaim validation on cache miss; xlayer always validates
        if let Some(output_root) = maybe_output_root {
            if output_root != claim {
                tracing::warn!(
                    game_index = %index,
                    ?game_address,
                    ?claim,
                    expected_output_root = ?output_root,
                    "Invalid game: root claim does not match computed output root"
                );
                return Ok(GameFetchResult::InvalidGame { index });
            }
        }

        tracing::info!(
            game_index = %index,
            ?game_type,
            ?game_address,
            parent_index = %parent_index,
            l2_block = %l2_block,
            ?status,
            ?proposal_status,
            deadline = %deadline,
            "Valid game: adding to cache"
        );

        let game = Game {
            index,
            address: game_address,
            parent_index,
            l2_block,
            status,
            proposal_status,
            deadline,
            should_attempt_to_resolve: false,
            should_attempt_to_claim_bond: false,
            aggregation_vkey,
            range_vkey_commitment,
            rollup_config_hash,
        };

        if !game.is_owned(&self.identity) {
            tracing::info!(
                game_index = %index,
                "Discovered foreign game (proposer's identity params don't match on-chain params) - tracking for DAG but not proving/resolving/claiming"
            );
        }

        let mut state = self.state.write().await;
        state.games.insert(index, game);

        Ok(GameFetchResult::ValidGame { game_address, deadline })
    }

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

        // for tz: one-shot check — confirmed_height maps to exactly one rootClaim;
        // incrementing block number would not change rootClaim, so skip and wait for next
        // checkpoint
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
            // for tz: skipped get_finalized_l2_block_number (requires
            // eth_getBlockByNumber("finalized"))

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

        // for tz: use confirmed checkpoint height instead of eth_getBlockByNumber("finalized")
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
}
