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
}
