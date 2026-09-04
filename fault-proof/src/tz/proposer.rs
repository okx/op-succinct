// TZ-specific implementations of `OPSuccinctProposer` methods whose logic diverges
// substantially from the xlayer path.
//
// Declared as a child module of `proposer` (via `#[path]`), so `use super::*` gives access to
// all types and private fields from proposer.rs without changing their visibility.

use super::*;
use futures::stream::{self, StreamExt, TryStreamExt};
use op_succinct_client_utils::types::AggregationInputs;
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues, SP1VerifyingKey};

/// Default chunk size (in blocks) for `fetch_blocks_range` when `TZ_BLOCKS_PER_FETCH`
/// is absent, non-positive, or unparseable.
const DEFAULT_TZ_BLOCKS_PER_FETCH: u64 = 1000;

fn bytes_to_mb(bytes: usize) -> f64 {
    bytes as f64 / 1024.0 / 1024.0
}

/// Resolve the `TZ_BLOCKS_PER_FETCH` chunk size from its raw env value.
///
/// Absent, non-positive (`0`), or unparseable values fall back to
/// [`DEFAULT_TZ_BLOCKS_PER_FETCH`] (1000). Extracted as a pure function so the
/// fallback semantics are unit-testable without touching process env.
fn resolve_blocks_per_fetch(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_TZ_BLOCKS_PER_FETCH)
}

/// Compute the per-chunk `fetch_blocks_range` argument pairs for one sub-range.
///
/// The DexState snapshot is the post-state of block `start`, so the blocks to replay are
/// the half-open interval `(start, end]` (first block = `start + 1`). They are fetched in
/// chunks of at most `blocks_per_fetch` blocks. Chunk `i` (1-based) covers
/// `(start + (i-1)·M, min(end, start + i·M)]`, returned here as the inclusive
/// `fetch_blocks_range(chunk_start, chunk_end)` argument pair. The number of chunks equals
/// `ceil((end - start) / blocks_per_fetch)`.
///
/// Pure function (no I/O) so the chunk arithmetic is unit-testable in isolation; the real
/// snapshot/blocks fetch + stdin assembly is exercised end-to-end.
fn compute_chunks(start: u64, end: u64, blocks_per_fetch: u64) -> Vec<(u64, u64)> {
    let total = end.saturating_sub(start);
    let step = blocks_per_fetch.max(1);
    let chunk_count = total.div_ceil(step);
    let mut chunks = Vec::with_capacity(chunk_count as usize);
    let mut cur = start.saturating_add(1);
    for _ in 0..chunk_count {
        let chunk_end = cur.saturating_add(step - 1).min(end);
        chunks.push((cur, chunk_end));
        cur = chunk_end.saturating_add(1);
    }
    chunks
}

/// The SOLE producer of the range-guest stdin boundary block (items ③–⑧ of the canonical order,
/// Spec §R4.3 — supersedes the R3 §R3.2 8-item table). Field order + types are isomorphic to the
/// guest read (`programs/tz/range/src/main.rs`): `tz_chain_id: u64`, then **`block_hash: B256`
/// (R4)**, then `(withdrawal_count: u32, withdrawal_branches: Vec<B256>)`, then
/// `(force_count: u32, force_branches: Vec<B256>)`. `block_hash` sits right after `tz_chain_id`
/// and before `withdrawal_count`, mirroring the upstream `TreeBoundaryResponse`. Branches are
/// `Vec<B256>` (SP1 serde `write`/`read`), NOT flat bytes — matching `io::read::<Vec<B256>>()`.
#[cfg(feature = "tz")]
pub(crate) struct BoundaryStdinFields {
    pub chain_id: u64,
    pub block_hash: alloy_primitives::B256,
    pub withdrawal_count: u32,
    pub withdrawal_branches: Vec<alloy_primitives::B256>,
    pub force_count: u32,
    pub force_branches: Vec<alloy_primitives::B256>,
}

/// Build the boundary stdin block from the TZ chain id (single Host source — CheckpointV2 envelope
/// or `TzConfig`) and the `TreeBoundaryWitness` (R2 #2/#3: no chain_id; R4: carries `block_hash`).
#[cfg(feature = "tz")]
pub(crate) fn boundary_stdin_fields(
    tz_chain_id: u64,
    w: &crate::tz::withdraw::types::TreeBoundaryWitness,
) -> BoundaryStdinFields {
    BoundaryStdinFields {
        chain_id: tz_chain_id,
        block_hash: w.block_hash,
        withdrawal_count: w.withdrawal_count,
        withdrawal_branches: w.withdrawal_active_branches.clone(),
        force_count: w.force_count,
        force_branches: w.force_active_branches.clone(),
    }
}

/// Proposer pre-proving boundary↔snapshot consistency check (spec §R4.2-2): the WB tree-boundary at
/// `start_block` MUST carry the same canonical block hash the guest will read from the snapshot as
/// `state.context.block_hash`. A mismatch means the WB returned a boundary for the wrong block
/// (e.g. a reorged block at the right height) — hard-fail BEFORE proving, never a warning. Pure +
/// unit-testable (mirrors [`assert_extra_data_self_consistent`]'s shape).
#[cfg(feature = "tz")]
pub(crate) fn assert_boundary_consistent(
    boundary: &crate::tz::withdraw::types::TreeBoundaryWitness,
    expected_block_hash: alloy_primitives::B256,
) -> anyhow::Result<()> {
    if boundary.block_hash != expected_block_hash {
        anyhow::bail!(
            "tz: boundary block_hash {:?} != canonical block hash {:?} at start_block",
            boundary.block_hash,
            expected_block_hash
        );
    }
    Ok(())
}

/// Proposer pre-Game self-consistency check (spec §7.2): the four-preimage `extraData` the
/// proposer is about to write MUST hash to the `expected_root_claim` it intends to commit,
/// otherwise the on-chain `_checkRootClaimCommitment` would revert. Pure + unit-testable.
#[cfg(feature = "tz")]
pub(crate) fn assert_extra_data_self_consistent(
    extra: &[u8],
    expected_root_claim: alloy_primitives::B256,
) -> anyhow::Result<()> {
    let pre = crate::tz::withdraw::claim::decode_four_preimage_extra_data(extra)?;
    let computed = crate::tz::withdraw::claim::claim_root(
        pre.block_hash,
        pre.app_hash,
        pre.withdrawal_root,
        pre.force_root,
    );
    if computed != expected_root_claim {
        anyhow::bail!("tz: extraData four-preimage does not hash to the intended rootClaim");
    }
    Ok(())
}

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
        // Four-field CheckpointV2 preimage at the proposal height (single fetch + cross-check
        // inside the provider). The submitted `rootClaim` is the four-field `claimRoot`,
        // and the SAME four fields encode the 164-byte extraData — one source, no forked
        // recompute (spec §R3.3).
        let mut preimage = self
            .l2_provider
            .fetch_checkpoint_preimage_at_block(next_l2_block_number_for_proposal)
            .await?;
        preimage.parent_index = parent_game_index;
        let output_root = crate::tz::l2_provider::compute_tz_root_claim(
            preimage.block_hash,
            preimage.app_hash,
            preimage.withdrawal_root,
            preimage.force_root,
        );
        // 164-byte four-field extraData via the SOLE encoder (never hand-rolled here).
        let extra_data =
            crate::tz::withdraw::claim::encode_four_preimage_extra_data(&preimage).to_vec();
        // Host mirror of the on-chain `_checkRootClaimCommitment`: the extraData four-preimage MUST
        // hash to the `rootClaim` we are about to submit, else abort BEFORE sending any transaction
        // (on-chain this else-branch is `revert InvalidRootClaimPreimage()`). Spec §R3.3.
        assert_extra_data_self_consistent(&extra_data, output_root)?;

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
    /// Fetches the DexState snapshot + `Vec<Block>` from the tz chain (single segment),
    /// generates a compressed range proof, then wraps it into an aggregation proof (Plonk or
    /// Groth16 per `AGG_PROOF_MODE`). Submits the proof bytes to
    /// `OPSuccinctFaultDisputeGame.prove`.
    ///
    /// In mock mode the same fetch path runs and range/agg guests `execute` (no real
    /// proving) via `ProofProvider::Mock`. `SP1ProofWithPublicValues::bytes()` returns
    /// empty bytes for mock Plonk/Groth16 proofs, satisfying `SP1MockVerifier`'s
    /// `proofBytes.length == 0` assertion.
    #[tracing::instrument(name = "[[Proving]]", skip(self), fields(game_address = ?game_address))]
    pub async fn prove_game(
        &self,
        game_address: Address,
        start_block: u64,
        end_block: u64,
    ) -> Result<(TxHash, u64, u64)> {
        let game = OPSuccinctFaultDisputeGame::new(game_address, self.l1_provider.clone());

        // Read game.l1Head() (CWIA arg stamped by DGF at create time). The aggregation
        // program commits this same value end-to-end so on-chain prove() check
        // `publicValues.l1Head == Hash.unwrap(game.l1Head())` succeeds.
        let game_l1_head = B256::from(game.l1Head().call().await?.0);

        // Mock mode is handled inside `tz_prove` via the `ProofProvider::Mock` backend:
        // the same fetch path (snapshot + blocks) runs, range/agg guests execute (no real
        // proving), and `create_mock_proof` packs the public values into proof bytes that
        // the on-chain `SP1MockVerifier` accepts. This mirrors the non-tz proposer mock
        // pattern and catches guest-side regressions that an empty-bytes shortcut would
        // miss.
        let proof_bytes = self.tz_prove(start_block, end_block, game_l1_head).await?;

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

    /// Run the twin-layer prove pipeline: split `(start_block, end_block]` into N
    /// (1 ≤ N ≤ 16) contiguous sub-ranges, prove each concurrently (capped at
    /// `min(max_concurrent_range_proofs, N)`), then aggregate the N compressed range
    /// proofs into a single aggregation proof. Returns the wrapped proof bytes ready for
    /// `OPSuccinctFaultDisputeGame.prove`.
    ///
    /// Mirrors the generic (non-tz) `prove_game` split→`buffer_unordered`→aggregate form
    /// (`proposer.rs:1240-1262`) but keeps the tz-specific Solidity-ABI `abi_decode` of
    /// `BootInfoStruct` (the non-tz path uses bincode `public_values.read()`).
    ///
    /// At `RANGE_SPLIT_COUNT=1` this is byte-equivalent to the previous single-segment
    /// implementation: `split` returns `vec![(start, end)]`, so one sub-range is proven and
    /// `AggregationInputs.boot_infos` has length 1.
    ///
    /// `game_l1_head` is the on-chain game.l1Head() CWIA arg; the aggregation guest commits
    /// this value to AggregationOutputs.l1Head so the on-chain prove() verifier passes.
    async fn tz_prove(
        &self,
        start_block: u64,
        end_block: u64,
        game_l1_head: B256,
    ) -> Result<alloy_primitives::Bytes> {
        // Split into N contiguous, non-overlapping sub-ranges (reuses the same contract as
        // the generic proposer). N=1 → vec![(start, end)] → byte-equivalent to single-segment.
        let ranges = self
            .config
            .range_split_count
            .split(start_block, end_block)
            .context("tz: failed to split range for proving")?;
        let num_ranges = ranges.len();
        tracing::info!(num_ranges, "tz: proving over {num_ranges} sub-range(s)");

        // One future per sub-range; each clones the proposer so the futures can run
        // concurrently. The signer is acquired only at the final on-chain submit
        // (in `prove_game`), never per sub-range, preserving SignerLock nonce ordering.
        let tasks = ranges.into_iter().enumerate().map(|(idx, (start, end))| {
            let this = self.clone();
            async move {
                let (range_proof, boot_info) = this.tz_range_proof(start, end).await?;
                Ok::<_, anyhow::Error>((idx, range_proof, boot_info))
            }
        });

        // Concurrency cap min(C, N); `try_collect` aborts on the first Err — not-yet-started
        // futures are never polled and in-flight futures are dropped (remote cleanup is not
        // guaranteed; the proposer loop re-spawns the task on the next tick).
        let max_concurrent = self.config.max_concurrent_range_proofs.get().min(num_ranges);
        let results: Vec<(usize, SP1ProofWithPublicValues, BootInfoStruct)> =
            stream::iter(tasks).buffer_unordered(max_concurrent).try_collect().await?;

        // `buffer_unordered` yields results out of completion order; reorder by sub-range
        // index so boot_infos form a contiguous chain for the aggregation guest's link check.
        let mut proofs = vec![None; num_ranges];
        let mut boot_infos = vec![None; num_ranges];
        for (idx, range_proof, boot_info) in results {
            proofs[idx] = Some(range_proof.proof.clone());
            boot_infos[idx] = Some(boot_info);
        }
        let proofs = proofs
            .into_iter()
            .enumerate()
            .map(|(idx, proof)| {
                proof.ok_or_else(|| anyhow::anyhow!("tz: missing proof for range index {idx}"))
            })
            .collect::<Result<Vec<SP1Proof>>>()?;
        let boot_infos = boot_infos
            .into_iter()
            .enumerate()
            .map(|(idx, boot)| {
                boot.ok_or_else(|| anyhow::anyhow!("tz: missing boot info for range index {idx}"))
            })
            .collect::<Result<Vec<BootInfoStruct>>>()?;

        let agg_inputs = AggregationInputs {
            boot_infos,
            // Pass-through: the aggregation guest commits this to AggregationOutputs.l1Head;
            // the on-chain prove() reads the same value via Hash.unwrap(game.l1Head()).
            latest_l1_checkpoint_head: game_l1_head,
            multi_block_vkey: self.prover.keys().range_vk.hash_u32(),
            prover_address: self.signer.address(),
        };
        let agg_stdin = aggregation_stdin(proofs, &self.prover.keys().range_vk, &agg_inputs)?;

        tracing::info!("tz: generating aggregation proof");
        let agg_proof = self.prover.generate_agg_proof(agg_stdin).await?;
        Ok(agg_proof.bytes().into())
    }

    /// Prove a single sub-range `(start_block, end_block]`: fetch the DexState snapshot at
    /// `start_block`, fetch the blocks in chunks, optionally run a local CPU execute, generate
    /// a compressed range proof, and `abi_decode` its `BootInfoStruct`.
    ///
    /// Returns the proof together with its decoded boot info so the caller can reorder the
    /// per-sub-range results and assemble the aggregation inputs.
    async fn tz_range_proof(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> Result<(SP1ProofWithPublicValues, BootInfoStruct)> {
        tracing::info!(
            start_block,
            end_block,
            "tz: fetching witness (snapshot + blocks) from tz chain"
        );
        let witness_fetch_started_at = std::time::Instant::now();
        let snapshot_fetch_started_at = std::time::Instant::now();
        let snapshot = self.l2_provider.fetch_dex_state_snapshot(start_block).await?;
        let snapshot_fetch_elapsed = snapshot_fetch_started_at.elapsed();
        let snapshot_bytes = snapshot.len();
        tracing::info!(
            start_block,
            elapsed_ms = snapshot_fetch_elapsed.as_millis() as u64,
            bytes = snapshot_bytes,
            size_mb = bytes_to_mb(snapshot_bytes),
            "tz: snapshot fetch complete"
        );

        let tz_blocks_per_fetch =
            resolve_blocks_per_fetch(std::env::var("TZ_BLOCKS_PER_FETCH").ok().as_deref());
        // snapshot is the post-state of block `start_block`; the blocks to replay are
        // (start_block, end_block] — i.e. starting from start_block + 1 (see `compute_chunks`).
        let chunks = compute_chunks(start_block, end_block, tz_blocks_per_fetch);
        let total_blocks = end_block.saturating_sub(start_block);
        let chunk_count: u32 = chunks.len().try_into().context("chunk_count overflows u32")?;

        let mut range_stdin = SP1Stdin::new();
        range_stdin.write_vec(snapshot); // ① snapshot
        range_stdin.write(&chunk_count); // ② chunk_count

        // ③–⑧ boundary block: the TZ chain id + the sub-range-start boundary `block_hash` (R4) +
        // the two-tree boundary the guest re-expands into pre-roots (spec §R4.3 canonical stdin
        // order). Produced ONLY by `boundary_stdin_fields`; the snapshot is the post-state of
        // `start_block`, so the boundary is taken at `start_block` (matching the guest's
        // `frontier_from_boundary`). This is a vkey-affecting change — Host write and guest read
        // land together (Task 5).
        let tz_chain_id = self.l2_provider.tz_chain_id().ok_or_else(|| {
            anyhow::anyhow!(
                "tz: range proof requires a configured TZ chain id (witness-builder client)"
            )
        })?;
        let boundary_witness = self.l2_provider.fetch_tree_boundary_witness(start_block).await?;
        // R4 §R4.2-2 hard-fail cross-check: the boundary's block_hash MUST equal the canonical
        // block hash at `start_block` — the same value the guest reads from the snapshot as
        // `state.context.block_hash`. Single independent source: the confirmed-block-info block
        // hash at `start_block` (via the checkpoint preimage). Mismatch ⇒ abort, no proof.
        let expected_block_hash = self
            .l2_provider
            .fetch_checkpoint_preimage_at_block(U256::from(start_block))
            .await?
            .block_hash;
        assert_boundary_consistent(&boundary_witness, expected_block_hash)?;
        let bf = boundary_stdin_fields(tz_chain_id, &boundary_witness);
        range_stdin.write(&bf.chain_id); // ③ tz_chain_id
        range_stdin.write(&bf.block_hash); // ④ block_hash (R4)
        range_stdin.write(&bf.withdrawal_count); // ⑤
        range_stdin.write(&bf.withdrawal_branches); // ⑥
        range_stdin.write(&bf.force_count); // ⑦
        range_stdin.write(&bf.force_branches); // ⑧

        let mut blocks_bytes = 0usize;
        for (chunk_start, chunk_end) in &chunks {
            let chunk = self.l2_provider.fetch_blocks_range(*chunk_start, *chunk_end).await?;
            blocks_bytes += chunk.len();
            range_stdin.write_vec(chunk);
        }
        let witness_fetch_elapsed = witness_fetch_started_at.elapsed();
        let witness_bytes = snapshot_bytes + blocks_bytes;
        tracing::info!(
            start_block,
            end_block,
            total_blocks,
            chunk_count,
            tz_blocks_per_fetch,
            snapshot_bytes,
            snapshot_size_mb = bytes_to_mb(snapshot_bytes),
            blocks_bytes,
            blocks_size_mb = bytes_to_mb(blocks_bytes),
            witness_bytes,
            witness_size_mb = bytes_to_mb(witness_bytes),
            elapsed_ms = witness_fetch_elapsed.as_millis() as u64,
            "tz: witness fetch complete"
        );

        if std::env::var("TZ_LOCAL_EXECUTE").ok().as_deref() == Some("1") {
            tracing::info!("tz: TZ_LOCAL_EXECUTE=1 — running range guest on local CPU first");
            let cpu = sp1_sdk::ProverClient::builder().cpu().build().await;
            match cpu.execute(Elf::Static(get_range_elf_embedded()), range_stdin.clone()).await {
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
        let boot_info = BootInfoStruct::abi_decode(range_proof.public_values.as_slice())
            .map_err(|e| anyhow::anyhow!("tz: failed to abi_decode range BootInfoStruct: {e}"))?;

        Ok((range_proof, boot_info))
    }
}

/// Validate that a range proof is the `Compressed` variant required by the aggregation guest.
///
/// Extracted from `aggregation_stdin` so the variant guard is unit-testable without
/// constructing an `SP1VerifyingKey` (which has no cheap test constructor): the guard itself
/// does not depend on the verifying key.
fn ensure_compressed(proof: &SP1Proof) -> Result<()> {
    if matches!(proof, SP1Proof::Compressed(_)) {
        Ok(())
    } else {
        Err(anyhow::anyhow!("aggregation_stdin: range proofs must be Compressed variant"))
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
        ensure_compressed(&proof)?;
        // Guaranteed Compressed by `ensure_compressed` above.
        if let SP1Proof::Compressed(compressed) = proof {
            stdin.write_proof(*compressed, range_vk.vk.clone());
        }
    }
    stdin.write(agg_inputs);
    Ok(stdin)
}

#[cfg(test)]
mod tests {
    use super::{compute_chunks, resolve_blocks_per_fetch, DEFAULT_TZ_BLOCKS_PER_FETCH};
    use crate::config::RangeSplitCount;
    use anyhow::{bail, Result};
    use futures::stream::{self, StreamExt, TryStreamExt};
    use rstest::rstest;
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    // ---------------- MT-1: chunk arithmetic (DM-2.1 / 2.2 / 2.3) ----------------
    // Pure-logic coverage of `compute_chunks` + `resolve_blocks_per_fetch`. The real
    // snapshot/blocks fetch + stdin assembly is exercised by E2E-4.

    #[rstest]
    // DM-2.1: total=200, M=1000 -> chunk_count=1, single chunk (start+1, end)
    #[case::single_chunk(1000, 1200, 1000, vec![(1001, 1200)])]
    // DM-2.2: total=2500, M=1000 -> chunk_count=3
    #[case::three_chunks(0, 2500, 1000, vec![(1, 1000), (1001, 2000), (2001, 2500)])]
    // exact multiple boundary: total=2000, M=1000 -> 2 full chunks, no trailing partial
    #[case::exact_multiple(0, 2000, 1000, vec![(1, 1000), (1001, 2000)])]
    // single-block sub-range
    #[case::single_block(5, 6, 1000, vec![(6, 6)])]
    fn compute_chunks_covers_half_open_interval(
        #[case] start: u64,
        #[case] end: u64,
        #[case] m: u64,
        #[case] expected: Vec<(u64, u64)>,
    ) {
        let chunks = compute_chunks(start, end, m);
        assert_eq!(chunks, expected, "start={start} end={end} m={m}");

        // chunk_count = ceil(total / M)
        let total = end - start;
        assert_eq!(chunks.len() as u64, total.div_ceil(m), "chunk_count mismatch");

        // first block = start + 1 (half-open (start, end]); last chunk ends at `end`.
        assert_eq!(chunks.first().unwrap().0, start + 1, "first block must be start+1");
        assert_eq!(chunks.last().unwrap().1, end, "last chunk must end at end");

        // contiguous, non-overlapping: each chunk resumes one past the previous end.
        for pair in chunks.windows(2) {
            assert_eq!(pair[0].1 + 1, pair[1].0, "chunks must be contiguous");
        }
    }

    #[rstest]
    #[case::present(Some("500"), 500)]
    #[case::absent(None, DEFAULT_TZ_BLOCKS_PER_FETCH)]
    #[case::zero(Some("0"), DEFAULT_TZ_BLOCKS_PER_FETCH)]
    #[case::non_numeric(Some("abc"), DEFAULT_TZ_BLOCKS_PER_FETCH)]
    #[case::negative(Some("-5"), DEFAULT_TZ_BLOCKS_PER_FETCH)]
    fn resolve_blocks_per_fetch_falls_back_to_default(
        #[case] raw: Option<&str>,
        #[case] expected: u64,
    ) {
        assert_eq!(resolve_blocks_per_fetch(raw), expected);
    }

    #[test]
    fn unparseable_m_chunks_as_default() {
        // DM-2.3: absent / 0 / "abc" -> chunking proceeds as if M=1000.
        let m = resolve_blocks_per_fetch(Some("abc"));
        assert_eq!(compute_chunks(0, 2500, m), vec![(1, 1000), (1001, 2000), (2001, 2500)]);
    }

    // ---------------- MT-2: index reorder (supports DM-1.2) ----------------
    // Toy mirror of the `vec![None; N]` + index-assign + `ok_or_else` block in `tz_prove`.
    // `buffer_unordered` yields out of completion order; the reorder must restore sub-range
    // order and surface a missing index as `Err` (never `.expect()` / panic).

    fn reorder<T>(num: usize, items: Vec<(usize, T)>) -> Result<Vec<T>> {
        let mut slots: Vec<Option<T>> = (0..num).map(|_| None).collect();
        for (idx, payload) in items {
            slots[idx] = Some(payload);
        }
        slots
            .into_iter()
            .enumerate()
            .map(|(idx, slot)| {
                slot.ok_or_else(|| anyhow::anyhow!("missing payload for range index {idx}"))
            })
            .collect()
    }

    #[test]
    fn reorder_restores_subrange_order_from_arbitrary_completion() {
        let items = vec![(2, 'c'), (0, 'a'), (3, 'd'), (1, 'b')];
        assert_eq!(reorder(4, items).unwrap(), vec!['a', 'b', 'c', 'd']);
    }

    #[test]
    fn reorder_errors_on_missing_index_without_panic() {
        let err = reorder(3, vec![(0, 'a'), (2, 'c')]).unwrap_err();
        assert!(err.to_string().contains("range index 1"), "got: {err}");
    }

    // ---------------- MT-3 / MT-4: shared toy prove closures ----------------

    async fn mock_prove(idx: usize, fail: bool, started: Arc<AtomicUsize>) -> Result<usize> {
        started.fetch_add(1, Ordering::SeqCst);
        if fail {
            bail!("tz: proof failed for range index {idx}");
        }
        Ok(idx)
    }

    async fn prove_ranges(
        ranges: Vec<(u64, u64)>,
        fail_idx: Option<usize>,
        concurrency: usize,
        started: Arc<AtomicUsize>,
    ) -> Result<Vec<usize>> {
        let tasks = ranges.into_iter().enumerate().map(|(idx, _range)| {
            let fail = fail_idx == Some(idx);
            let started = started.clone();
            async move { mock_prove(idx, fail, started).await }
        });
        stream::iter(tasks).buffer_unordered(concurrency).try_collect().await
    }

    // MT-3: failure-abort (DM-1.5). One sub-range fails -> try_collect resolves Err whose
    // message identifies the failing range; not-yet-started tasks are never polled.
    #[rstest]
    #[case::first(0)]
    #[case::middle(1)]
    #[case::last(3)]
    #[tokio::test]
    async fn failure_aborts_and_stops_pulling(#[case] fail_idx: usize) {
        let ranges = RangeSplitCount::new(4).unwrap().split(0, 100).unwrap();
        let started = Arc::new(AtomicUsize::new(0));
        // concurrency = 1 so futures start strictly in index order; once the failing index
        // aborts, `buffer_unordered` stops pulling, so no later task is ever started.
        let err = prove_ranges(ranges, Some(fail_idx), 1, started.clone()).await.unwrap_err();
        assert!(err.to_string().contains(&format!("range index {fail_idx}")), "got: {err}");
        assert!(
            started.load(Ordering::SeqCst) <= fail_idx + 1,
            "started {} tasks; expected <= {} (later tasks must not start)",
            started.load(Ordering::SeqCst),
            fail_idx + 1
        );
    }

    // MT-4: concurrency + throttle (DM-1.3 / DM-1.6) via a deterministic in-flight gauge —
    // no wall-clock timestamp assertions.
    async fn gauged_prove(
        idx: usize,
        in_flight: Arc<AtomicUsize>,
        max_seen: Arc<AtomicUsize>,
    ) -> Result<usize> {
        let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        max_seen.fetch_max(now, Ordering::SeqCst);
        // Hold the slot briefly so overlapping tasks are observable on the gauge.
        tokio::time::sleep(Duration::from_millis(10)).await;
        in_flight.fetch_sub(1, Ordering::SeqCst);
        Ok(idx)
    }

    async fn run_gauged(num: u8, concurrency: usize) -> (Vec<usize>, usize) {
        let ranges = RangeSplitCount::new(num).unwrap().split(0, num as u64 * 100).unwrap();
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let tasks = ranges.into_iter().enumerate().map(|(idx, _range)| {
            let in_flight = in_flight.clone();
            let max_seen = max_seen.clone();
            async move { gauged_prove(idx, in_flight, max_seen).await }
        });
        let mut results: Vec<usize> =
            stream::iter(tasks).buffer_unordered(concurrency).try_collect().await.unwrap();
        results.sort_unstable();
        (results, max_seen.load(Ordering::SeqCst))
    }

    #[tokio::test]
    async fn concurrency_runs_in_parallel_not_serial() {
        // DM-1.3: C>1, N>=2 -> observed max_in_flight > 1 and reorder yields 0..N.
        let (indices, max_in_flight) = run_gauged(4, 4).await;
        assert_eq!(indices, vec![0, 1, 2, 3]);
        assert!(max_in_flight > 1, "expected concurrent execution, max_in_flight={max_in_flight}");
    }

    #[tokio::test]
    async fn concurrency_is_throttled_to_cap() {
        // DM-1.6: N=16, C=8 -> all 16 complete, <=8 in flight at once, indices 0..16.
        let (indices, max_in_flight) = run_gauged(16, 8).await;
        assert_eq!(indices, (0..16).collect::<Vec<_>>());
        assert!(max_in_flight <= 8, "throttle breached, max_in_flight={max_in_flight}");
        assert!(max_in_flight > 1, "expected concurrency, max_in_flight={max_in_flight}");
    }

    // ---------------- MT-6: env validation (DM-4.3) ----------------
    // `ProposerConfig::from_env` parses RANGE_SPLIT_COUNT via
    // `env::var(..).parse::<RangeSplitCount>()` — i.e. `RangeSplitCount::from_str`. Testing
    // that parse path directly validates the rejection contract without mutating process-global
    // env (racy across parallel tests) or supplying the dozen unrelated vars `from_env`
    // requires.

    #[rstest]
    #[case::zero("0")]
    #[case::too_big("17")]
    fn range_split_count_rejects_out_of_range(#[case] raw: &str) {
        let err = raw.parse::<RangeSplitCount>().unwrap_err();
        assert!(
            err.to_string().contains(&format!("range splits must be between 1 and 16, got {raw}")),
            "got: {err}"
        );
    }

    #[test]
    fn range_split_count_rejects_non_numeric() {
        assert!("abc".parse::<RangeSplitCount>().is_err());
    }

    // ---------------- MT-5: aggregation_stdin Compressed guard (DM-3.2) ----------------
    // Direct test of the real guard `aggregation_stdin` applies to each range proof. A
    // non-Compressed variant must be rejected with the exact message. `SP1VerifyingKey` has
    // no cheap test constructor, so the guard was extracted to `ensure_compressed` (vk-free).

    #[test]
    fn ensure_compressed_rejects_non_compressed_variant() {
        // Plonk is a non-Compressed variant (PlonkBn254Proof derives Default).
        let proof = sp1_sdk::SP1Proof::Plonk(Default::default());
        let err = super::ensure_compressed(&proof).unwrap_err();
        assert_eq!(err.to_string(), "aggregation_stdin: range proofs must be Compressed variant");
    }
}

#[cfg(all(test, feature = "tz"))]
mod tz_boundary_tests {
    use super::{
        assert_boundary_consistent, assert_extra_data_self_consistent, boundary_stdin_fields,
    };
    use crate::tz::withdraw::{claim::claim_root, types::TreeBoundaryWitness};
    use alloy_primitives::B256;

    /// A minimal valid boundary carrying `block_hash` (R4). popcount(3) == 2 withdrawal branches.
    fn boundary_with(block_hash: B256) -> TreeBoundaryWitness {
        TreeBoundaryWitness {
            schema_version: 2,
            block_height: 50,
            block_hash,
            withdrawal_count: 3,
            withdrawal_active_branches: vec![B256::repeat_byte(0x11), B256::repeat_byte(0x22)],
            force_count: 0,
            force_active_branches: vec![],
        }
    }

    #[test]
    fn boundary_stdin_fields_orders_chain_id_first_then_two_trees() {
        // R2 removed `chain_id` from the witness; the chain id now enters via the producer argument
        // (single Host source) and is the FIRST stdin field (guest reads it as stdin item ③).
        let f = boundary_stdin_fields(196, &boundary_with(B256::repeat_byte(0xbb)));
        assert_eq!(f.chain_id, 196);
        assert_eq!(f.withdrawal_count, 3);
        // popcount(3) == 2 branches, carried as `Vec<B256>` (the guest reads `Vec<B256>` via SP1
        // serde `read()`, NOT flat bytes) and preserved in order.
        assert_eq!(f.withdrawal_branches, vec![B256::repeat_byte(0x11), B256::repeat_byte(0x22)]);
        assert_eq!(f.force_count, 0);
        assert!(f.force_branches.is_empty());
    }

    #[test]
    fn boundary_stdin_fields_carries_block_hash_after_chain_id() {
        // R4 §R4.3: `block_hash` is stdin item ④ (right after `tz_chain_id`), taken from the
        // witness.
        let f = boundary_stdin_fields(196, &boundary_with(B256::repeat_byte(0x11)));
        assert_eq!(f.chain_id, 196);
        assert_eq!(f.block_hash, B256::repeat_byte(0x11));
    }

    #[test]
    fn assert_boundary_consistent_rejects_wrong_block() {
        // R4 §R4.2-2: equal ⇒ Ok; mismatch ⇒ hard Err (Host aborts before proving).
        let w = boundary_with(B256::repeat_byte(0x11));
        assert!(assert_boundary_consistent(&w, B256::repeat_byte(0x11)).is_ok());
        let err = assert_boundary_consistent(&w, B256::repeat_byte(0x22)).unwrap_err();
        assert!(err.to_string().contains("boundary block_hash"));
    }

    /// Build a 164-byte four-preimage extraData for the given fields (mirrors the CWIA layout).
    fn extra(bh: B256, ah: B256, wr: B256, fr: B256) -> [u8; 164] {
        let mut e = [0u8; 164];
        e[24..32].copy_from_slice(&100u64.to_be_bytes()); // l2BlockNumber
        e[32..36].copy_from_slice(&u32::MAX.to_be_bytes()); // parentIndex
        e[36..68].copy_from_slice(bh.as_slice());
        e[68..100].copy_from_slice(ah.as_slice());
        e[100..132].copy_from_slice(wr.as_slice());
        e[132..164].copy_from_slice(fr.as_slice());
        e
    }

    #[test]
    fn extra_data_self_consistency_accepts_matching_root_and_rejects_mismatch() {
        let (bh, ah, wr, fr) = (
            B256::repeat_byte(0x11),
            B256::repeat_byte(0x22),
            B256::repeat_byte(0x33),
            B256::repeat_byte(0x44),
        );
        let e = extra(bh, ah, wr, fr);
        let expected = claim_root(bh, ah, wr, fr);
        assert!(assert_extra_data_self_consistent(&e, expected).is_ok());
        // A different intended rootClaim ⇒ rejected (would revert on-chain).
        assert!(assert_extra_data_self_consistent(&e, B256::repeat_byte(0xEE)).is_err());
    }
}
