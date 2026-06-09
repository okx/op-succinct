// TZ-specific implementations of `OPSuccinctProposer` methods whose logic diverges
// substantially from the xlayer path.
//
// Declared as a child module of `proposer` (via `#[path]`), so `use super::*` gives access to
// all types and private fields from proposer.rs without changing their visibility.

use super::*;
use std::io::Read;

use futures::{stream, StreamExt, TryStreamExt};
use op_succinct_client_utils::types::AggregationInputs;
use sp1_sdk::{SP1Proof, SP1VerifyingKey};
use tempfile::NamedTempFile;

fn bytes_to_mb(bytes: usize) -> f64 {
    bytes as f64 / 1024.0 / 1024.0
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

    /// Run the twin-layer prove pipeline (single segment): range proof → aggregation proof.
    /// Returns groth16-wrapped proof bytes ready for OPSuccinctFaultDisputeGame.prove.
    ///
    /// `game_l1_head` is the on-chain game.l1Head() CWIA arg; the aggregation guest commits
    /// this value to AggregationOutputs.l1Head so the on-chain prove() verifier passes.
    async fn tz_prove(
        &self,
        start_block: u64,
        end_block: u64,
        game_l1_head: B256,
    ) -> Result<alloy_primitives::Bytes> {
        tracing::info!(
            start_block,
            end_block,
            "tz: fetching witness (snapshot + blocks) from tz chain"
        );
        let witness_fetch_started_at = std::time::Instant::now();
        // snapshot is the post-state of block `start_block`; the blocks to replay are
        // (start_block, end_block] — i.e. starting from start_block + 1.
        let first_block = start_block.saturating_add(1);
        let total_blocks = end_block.saturating_sub(start_block);
        let block_fetch_config = TzBlockFetchConfig::from_env();

        let (snapshot, blocks_witness) = tokio::try_join!(
            self.fetch_tz_snapshot_for_witness(start_block),
            self.fetch_tz_blocks_witness(first_block, end_block, total_blocks, block_fetch_config)
        )?;
        let snapshot_bytes = snapshot.len();

        let mut range_stdin = SP1Stdin::new();
        range_stdin.write_vec(snapshot);
        let chunk_count = blocks_witness.chunk_count;
        let blocks_bytes = blocks_witness.blocks_bytes;
        blocks_witness.write_to_stdin(&mut range_stdin)?;

        let witness_fetch_elapsed = witness_fetch_started_at.elapsed();
        let witness_bytes = snapshot_bytes + blocks_bytes;
        tracing::info!(
            start_block,
            end_block,
            total_blocks,
            chunk_count,
            stream_frame_blocks = block_fetch_config.stream_frame_blocks,
            segment_stream_concurrency = block_fetch_config.segment_stream_concurrency,
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
        let boot_info = BootInfoStruct::abi_decode(range_proof.public_values.as_slice())
            .map_err(|e| anyhow::anyhow!("tz: failed to abi_decode range BootInfoStruct: {e}"))?;

        let agg_inputs = AggregationInputs {
            boot_infos: vec![boot_info],
            // Pass-through: the aggregation guest commits this to AggregationOutputs.l1Head;
            // the on-chain prove() reads the same value via Hash.unwrap(game.l1Head()).
            latest_l1_checkpoint_head: game_l1_head,
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

    async fn fetch_tz_snapshot_for_witness(&self, start_block: u64) -> Result<Vec<u8>> {
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
        Ok(snapshot)
    }

    async fn fetch_tz_blocks_witness(
        &self,
        first_block: u64,
        end_block: u64,
        total_blocks: u64,
        config: TzBlockFetchConfig,
    ) -> Result<TzBlocksWitness> {
        if total_blocks == 0 {
            return Ok(TzBlocksWitness::empty());
        }

        self.fetch_tz_streamed_blocks_witness(
            first_block,
            end_block,
            config.stream_frame_blocks,
            config.stream_segment_blocks,
            config.segment_stream_concurrency,
        )
        .await
    }

    async fn fetch_tz_streamed_blocks_witness(
        &self,
        first_block: u64,
        end_block: u64,
        frame_blocks: u64,
        stream_segment_blocks: u64,
        segment_concurrency: usize,
    ) -> Result<TzBlocksWitness> {
        let segment_concurrency = segment_concurrency.max(1);
        let segments = split_tz_stream_segments(first_block, end_block, stream_segment_blocks)?;
        tracing::info!(
            first_block,
            end_block,
            segment_count = segments.len(),
            stream_frame_blocks = frame_blocks,
            stream_segment_blocks,
            segment_stream_concurrency = segment_concurrency,
            "tz: fetching blocks with stream endpoint"
        );

        let l2_provider = Arc::clone(&self.l2_provider);
        let mut segment_files = stream::iter(segments.into_iter())
            .map(|segment| {
                let l2_provider = Arc::clone(&l2_provider);
                async move {
                    let temp_file = NamedTempFile::new()
                        .context("failed to create tz block stream temp file")?;
                    let result = l2_provider
                        .stream_blocks_segment_to_file(
                            segment.start,
                            segment.end,
                            frame_blocks,
                            temp_file.path(),
                        )
                        .await?;
                    anyhow::ensure!(
                        result.start == segment.start && result.end == segment.end,
                        "tz block stream segment result mismatch: requested={}..{}, got={}..{}",
                        segment.start,
                        segment.end,
                        result.start,
                        result.end
                    );
                    Ok::<TzStreamSegmentFile, anyhow::Error>(TzStreamSegmentFile {
                        segment,
                        frame_count: result.frame_count,
                        payload_bytes: result.payload_bytes,
                        temp_file,
                    })
                }
            })
            .buffer_unordered(segment_concurrency)
            .try_collect::<Vec<_>>()
            .await?;

        sort_streamed_segments_for_replay(&mut segment_files);
        let chunk_count = segment_files.iter().try_fold(0u32, |acc, segment| {
            acc.checked_add(segment.frame_count).context("chunk_count overflows u32")
        })?;
        let blocks_bytes = segment_files.iter().try_fold(0usize, |acc, segment| {
            acc.checked_add(segment.payload_bytes).context("tz streamed block byte count overflow")
        })?;

        Ok(TzBlocksWitness {
            chunk_count,
            blocks_bytes,
            chunks: TzBlockChunks::Streamed(segment_files),
        })
    }
}

const TZ_STORAGE_SEGMENT_BLOCKS: u64 = 10_000;

#[derive(Clone, Copy, Debug)]
struct TzBlockFetchConfig {
    stream_frame_blocks: u64,
    stream_segment_blocks: u64,
    segment_stream_concurrency: usize,
}

impl TzBlockFetchConfig {
    fn from_env() -> Self {
        Self {
            stream_frame_blocks: env_positive_u64("TZ_STREAM_FRAME_BLOCKS", 100),
            stream_segment_blocks: env_positive_u64(
                "TZ_STREAM_SEGMENT_BLOCKS",
                TZ_STORAGE_SEGMENT_BLOCKS,
            ),
            segment_stream_concurrency: env_positive_usize("TZ_SEGMENT_STREAM_CONCURRENCY", 4),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TzBlockSegment {
    start: u64,
    end: u64,
}

struct TzStreamSegmentFile {
    segment: TzBlockSegment,
    frame_count: u32,
    payload_bytes: usize,
    temp_file: NamedTempFile,
}

struct TzBlocksWitness {
    chunk_count: u32,
    blocks_bytes: usize,
    chunks: TzBlockChunks,
}

enum TzBlockChunks {
    Streamed(Vec<TzStreamSegmentFile>),
}

impl TzBlocksWitness {
    fn empty() -> Self {
        Self { chunk_count: 0, blocks_bytes: 0, chunks: TzBlockChunks::Streamed(Vec::new()) }
    }

    fn write_to_stdin(self, range_stdin: &mut SP1Stdin) -> Result<()> {
        range_stdin.write(&self.chunk_count);
        match self.chunks {
            TzBlockChunks::Streamed(segments) => {
                let mut written = 0u32;
                for segment in segments {
                    let frames = replay_stream_segment_file(segment.temp_file.path(), range_stdin)
                        .with_context(|| {
                            format!(
                                "failed to replay tz stream segment {}..{}",
                                segment.segment.start, segment.segment.end
                            )
                        })?;
                    anyhow::ensure!(
                        frames == segment.frame_count,
                        "stream segment frame count mismatch for {}..{}: expected={}, got={}",
                        segment.segment.start,
                        segment.segment.end,
                        segment.frame_count,
                        frames
                    );
                    written =
                        written.checked_add(frames).context("written chunk count overflows u32")?;
                }
                anyhow::ensure!(
                    written == self.chunk_count,
                    "stream chunk count mismatch: expected={}, got={}",
                    self.chunk_count,
                    written
                );
            }
        }
        Ok(())
    }
}

fn env_positive_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

fn env_positive_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

fn split_tz_stream_segments(
    start: u64,
    end: u64,
    max_segment_blocks: u64,
) -> Result<Vec<TzBlockSegment>> {
    if start > end {
        return Ok(Vec::new());
    }
    anyhow::ensure!(start > 0, "block height 0 is not supported");
    anyhow::ensure!(max_segment_blocks > 0, "max segment blocks must be greater than 0");

    let mut segments = Vec::new();
    let mut cur = start;
    while cur <= end {
        let max_configured_end =
            cur.checked_add(max_segment_blocks.saturating_sub(1)).unwrap_or(u64::MAX);
        let segment_end = tz_segment_upper_bound(cur).min(max_configured_end).min(end);
        segments.push(TzBlockSegment { start: cur, end: segment_end });
        if segment_end == u64::MAX {
            break;
        }
        cur = segment_end + 1;
    }
    Ok(segments)
}

fn tz_segment_upper_bound(height: u64) -> u64 {
    ((height - 1) / TZ_STORAGE_SEGMENT_BLOCKS)
        .checked_add(1)
        .and_then(|segment| segment.checked_mul(TZ_STORAGE_SEGMENT_BLOCKS))
        .unwrap_or(u64::MAX)
}

fn sort_streamed_segments_for_replay(segments: &mut [TzStreamSegmentFile]) {
    segments.sort_by_key(|segment| segment.segment.start);
}

fn replay_stream_segment_file(path: &std::path::Path, range_stdin: &mut SP1Stdin) -> Result<u32> {
    replay_stream_segment_payloads(path, |payload| {
        range_stdin.write_vec(payload);
        Ok(())
    })
}

fn replay_stream_segment_payloads<F>(path: &std::path::Path, mut on_payload: F) -> Result<u32>
where
    F: FnMut(Vec<u8>) -> Result<()>,
{
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("failed to open tz stream temp file {path:?}"))?;
    let mut frames = 0u32;
    loop {
        let mut len_buf = [0u8; 8];
        match file.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e).context("failed to read tz stream local frame length"),
        }
        let payload_len_u64 = u64::from_be_bytes(len_buf);
        let payload_len: usize =
            payload_len_u64.try_into().context("tz stream local frame length overflows usize")?;
        let mut payload = vec![0u8; payload_len];
        file.read_exact(&mut payload).context("failed to read tz stream local frame payload")?;
        on_payload(payload)?;
        frames = frames.checked_add(1).context("tz stream local frame count overflows u32")?;
    }
    Ok(frames)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsString, io::Write, sync::Mutex};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: Option<&str>) -> Self {
            let prev = std::env::var_os(key);
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
            Self { key, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn split_tz_stream_segments_splits_cross_segment_range() {
        let segments = split_tz_stream_segments(8001, 44000, TZ_STORAGE_SEGMENT_BLOCKS).unwrap();
        assert_eq!(
            segments,
            vec![
                TzBlockSegment { start: 8001, end: 10000 },
                TzBlockSegment { start: 10001, end: 20000 },
                TzBlockSegment { start: 20001, end: 30000 },
                TzBlockSegment { start: 30001, end: 40000 },
                TzBlockSegment { start: 40001, end: 44000 },
            ]
        );
    }

    #[test]
    fn split_tz_stream_segments_keeps_exact_segment_range() {
        let segments = split_tz_stream_segments(10001, 20000, TZ_STORAGE_SEGMENT_BLOCKS).unwrap();
        assert_eq!(segments, vec![TzBlockSegment { start: 10001, end: 20000 }]);
    }

    #[test]
    fn split_tz_stream_segments_keeps_single_partial_segment() {
        let segments = split_tz_stream_segments(15000, 15123, TZ_STORAGE_SEGMENT_BLOCKS).unwrap();
        assert_eq!(segments, vec![TzBlockSegment { start: 15000, end: 15123 }]);
    }

    #[test]
    fn split_tz_stream_segments_honors_smaller_configured_segment_size() {
        let segments = split_tz_stream_segments(8001, 14000, 2000).unwrap();
        assert_eq!(
            segments,
            vec![
                TzBlockSegment { start: 8001, end: 10000 },
                TzBlockSegment { start: 10001, end: 12000 },
                TzBlockSegment { start: 12001, end: 14000 },
            ]
        );
    }

    #[test]
    fn split_tz_stream_segments_never_crosses_storage_segment_boundary() {
        let segments = split_tz_stream_segments(9001, 12000, 5000).unwrap();
        assert_eq!(
            segments,
            vec![
                TzBlockSegment { start: 9001, end: 10000 },
                TzBlockSegment { start: 10001, end: 12000 },
            ]
        );
    }

    #[test]
    fn block_fetch_config_reads_stream_settings() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _frame = EnvVarGuard::set("TZ_STREAM_FRAME_BLOCKS", Some("250"));
        let _segment_blocks = EnvVarGuard::set("TZ_STREAM_SEGMENT_BLOCKS", Some("2000"));
        let _concurrency = EnvVarGuard::set("TZ_SEGMENT_STREAM_CONCURRENCY", Some("7"));

        let config = TzBlockFetchConfig::from_env();

        assert_eq!(config.stream_frame_blocks, 250);
        assert_eq!(config.stream_segment_blocks, 2000);
        assert_eq!(config.segment_stream_concurrency, 7);
    }

    fn temp_segment(start: u64, end: u64, payloads: &[&[u8]]) -> Result<TzStreamSegmentFile> {
        let mut temp_file = NamedTempFile::new()?;
        let mut payload_bytes = 0usize;
        for payload in payloads {
            temp_file.as_file_mut().write_all(&(payload.len() as u64).to_be_bytes())?;
            temp_file.as_file_mut().write_all(payload)?;
            payload_bytes += payload.len();
        }
        temp_file.as_file_mut().flush()?;
        Ok(TzStreamSegmentFile {
            segment: TzBlockSegment { start, end },
            frame_count: payloads.len().try_into().unwrap(),
            payload_bytes,
            temp_file,
        })
    }

    fn collect_streamed_payloads(mut segments: Vec<TzStreamSegmentFile>) -> Result<Vec<Vec<u8>>> {
        sort_streamed_segments_for_replay(&mut segments);
        let mut payloads = Vec::new();
        for segment in &segments {
            replay_stream_segment_payloads(segment.temp_file.path(), |payload| {
                payloads.push(payload);
                Ok(())
            })?;
        }
        Ok(payloads)
    }

    #[test]
    fn streamed_segments_replay_in_order_after_out_of_order_completion() {
        let first = temp_segment(10001, 10002, &[b"10001", b"10002"]).unwrap();
        let second = temp_segment(20001, 20001, &[b"20001"]).unwrap();

        let payloads = collect_streamed_payloads(vec![second, first]).unwrap();

        assert_eq!(payloads, vec![b"10001".to_vec(), b"10002".to_vec(), b"20001".to_vec()]);
    }
}
