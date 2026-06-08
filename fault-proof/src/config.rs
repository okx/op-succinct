use std::{
    env,
    num::{NonZeroU8, NonZeroUsize},
    path::PathBuf,
    str::FromStr,
};

use alloy_primitives::Address;
use alloy_transport_http::reqwest::Url;
use anyhow::{bail, Result};
use crate::contract::ProofType;
use op_succinct_host_utils::network::parse_fulfillment_strategy;
use serde::{Deserialize, Serialize};
use sp1_sdk::{network::FulfillmentStrategy, SP1ProofMode};

#[derive(Debug, Clone)]
pub struct ProposerConfig {
    /// The L1 RPC URL.
    pub l1_rpc: Url,

    /// The L2 RPC URL.
    pub l2_rpc: Url,

    /// The address of the AnchorStateRegistry contract.
    pub anchor_state_registry_address: Address,

    /// The address of the factory contract.
    pub factory_address: Address,

    /// Whether to use mock mode.
    pub mock_mode: bool,

    /// Whether to use fast finality mode.
    pub fast_finality_mode: bool,

    /// The interval in blocks between proposing new games.
    pub proposal_interval_in_blocks: u64,

    /// The interval in seconds between checking for new proposals and game resolution.
    /// During each interval, the proposer:
    /// 1. Checks the safe L2 head block number
    /// 2. Gets the latest valid proposal
    /// 3. Creates a new game if conditions are met
    /// 4. Optionally attempts to resolve unchallenged games
    pub fetch_interval: u64,

    /// The type of game to propose.
    pub game_type: u32,

    /// The max number of defense tasks to run concurrently.
    pub max_concurrent_defense_tasks: u64,

    /// Whether to fallback to timestamp-based L1 head estimation even though SafeDB is not
    /// activated for op-node.
    pub safe_db_fallback: bool,

    /// The metrics port.
    pub metrics_port: u16,

    /// Maximum concurrent proving tasks allowed in fast finality mode.
    /// This limit prevents game creation when proving capacity is reached.
    pub fast_finality_proving_limit: u64,

    /// Whether to expect NETWORK_PRIVATE_KEY to be an AWS KMS key ARN instead of a
    /// plaintext private key.
    pub use_kms_requester: bool,

    /// The number of segments to split the range into (1-16).
    pub range_split_count: RangeSplitCount,

    /// The maximum number of concurrent range proof tasks. (default: 1)
    ///
    /// Increasing this feeds more work into the prover and host in parallel; tune carefully based
    /// on observed latency, and system resources before deviating from default.
    pub max_concurrent_range_proofs: NonZeroUsize,

    /// Configuration for proof provider operations.
    pub proof_provider: ProofProviderConfig,

    /// Optional path to backup file for persisting proposer state across restarts.
    pub backup_path: Option<PathBuf>,

    /// Maximum time (in seconds) to wait for an L1 transaction submitted by the proposer to
    /// reach the required number of confirmations before the watcher gives up. Setting this
    /// too low risks declaring "confirmation timeout" on transactions that actually land on
    /// chain, which can produce duplicate sibling games on retry. Defaults to 60 to preserve
    /// the historical signer behavior; raise it (e.g. 180) on networks where mempool inclusion
    /// plus the configured confirmation depth needs more headroom.
    pub tx_confirmation_timeout: u64,

    /// Whether to enable pre-proposal host verification.
    ///
    /// When enabled, the proposer runs kona natively against each new batcher cycle before
    /// submitting a game, confirming the range is derivable from L1. Game creation is blocked
    /// until the target block passes verification.
    ///
    /// Defaults to false. Set ENABLE_HOST_VERIFICATION=true to opt in.
    pub enable_host_verification: bool,

    /// Number of L2 blocks per verification chunk when host verification is enabled.
    ///
    /// The verification range is split into consecutive chunks of this size; each chunk is
    /// independently fetched and executed, with one log line emitted per chunk. Smaller values
    /// give finer-grained progress visibility; larger values reduce fetch overhead.
    ///
    /// Default: 300 (~2-3 batcher cycles at 120 blocks/cycle).
    pub host_verification_chunk_size: u64,

    /// TEE host service URL. Required when DEFAULT_PROOF_TYPE=tee.
    pub tee_host_url: Option<Url>,

    /// Milliseconds between TEE task polls. Default: 5000.
    pub tee_poll_interval_ms: u64,

    /// Maximum time (seconds) to wait for a single TEE task. Default: 14400 (4 hours).
    pub tee_task_timeout: u64,

    /// Default proof type for unchallenged (fast-finality) games. Default: ZK.
    pub default_proof_type: ProofType,
}

/// Helper function to parse a comma-separated list of addresses
fn parse_whitelist(whitelist_str: &str) -> Result<Option<Vec<Address>>> {
    if whitelist_str.is_empty() {
        return Ok(None);
    }

    let addresses: Result<Vec<Address>> = whitelist_str
        .split(',')
        .map(|addr_str| {
            let addr_str = addr_str.trim().trim_start_matches("0x");
            // Add 0x prefix since addresses are provided without it
            let addr_with_prefix = format!("0x{}", addr_str);
            Address::from_str(&addr_with_prefix)
                .map_err(|e| anyhow::anyhow!("Failed to parse address '{}': {:?}", addr_str, e))
        })
        .collect();

    addresses.map(|addrs| if addrs.is_empty() { None } else { Some(addrs) })
}

impl ProposerConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            l1_rpc: env::var("L1_RPC")?.parse().expect("L1_RPC not set"),
            l2_rpc: env::var("L2_RPC")?.parse().expect("L2_RPC not set"),
            anchor_state_registry_address: env::var("ANCHOR_STATE_REGISTRY_ADDRESS")?
                .parse()
                .expect("ANCHOR_STATE_REGISTRY_ADDRESS not set"),
            factory_address: env::var("FACTORY_ADDRESS")?.parse().expect("FACTORY_ADDRESS not set"),
            mock_mode: env::var("MOCK_MODE").unwrap_or("false".to_string()).parse()?,
            fast_finality_mode: env::var("FAST_FINALITY_MODE")
                .unwrap_or("false".to_string())
                .parse()?,
            proposal_interval_in_blocks: env::var("PROPOSAL_INTERVAL_IN_BLOCKS")
                .unwrap_or("1800".to_string())
                .parse()?,
            fetch_interval: env::var("FETCH_INTERVAL").unwrap_or("30".to_string()).parse()?,
            game_type: env::var("GAME_TYPE").expect("GAME_TYPE not set").parse()?,
            max_concurrent_defense_tasks: env::var("MAX_CONCURRENT_DEFENSE_TASKS")
                .unwrap_or("8".to_string())
                .parse()?,
            safe_db_fallback: env::var("SAFE_DB_FALLBACK")
                .unwrap_or("false".to_string())
                .parse()?,
            metrics_port: env::var("PROPOSER_METRICS_PORT")
                .unwrap_or("9000".to_string())
                .parse()?,
            fast_finality_proving_limit: env::var("FAST_FINALITY_PROVING_LIMIT")
                .unwrap_or("1".to_string())
                .parse()?,
            use_kms_requester: env::var("USE_KMS_REQUESTER")
                .unwrap_or("false".to_string())
                .parse()?,
            range_split_count: env::var("RANGE_SPLIT_COUNT").unwrap_or("1".to_string()).parse()?,
            max_concurrent_range_proofs: env::var("MAX_CONCURRENT_RANGE_PROOFS")
                .unwrap_or("1".to_string())
                .parse()?,
            proof_provider: ProofProviderConfig::from_env()?,
            backup_path: env::var("BACKUP_PATH").ok().map(PathBuf::from),
            tx_confirmation_timeout: env::var("TX_CONFIRMATION_TIMEOUT")
                .unwrap_or("60".to_string())
                .parse()?,
            enable_host_verification: env::var("ENABLE_HOST_VERIFICATION")
                .unwrap_or("false".to_string())
                .parse()?,
            host_verification_chunk_size: {
                let v: u64 = env::var("HOST_VERIFICATION_CHUNK_SIZE")
                    .unwrap_or("300".to_string())
                    .parse()?;
                anyhow::ensure!(v > 0, "HOST_VERIFICATION_CHUNK_SIZE must be > 0");
                v
            },
            tee_host_url: env::var("TEE_HOST_URL").ok().map(|s| s.parse()).transpose()?,
            tee_poll_interval_ms: env::var("TEE_POLL_INTERVAL_MS")
                .unwrap_or("5000".to_string())
                .parse()?,
            tee_task_timeout: env::var("TEE_TASK_TIMEOUT")
                .unwrap_or("14400".to_string())
                .parse()?,
            default_proof_type: match env::var("DEFAULT_PROOF_TYPE")
                .unwrap_or("zk".to_string())
                .to_lowercase()
                .as_str()
            {
                "tee" => ProofType::TEE,
                _ => ProofType::ZK,
            },
        })
    }

    /// Log the configuration using structured tracing fields.
    pub fn log(&self) {
        tracing::info!(
            l1_rpc = %self.l1_rpc,
            l2_rpc = %self.l2_rpc,
            factory_address = %self.factory_address,
            mock_mode = self.mock_mode,
            fast_finality_mode = self.fast_finality_mode,
            game_type = self.game_type,
            proposal_interval_in_blocks = self.proposal_interval_in_blocks,
            fetch_interval = self.fetch_interval,
            max_concurrent_defense_tasks = self.max_concurrent_defense_tasks,
            safe_db_fallback = self.safe_db_fallback,
            metrics_port = self.metrics_port,
            fast_finality_proving_limit = self.fast_finality_proving_limit,
            use_kms_requester = self.use_kms_requester,
            range_split_count = ?self.range_split_count,
            max_concurrent_range_proofs = ?self.max_concurrent_range_proofs,
            // Proof provider fields
            timeout = self.proof_provider.timeout,
            network_calls_timeout = self.proof_provider.network_calls_timeout,
            auction_timeout = self.proof_provider.auction_timeout,
            range_proof_strategy = ?self.proof_provider.range_proof_strategy,
            agg_proof_strategy = ?self.proof_provider.agg_proof_strategy,
            agg_proof_mode = ?self.proof_provider.agg_proof_mode,
            range_cycle_limit = self.proof_provider.range_cycle_limit,
            range_gas_limit = self.proof_provider.range_gas_limit,
            agg_cycle_limit = self.proof_provider.agg_cycle_limit,
            agg_gas_limit = self.proof_provider.agg_gas_limit,
            max_price_per_pgu = self.proof_provider.max_price_per_pgu,
            min_auction_period = self.proof_provider.min_auction_period,
            whitelist = ?self.proof_provider.whitelist,
            backup_path = ?self.backup_path,
            tx_confirmation_timeout = self.tx_confirmation_timeout,
            enable_host_verification = self.enable_host_verification,
            host_verification_chunk_size = self.host_verification_chunk_size,
            tee_host_url = ?self.tee_host_url,
            tee_poll_interval_ms = self.tee_poll_interval_ms,
            tee_task_timeout = self.tee_task_timeout,
            default_proof_type = ?self.default_proof_type,
            "Proposer configuration loaded"
        );
    }
}

/// Configuration for proof provider operations (network calls, timeouts, limits).
#[derive(Debug, Clone)]
pub struct ProofProviderConfig {
    /// The timeout for proving (in seconds). Used as the server-side deadline for proof requests
    /// and as the client-side maximum wait time in `wait_for_proof`.
    pub timeout: u64,

    /// The timeout for individual network API calls like `get_proof_status` (in seconds).
    /// If a single call exceeds this, it will be retried.
    pub network_calls_timeout: u64,

    /// The auction timeout (in seconds). If a proof request remains in "Requested" state
    /// (no prover picked it up) beyond `created_at + auction_timeout`, the request is cancelled.
    pub auction_timeout: u64,

    /// Proof fulfillment strategy for range proofs.
    pub range_proof_strategy: FulfillmentStrategy,

    /// Proof fulfillment strategy for aggregation proofs.
    pub agg_proof_strategy: FulfillmentStrategy,

    /// Proof mode for aggregation proofs (Groth16 or Plonk).
    pub agg_proof_mode: SP1ProofMode,

    /// The cycle limit to use for range proofs.
    pub range_cycle_limit: u64,

    /// The gas limit to use for range proofs.
    pub range_gas_limit: u64,

    /// The cycle limit to use for aggregation proofs.
    pub agg_cycle_limit: u64,

    /// The gas limit to use for aggregation proofs.
    pub agg_gas_limit: u64,

    /// The maximum price per pgu for proving.
    pub max_price_per_pgu: u64,

    /// The minimum auction period (in seconds).
    pub min_auction_period: u64,

    /// The list of prover addresses that are allowed to bid on proof requests.
    pub whitelist: Option<Vec<Address>>,
}

impl ProofProviderConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            timeout: env::var("TIMEOUT").unwrap_or("14400".to_string()).parse()?, // 4 hours
            network_calls_timeout: env::var("NETWORK_CALLS_TIMEOUT")
                .unwrap_or("15".to_string())
                .parse()?,
            auction_timeout: env::var("AUCTION_TIMEOUT")
                .unwrap_or("60".to_string()) // 1 minute
                .parse()?,
            range_proof_strategy: parse_fulfillment_strategy(
                env::var("RANGE_PROOF_STRATEGY").unwrap_or("reserved".to_string()),
            )?,
            agg_proof_strategy: parse_fulfillment_strategy(
                env::var("AGG_PROOF_STRATEGY").unwrap_or("reserved".to_string()),
            )?,
            agg_proof_mode: if env::var("AGG_PROOF_MODE")
                .unwrap_or("plonk".to_string())
                .to_lowercase() ==
                "groth16"
            {
                SP1ProofMode::Groth16
            } else {
                SP1ProofMode::Plonk
            },
            range_cycle_limit: env::var("RANGE_CYCLE_LIMIT")
                .unwrap_or("1000000000000".to_string()) // 1 trillion
                .parse()?,
            range_gas_limit: env::var("RANGE_GAS_LIMIT")
                .unwrap_or("1000000000000".to_string()) // 1 trillion
                .parse()?,
            agg_cycle_limit: env::var("AGG_CYCLE_LIMIT")
                .unwrap_or("1000000000000".to_string()) // 1 trillion
                .parse()?,
            agg_gas_limit: env::var("AGG_GAS_LIMIT")
                .unwrap_or("1000000000000".to_string()) // 1 trillion
                .parse()?,
            max_price_per_pgu: env::var("MAX_PRICE_PER_PGU")
                .unwrap_or("300000000".to_string()) // 0.3 PROVE per billion PGU
                .parse()?,
            min_auction_period: env::var("MIN_AUCTION_PERIOD")
                .unwrap_or("1".to_string())
                .parse()?,
            whitelist: parse_whitelist(&env::var("WHITELIST").unwrap_or("".to_string()))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ChallengerConfig {
    pub l1_rpc: Url,
    pub l2_rpc: Url,

    /// The address of the AnchorStateRegistry contract.
    pub anchor_state_registry_address: Address,

    pub factory_address: Address,

    /// The interval in seconds between checking for new challenges opportunities.
    pub fetch_interval: u64,

    /// The game type to challenge.
    pub game_type: u32,

    /// The metrics port.
    pub metrics_port: u16,

    /// Percentage (0.0-100.0) of valid games to challenge maliciously for testing.
    /// Set to 0.0 (default) for production use (honest challenging only).
    /// Set to >0.0 for testing defense mechanisms.
    pub malicious_challenge_percentage: f64,

    /// Maximum time (in seconds) to wait for an L1 transaction submitted by the challenger to
    /// reach the required number of confirmations before the watcher gives up. Setting this
    /// too low risks declaring "confirmation timeout" on transactions that actually land on
    /// chain, which can lead to redundant retries. Defaults to 60 to preserve the historical
    /// signer behavior; raise it (e.g. 180) on networks where mempool inclusion plus the
    /// configured confirmation depth needs more headroom.
    pub tx_confirmation_timeout: u64,

    /// Proof type to request when challenging. Default: ZK.
    pub challenge_proof_type: ProofType,
}

impl ChallengerConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            l1_rpc: env::var("L1_RPC")?.parse().expect("L1_RPC not set"),
            l2_rpc: env::var("L2_RPC")?.parse().expect("L2_RPC not set"),
            anchor_state_registry_address: env::var("ANCHOR_STATE_REGISTRY_ADDRESS")?
                .parse()
                .expect("ANCHOR_STATE_REGISTRY_ADDRESS not set"),
            factory_address: env::var("FACTORY_ADDRESS")?.parse().expect("FACTORY_ADDRESS not set"),
            game_type: env::var("GAME_TYPE").expect("GAME_TYPE not set").parse()?,
            fetch_interval: env::var("FETCH_INTERVAL").unwrap_or("30".to_string()).parse()?,
            metrics_port: env::var("CHALLENGER_METRICS_PORT")
                .unwrap_or("9001".to_string())
                .parse()?,
            malicious_challenge_percentage: env::var("MALICIOUS_CHALLENGE_PERCENTAGE")
                .unwrap_or("0.0".to_string())
                .parse()?,
            tx_confirmation_timeout: env::var("TX_CONFIRMATION_TIMEOUT")
                .unwrap_or("60".to_string())
                .parse()?,
            challenge_proof_type: match env::var("CHALLENGE_PROOF_TYPE")
                .unwrap_or("zk".to_string())
                .to_lowercase()
                .as_str()
            {
                "tee" => ProofType::TEE,
                _ => ProofType::ZK,
            },
        })
    }

    /// Log the configuration using structured tracing fields.
    pub fn log(&self) {
        tracing::info!(
            l1_rpc = %self.l1_rpc,
            l2_rpc = %self.l2_rpc,
            anchor_state_registry_address = %self.anchor_state_registry_address,
            factory_address = %self.factory_address,
            game_type = self.game_type,
            fetch_interval = self.fetch_interval,
            metrics_port = self.metrics_port,
            malicious_challenge_percentage = self.malicious_challenge_percentage,
            tx_confirmation_timeout = self.tx_confirmation_timeout,
            challenge_proof_type = ?self.challenge_proof_type,
            "Challenger configuration loaded"
        );
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
/// The config for deploying the OPSuccinctFaultDisputeGame.
/// Note: The fields should be in alphabetical order for Solidity to parse it correctly.
pub struct FaultDisputeGameConfig {
    pub aggregation_vkey: String,
    pub challenger_addresses: Vec<String>,
    pub challenger_bond_wei: u64,
    pub dispute_game_finality_delay_seconds: u64,
    pub fallback_timeout_fp_secs: u64,
    pub game_type: u32,
    pub initial_bond_wei: u64,
    pub max_challenge_duration: u64,
    pub max_prove_duration: u64,
    pub optimism_portal2_address: String,
    pub permissionless_mode: bool,
    pub proposer_addresses: Vec<String>,
    pub range_vkey_commitment: String,
    pub rollup_config_hash: String,
    pub starting_l2_block_number: u64,
    pub starting_root: String,
    pub system_config_address: String,
    pub use_sp1_mock_verifier: bool,
    pub verifier_address: String,
}

/// How many chunks the range proof input is partitioned into (1-16 inclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RangeSplitCount(NonZeroU8);

impl RangeSplitCount {
    pub const MAX: u8 = 16;

    /// Create a new `RangeSplitCount`.
    pub fn new(count: u8) -> Result<Self> {
        if count == 0 || count > Self::MAX {
            bail!("range splits must be between 1 and 16, got {count}");
        }

        let count = NonZeroU8::new(count)
            .ok_or_else(|| anyhow::anyhow!("range splits must be non zero"))?;

        Ok(Self(count))
    }

    /// Returns a `RangeSplitCount` of one.
    pub fn one() -> Self {
        Self(NonZeroU8::new(1).expect("1 is non-zero"))
    }

    /// Convert to `usize`.
    pub fn to_usize(self) -> usize {
        self.0.get() as usize
    }

    /// Split a block range into up to `count` contiguous, non-empty subranges for proving.
    ///
    /// # Proving semantics
    /// Each tuple `(start, end)` represents a proving range where:
    /// - `start` is the **agreed** block (already-proven checkpoint)
    /// - `end` is the **claimed** block (included in the proof)
    ///
    /// # Behavior
    /// - Errors if `start > end` or the range is empty.
    /// - Caps the number of produced segments to the number of blocks in the range.
    /// - Uses ceil division for even segments; may yield fewer than requested (e.g., 9 blocks ÷ 4 →
    ///   step=3 → 3 segments: (0,3], (3,6], (6,9]).
    /// - Returns ranges that exactly cover `(start, end]` with no gaps or overlaps.
    ///
    /// NOTE: At runtime, the actual interval may slightly differ from `proposal_interval_in_blocks`
    /// because if a game already exists at the target L2 block, the proposer increments the block
    /// number until it finds an unused slot (e.g., 1802 blocks instead of 1800). Since we divide
    /// the actual total by the split count, drift just slightly adjusts range sizes.
    pub fn split(&self, start: u64, end: u64) -> Result<Vec<(u64, u64)>> {
        let total = end.checked_sub(start).ok_or_else(|| {
            anyhow::anyhow!("end block {end} is not greater than start block {start}")
        })?;
        if total == 0 {
            bail!("start block equals end block ({start}); nothing to prove");
        }

        let splits = self.to_usize();

        if splits == 1 {
            return Ok(vec![(start, end)]);
        }

        // Never split into more parts than there are blocks.
        let segments = splits.min(total as usize);
        let mut ranges = Vec::with_capacity(segments);

        let step = total.div_ceil(segments as u64);

        let mut cur = start;
        for _ in 0..segments {
            if cur >= end {
                break;
            }
            let next = cur.saturating_add(step).min(end);
            ranges.push((cur, next));
            cur = next;
        }

        Ok(ranges)
    }
}

impl TryFrom<u64> for RangeSplitCount {
    type Error = anyhow::Error;

    fn try_from(value: u64) -> Result<Self> {
        let count: u8 = value
            .try_into()
            .map_err(|_| anyhow::anyhow!("range splits must be between 1 and 16, got {value}"))?;
        Self::new(count)
    }
}

impl FromStr for RangeSplitCount {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let value: u64 = s.parse()?;
        Self::try_from(value)
    }
}

#[cfg(test)]
mod split_range_tests {
    use crate::config::RangeSplitCount;
    use rstest::rstest;

    fn range_split_count(count: u8) -> RangeSplitCount {
        RangeSplitCount::new(count).expect("valid range split count")
    }

    /// Assert that ranges are non-empty, contiguous, and exactly cover [start, end).
    fn assert_contiguous_cover(ranges: &[(u64, u64)], start: u64, end: u64) {
        assert!(!ranges.is_empty(), "expected at least one range");
        assert_eq!(ranges.first().unwrap().0, start, "first range should start at {start}");
        assert_eq!(ranges.last().unwrap().1, end, "last range should end at {end}");
        for window in ranges.windows(2) {
            let a = window[0];
            let b = window[1];
            assert!(a.0 < a.1, "range must be non-empty: {}-{}", a.0, a.1);
            assert_eq!(a.1, b.0, "ranges must be contiguous: {} != {}", a.1, b.0);
            assert!(b.0 < b.1, "range must be non-empty: {}-{}", b.0, b.1);
        }
    }

    #[rstest]
    #[case::single_split(range_split_count(1), 10, 20, &[(10, 20)])]
    #[case::single_block(range_split_count(2), 0, 1, &[(0, 1)])]
    #[case::no_empty_tail(range_split_count(4), 0, 5, &[(0, 2), (2, 4), (4, 5)])]
    #[case::offset_uneven(range_split_count(4), 5, 14, &[(5, 8), (8, 11), (11, 14)])]
    #[case::even_split(range_split_count(4), 0, 10, &[(0, 3), (3, 6), (6, 9), (9, 10)])]
    #[case::large_splits_small_range(range_split_count(15), 0, 1, &[(0, 1)])]
    #[case::max_splits_exact(
        range_split_count(RangeSplitCount::MAX),
        0,
        16,
        &[
            (0, 1),
            (1, 2),
            (2, 3),
            (3, 4),
            (4, 5),
            (5, 6),
            (6, 7),
            (7, 8),
            (8, 9),
            (9, 10),
            (10, 11),
            (11, 12),
            (12, 13),
            (13, 14),
            (14, 15),
            (15, 16)
        ]
    )]
    #[case::max_splits_caps(range_split_count(RangeSplitCount::MAX), 0, 3, &[(0, 1), (1, 2), (2, 3)])]
    #[case::stop_when_done(
        RangeSplitCount::new(15).unwrap(),
        0,
        16,
        &[(0, 2), (2, 4), (4, 6), (6, 8), (8, 10), (10, 12), (12, 14), (14, 16)]
    )]
    #[case::drift_up(range_split_count(4), 0, 1802, &[(0, 451), (451, 902), (902, 1353), (1353, 1802)])]
    fn test_splits_expected_paths(
        #[case] splits: RangeSplitCount,
        #[case] start: u64,
        #[case] end: u64,
        #[case] expected: &[(u64, u64)],
    ) {
        let ranges = splits.split(start, end).expect("split should succeed");
        assert_eq!(ranges, expected);
        assert_contiguous_cover(&ranges, start, end);
    }

    #[test]
    fn test_splits_extreme() {
        let start = u64::MAX - 100;
        let end = u64::MAX;
        let ranges =
            RangeSplitCount::new(15).unwrap().split(start, end).expect("split should succeed");
        assert_contiguous_cover(&ranges, start, end);
    }

    #[test]
    fn test_errors_on_reversed_bounds() {
        let err = RangeSplitCount::new(2).unwrap().split(8, 3).unwrap_err();
        assert!(
            err.to_string().contains("not greater than start block"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_errors_on_empty_range() {
        let err = RangeSplitCount::new(2).unwrap().split(5, 5).unwrap_err();
        assert!(err.to_string().contains("equals end block"), "unexpected error: {err}");
    }

    #[test]
    fn test_rejects_zero() {
        let err = RangeSplitCount::new(0).unwrap_err();
        assert!(err.to_string().contains("between 1 and 16"), "unexpected error: {err}");
    }

    #[test]
    fn test_rejects_above_max_from_str() {
        let err = "17".parse::<RangeSplitCount>().unwrap_err();
        assert!(err.to_string().contains("between 1 and 16"), "unexpected error: {err}");
    }
}

#[cfg(test)]
mod host_verification_config_tests {
    use super::*;
    use std::{env, sync::Mutex};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn set_required_env_vars() {
        env::set_var("L1_RPC", "http://localhost:8545");
        env::set_var("L2_RPC", "http://localhost:9545");
        env::set_var("ANCHOR_STATE_REGISTRY_ADDRESS", "0x0000000000000000000000000000000000000001");
        env::set_var("FACTORY_ADDRESS", "0x0000000000000000000000000000000000000002");
        env::set_var("GAME_TYPE", "1");
    }

    fn clear_host_verification_env_vars() {
        env::remove_var("ENABLE_HOST_VERIFICATION");
        env::remove_var("HOST_VERIFICATION_CHUNK_SIZE");
    }

    #[test]
    fn host_verification_config_parsing() {
        let _lock = ENV_LOCK.lock().unwrap();
        set_required_env_vars();

        // Test 1: defaults when env vars not set
        clear_host_verification_env_vars();
        let config = ProposerConfig::from_env().unwrap();
        assert!(!config.enable_host_verification, "default should be false");
        assert_eq!(config.host_verification_chunk_size, 300, "default chunk size should be 300");

        // Test 2: explicit true with custom chunk size
        env::set_var("ENABLE_HOST_VERIFICATION", "true");
        env::set_var("HOST_VERIFICATION_CHUNK_SIZE", "500");
        let config = ProposerConfig::from_env().unwrap();
        assert!(config.enable_host_verification, "should parse true");
        assert_eq!(config.host_verification_chunk_size, 500, "should parse custom chunk size");

        // Test 3: explicit false
        env::set_var("ENABLE_HOST_VERIFICATION", "false");
        let config = ProposerConfig::from_env().unwrap();
        assert!(!config.enable_host_verification, "should parse explicit false");

        clear_host_verification_env_vars();
    }
}

#[cfg(test)]
mod tee_config_tests {
    use super::*;
    use std::{env, sync::Mutex};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn set_required_proposer_env() {
        env::set_var("L1_RPC", "http://localhost:8545");
        env::set_var("L2_RPC", "http://localhost:9545");
        env::set_var("ANCHOR_STATE_REGISTRY_ADDRESS", "0x0000000000000000000000000000000000000001");
        env::set_var("FACTORY_ADDRESS", "0x0000000000000000000000000000000000000002");
        env::set_var("GAME_TYPE", "1");
    }

    fn set_required_challenger_env() {
        env::set_var("L1_RPC", "http://localhost:8545");
        env::set_var("L2_RPC", "http://localhost:9545");
        env::set_var("ANCHOR_STATE_REGISTRY_ADDRESS", "0x0000000000000000000000000000000000000001");
        env::set_var("FACTORY_ADDRESS", "0x0000000000000000000000000000000000000002");
        env::set_var("GAME_TYPE", "1");
    }

    fn clear_tee_env() {
        env::remove_var("TEE_HOST_URL");
        env::remove_var("TEE_POLL_INTERVAL_MS");
        env::remove_var("TEE_TASK_TIMEOUT");
        env::remove_var("DEFAULT_PROOF_TYPE");
        env::remove_var("CHALLENGE_PROOF_TYPE");
    }

    #[test]
    fn proposer_tee_defaults() {
        let _lock = ENV_LOCK.lock().unwrap();
        set_required_proposer_env();
        clear_tee_env();
        let config = ProposerConfig::from_env().unwrap();
        assert!(config.tee_host_url.is_none());
        assert_eq!(config.tee_poll_interval_ms, 5000);
        assert_eq!(config.tee_task_timeout, 14400);
        assert_eq!(config.default_proof_type, ProofType::ZK);
        clear_tee_env();
    }

    #[test]
    fn proposer_tee_configured() {
        let _lock = ENV_LOCK.lock().unwrap();
        set_required_proposer_env();
        clear_tee_env();
        env::set_var("TEE_HOST_URL", "http://localhost:8080");
        env::set_var("TEE_POLL_INTERVAL_MS", "3000");
        env::set_var("TEE_TASK_TIMEOUT", "7200");
        env::set_var("DEFAULT_PROOF_TYPE", "tee");
        let config = ProposerConfig::from_env().unwrap();
        assert_eq!(config.tee_host_url.as_ref().unwrap().as_str(), "http://localhost:8080/");
        assert_eq!(config.tee_poll_interval_ms, 3000);
        assert_eq!(config.tee_task_timeout, 7200);
        assert_eq!(config.default_proof_type, ProofType::TEE);
        clear_tee_env();
    }

    #[test]
    fn proof_type_case_insensitive() {
        let _lock = ENV_LOCK.lock().unwrap();
        set_required_proposer_env();
        clear_tee_env();
        env::set_var("DEFAULT_PROOF_TYPE", "TEE");
        let config = ProposerConfig::from_env().unwrap();
        assert_eq!(config.default_proof_type, ProofType::TEE);
        env::set_var("DEFAULT_PROOF_TYPE", "Tee");
        let config = ProposerConfig::from_env().unwrap();
        assert_eq!(config.default_proof_type, ProofType::TEE);
        clear_tee_env();
    }

    #[test]
    fn challenger_proof_type_defaults() {
        let _lock = ENV_LOCK.lock().unwrap();
        set_required_challenger_env();
        clear_tee_env();
        let config = ChallengerConfig::from_env().unwrap();
        assert_eq!(config.challenge_proof_type, ProofType::ZK);
        clear_tee_env();
    }

    #[test]
    fn challenger_proof_type_tee() {
        let _lock = ENV_LOCK.lock().unwrap();
        set_required_challenger_env();
        clear_tee_env();
        env::set_var("CHALLENGE_PROOF_TYPE", "tee");
        let config = ChallengerConfig::from_env().unwrap();
        assert_eq!(config.challenge_proof_type, ProofType::TEE);
        clear_tee_env();
    }
}
