# tz Chain Adaptation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Cargo feature `tz` to `fault-proof` crate, enabling `tz-proposer` and `tz-challenger` binaries that adapt op-succinct to the TradeZone L2 chain's REST API and `keccak256(blockHash ++ stateHash)` rootClaim formula without modifying the existing xlayer path.

**Architecture:** `TzChainClient` wraps the `/chain/confirmed_block_info` REST API; `TzL2Provider` implements `L2ProviderTrait` using `TzChainClient`; both proposer and challenger accept an injected `Arc<dyn L2ProviderTrait>` so tz logic is isolated behind `#[cfg(feature = "tz")]`. All changes to existing files are annotated with `// for tz:`.

**Tech Stack:** Rust, `reqwest` (HTTP), `thiserror` (errors), `serde_json` (API parsing), `alloy-primitives` (B256/U256/keccak256), `async-trait`, `wiremock` (test HTTP mocking).

**Phase 1 note:** The SP1 proof pipeline is out of scope. For Phase 1 deployments set `SP1_PROVER=cluster` — cluster mode derives keys without loading a local ELF, so the placeholder `fault-proof/elfs/tz-range.elf` is accepted but never read.

---

## File Map

**New files:**
- `fault-proof/src/tz_chain_client.rs` — `TzChainClient`, `TzBlockInfo`, `TzCacheMissError`
- `fault-proof/src/tz_l2_provider.rs` — `TzL2Provider` implementing `L2ProviderTrait`, `compute_tz_root_claim()`
- `fault-proof/src/tz_proposer_config.rs` — `TzConfig` parsed from env vars
- `fault-proof/bin/tz_proposer.rs` — `tz-proposer` binary entry
- `fault-proof/bin/tz_challenger.rs` — `tz-challenger` binary entry
- `fault-proof/elfs/tz-range.elf` — empty placeholder (Phase 1)

**Modified files:**
- `fault-proof/Cargo.toml` — tz feature, optional deps, bin entries, wiremock dev-dep
- `fault-proof/src/lib.rs` — extend `L2ProviderTrait`, add module declarations
- `fault-proof/src/proposer.rs` — field type, `new()` wrap, `new_with_l2_provider()`, six `#[cfg]` patches
- `fault-proof/src/challenger.rs` — field type, `new()` wrap, `new_with_l2_provider()`, one `#[cfg]` patch

---

## Task 1: Cargo.toml — tz feature, optional deps, bin entries

**Files:**
- Modify: `fault-proof/Cargo.toml`

- [ ] **Step 1: Add optional dependencies**

  In the `[dependencies]` section, add after the existing `tikv-jemallocator` line:

  ```toml
  # for tz: HTTP client and error types (optional, only compiled with tz feature)
  reqwest = { workspace = true, optional = true, features = ["json"] }
  thiserror = { workspace = true, optional = true }
  ```

- [ ] **Step 2: Add tz feature to [features] section**

  The current `[features]` block ends with `integration = []`. Add `tz`:

  ```toml
  tz = ["reqwest", "thiserror"]
  ```

  Full block after change:
  ```toml
  [features]
  default = ["ethereum"]
  celestia = ["op-succinct-proof-utils/celestia"]
  eigenda = ["op-succinct-proof-utils/eigenda"]
  ethereum = ["op-succinct-proof-utils/ethereum"]
  integration = []
  tz = ["reqwest", "thiserror"]
  ```

- [ ] **Step 3: Add bin entries**

  After the existing `[[bin]]` entries for `proposer` and `challenger`, add:

  ```toml
  [[bin]]
  name = "tz-proposer"
  path = "bin/tz_proposer.rs"
  required-features = ["tz"]

  [[bin]]
  name = "tz-challenger"
  path = "bin/tz_challenger.rs"
  required-features = ["tz"]
  ```

- [ ] **Step 4: Add wiremock to dev-dependencies**

  ```toml
  wiremock = "0.6"
  ```

- [ ] **Step 5: Verify Cargo.toml parses**

  ```bash
  cd fault-proof && cargo check 2>&1 | head -5
  ```

  Expected: clean (no errors). If `missing file` errors appear for the new bins, that's expected and resolved in Task 8.

- [ ] **Step 6: Commit**

  ```bash
  git add fault-proof/Cargo.toml
  git commit -m "chore(tz): add tz feature, optional deps, and bin entries to Cargo.toml"
  ```

---

## Task 2: lib.rs — extend L2ProviderTrait + module declarations

**Files:**
- Modify: `fault-proof/src/lib.rs`

- [ ] **Step 1: Add two default methods to L2ProviderTrait**

  The trait currently ends after `compute_output_root_at_block`. Append inside the trait block:

  ```rust
      // for tz: default returns None; TzL2Provider overrides to return confirmed_height when ready
      async fn get_next_proposal_block(
          &self,
          _canonical_head: U256,
          _proposal_interval: u64,
      ) -> Result<Option<U256>> {
          Ok(None) // xlayer falls through to host-based finalized block logic
      }

      // for tz: evict history cache entries below anchor_height; xlayer no-op
      fn evict_cache_below(&self, _anchor_height: u64) {}
  ```

  The full trait block after the change:
  ```rust
  #[async_trait]
  pub trait L2ProviderTrait {
      async fn get_l2_block_by_number(
          &self,
          block_number: BlockNumberOrTag,
      ) -> Result<Block<Transaction>>;

      async fn get_l2_storage_root(
          &self,
          address: Address,
          block_number: BlockNumberOrTag,
      ) -> Result<B256>;

      async fn compute_output_root_at_block(&self, l2_block_number: U256) -> Result<FixedBytes<32>>;

      // for tz: default returns None; TzL2Provider overrides to return confirmed_height when ready
      async fn get_next_proposal_block(
          &self,
          _canonical_head: U256,
          _proposal_interval: u64,
      ) -> Result<Option<U256>> {
          Ok(None)
      }

      // for tz: evict history cache entries below anchor_height; xlayer no-op
      fn evict_cache_below(&self, _anchor_height: u64) {}
  }
  ```

- [ ] **Step 2: Add tz module declarations**

  After the existing `pub mod prover;` line, add:

  ```rust
  // for tz: new modules for tz chain adaptation
  #[cfg(feature = "tz")] pub mod tz_chain_client;
  #[cfg(feature = "tz")] pub mod tz_l2_provider;
  #[cfg(feature = "tz")] pub mod tz_proposer_config;
  ```

- [ ] **Step 3: Verify xlayer path still compiles**

  ```bash
  cargo check -p op-succinct-fp 2>&1 | head -10
  ```

  Expected: clean. The default methods satisfy `impl L2ProviderTrait for L2Provider` (which now inherits the defaults automatically).

- [ ] **Step 4: Commit**

  ```bash
  git add fault-proof/src/lib.rs
  git commit -m "feat(tz): extend L2ProviderTrait with default get_next_proposal_block and evict_cache_below"
  ```

---

## Task 3: proposer.rs — field type + new() wrap + new_with_l2_provider

**Files:**
- Modify: `fault-proof/src/proposer.rs`

- [ ] **Step 1: Change l2_provider field type (line ~258)**

  Find:
  ```rust
  pub l2_provider: L2Provider,
  ```

  Replace with:
  ```rust
  // for tz: changed from L2Provider to trait object to support TzL2Provider injection
  pub l2_provider: Arc<dyn L2ProviderTrait + Send + Sync>,
  ```

- [ ] **Step 2: Update new() to wrap L2Provider in Arc (line ~358)**

  Find in the `new()` body:
  ```rust
  let l1_provider = ProviderBuilder::default().connect_http(config.l1_rpc.clone());
  let l2_provider = ProviderBuilder::default().connect_http(config.l2_rpc.clone());
  ```

  Replace with:
  ```rust
  let l1_provider = ProviderBuilder::default().connect_http(config.l1_rpc.clone());
  // for tz: wrap in Arc<dyn L2ProviderTrait> to match new field type
  let l2_provider: Arc<dyn L2ProviderTrait + Send + Sync> =
      Arc::new(ProviderBuilder::default().connect_http(config.l2_rpc.clone()));
  ```

- [ ] **Step 3: Add new_with_l2_provider() after new()**

  Insert the following function after the closing `}` of `new()`:

  ```rust
  /// Creates a new proposer with an injected L2 provider, rollup config hash, and range ELF.
  // for tz: avoids optimism_rollupConfig RPC and allows custom L2 data source
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
          // for tz: use injected range_elf instead of get_range_elf_embedded()
          let range_pk = np.setup(Elf::Static(range_elf)).await?;
          let range_vk = range_pk.verifying_key().clone();
          let agg_pk = np.setup(Elf::Static(AGGREGATION_ELF)).await?;
          let agg_vk = agg_pk.verifying_key().clone();
          (range_pk, range_vk, agg_pk, agg_vk, Some(np), Some(nm))
      };

      let aggregation_vkey = B256::from(agg_vk.bytes32_raw());
      let range_vkey_commitment = B256::from(range_vk.hash_bytes());
      // for tz: use provided rollup_config_hash instead of hash_rollup_config(fetcher.rollup_config?)
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
          // for tz: injected l2_provider instead of constructing from config.l2_rpc
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
  ```

- [ ] **Step 4: Verify proposer compiles**

  ```bash
  cargo check -p op-succinct-fp 2>&1 | head -20
  ```

  Expected: clean (no errors from proposer.rs changes).

- [ ] **Step 5: Commit**

  ```bash
  git add fault-proof/src/proposer.rs
  git commit -m "feat(tz): change proposer l2_provider to Arc<dyn L2ProviderTrait> and add new_with_l2_provider"
  ```

---

## Task 4: challenger.rs — field type + new() wrap + new_with_l2_provider

**Files:**
- Modify: `fault-proof/src/challenger.rs`

- [ ] **Step 1: Change l2_provider field type (line ~35)**

  Find:
  ```rust
  l2_provider: L2Provider,
  ```

  Replace with:
  ```rust
  // for tz: changed from L2Provider to trait object to support TzL2Provider injection
  l2_provider: Arc<dyn L2ProviderTrait + Send + Sync>,
  ```

- [ ] **Step 2: Add Arc import**

  At the top of the file, find:
  ```rust
  use std::{
      collections::HashMap,
      sync::{Arc, OnceLock},
      time::Duration,
  };
  ```

  `Arc` is already imported. Good — no change needed.

- [ ] **Step 3: Update new() to wrap L2Provider (line ~60)**

  Find in `new()`:
  ```rust
  l2_provider: ProviderBuilder::default().connect_http(l2_rpc),
  ```

  Replace with:
  ```rust
  // for tz: wrap in Arc<dyn L2ProviderTrait> to match new field type
  l2_provider: Arc::new(ProviderBuilder::default().connect_http(l2_rpc))
      as Arc<dyn L2ProviderTrait + Send + Sync>,
  ```

- [ ] **Step 4: Add new_with_l2_provider() after new()**

  Insert after the closing `}` of `new()`:

  ```rust
  /// Creates a new challenger with an injected L2 provider.
  // for tz: allows custom L2 data source without constructing from config.l2_rpc
  pub fn new_with_l2_provider(
      config: ChallengerConfig,
      l1_provider: L1Provider,
      anchor_state_registry: AnchorStateRegistryInstance<P>,
      factory: DisputeGameFactoryInstance<P>,
      signer: SignerLock,
      l2_provider: Arc<dyn L2ProviderTrait + Send + Sync>,
  ) -> Self {
      OPSuccinctChallenger {
          config,
          signer,
          l1_provider,
          // for tz: injected l2_provider instead of constructing from config.l2_rpc
          l2_provider,
          anchor_state_registry,
          factory,
          challenger_bond: OnceLock::new(),
          state: Arc::new(Mutex::new(ChallengerState {
              cursor: U256::ZERO,
              games: HashMap::new(),
          })),
      }
  }
  ```

- [ ] **Step 5: Verify challenger compiles**

  ```bash
  cargo check -p op-succinct-fp 2>&1 | head -20
  ```

  Expected: clean.

- [ ] **Step 6: Commit**

  ```bash
  git add fault-proof/src/challenger.rs
  git commit -m "feat(tz): change challenger l2_provider to Arc<dyn L2ProviderTrait> and add new_with_l2_provider"
  ```

---

## Task 5: tz_chain_client.rs — HTTP client with tests

**Files:**
- Create: `fault-proof/src/tz_chain_client.rs`

- [ ] **Step 1: Write the failing tests first**

  Create `fault-proof/src/tz_chain_client.rs` with the test module only:

  ```rust
  use std::collections::HashMap;
  use alloy_primitives::B256;
  use anyhow::{anyhow, Result};

  #[derive(Debug, thiserror::Error)]
  #[error("TzChainClient: no cached checkpoint for height {0}")]
  pub struct TzCacheMissError(pub u64);

  #[derive(Clone)]
  pub struct TzBlockInfo {
      pub height: u64,
      pub block_hash: B256,
      pub state_hash: B256,
  }

  pub struct TzChainClient {
      endpoints: Vec<String>,
      history: std::sync::Mutex<HashMap<u64, TzBlockInfo>>,
      client: reqwest::Client,
  }

  impl TzChainClient {
      pub fn new(endpoints: Vec<String>) -> Self {
          Self {
              endpoints,
              history: std::sync::Mutex::new(HashMap::new()),
              client: reqwest::Client::builder()
                  .timeout(std::time::Duration::from_secs(10))
                  .build()
                  .expect("failed to build reqwest client"),
          }
      }

      pub async fn get_confirmed_block_info(&self) -> Result<TzBlockInfo> {
          todo!()
      }

      pub fn get_confirmed_block_info_at_height(&self, height: u64) -> Result<TzBlockInfo> {
          todo!()
      }

      pub fn evict_below(&self, anchor_height: u64) {
          todo!()
      }
  }

  #[cfg(test)]
  mod tests {
      use super::*;
      use wiremock::{
          matchers::{method, path},
          Mock, MockServer, ResponseTemplate,
      };

      const HASH_A: &str =
          "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      const HASH_B: &str =
          "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

      #[tokio::test]
      async fn get_confirmed_block_info_parses_ok_response() {
          let mock_server = MockServer::start().await;
          Mock::given(method("GET"))
              .and(path("/chain/confirmed_block_info"))
              .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                  "code": 0,
                  "message": "ok",
                  "data": { "height": 12345u64, "blockHash": HASH_A, "stateHash": HASH_B }
              })))
              .mount(&mock_server)
              .await;

          let client = TzChainClient::new(vec![mock_server.uri()]);
          let info = client.get_confirmed_block_info().await.unwrap();
          assert_eq!(info.height, 12345);
          assert_eq!(info.block_hash, HASH_A.parse::<B256>().unwrap());
          assert_eq!(info.state_hash, HASH_B.parse::<B256>().unwrap());
      }

      #[tokio::test]
      async fn get_confirmed_block_info_returns_err_when_data_null() {
          let mock_server = MockServer::start().await;
          Mock::given(method("GET"))
              .and(path("/chain/confirmed_block_info"))
              .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                  "code": 0,
                  "message": "ok",
                  "data": null
              })))
              .mount(&mock_server)
              .await;

          let client = TzChainClient::new(vec![mock_server.uri()]);
          assert!(client.get_confirmed_block_info().await.is_err());
      }

      #[tokio::test]
      async fn get_confirmed_block_info_failover_to_second_endpoint() {
          let good_server = MockServer::start().await;
          Mock::given(method("GET"))
              .and(path("/chain/confirmed_block_info"))
              .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                  "code": 0,
                  "message": "ok",
                  "data": { "height": 999u64, "blockHash": HASH_A, "stateHash": HASH_B }
              })))
              .mount(&good_server)
              .await;

          // First endpoint returns 500; second endpoint is healthy.
          let client = TzChainClient::new(vec![
              "http://127.0.0.1:1".to_string(), // unreachable
              good_server.uri(),
          ]);
          let info = client.get_confirmed_block_info().await.unwrap();
          assert_eq!(info.height, 999);
      }

      #[test]
      fn get_confirmed_block_info_at_height_returns_cache_miss() {
          let client = TzChainClient::new(vec!["http://unused".to_string()]);
          let err = client.get_confirmed_block_info_at_height(42).unwrap_err();
          assert!(err.downcast_ref::<TzCacheMissError>().is_some());
      }

      #[tokio::test]
      async fn get_confirmed_block_info_at_height_returns_cached_entry() {
          let mock_server = MockServer::start().await;
          Mock::given(method("GET"))
              .and(path("/chain/confirmed_block_info"))
              .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                  "code": 0,
                  "message": "ok",
                  "data": { "height": 100u64, "blockHash": HASH_A, "stateHash": HASH_B }
              })))
              .mount(&mock_server)
              .await;

          let client = TzChainClient::new(vec![mock_server.uri()]);
          client.get_confirmed_block_info().await.unwrap();
          let info = client.get_confirmed_block_info_at_height(100).unwrap();
          assert_eq!(info.height, 100);
      }

      #[test]
      fn evict_below_removes_entries_below_anchor() {
          let client = TzChainClient::new(vec!["http://unused".to_string()]);
          {
              let mut h = client.history.lock().unwrap();
              for height in [10u64, 20, 30, 40] {
                  h.insert(height, TzBlockInfo {
                      height,
                      block_hash: B256::ZERO,
                      state_hash: B256::ZERO,
                  });
              }
          }
          client.evict_below(25);
          let h = client.history.lock().unwrap();
          assert!(!h.contains_key(&10));
          assert!(!h.contains_key(&20));
          assert!(h.contains_key(&30));
          assert!(h.contains_key(&40));
      }
  }
  ```

- [ ] **Step 2: Run tests to confirm they fail (todo!() panics)**

  ```bash
  cargo test -p op-succinct-fp --features tz tz_chain_client 2>&1 | tail -20
  ```

  Expected: tests panic with `not yet implemented` or similar.

- [ ] **Step 3: Implement get_confirmed_block_info()**

  Replace the `todo!()` in `get_confirmed_block_info` with:

  ```rust
  pub async fn get_confirmed_block_info(&self) -> Result<TzBlockInfo> {
      #[derive(serde::Deserialize)]
      struct ApiResponse {
          code: i32,
          data: Option<TzBlockInfoRaw>,
      }
      #[derive(serde::Deserialize)]
      #[serde(rename_all = "camelCase")]
      struct TzBlockInfoRaw {
          height: u64,
          block_hash: B256,
          state_hash: B256,
      }

      let mut last_err = anyhow!("no endpoints configured");
      for endpoint in &self.endpoints {
          let url = format!("{}/chain/confirmed_block_info", endpoint);
          let resp = match self.client.get(&url).send().await {
              Ok(r) => r,
              Err(e) => { last_err = e.into(); continue; }
          };
          if !resp.status().is_success() {
              last_err = anyhow!("HTTP {}", resp.status());
              continue;
          }
          let api: ApiResponse = match resp.json().await {
              Ok(a) => a,
              Err(e) => { last_err = e.into(); continue; }
          };
          if api.code != 0 {
              last_err = anyhow!("API code {}", api.code);
              continue;
          }
          let raw = api.data.ok_or_else(|| anyhow!("tz chain has no checkpoint yet"))?;
          let info = TzBlockInfo {
              height: raw.height,
              block_hash: raw.block_hash,
              state_hash: raw.state_hash,
          };
          self.history.lock().unwrap().insert(info.height, info.clone());
          return Ok(info);
      }
      Err(last_err)
  }
  ```

- [ ] **Step 4: Implement get_confirmed_block_info_at_height()**

  Replace the `todo!()`:

  ```rust
  pub fn get_confirmed_block_info_at_height(&self, height: u64) -> Result<TzBlockInfo> {
      self.history
          .lock()
          .unwrap()
          .get(&height)
          .cloned()
          .ok_or_else(|| anyhow::Error::new(TzCacheMissError(height)))
  }
  ```

- [ ] **Step 5: Implement evict_below()**

  Replace the `todo!()`:

  ```rust
  pub fn evict_below(&self, anchor_height: u64) {
      self.history.lock().unwrap().retain(|&h, _| h >= anchor_height);
  }
  ```

- [ ] **Step 6: Run tests — all should pass**

  ```bash
  cargo test -p op-succinct-fp --features tz tz_chain_client 2>&1 | tail -20
  ```

  Expected: all 6 tests pass.

- [ ] **Step 7: Commit**

  ```bash
  git add fault-proof/src/tz_chain_client.rs
  git commit -m "feat(tz): add TzChainClient with REST API polling, history cache, and tests"
  ```

---

## Task 6: tz_l2_provider.rs — TzL2Provider with tests

**Files:**
- Create: `fault-proof/src/tz_l2_provider.rs`

- [ ] **Step 1: Write failing tests first**

  Create `fault-proof/src/tz_l2_provider.rs`:

  ```rust
  use std::sync::Arc;

  use alloy_eips::BlockNumberOrTag;
  use alloy_primitives::{keccak256, Address, FixedBytes, B256, U256};
  use alloy_rpc_types_eth::Block;
  use anyhow::Result;
  use async_trait::async_trait;
  use op_alloy_rpc_types::Transaction;

  use crate::{
      tz_chain_client::{TzCacheMissError, TzChainClient},
      L2ProviderTrait,
  };

  pub struct TzL2Provider {
      pub tz_client: Arc<TzChainClient>,
  }

  /// Compute tz rootClaim: keccak256(blockHash ++ stateHash).
  pub fn compute_tz_root_claim(block_hash: B256, state_hash: B256) -> FixedBytes<32> {
      keccak256([block_hash.as_slice(), state_hash.as_slice()].concat())
  }

  #[async_trait]
  impl L2ProviderTrait for TzL2Provider {
      async fn get_l2_block_by_number(
          &self,
          _block_number: BlockNumberOrTag,
      ) -> Result<Block<Transaction>> {
          unreachable!("TzL2Provider does not support get_l2_block_by_number")
      }

      async fn get_l2_storage_root(
          &self,
          _address: Address,
          _block_number: BlockNumberOrTag,
      ) -> Result<B256> {
          unreachable!("TzL2Provider does not support get_l2_storage_root")
      }

      async fn compute_output_root_at_block(&self, l2_block_number: U256) -> Result<FixedBytes<32>> {
          let height = l2_block_number.to::<u64>();
          let info = self.tz_client.get_confirmed_block_info_at_height(height)?;
          Ok(compute_tz_root_claim(info.block_hash, info.state_hash))
      }

      async fn get_next_proposal_block(
          &self,
          canonical_head: U256,
          proposal_interval: u64,
      ) -> Result<Option<U256>> {
          let info = match self.tz_client.get_confirmed_block_info().await {
              Ok(i) => i,
              Err(_) => return Ok(None),
          };
          let confirmed = U256::from(info.height);
          if confirmed.saturating_sub(canonical_head) < U256::from(proposal_interval) {
              return Ok(None);
          }
          Ok(Some(confirmed))
      }

      fn evict_cache_below(&self, anchor_height: u64) {
          self.tz_client.evict_below(anchor_height);
      }
  }

  #[cfg(test)]
  mod tests {
      use super::*;
      use crate::tz_chain_client::TzBlockInfo;
      use wiremock::{
          matchers::{method, path},
          Mock, MockServer, ResponseTemplate,
      };

      const HASH_A: &str =
          "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      const HASH_B: &str =
          "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

      fn hash_a() -> B256 { HASH_A.parse().unwrap() }
      fn hash_b() -> B256 { HASH_B.parse().unwrap() }

      #[test]
      fn compute_tz_root_claim_matches_manual_keccak() {
          let expected = keccak256(
              [hash_a().as_slice(), hash_b().as_slice()].concat()
          );
          assert_eq!(compute_tz_root_claim(hash_a(), hash_b()), expected);
      }

      #[test]
      fn compute_tz_root_claim_differs_for_swapped_inputs() {
          let ab = compute_tz_root_claim(hash_a(), hash_b());
          let ba = compute_tz_root_claim(hash_b(), hash_a());
          assert_ne!(ab, ba);
      }

      fn make_provider_with_cached(height: u64, block_hash: B256, state_hash: B256) -> TzL2Provider {
          let client = Arc::new(TzChainClient::new(vec!["http://unused".to_string()]));
          {
              let mut h = client.history.lock().unwrap();
              h.insert(height, TzBlockInfo { height, block_hash, state_hash });
          }
          TzL2Provider { tz_client: client }
      }

      #[tokio::test]
      async fn compute_output_root_cache_hit_returns_correct_hash() {
          let provider = make_provider_with_cached(100, hash_a(), hash_b());
          let result = provider.compute_output_root_at_block(U256::from(100u64)).await.unwrap();
          assert_eq!(result, compute_tz_root_claim(hash_a(), hash_b()));
      }

      #[tokio::test]
      async fn compute_output_root_cache_miss_returns_tz_cache_miss_error() {
          let provider = make_provider_with_cached(100, hash_a(), hash_b());
          let err = provider
              .compute_output_root_at_block(U256::from(999u64))
              .await
              .unwrap_err();
          assert!(err.downcast_ref::<TzCacheMissError>().is_some());
          assert_eq!(err.downcast_ref::<TzCacheMissError>().unwrap().0, 999);
      }

      #[tokio::test]
      async fn get_next_proposal_block_returns_none_when_interval_not_met() {
          let mock_server = MockServer::start().await;
          Mock::given(method("GET"))
              .and(path("/chain/confirmed_block_info"))
              .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                  "code": 0, "message": "ok",
                  "data": { "height": 1050u64, "blockHash": HASH_A, "stateHash": HASH_B }
              })))
              .mount(&mock_server)
              .await;

          let client = Arc::new(TzChainClient::new(vec![mock_server.uri()]));
          let provider = TzL2Provider { tz_client: client };
          // canonical_head=1000, interval=100 => need confirmed >= 1100; got 1050 → None
          let result = provider
              .get_next_proposal_block(U256::from(1000u64), 100)
              .await
              .unwrap();
          assert!(result.is_none());
      }

      #[tokio::test]
      async fn get_next_proposal_block_returns_confirmed_when_interval_met() {
          let mock_server = MockServer::start().await;
          Mock::given(method("GET"))
              .and(path("/chain/confirmed_block_info"))
              .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                  "code": 0, "message": "ok",
                  "data": { "height": 1200u64, "blockHash": HASH_A, "stateHash": HASH_B }
              })))
              .mount(&mock_server)
              .await;

          let client = Arc::new(TzChainClient::new(vec![mock_server.uri()]));
          let provider = TzL2Provider { tz_client: client };
          // canonical_head=1000, interval=100 => need confirmed >= 1100; got 1200 → Some(1200)
          let result = provider
              .get_next_proposal_block(U256::from(1000u64), 100)
              .await
              .unwrap();
          assert_eq!(result, Some(U256::from(1200u64)));
      }

      #[tokio::test]
      async fn get_next_proposal_block_returns_none_on_api_error() {
          let client = Arc::new(TzChainClient::new(vec!["http://127.0.0.1:1".to_string()]));
          let provider = TzL2Provider { tz_client: client };
          let result = provider
              .get_next_proposal_block(U256::from(0u64), 100)
              .await
              .unwrap();
          assert!(result.is_none());
      }
  }
  ```

- [ ] **Step 2: Run tests**

  ```bash
  cargo test -p op-succinct-fp --features tz tz_l2_provider 2>&1 | tail -20
  ```

  Expected: all 7 tests pass (implementations are already complete in the file above).

- [ ] **Step 3: Commit**

  ```bash
  git add fault-proof/src/tz_l2_provider.rs
  git commit -m "feat(tz): add TzL2Provider implementing L2ProviderTrait with rootClaim and proposal logic"
  ```

---

## Task 7: tz_proposer_config.rs — TzConfig with tests

**Files:**
- Create: `fault-proof/src/tz_proposer_config.rs`

- [ ] **Step 1: Write failing tests first**

  Create `fault-proof/src/tz_proposer_config.rs` with only stub + tests:

  ```rust
  use alloy_primitives::B256;
  use anyhow::{anyhow, Result};

  pub struct TzConfig {
      pub rpc_urls: Vec<String>,
      /// tz dispute game type ID; default 1961
      pub game_type: u32,
      /// proposer only; None for challenger
      pub rollup_config_hash: Option<B256>,
  }

  impl TzConfig {
      pub fn from_env() -> Result<Self> {
          todo!()
      }

      pub fn challenger_from_env() -> Result<Self> {
          todo!()
      }

      fn parse_rpc_urls() -> Result<Vec<String>> {
          todo!()
      }

      fn parse_game_type() -> u32 {
          todo!()
      }
  }

  #[cfg(test)]
  mod tests {
      use super::*;
      use std::env;

      fn clear_tz_env() {
          env::remove_var("TZ_RPC_URLS");
          env::remove_var("TZ_ROLLUP_CONFIG_HASH");
          env::remove_var("TZ_GAME_TYPE");
      }

      #[test]
      fn from_env_parses_all_vars() {
          clear_tz_env();
          env::set_var("TZ_RPC_URLS", "http://a:8080,http://b:8080");
          env::set_var(
              "TZ_ROLLUP_CONFIG_HASH",
              "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          );
          env::set_var("TZ_GAME_TYPE", "42");

          let cfg = TzConfig::from_env().unwrap();
          assert_eq!(cfg.rpc_urls, vec!["http://a:8080", "http://b:8080"]);
          assert_eq!(cfg.game_type, 42);
          assert!(cfg.rollup_config_hash.is_some());
          clear_tz_env();
      }

      #[test]
      fn from_env_errors_when_rpc_urls_missing() {
          clear_tz_env();
          env::set_var(
              "TZ_ROLLUP_CONFIG_HASH",
              "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          );
          assert!(TzConfig::from_env().is_err());
          clear_tz_env();
      }

      #[test]
      fn from_env_errors_when_rollup_config_hash_missing() {
          clear_tz_env();
          env::set_var("TZ_RPC_URLS", "http://a:8080");
          assert!(TzConfig::from_env().is_err());
          clear_tz_env();
      }

      #[test]
      fn game_type_defaults_to_1961_when_unset() {
          clear_tz_env();
          env::set_var("TZ_RPC_URLS", "http://a:8080");
          env::set_var(
              "TZ_ROLLUP_CONFIG_HASH",
              "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          );
          let cfg = TzConfig::from_env().unwrap();
          assert_eq!(cfg.game_type, 1961);
          clear_tz_env();
      }

      #[test]
      fn challenger_from_env_does_not_require_rollup_config_hash() {
          clear_tz_env();
          env::set_var("TZ_RPC_URLS", "http://a:8080");
          let cfg = TzConfig::challenger_from_env().unwrap();
          assert!(cfg.rollup_config_hash.is_none());
          clear_tz_env();
      }
  }
  ```

- [ ] **Step 2: Run tests to confirm they fail**

  ```bash
  cargo test -p op-succinct-fp --features tz tz_proposer_config 2>&1 | tail -10
  ```

  Expected: tests panic with `not yet implemented`.

- [ ] **Step 3: Implement TzConfig**

  Replace stub bodies:

  ```rust
  impl TzConfig {
      pub fn from_env() -> Result<Self> {
          let rpc_urls = Self::parse_rpc_urls()?;
          let game_type = Self::parse_game_type();
          let hash_str = std::env::var("TZ_ROLLUP_CONFIG_HASH")
              .map_err(|_| anyhow!("TZ_ROLLUP_CONFIG_HASH not set"))?;
          let rollup_config_hash = hash_str
              .parse::<B256>()
              .map_err(|e| anyhow!("invalid TZ_ROLLUP_CONFIG_HASH: {e}"))?;
          Ok(Self { rpc_urls, game_type, rollup_config_hash: Some(rollup_config_hash) })
      }

      pub fn challenger_from_env() -> Result<Self> {
          Ok(Self {
              rpc_urls: Self::parse_rpc_urls()?,
              game_type: Self::parse_game_type(),
              rollup_config_hash: None,
          })
      }

      fn parse_rpc_urls() -> Result<Vec<String>> {
          let raw = std::env::var("TZ_RPC_URLS")
              .map_err(|_| anyhow!("TZ_RPC_URLS not set"))?;
          Ok(raw.split(',').map(str::trim).map(String::from).collect())
      }

      fn parse_game_type() -> u32 {
          std::env::var("TZ_GAME_TYPE")
              .ok()
              .and_then(|s| s.parse().ok())
              .unwrap_or(1961)
      }
  }
  ```

- [ ] **Step 4: Run tests — all should pass**

  ```bash
  cargo test -p op-succinct-fp --features tz tz_proposer_config 2>&1 | tail -10
  ```

  Expected: 5 tests pass.

- [ ] **Step 5: Commit**

  ```bash
  git add fault-proof/src/tz_proposer_config.rs
  git commit -m "feat(tz): add TzConfig for reading tz chain env vars with tests"
  ```

---

## Task 8: Placeholder ELF and binary entry files

**Files:**
- Create: `fault-proof/elfs/tz-range.elf` (empty placeholder)
- Create: `fault-proof/bin/tz_proposer.rs`
- Create: `fault-proof/bin/tz_challenger.rs`

- [ ] **Step 1: Create placeholder ELF**

  ```bash
  mkdir -p fault-proof/elfs
  touch fault-proof/elfs/tz-range.elf
  ```

  This empty file satisfies `include_bytes!` at compile time. Phase 1 deployments use `SP1_PROVER=cluster` so the ELF content is never read by the SP1 runtime.

- [ ] **Step 2: Create tz_proposer.rs**

  Create `fault-proof/bin/tz_proposer.rs`:

  ```rust
  use std::sync::Arc;

  use alloy_provider::ProviderBuilder;
  use anyhow::Result;
  use fault_proof::{
      challenger::OPSuccinctChallenger,
      config::ProposerConfig,
      contract::{AnchorStateRegistry, DisputeGameFactory},
      prometheus::ProposerGauge,
      proposer::OPSuccinctProposer,
      tz_chain_client::TzChainClient,
      tz_l2_provider::TzL2Provider,
      tz_proposer_config::TzConfig,
      L2ProviderTrait,
  };
  use op_succinct_host_utils::{
      fetcher::OPSuccinctDataFetcher,
      metrics::{init_metrics, MetricsGauge},
      setup_logger,
  };
  use op_succinct_proof_utils::initialize_host;
  use op_succinct_signer_utils::SignerLock;
  use tikv_jemallocator::Jemalloc;

  #[global_allocator]
  static ALLOCATOR: Jemalloc = Jemalloc;

  // for tz: placeholder ELF; replace with real tz range program ELF in Phase 2
  static TZ_RANGE_ELF: &[u8] = include_bytes!("../elfs/tz-range.elf");

  fn main() {
      dotenv::from_filename(".env.tz-proposer").ok();

      // for tz: parse TzConfig (sync) before tokio starts so set_var is single-threaded safe
      let tz_config = TzConfig::from_env().expect("invalid tz config");

      // for tz: inject GAME_TYPE so ProposerConfig::from_env() succeeds
      if std::env::var("GAME_TYPE").is_err() {
          std::env::set_var("GAME_TYPE", tz_config.game_type.to_string());
      }

      tokio::runtime::Builder::new_multi_thread()
          .enable_all()
          .build()
          .unwrap()
          .block_on(run(tz_config))
          .unwrap();
  }

  async fn run(tz_config: TzConfig) -> Result<()> {
      setup_logger();

      let proposer_config = ProposerConfig::from_env()?;
      proposer_config.log();

      let tz_client = Arc::new(TzChainClient::new(tz_config.rpc_urls));
      let l2_provider: Arc<dyn L2ProviderTrait + Send + Sync> =
          Arc::new(TzL2Provider { tz_client });

      let proposer_signer = SignerLock::from_env().await?;
      let l1_provider = ProviderBuilder::new().connect_http(proposer_config.l1_rpc.clone());

      let anchor_state_registry = AnchorStateRegistry::new(
          proposer_config.anchor_state_registry_address,
          l1_provider.clone(),
      );
      let factory = DisputeGameFactory::new(proposer_config.factory_address, l1_provider.clone());

      // for tz: use new() without rollup_config; tz node does not support optimism_rollupConfig
      let fetcher = OPSuccinctDataFetcher::new();
      let host = initialize_host(Arc::new(fetcher.clone()));

      let proposer = Arc::new(
          OPSuccinctProposer::new_with_l2_provider(
              proposer_config,
              proposer_signer,
              anchor_state_registry,
              factory,
              Arc::new(fetcher),
              host,
              l2_provider,
              tz_config.rollup_config_hash.expect("TZ_ROLLUP_CONFIG_HASH must be set"),
              TZ_RANGE_ELF,
          )
          .await?,
      );

      ProposerGauge::register_all();
      init_metrics(&proposer.config.metrics_port);
      ProposerGauge::init_all();

      // validate_anchor_l2_block is skipped inside startup_validations via #[cfg(not(feature="tz"))]
      proposer.run().await.expect("Runs in an infinite loop");
      Ok(())
  }
  ```

- [ ] **Step 3: Create tz_challenger.rs**

  Create `fault-proof/bin/tz_challenger.rs`:

  ```rust
  use std::{sync::Arc, time::Duration};

  use alloy_provider::ProviderBuilder;
  use anyhow::Result;
  use fault_proof::{
      challenger::OPSuccinctChallenger,
      config::ChallengerConfig,
      contract::{AnchorStateRegistry, DisputeGameFactory},
      prometheus::ChallengerGauge,
      tz_chain_client::TzChainClient,
      tz_l2_provider::TzL2Provider,
      tz_proposer_config::TzConfig,
      L2ProviderTrait,
  };
  use op_succinct_host_utils::{
      metrics::{init_metrics, MetricsGauge},
      setup_logger,
  };
  use op_succinct_signer_utils::SignerLock;
  use tikv_jemallocator::Jemalloc;

  #[global_allocator]
  static ALLOCATOR: Jemalloc = Jemalloc;

  fn main() {
      dotenv::from_filename(".env.tz-challenger").ok();

      // for tz: parse TzConfig (sync) before tokio starts
      let tz_config = TzConfig::challenger_from_env().expect("invalid tz config");

      // for tz: inject GAME_TYPE so ChallengerConfig::from_env() succeeds
      if std::env::var("GAME_TYPE").is_err() {
          std::env::set_var("GAME_TYPE", tz_config.game_type.to_string());
      }

      tokio::runtime::Builder::new_multi_thread()
          .enable_all()
          .build()
          .unwrap()
          .block_on(run(tz_config))
          .unwrap();
  }

  async fn run(tz_config: TzConfig) -> Result<()> {
      setup_logger();

      let challenger_config = ChallengerConfig::from_env()?;
      challenger_config.log();

      let tz_client = Arc::new(TzChainClient::new(tz_config.rpc_urls));
      let l2_provider: Arc<dyn L2ProviderTrait + Send + Sync> =
          Arc::new(TzL2Provider { tz_client: Arc::clone(&tz_client) });

      // for tz: background task polls /chain/confirmed_block_info every 60s to pre-fill cache
      // so fetch_game does not miss checkpoints observed between sync_state cycles
      let poll_client = Arc::clone(&tz_client);
      tokio::spawn(async move {
          let mut interval = tokio::time::interval(Duration::from_secs(60));
          loop {
              interval.tick().await;
              if let Err(e) = poll_client.get_confirmed_block_info().await {
                  tracing::warn!("tz: checkpoint poll failed: {e}");
              }
          }
      });

      let challenger_signer = SignerLock::from_env().await?;
      let l1_provider = ProviderBuilder::default()
          .connect_http(challenger_config.l1_rpc.clone());

      let anchor_state_registry = AnchorStateRegistry::new(
          challenger_config.anchor_state_registry_address,
          l1_provider.clone(),
      );
      let factory =
          DisputeGameFactory::new(challenger_config.factory_address, l1_provider.clone());

      let mut challenger = OPSuccinctChallenger::new_with_l2_provider(
          challenger_config,
          l1_provider,
          anchor_state_registry,
          factory,
          challenger_signer,
          l2_provider,
      );

      ChallengerGauge::register_all();
      init_metrics(&challenger.config.metrics_port);
      ChallengerGauge::init_all();

      challenger.run().await.expect("Runs in an infinite loop");
      Ok(())
  }
  ```

- [ ] **Step 4: Verify tz binaries compile**

  ```bash
  cargo check -p op-succinct-fp --features tz --bins 2>&1 | head -20
  ```

  Expected: clean. Both `tz-proposer` and `tz-challenger` compile.

- [ ] **Step 5: Commit**

  ```bash
  git add fault-proof/elfs/tz-range.elf fault-proof/bin/tz_proposer.rs fault-proof/bin/tz_challenger.rs
  git commit -m "feat(tz): add tz-proposer and tz-challenger binary entry files and placeholder ELF"
  ```

---

## Task 9: proposer.rs — remaining #[cfg] patches

**Files:**
- Modify: `fault-proof/src/proposer.rs`

Six targeted patches in existing functions. Make each change, run `cargo check --features tz` after all six, then commit once.

- [ ] **Step 1: Import TzCacheMissError at top of file**

  After the existing `use crate::{ ... }` block, add:

  ```rust
  // for tz: import cache-miss error for graceful skip in proposer fetch_game
  #[cfg(feature = "tz")]
  use crate::tz_chain_client::TzCacheMissError;
  ```

- [ ] **Step 2: startup_validations — skip validate_anchor_l2_block**

  Find in `startup_validations()`:
  ```rust
  Self::validate_anchor_l2_block(
      anchor_l2_block,
      &self.config,
      self.host.as_ref(),
      self.fetcher.as_ref(),
  )
  .await?;
  ```

  Replace with:
  ```rust
  // for tz: validate_anchor_l2_block requires eth_getBlockByNumber("finalized") which tz does not support
  #[cfg(not(feature = "tz"))]
  Self::validate_anchor_l2_block(
      anchor_l2_block,
      &self.config,
      self.host.as_ref(),
      self.fetcher.as_ref(),
  )
  .await?;
  ```

- [ ] **Step 3: fetch_proposer_metrics — skip get_finalized_l2_block_number**

  Find in `fetch_proposer_metrics()`:
  ```rust
  if let Some(finalized_l2_block_number) = self
      .host
      .get_finalized_l2_block_number(&self.fetcher, canonical_head_l2_block.to::<u64>())
      .await?
  {
      ProposerGauge::FinalizedL2BlockNumber.set(finalized_l2_block_number as f64);
  }
  ```

  Replace with:
  ```rust
  // for tz: tz node does not support eth_getBlockByNumber("finalized"); skip this metric
  #[cfg(not(feature = "tz"))]
  if let Some(finalized_l2_block_number) = self
      .host
      .get_finalized_l2_block_number(&self.fetcher, canonical_head_l2_block.to::<u64>())
      .await?
  {
      ProposerGauge::FinalizedL2BlockNumber.set(finalized_l2_block_number as f64);
  }
  ```

- [ ] **Step 4: fetch_game (proposer) — cache miss handling**

  In `fetch_game()`, find:
  ```rust
  let l2_block = contract.l2BlockNumber().call().await?;
  let output_root = self.l2_provider.compute_output_root_at_block(l2_block).await?;
  let claim = contract.rootClaim().call().await?;
  ```

  Replace with:
  ```rust
  let l2_block = contract.l2BlockNumber().call().await?;

  // for tz: cache miss — own games skip rootClaim validation; foreign games also enter
  // state.games to preserve canonical head tracking in multi-proposer deployments
  #[cfg(feature = "tz")]
  let maybe_output_root: Option<FixedBytes<32>> = {
      match self.l2_provider.compute_output_root_at_block(l2_block).await {
          Ok(root) => Some(root),
          Err(e) if e.downcast_ref::<TzCacheMissError>().is_some() => {
              let creator = contract.gameCreator().call().await?;
              if creator == self.signer.address() {
                  tracing::debug!(game_index = %index, l2_block_number = %l2_block,
                      "tz: cache miss — own game, skipping rootClaim validation");
              } else {
                  tracing::warn!(game_index = %index, l2_block_number = %l2_block, %creator,
                      "tz: cache miss — foreign game, adding to state without rootClaim validation");
              }
              None
          }
          Err(e) => return Err(e),
      }
  };
  #[cfg(not(feature = "tz"))]
  let maybe_output_root: Option<FixedBytes<32>> =
      Some(self.l2_provider.compute_output_root_at_block(l2_block).await?);

  let claim = contract.rootClaim().call().await?;
  ```

  Then find the rootClaim validation block:
  ```rust
  // Validate output root. If invalid, drop the game, setting the cursor to this index.
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
  ```

  Replace with:
  ```rust
  // for tz: skip validation on cache miss; xlayer always validates (maybe_output_root is always Some)
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
  ```

- [ ] **Step 5: should_create_game — tz short-circuit**

  In `should_create_game()`, find the line just before the `get_finalized_l2_block_number` call:
  ```rust
  let next_l2_block_number_for_proposal =
      canonical_head_l2_block + U256::from(self.config.proposal_interval_in_blocks);

  let finalized_l2_head_block_number = self
      .host
      .get_finalized_l2_block_number(...)
  ```

  Insert between those two sections:
  ```rust
  // for tz: always return here — never fall through to get_finalized_l2_block_number
  // which requires eth_getBlockByNumber("finalized")
  #[cfg(feature = "tz")]
  {
      return match self.l2_provider
          .get_next_proposal_block(
              canonical_head_l2_block,
              self.config.proposal_interval_in_blocks,
          )
          .await?
      {
          Some(target) => Ok((true, target, parent_game_index)),
          None => Ok((false, U256::ZERO, u32::MAX)),
      };
  }
  ```

- [ ] **Step 6: handle_game_creation — UUID collision one-shot check**

  Find the `while maybe_existing_game != Address::ZERO` loop:
  ```rust
  while maybe_existing_game != Address::ZERO {
      next_l2_block_number_for_proposal += U256::from(1);
      output_root = self
          .l2_provider
          .compute_output_root_at_block(next_l2_block_number_for_proposal)
          .await?;
      extra_data = (next_l2_block_number_for_proposal, parent_game_index).abi_encode_packed();
      maybe_existing_game = self
          .factory
          .games(self.config.game_type, output_root, extra_data.clone().into())
          .call()
          .await?
          .proxy;
  }
  ```

  Replace with:
  ```rust
  // for tz: one-shot check — confirmed_height maps to exactly one rootClaim;
  // incrementing block number would not change rootClaim, so skip and wait for next checkpoint
  #[cfg(feature = "tz")]
  if maybe_existing_game != Address::ZERO {
      tracing::info!(
          l2_block_number = %next_l2_block_number_for_proposal,
          "tz: game already exists for this checkpoint, skipping"
      );
      return Ok(());
  }

  // xlayer: retry with incremented block number on UUID collision (original behavior preserved)
  #[cfg(not(feature = "tz"))]
  while maybe_existing_game != Address::ZERO {
      next_l2_block_number_for_proposal += U256::from(1);
      output_root = self
          .l2_provider
          .compute_output_root_at_block(next_l2_block_number_for_proposal)
          .await?;
      extra_data = (next_l2_block_number_for_proposal, parent_game_index).abi_encode_packed();
      maybe_existing_game = self
          .factory
          .games(self.config.game_type, output_root, extra_data.clone().into())
          .call()
          .await?
          .proxy;
  }
  ```

- [ ] **Step 7: sync_state — evict cache after anchor advances**

  Find the end of `sync_state()`:
  ```rust
  pub async fn sync_state(&self) -> Result<()> {
      self.sync_games().await?;
      self.sync_anchor_game().await?;
      self.compute_canonical_head().await;

      Ok(())
  }
  ```

  Replace with:
  ```rust
  pub async fn sync_state(&self) -> Result<()> {
      self.sync_games().await?;
      self.sync_anchor_game().await?;
      self.compute_canonical_head().await;

      // for tz: evict cache entries below anchor_height after each sync cycle
      // xlayer: evict_cache_below is a no-op on the default L2Provider
      #[cfg(feature = "tz")]
      {
          let anchor_height = self.state.read().await
              .anchor_game.as_ref()
              .map(|g| g.l2_block.to::<u64>())
              .unwrap_or(0);
          if anchor_height > 0 {
              self.l2_provider.evict_cache_below(anchor_height);
          }
      }

      Ok(())
  }
  ```

- [ ] **Step 8: Verify full tz build passes**

  ```bash
  cargo check -p op-succinct-fp --features tz 2>&1 | head -20
  ```

  Expected: clean.

- [ ] **Step 9: Verify xlayer build is unaffected**

  ```bash
  cargo check -p op-succinct-fp 2>&1 | head -10
  ```

  Expected: clean.

- [ ] **Step 10: Commit**

  ```bash
  git add fault-proof/src/proposer.rs
  git commit -m "feat(tz): add cfg patches to proposer (validations, metrics, game creation, cache eviction)"
  ```

---

## Task 10: challenger.rs — fetch_game cache miss patch

**Files:**
- Modify: `fault-proof/src/challenger.rs`

- [ ] **Step 1: Import TzCacheMissError**

  Add after the existing `use crate::{ ... }` block:

  ```rust
  // for tz: import cache-miss error for graceful skip in challenger fetch_game
  #[cfg(feature = "tz")]
  use crate::tz_chain_client::TzCacheMissError;
  ```

- [ ] **Step 2: Patch fetch_game — skip game on cache miss**

  Find in `fetch_game()`:
  ```rust
  let computed_output_root =
      self.l2_provider.compute_output_root_at_block(l2_block_number).await?;
  ```

  Replace with:
  ```rust
  // for tz: cache miss means checkpoint not yet observed; skip game (cannot decide whether to
  // challenge without computing the rootClaim)
  #[cfg(feature = "tz")]
  let computed_output_root = match
      self.l2_provider.compute_output_root_at_block(l2_block_number).await
  {
      Ok(root) => root,
      Err(e) if e.downcast_ref::<TzCacheMissError>().is_some() => {
          tracing::debug!(
              game_index = %index,
              l2_block_number = %l2_block_number,
              "tz: no cached checkpoint, skipping game"
          );
          let mut state = self.state.lock().await;
          state.cursor = index;
          return Ok(());
      }
      Err(e) => return Err(e),
  };
  #[cfg(not(feature = "tz"))]
  let computed_output_root =
      self.l2_provider.compute_output_root_at_block(l2_block_number).await?;
  ```

- [ ] **Step 3: Verify full build (both feature sets)**

  ```bash
  cargo check -p op-succinct-fp --features tz 2>&1 | head -10
  cargo check -p op-succinct-fp 2>&1 | head -10
  ```

  Both expected: clean.

- [ ] **Step 4: Run all tz unit tests**

  ```bash
  cargo test -p op-succinct-fp --features tz 2>&1 | tail -20
  ```

  Expected: all tests pass (tz_chain_client, tz_l2_provider, tz_proposer_config).

- [ ] **Step 5: Run xlayer unit tests**

  ```bash
  cargo test -p op-succinct-fp 2>&1 | tail -10
  ```

  Expected: existing tests pass without regression.

- [ ] **Step 6: Commit**

  ```bash
  git add fault-proof/src/challenger.rs
  git commit -m "feat(tz): add cache miss skip in challenger fetch_game for tz feature"
  ```

---

## Verification Checklist

After all tasks complete:

- [ ] `cargo check -p op-succinct-fp --features tz` — clean
- [ ] `cargo check -p op-succinct-fp` — clean (xlayer unaffected)
- [ ] `cargo build -p op-succinct-fp --features tz --bin tz-proposer` — produces binary
- [ ] `cargo build -p op-succinct-fp --features tz --bin tz-challenger` — produces binary
- [ ] `cargo test -p op-succinct-fp --features tz` — all new tests pass
- [ ] `cargo test -p op-succinct-fp` — no regressions
- [ ] All modified lines in existing files have `// for tz:` comments

## Environment Variables for Deployment

| Variable | Binary | Default | Required |
|----------|--------|---------|----------|
| `TZ_RPC_URLS` | both | — | yes |
| `TZ_ROLLUP_CONFIG_HASH` | proposer | — | yes |
| `TZ_GAME_TYPE` | both | `1961` | no |
| `SP1_PROVER` | proposer | — | set to `cluster` for Phase 1 |
| Standard op-succinct env vars | both | — | yes (L1_RPC, FACTORY_ADDRESS, etc.) |
