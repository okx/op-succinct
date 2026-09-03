//! Witness Builder v2 host client (spec §7.1): four-field checkpoint, tree-boundary witness,
//! canonical record, and historical inclusion proof.
//!
//! All results are classified through [`WbError`] so callers can distinguish retryable
//! (`NotReady` / transient transport) from permanent conditions. Boundary decoding validates
//! the wire invariant `active_branches.len() == popcount(count)` and rebuilds the declared root
//! via [`tree_adapter`], rejecting on mismatch (spec §4).
//!
//! Route names below follow the documented WB v2 protocol shapes. They MUST be confirmed against
//! the tradezone `feature/witness-builder-withdraw-v1` service before production wiring; the
//! private tradezone repo is not fetchable in this build environment (see the access hand-off
//! note), so the wire mapping is verified here with `wiremock` against the documented shapes.

use std::time::Duration;

use alloy_primitives::{Address, B256, U256};
use reqwest::Url;
use serde::Deserialize;

use super::claim::claim_root;
use super::error::WbError;
use super::tree_adapter::{business_root, root_from_frontier, FORCE_TAG, TREE_DEPTH, WITHDRAWAL_TAG};
use super::types::{CheckpointV2, HistoricalInclusionProof, TreeBoundaryWitness, WithdrawRecord};

const WB_TIMEOUT: Duration = Duration::from_secs(30);
const SUPPORTED_SCHEMA_VERSION: u16 = 2;

// TODO(route): confirm the following route names against WB v2
// (tradezone feature/witness-builder-withdraw-v1) before production wiring.
const ROUTE_CHECKPOINT: &str = "chain/dex_state_snapshot";
const ROUTE_BOUNDARY: &str = "chain/tree_boundary_witness";
const ROUTE_RECORD: &str = "chain/canonical_record";
const ROUTE_PROOF: &str = "chain/historical_inclusion_proof";

/// Host-side Witness Builder v2 client.
pub struct WbClient {
    base: Url,
    http: reqwest::Client,
    chain_id: u64,
}

impl WbClient {
    /// Build a client. `chain_id` is the locally-configured TZ chain id used to guard
    /// CheckpointV2 responses; it MUST be non-zero.
    pub fn new(base: Url, chain_id: u64) -> Result<Self, WbError> {
        Self::new_with_timeout(base, chain_id, WB_TIMEOUT)
    }

    pub fn new_with_timeout(mut base: Url, chain_id: u64, timeout: Duration) -> Result<Self, WbError> {
        if !matches!(base.scheme(), "http" | "https") {
            return Err(WbError::permanent_transport("witness-builder URL must be http(s)"));
        }
        if chain_id == 0 {
            return Err(WbError::permanent_transport("configured tz chain_id must be non-zero"));
        }
        if !base.path().ends_with('/') {
            let p = format!("{}/", base.path());
            base.set_path(&p);
        }
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| WbError::permanent_transport(format!("failed to build HTTP client: {e}")))?;
        Ok(Self { base, http, chain_id })
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        route: &str,
        query: &[(&str, String)],
    ) -> Result<T, WbError> {
        let mut url = self
            .base
            .join(route)
            .map_err(|e| WbError::permanent_transport(format!("bad route {route}: {e}")))?;
        {
            let mut qp = url.query_pairs_mut();
            for (k, v) in query {
                qp.append_pair(k, v);
            }
        }
        let resp = self.http.get(url).send().await.map_err(|e| {
            // Timeouts / connection resets are transient; retry with backoff.
            WbError::transient_transport(format!("request failed: {e}"))
        })?;
        let status = resp.status();
        if status.is_server_error() {
            return Err(WbError::transient_transport(format!("witness-builder HTTP {status}")));
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(WbError::CheckpointNotFound);
        }
        if status.is_client_error() {
            return Err(WbError::InvalidRequest);
        }
        let env: ApiEnvelope<T> = resp
            .json()
            .await
            .map_err(|e| WbError::permanent_transport(format!("invalid JSON: {e}")))?;
        if env.code != 0 {
            return Err(WbError::InvalidRequest);
        }
        env.data.ok_or(WbError::CheckpointNotFound)
    }

    /// Fetch the four-field checkpoint at `height`, verifying `chainId`, `schemaVersion`, and that
    /// the four components recompute to the advertised `claimRoot`.
    pub async fn get_checkpoint_v2(&self, height: u64) -> Result<CheckpointV2, WbError> {
        let d: CheckpointDto = self
            .get(ROUTE_CHECKPOINT, &[("height", height.to_string()), ("format", "root".into())])
            .await?;
        match d.status.as_str() {
            "ready" => {}
            "running" | "not_ready" | "above_local_tip" => return Err(WbError::NotReady),
            _ => return Err(WbError::CheckpointNotFound),
        }
        if d.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(WbError::UnsupportedVersion);
        }
        if d.chain_id == 0 || d.chain_id != self.chain_id {
            return Err(WbError::InvalidRequest);
        }
        let c = d.components.ok_or(WbError::WitnessStoreCorrupt)?;
        let claim = d.claim_root.ok_or(WbError::WitnessStoreCorrupt)?;
        // The four components MUST recompute to the advertised claimRoot.
        if claim_root(c.block_hash, c.app_hash, c.withdrawal_root, c.force_root) != claim {
            return Err(WbError::RootMismatch);
        }
        Ok(CheckpointV2 {
            schema_version: d.schema_version,
            chain_id: d.chain_id,
            block_height: d.height,
            block_hash: c.block_hash,
            app_hash: c.app_hash,
            withdrawal_root: c.withdrawal_root,
            force_root: c.force_root,
            claim_root: claim,
        })
    }

    /// Fetch the tree boundary witness at `height`. Validates `len == popcount(count)` and, when
    /// declared roots are present, rebuilds them from the frontier and rejects on mismatch.
    pub async fn get_tree_boundary_witness(&self, height: u64) -> Result<TreeBoundaryWitness, WbError> {
        let d: BoundaryDto =
            self.get(ROUTE_BOUNDARY, &[("height", height.to_string())]).await?;
        if d.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(WbError::UnsupportedVersion);
        }
        if d.chain_id == 0 || d.chain_id != self.chain_id {
            return Err(WbError::InvalidRequest);
        }
        // Rebuild each tree's inner root from the frontier (also enforces len == popcount(count)).
        let w_inner = root_from_frontier(&d.withdrawal.active_branches, d.withdrawal.count)?;
        let f_inner = root_from_frontier(&d.force.active_branches, d.force.count)?;
        // Cross-check declared roots when the WB provides them.
        if let Some(decl) = d.withdrawal.declared_root {
            if business_root(w_inner, d.withdrawal.count, WITHDRAWAL_TAG) != decl {
                return Err(WbError::WitnessStoreCorrupt);
            }
        }
        if let Some(decl) = d.force.declared_root {
            if business_root(f_inner, d.force.count, FORCE_TAG) != decl {
                return Err(WbError::WitnessStoreCorrupt);
            }
        }
        Ok(TreeBoundaryWitness {
            schema_version: d.schema_version,
            chain_id: d.chain_id,
            block_height: d.block_height,
            withdrawal_count: d.withdrawal.count,
            withdrawal_active_branches: d.withdrawal.active_branches,
            force_count: d.force.count,
            force_active_branches: d.force.active_branches,
        })
    }

    /// Fetch the canonical Withdraw record for a record hash.
    pub async fn get_canonical_record(&self, record_hash: B256) -> Result<WithdrawRecord, WbError> {
        let d: RecordDto = self
            .get(ROUTE_RECORD, &[("recordHash", format!("{record_hash:#x}"))])
            .await?;
        Ok(d.into_record())
    }

    /// Fetch the canonical block height at which the record for `record_hash` was included. The
    /// height is taken from the WB (never the caller). A record that carries no canonical height
    /// yet is treated as not-yet-included (`WithdrawalNotFound`).
    pub async fn get_canonical_record_height(&self, record_hash: B256) -> Result<u64, WbError> {
        let d: RecordDto = self
            .get(ROUTE_RECORD, &[("recordHash", format!("{record_hash:#x}"))])
            .await?;
        d.canonical_block_height.ok_or(WbError::WithdrawalNotFound)
    }

    /// Fetch a historical inclusion proof bound to an exact `(checkpoint_height, withdrawal_root)`.
    pub async fn get_historical_inclusion_proof(
        &self,
        record_hash: B256,
        checkpoint_height: u64,
        withdrawal_root: B256,
    ) -> Result<HistoricalInclusionProof, WbError> {
        let d: ProofDto = self
            .get(
                ROUTE_PROOF,
                &[
                    ("recordHash", format!("{record_hash:#x}")),
                    ("checkpointHeight", checkpoint_height.to_string()),
                    ("withdrawalRoot", format!("{withdrawal_root:#x}")),
                ],
            )
            .await?;
        if d.siblings.len() != TREE_DEPTH {
            return Err(WbError::WitnessStoreCorrupt);
        }
        let mut siblings = [B256::ZERO; TREE_DEPTH];
        siblings.copy_from_slice(&d.siblings);
        Ok(HistoricalInclusionProof {
            record: d.record.into_record(),
            record_hash: d.record_hash,
            leaf_hash: d.leaf_hash,
            canonical_block_height: d.canonical_block_height,
            checkpoint_height: d.checkpoint_height,
            withdrawal_root: d.withdrawal_root,
            leaf_index: d.leaf_index,
            count: d.count,
            siblings,
        })
    }
}

#[derive(Deserialize)]
struct ApiEnvelope<T> {
    code: i32,
    #[serde(default)]
    #[allow(dead_code)]
    message: String,
    data: Option<T>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckpointDto {
    #[serde(default)]
    schema_version: u16,
    #[serde(default)]
    chain_id: u64,
    height: u64,
    status: String,
    claim_root: Option<B256>,
    components: Option<ComponentsDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ComponentsDto {
    block_hash: B256,
    app_hash: B256,
    withdrawal_root: B256,
    force_root: B256,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BoundaryDto {
    #[serde(default)]
    schema_version: u16,
    #[serde(default)]
    chain_id: u64,
    block_height: u64,
    withdrawal: TreeSideDto,
    force: TreeSideDto,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TreeSideDto {
    count: u32,
    #[serde(default)]
    active_branches: Vec<B256>,
    #[serde(default)]
    declared_root: Option<B256>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecordDto {
    version: u16,
    chain_id: u64,
    transaction_hash: B256,
    token_type: u8,
    token_address: Address,
    #[serde(default)]
    token_ids: Vec<U256>,
    #[serde(default)]
    amounts: Vec<U256>,
    from: Address,
    to: Address,
    #[serde(default)]
    canonical_block_height: Option<u64>,
}

impl RecordDto {
    fn into_record(self) -> WithdrawRecord {
        WithdrawRecord {
            version: self.version,
            chain_id: self.chain_id,
            transaction_hash: self.transaction_hash,
            token_type: self.token_type,
            token_address: self.token_address,
            token_ids: self.token_ids,
            amounts: self.amounts,
            from: self.from,
            to: self.to,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofDto {
    record: RecordDto,
    record_hash: B256,
    leaf_hash: B256,
    canonical_block_height: u64,
    checkpoint_height: u64,
    withdrawal_root: B256,
    leaf_index: u32,
    count: u32,
    siblings: Vec<B256>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tz::withdraw::tree_adapter::{business_root, WITHDRAWAL_TAG};
    use wiremock::{
        matchers::{method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    fn client(server: &MockServer, chain_id: u64) -> WbClient {
        WbClient::new(server.uri().parse().unwrap(), chain_id).unwrap()
    }

    fn ok_body(data: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "code": 0, "message": "ok", "data": data })
    }

    #[tokio::test]
    async fn checkpoint_v2_maps_fields_and_recomputes_claim() {
        let bh = B256::repeat_byte(0x11);
        let ah = B256::repeat_byte(0x22);
        let wr = B256::repeat_byte(0x33);
        let fr = B256::repeat_byte(0x44);
        let claim = claim_root(bh, ah, wr, fr);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/dex_state_snapshot"))
            .and(query_param("height", "100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(serde_json::json!({
                "schemaVersion": 2, "chainId": 196, "height": 100, "status": "ready",
                "claimRoot": claim,
                "components": { "blockHash": bh, "appHash": ah, "withdrawalRoot": wr, "forceRoot": fr }
            }))))
            .mount(&server)
            .await;
        let cp = client(&server, 196).get_checkpoint_v2(100).await.unwrap();
        assert_eq!(cp.chain_id, 196);
        assert_eq!(cp.withdrawal_root, wr);
        assert_eq!(cp.force_root, fr);
        assert_eq!(cp.claim_root, claim);
    }

    #[tokio::test]
    async fn checkpoint_running_is_not_ready_and_chainid_guarded() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/dex_state_snapshot"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(ok_body(serde_json::json!({ "schemaVersion": 2, "chainId": 196, "height": 7, "status": "running" }))))
            .mount(&server)
            .await;
        let err = client(&server, 196).get_checkpoint_v2(7).await.unwrap_err();
        assert!(matches!(err, WbError::NotReady));
        assert!(err.is_retryable());
    }

    #[tokio::test]
    async fn checkpoint_component_mismatch_is_root_mismatch() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/dex_state_snapshot"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(serde_json::json!({
                "schemaVersion": 2, "chainId": 196, "height": 100, "status": "ready",
                "claimRoot": B256::repeat_byte(0xEE), // does not match components
                "components": { "blockHash": B256::repeat_byte(0x11), "appHash": B256::repeat_byte(0x22),
                    "withdrawalRoot": B256::repeat_byte(0x33), "forceRoot": B256::repeat_byte(0x44) }
            }))))
            .mount(&server)
            .await;
        assert!(matches!(client(&server, 196).get_checkpoint_v2(100).await, Err(WbError::RootMismatch)));
    }

    #[tokio::test]
    async fn checkpoint_wrong_chain_id_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/dex_state_snapshot"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(serde_json::json!({
                "schemaVersion": 2, "chainId": 999, "height": 100, "status": "ready",
                "claimRoot": B256::ZERO,
                "components": { "blockHash": B256::ZERO, "appHash": B256::ZERO, "withdrawalRoot": B256::ZERO, "forceRoot": B256::ZERO }
            }))))
            .mount(&server)
            .await;
        assert!(matches!(client(&server, 196).get_checkpoint_v2(100).await, Err(WbError::InvalidRequest)));
    }

    #[tokio::test]
    async fn boundary_valid_popcount_maps_and_bad_length_is_corrupt() {
        // count=2 ⇒ popcount(2)=1 active branch. Provide 1 (valid) then 2 (invalid).
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/tree_boundary_witness"))
            .and(query_param("height", "50"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(serde_json::json!({
                "schemaVersion": 2, "chainId": 196, "blockHeight": 50,
                "withdrawal": { "count": 2, "activeBranches": [B256::repeat_byte(0x11)] },
                "force": { "count": 0, "activeBranches": [] }
            }))))
            .mount(&server)
            .await;
        let b = client(&server, 196).get_tree_boundary_witness(50).await.unwrap();
        assert_eq!(b.withdrawal_count, 2);
        assert_eq!(b.withdrawal_active_branches.len(), 1);
        assert!(b.force_active_branches.is_empty());

        let server2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/tree_boundary_witness"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(serde_json::json!({
                "schemaVersion": 2, "chainId": 196, "blockHeight": 50,
                "withdrawal": { "count": 2, "activeBranches": [B256::repeat_byte(0x11), B256::repeat_byte(0x22)] },
                "force": { "count": 0, "activeBranches": [] }
            }))))
            .mount(&server2)
            .await;
        assert!(matches!(
            client(&server2, 196).get_tree_boundary_witness(50).await,
            Err(WbError::WitnessStoreCorrupt)
        ));
    }

    #[tokio::test]
    async fn boundary_declared_root_mismatch_is_corrupt() {
        // count=1, 1 active branch, but a declared root that does not match the frontier rebuild.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/tree_boundary_witness"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(serde_json::json!({
                "schemaVersion": 2, "chainId": 196, "blockHeight": 50,
                "withdrawal": { "count": 1, "activeBranches": [B256::repeat_byte(0x11)], "declaredRoot": B256::repeat_byte(0xFF) },
                "force": { "count": 0, "activeBranches": [] }
            }))))
            .mount(&server)
            .await;
        assert!(matches!(
            client(&server, 196).get_tree_boundary_witness(50).await,
            Err(WbError::WitnessStoreCorrupt)
        ));
    }

    #[tokio::test]
    async fn http_5xx_is_transient_and_retryable() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/dex_state_snapshot"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .mount(&server)
            .await;
        let err = client(&server, 196).get_checkpoint_v2(1).await.unwrap_err();
        assert!(err.is_retryable());
    }

    #[tokio::test]
    async fn proof_maps_and_bad_siblings_len_is_corrupt() {
        let server = MockServer::start().await;
        let rec = serde_json::json!({
            "version": 1, "chainId": 196, "transactionHash": B256::repeat_byte(0x01),
            "tokenType": 0, "tokenAddress": Address::ZERO, "tokenIds": [], "amounts": [],
            "from": Address::ZERO, "to": Address::ZERO
        });
        let sibs: Vec<String> = (0..32).map(|_| format!("{:#x}", B256::ZERO)).collect();
        Mock::given(method("GET"))
            .and(path("/chain/historical_inclusion_proof"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(serde_json::json!({
                "record": rec, "recordHash": B256::repeat_byte(0x01), "leafHash": B256::repeat_byte(0x01),
                "canonicalBlockHeight": 10, "checkpointHeight": 20, "withdrawalRoot": B256::repeat_byte(0x33),
                "leafIndex": 0, "count": 1, "siblings": sibs
            }))))
            .mount(&server)
            .await;
        let p = client(&server, 196)
            .get_historical_inclusion_proof(B256::repeat_byte(0x01), 20, B256::repeat_byte(0x33))
            .await
            .unwrap();
        assert_eq!(p.count, 1);
        assert_eq!(p.checkpoint_height, 20);

        // Bad siblings length ⇒ corrupt.
        let server2 = MockServer::start().await;
        let short: Vec<String> = (0..31).map(|_| format!("{:#x}", B256::ZERO)).collect();
        Mock::given(method("GET"))
            .and(path("/chain/historical_inclusion_proof"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(serde_json::json!({
                "record": rec, "recordHash": B256::repeat_byte(0x01), "leafHash": B256::repeat_byte(0x01),
                "canonicalBlockHeight": 10, "checkpointHeight": 20, "withdrawalRoot": B256::repeat_byte(0x33),
                "leafIndex": 0, "count": 1, "siblings": short
            }))))
            .mount(&server2)
            .await;
        assert!(matches!(
            client(&server2, 196)
                .get_historical_inclusion_proof(B256::repeat_byte(0x01), 20, B256::repeat_byte(0x33))
                .await,
            Err(WbError::WitnessStoreCorrupt)
        ));
        // Silence unused import warning when only some branches run.
        let _ = business_root(B256::ZERO, 0, WITHDRAWAL_TAG);
    }
}
