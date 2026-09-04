use std::time::Duration;

use alloy_primitives::{keccak256, B256};
use alloy_provider::Provider;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use reqwest::Url;
use serde::Deserialize;

use crate::{
    checked_l2_block_number,
    contract::AnchorStateRegistry::AnchorStateRegistryInstance,
    game_validator::{
        classify_computed_output_root, GameValidation, GameValidationRequest, GameValidator,
        InvalidReason, UnavailableReason,
    },
};

pub const TZ_CUTOFF_MARGIN_SECS: u64 = 3600;
const ROOT_QUERY_TIMEOUT: Duration = Duration::from_secs(30);

/// TZ claim validator backed by one fixed witness-builder root oracle.
pub struct TzGameValidator<P>
where
    P: Provider + Clone,
{
    anchor_state_registry: AnchorStateRegistryInstance<P>,
    root_client: TzRootClient,
}

impl<P> TzGameValidator<P>
where
    P: Provider + Clone,
{
    pub fn new(
        anchor_state_registry: AnchorStateRegistryInstance<P>,
        witness_builder_url: Url,
        chain_id: u64,
    ) -> Result<Self> {
        Ok(Self {
            anchor_state_registry,
            root_client: TzRootClient::new(witness_builder_url, chain_id)?,
        })
    }

    #[cfg(test)]
    fn with_root_client(
        anchor_state_registry: AnchorStateRegistryInstance<P>,
        root_client: TzRootClient,
    ) -> Self {
        Self { anchor_state_registry, root_client }
    }

    async fn validate_anchor(&self) -> Result<()> {
        let anchor = self
            .anchor_state_registry
            .getAnchorRoot()
            .call()
            .await
            .context("failed to fetch current anchor root")?;
        let anchor_height = checked_l2_block_number(anchor._1)
            .context("anchor height cannot be represented by the witness-builder API")?;
        let response = self
            .root_client
            .query(anchor_height)
            .await
            .context("failed to query witness-builder root at current anchor")?;

        match response {
            RootQuery::Ready { claim_root } if claim_root == anchor._0 => {
                tracing::info!(anchor_height, anchor_root = ?anchor._0, "Validated TZ witness-builder against current anchor");
                Ok(())
            }
            RootQuery::Ready { claim_root } => bail!(
                "witness-builder claim root {claim_root:?} at anchor height {anchor_height} does not match ASR root {:?}",
                anchor._0
            ),
            other => bail!(
                "witness-builder root at anchor height {anchor_height} is not ready: {other:?}"
            ),
        }
    }
}

#[async_trait]
impl<P> GameValidator for TzGameValidator<P>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    async fn validate_startup(&self) -> Result<()> {
        self.validate_anchor().await
    }

    async fn validate(&self, request: &GameValidationRequest) -> GameValidation {
        let claimed_height = match checked_l2_block_number(request.l2_block_number) {
            Ok(height) => height,
            Err(_) => return GameValidation::Invalid(InvalidReason::L2BlockNumberOverflow),
        };

        let response = match self.root_client.query(claimed_height).await {
            Ok(response) => response,
            Err(error) => {
                tracing::error!(
                    game_index = %request.game_index,
                    game_address = ?request.game_address,
                    claimed_height,
                    error = %error,
                    "TZ witness-builder root query failed; will retry"
                );
                return GameValidation::Unavailable(UnavailableReason::DataUnavailable(
                    error.to_string(),
                ));
            }
        };

        match response {
            RootQuery::Ready { claim_root } => {
                classify_computed_output_root(request.output_root, claim_root)
            }
            RootQuery::Running => GameValidation::Unavailable(UnavailableReason::NeedsReplay),
            RootQuery::AboveLocalTip { local_tip } => {
                let cutoff = request.deadline.saturating_sub(TZ_CUTOFF_MARGIN_SECS);
                if request.now_timestamp >= cutoff && request.now_timestamp < request.deadline {
                    tracing::error!(
                        game_index = %request.game_index,
                        game_address = ?request.game_address,
                        claimed_height,
                        local_tip,
                        cutoff,
                        deadline = request.deadline,
                        "TZ claim remains above the fixed witness-builder tip at cutoff; marking invalid"
                    );
                    GameValidation::Invalid(InvalidReason::BeyondLocalTipAtCutoff {
                        claimed_height,
                        local_tip,
                    })
                } else {
                    tracing::warn!(
                        game_index = %request.game_index,
                        game_address = ?request.game_address,
                        claimed_height,
                        local_tip,
                        cutoff,
                        deadline = request.deadline,
                        "TZ claim is above the fixed witness-builder tip; will retry"
                    );
                    GameValidation::Unavailable(UnavailableReason::BeyondLocalTip { local_tip })
                }
            }
            RootQuery::DataUnavailable { detail } => {
                tracing::error!(
                    game_index = %request.game_index,
                    game_address = ?request.game_address,
                    claimed_height,
                    %detail,
                    "TZ witness-builder cannot currently provide the canonical root; will retry"
                );
                GameValidation::Unavailable(UnavailableReason::DataUnavailable(detail))
            }
        }
    }
}

#[derive(Clone)]
struct TzRootClient {
    base_url: Url,
    client: reqwest::Client,
    /// Locally-configured TZ chain id; witness-builder responses that carry a different
    /// `chainId` are rejected (spec §7.3 — guard against querying the wrong chain).
    chain_id: u64,
}

impl TzRootClient {
    fn new(base_url: Url, chain_id: u64) -> Result<Self> {
        Self::new_with_timeout(base_url, chain_id, ROOT_QUERY_TIMEOUT)
    }

    fn new_with_timeout(mut base_url: Url, chain_id: u64, timeout: Duration) -> Result<Self> {
        if !matches!(base_url.scheme(), "http" | "https") {
            bail!("witness-builder URL must use http or https");
        }
        if chain_id == 0 {
            bail!("TZ chain_id must be non-zero");
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .context("failed to build TZ witness-builder HTTP client")?;
        Ok(Self { base_url, client, chain_id })
    }

    async fn query(&self, height: u64) -> Result<RootQuery> {
        let mut url = self
            .base_url
            .join("chain/dex_state_snapshot")
            .context("failed to construct TZ root query URL")?;
        url.query_pairs_mut()
            .append_pair("height", &height.to_string())
            .append_pair("format", "root")
            // R2 #1: omitting schemaVersion makes the WB default to v1; the challenger requires v2.
            .append_pair("schemaVersion", "2");

        let response =
            self.client.get(url.clone()).send().await.with_context(|| {
                format!("request to witness-builder failed for height {height}")
            })?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            bail!("witness-builder returned HTTP {status} for height {height}: {body}");
        }

        let envelope: ApiEnvelope<RootResponse> = response
            .json()
            .await
            .with_context(|| format!("invalid witness-builder response for height {height}"))?;
        if envelope.code != 0 {
            bail!(
                "witness-builder returned API code {} for height {height}: {}",
                envelope.code,
                envelope.message
            );
        }
        let data = envelope.data.ok_or_else(|| {
            anyhow!(
                "witness-builder response missing data for height {height}: {}",
                envelope.message
            )
        })?;
        if data.height != height {
            bail!(
                "witness-builder response height {} does not match requested height {height}",
                data.height
            );
        }

        match data.status.as_str() {
            "ready" => {
                Ok(RootQuery::Ready { claim_root: validate_ready_response(data, self.chain_id)? })
            }
            "running" => Ok(RootQuery::Running),
            "above_local_tip" => {
                let local_tip = data
                    .local_tip
                    .ok_or_else(|| anyhow!("above_local_tip response missing localTip"))?;
                if local_tip >= height {
                    bail!(
                        "inconsistent above_local_tip response for height {height}: local tip {local_tip} must be lower"
                    );
                }
                Ok(RootQuery::AboveLocalTip { local_tip })
            }
            "capacity_unavailable" | "no_base_snapshot" | "history_pruned" | "failed" => {
                Ok(RootQuery::DataUnavailable { detail: data.detail.unwrap_or(data.status) })
            }
            status => bail!("unknown witness-builder root status {status:?}"),
        }
    }
}

fn validate_ready_response(data: RootResponse, configured_chain_id: u64) -> Result<B256> {
    // R2 #1: the challenger always requests schemaVersion=2; a non-v2 (or absent) response means
    // the request was not honored — reject rather than silently accept a v1 body.
    if data.schema_version != Some(2) {
        bail!(
            "witness-builder ready response is not schemaVersion=2 (got {:?})",
            data.schema_version
        );
    }
    // R2 #3: chainId guard — a bare non-zero top-level field that must match the configured TZ
    // chain (spec §7.3). Reject wrong-chain data (do not advance / do not challenge on it).
    match data.chain_id {
        Some(chain_id) if chain_id != 0 => {
            if chain_id != configured_chain_id {
                bail!(
                    "ready response chainId {chain_id} does not match configured TZ chain id {configured_chain_id}"
                );
            }
        }
        _ => bail!("v2 ready response missing or zero top-level chainId"),
    }

    let block_hash = data
        .canonical_block_hash
        .ok_or_else(|| anyhow!("ready response missing canonicalBlockHash"))?;
    let claim_root = data.claim_root.ok_or_else(|| anyhow!("ready response missing claimRoot"))?;
    // R2 #1/#3: the four fields are FLAT top-level (no nested `components`).
    let app_hash = data.app_hash.ok_or_else(|| anyhow!("v2 ready response missing appHash"))?;
    let withdrawal_root =
        data.withdrawal_root.ok_or_else(|| anyhow!("v2 ready response missing withdrawalRoot"))?;
    let force_root =
        data.force_root.ok_or_else(|| anyhow!("v2 ready response missing forceRoot"))?;
    let components = RootComponents { block_hash, app_hash, withdrawal_root, force_root };
    // Recompute the four-field claimRoot and compare (spec §5.3: equivalent to field-by-field since
    // the contract binds rootClaim == keccak256(blockHash‖appHash‖withdrawalRoot‖forceRoot)).
    if compute_v3_claim_root(&components) != claim_root {
        bail!("ready response four fields do not recompute to claimRoot");
    }
    Ok(claim_root)
}

fn compute_v3_claim_root(components: &RootComponents) -> B256 {
    let mut preimage = [0u8; 128];
    preimage[..32].copy_from_slice(components.block_hash.as_slice());
    preimage[32..64].copy_from_slice(components.app_hash.as_slice());
    preimage[64..96].copy_from_slice(components.withdrawal_root.as_slice());
    preimage[96..].copy_from_slice(components.force_root.as_slice());
    keccak256(preimage)
}

#[derive(Debug, PartialEq, Eq)]
enum RootQuery {
    Ready { claim_root: B256 },
    Running,
    AboveLocalTip { local_tip: u64 },
    DataUnavailable { detail: String },
}

#[derive(Deserialize)]
struct ApiEnvelope<T> {
    code: i32,
    #[serde(default)]
    message: String,
    data: Option<T>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RootResponse {
    height: u64,
    status: String,
    // R2 #1/#3: flat v2 body — four roots + chainId are TOP-LEVEL; there is no nested
    // `components`.
    #[serde(default)]
    schema_version: Option<u16>,
    #[serde(default)]
    chain_id: Option<u64>,
    canonical_block_hash: Option<B256>,
    claim_root: Option<B256>,
    #[serde(default)]
    app_hash: Option<B256>,
    #[serde(default)]
    withdrawal_root: Option<B256>,
    #[serde(default)]
    force_root: Option<B256>,
    local_tip: Option<u64>,
    detail: Option<String>,
}

/// The four claim components, assembled from the flat top-level response fields (no longer
/// deserialized from a nested `components` object).
struct RootComponents {
    block_hash: B256,
    app_hash: B256,
    withdrawal_root: B256,
    force_root: B256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{rpc::client::RpcClient, transports::mock::Asserter};
    use alloy_primitives::{Address, U256};
    use alloy_provider::RootProvider;
    use alloy_sol_types::SolValue;
    use wiremock::{
        matchers::{method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    const TEST_CHAIN_ID: u64 = 196;

    fn request(now_timestamp: u64, deadline: u64) -> GameValidationRequest {
        GameValidationRequest {
            game_index: U256::ZERO,
            game_address: Address::ZERO,
            l1_head: B256::ZERO,
            l2_block_number: U256::from(123),
            output_root: B256::repeat_byte(0xaa),
            deadline,
            now_timestamp,
        }
    }

    fn validator(server: &MockServer) -> TzGameValidator<RootProvider> {
        let asserter = Asserter::new();
        let provider = RootProvider::new(RpcClient::mocked(asserter));
        let asr = crate::contract::AnchorStateRegistry::new(Address::ZERO, provider);
        TzGameValidator::with_root_client(
            asr,
            TzRootClient::new(server.uri().parse().unwrap(), TEST_CHAIN_ID).unwrap(),
        )
    }

    async fn mount_response(server: &MockServer, data: serde_json::Value) {
        mount_response_at_height(server, 123, data).await;
    }

    async fn mount_response_at_height(server: &MockServer, height: u64, data: serde_json::Value) {
        mount_template_at_height(
            server,
            height,
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "message": "OK",
                "data": data
            })),
        )
        .await;
    }

    async fn mount_template_at_height(
        server: &MockServer,
        height: u64,
        template: ResponseTemplate,
    ) {
        Mock::given(method("GET"))
            .and(path("/chain/dex_state_snapshot"))
            .and(query_param("height", height.to_string()))
            .and(query_param("format", "root"))
            .respond_with(template)
            .mount(server)
            .await;
    }

    fn ready_data(claim_root: B256) -> serde_json::Value {
        serde_json::json!({
            "stateAvailable": true,
            "baseSnapshotHeight": 0,
            "height": 123,
            "status": "ready",
            "canonicalBlockHash": B256::repeat_byte(0x11),
            "claimRoot": claim_root
        })
    }

    fn tradezone_status_data(
        status: &str,
        local_tip: Option<u64>,
        detail: Option<&str>,
    ) -> serde_json::Value {
        let mut data = serde_json::json!({
            "stateAvailable": status == "ready",
            "baseSnapshotHeight": 0,
            "height": 123,
            "status": status,
        });
        let object = data.as_object_mut().unwrap();
        if let Some(local_tip) = local_tip {
            object.insert("localTip".to_string(), local_tip.into());
        }
        if let Some(detail) = detail {
            object.insert("detail".to_string(), detail.into());
        }
        data
    }

    #[test]
    fn v3_claim_root_uses_all_four_components_in_order() {
        let components = RootComponents {
            block_hash: B256::repeat_byte(0x11),
            app_hash: B256::repeat_byte(0x22),
            withdrawal_root: B256::repeat_byte(0x33),
            force_root: B256::repeat_byte(0x44),
        };
        let mut expected_preimage = Vec::new();
        expected_preimage.extend_from_slice(components.block_hash.as_slice());
        expected_preimage.extend_from_slice(components.app_hash.as_slice());
        expected_preimage.extend_from_slice(components.withdrawal_root.as_slice());
        expected_preimage.extend_from_slice(components.force_root.as_slice());

        assert_eq!(compute_v3_claim_root(&components), keccak256(expected_preimage));
    }

    #[tokio::test]
    async fn startup_requires_witness_builder_to_match_current_anchor() {
        let server = MockServer::start().await;
        let asserter = Asserter::new();
        let provider = RootProvider::new(RpcClient::mocked(asserter.clone()));
        let asr = crate::contract::AnchorStateRegistry::new(Address::ZERO, provider);
        let validator = TzGameValidator::with_root_client(
            asr,
            TzRootClient::new(server.uri().parse().unwrap(), TEST_CHAIN_ID).unwrap(),
        );
        let anchor_root = B256::repeat_byte(0xaa);
        asserter.push_success(&(anchor_root, U256::from(77)).abi_encode());
        mount_response_at_height(
            &server,
            77,
            serde_json::json!({
                "height": 77,
                "status": "ready",
                "canonicalBlockHash": B256::repeat_byte(0x11),
                "claimRoot": anchor_root
            }),
        )
        .await;

        validator.validate_startup().await.unwrap();
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn startup_rejects_non_ready_or_mismatched_anchor_root() {
        for data in [
            serde_json::json!({ "height": 77, "status": "running" }),
            serde_json::json!({
                "height": 76,
                "status": "ready",
                "canonicalBlockHash": B256::repeat_byte(0x11),
                "claimRoot": B256::repeat_byte(0xaa)
            }),
            serde_json::json!({
                "height": 77,
                "status": "ready",
                "canonicalBlockHash": B256::repeat_byte(0x11),
                "claimRoot": B256::repeat_byte(0xbb)
            }),
        ] {
            let server = MockServer::start().await;
            let asserter = Asserter::new();
            let provider = RootProvider::new(RpcClient::mocked(asserter.clone()));
            let asr = crate::contract::AnchorStateRegistry::new(Address::ZERO, provider);
            let validator = TzGameValidator::with_root_client(
                asr,
                TzRootClient::new(server.uri().parse().unwrap(), TEST_CHAIN_ID).unwrap(),
            );
            asserter.push_success(&(B256::repeat_byte(0xaa), U256::from(77)).abi_encode());
            mount_response_at_height(&server, 77, data).await;

            assert!(validator.validate_startup().await.is_err());
            assert!(asserter.read_q().is_empty());
        }
    }

    #[tokio::test]
    async fn startup_rejects_http_and_api_failures() {
        let templates = [
            ResponseTemplate::new(503).set_body_string("unavailable"),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 42,
                "message": "root index unavailable",
                "data": null
            })),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "message": "missing data",
                "data": null
            })),
        ];

        for template in templates {
            let server = MockServer::start().await;
            let asserter = Asserter::new();
            let provider = RootProvider::new(RpcClient::mocked(asserter.clone()));
            let asr = crate::contract::AnchorStateRegistry::new(Address::ZERO, provider);
            let validator = TzGameValidator::with_root_client(
                asr,
                TzRootClient::new(server.uri().parse().unwrap(), TEST_CHAIN_ID).unwrap(),
            );
            asserter.push_success(&(B256::repeat_byte(0xaa), U256::from(77)).abi_encode());
            mount_template_at_height(&server, 77, template).await;

            assert!(validator.validate_startup().await.is_err());
            assert!(asserter.read_q().is_empty());
        }
    }

    #[tokio::test]
    async fn ready_root_is_compared_with_claim() {
        let server = MockServer::start().await;
        mount_response(&server, ready_data(B256::repeat_byte(0xaa))).await;
        assert_eq!(validator(&server).validate(&request(0, 10_000)).await, GameValidation::Valid);

        server.reset().await;
        mount_response(&server, ready_data(B256::repeat_byte(0xbb))).await;
        assert_eq!(
            validator(&server).validate(&request(0, 10_000)).await,
            GameValidation::Invalid(InvalidReason::OutputRootMismatch)
        );
    }

    #[tokio::test]
    async fn accepts_tradezone_production_root_wire_shapes() {
        let server = MockServer::start().await;
        let client = TzRootClient::new(server.uri().parse().unwrap(), TEST_CHAIN_ID).unwrap();

        mount_response(&server, ready_data(B256::repeat_byte(0xaa))).await;
        assert_eq!(
            client.query(123).await.unwrap(),
            RootQuery::Ready { claim_root: B256::repeat_byte(0xaa) }
        );

        server.reset().await;
        mount_response(&server, tradezone_status_data("running", None, None)).await;
        assert_eq!(client.query(123).await.unwrap(), RootQuery::Running);

        server.reset().await;
        mount_response(&server, tradezone_status_data("above_local_tip", Some(100), None)).await;
        assert_eq!(client.query(123).await.unwrap(), RootQuery::AboveLocalTip { local_tip: 100 });

        server.reset().await;
        mount_response(
            &server,
            tradezone_status_data("capacity_unavailable", None, Some("active replay jobs: 1/1")),
        )
        .await;
        assert_eq!(
            client.query(123).await.unwrap(),
            RootQuery::DataUnavailable { detail: "active replay jobs: 1/1".to_string() }
        );
    }

    #[tokio::test]
    async fn running_is_retryable() {
        let server = MockServer::start().await;
        mount_response(&server, serde_json::json!({ "height": 123, "status": "running" })).await;
        assert_eq!(
            validator(&server).validate(&request(0, 10_000)).await,
            GameValidation::Unavailable(UnavailableReason::NeedsReplay)
        );
    }

    #[tokio::test]
    async fn oversized_height_does_not_query_witness_builder() {
        let server = MockServer::start().await;
        let mut request = request(0, 10_000);
        request.l2_block_number = U256::from(u64::MAX) + U256::from(1);

        assert_eq!(
            validator(&server).validate(&request).await,
            GameValidation::Invalid(InvalidReason::L2BlockNumberOverflow)
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn above_tip_changes_only_inside_cutoff_window() {
        let server = MockServer::start().await;
        mount_response(
            &server,
            serde_json::json!({ "height": 123, "status": "above_local_tip", "localTip": 100 }),
        )
        .await;
        let validator = validator(&server);
        let deadline = 10_000;
        let cutoff = deadline - TZ_CUTOFF_MARGIN_SECS;

        assert_eq!(
            validator.validate(&request(cutoff - 1, deadline)).await,
            GameValidation::Unavailable(UnavailableReason::BeyondLocalTip { local_tip: 100 })
        );
        assert_eq!(
            validator.validate(&request(cutoff, deadline)).await,
            GameValidation::Invalid(InvalidReason::BeyondLocalTipAtCutoff {
                claimed_height: 123,
                local_tip: 100,
            })
        );
        assert_eq!(
            validator.validate(&request(deadline - 1, deadline)).await,
            GameValidation::Invalid(InvalidReason::BeyondLocalTipAtCutoff {
                claimed_height: 123,
                local_tip: 100,
            })
        );
        assert_eq!(
            validator.validate(&request(deadline, deadline)).await,
            GameValidation::Unavailable(UnavailableReason::BeyondLocalTip { local_tip: 100 })
        );
    }

    #[tokio::test]
    async fn inconsistent_above_tip_response_is_never_invalid() {
        for local_tip in [123, 124] {
            let server = MockServer::start().await;
            mount_response(
                &server,
                serde_json::json!({
                    "height": 123,
                    "status": "above_local_tip",
                    "localTip": local_tip
                }),
            )
            .await;

            assert!(matches!(
                validator(&server).validate(&request(9_999, 10_000)).await,
                GameValidation::Unavailable(UnavailableReason::DataUnavailable(_))
            ));
        }
    }

    #[tokio::test]
    async fn cutoff_refetch_that_becomes_ready_compares_the_root() {
        let server = MockServer::start().await;
        mount_response(
            &server,
            serde_json::json!({ "height": 123, "status": "above_local_tip", "localTip": 100 }),
        )
        .await;
        let validator = validator(&server);
        assert!(matches!(
            validator.validate(&request(6_399, 10_000)).await,
            GameValidation::Unavailable(UnavailableReason::BeyondLocalTip { .. })
        ));

        server.reset().await;
        mount_response(&server, ready_data(B256::repeat_byte(0xaa))).await;
        assert_eq!(validator.validate(&request(6_400, 10_000)).await, GameValidation::Valid);
    }

    #[tokio::test]
    async fn short_deadline_uses_saturating_cutoff() {
        let server = MockServer::start().await;
        mount_response(
            &server,
            serde_json::json!({ "height": 123, "status": "above_local_tip", "localTip": 100 }),
        )
        .await;
        assert!(matches!(
            validator(&server).validate(&request(0, 100)).await,
            GameValidation::Invalid(InvalidReason::BeyondLocalTipAtCutoff { .. })
        ));
    }

    #[tokio::test]
    async fn response_height_and_component_mismatch_are_unavailable() {
        let server = MockServer::start().await;
        mount_response(
            &server,
            serde_json::json!({
                "height": 122,
                "status": "ready",
                "canonicalBlockHash": B256::repeat_byte(0x11),
                "claimRoot": B256::repeat_byte(0xaa)
            }),
        )
        .await;
        assert!(matches!(
            validator(&server).validate(&request(0, 10_000)).await,
            GameValidation::Unavailable(UnavailableReason::DataUnavailable(_))
        ));

        server.reset().await;
        mount_response(
            &server,
            serde_json::json!({
                "height": 123,
                "status": "ready",
                "canonicalBlockHash": B256::repeat_byte(0x11),
                "claimRoot": B256::repeat_byte(0xaa),
                "components": {
                    "blockHash": B256::repeat_byte(0x11),
                    "appHash": B256::repeat_byte(0x22),
                    "withdrawalRoot": B256::repeat_byte(0x33),
                    "forceRoot": B256::repeat_byte(0x44)
                }
            }),
        )
        .await;
        assert!(matches!(
            validator(&server).validate(&request(0, 10_000)).await,
            GameValidation::Unavailable(UnavailableReason::DataUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn malformed_api_responses_are_unavailable() {
        let server = MockServer::start().await;
        let templates = [
            ResponseTemplate::new(503).set_body_string("unavailable"),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 7,
                "message": "business failure",
                "data": null
            })),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "message": "missing data",
                "data": null
            })),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": 0,
                "message": "ok",
                "data": { "height": 123, "status": "unknown" }
            })),
            ResponseTemplate::new(200).set_body_string("not-json"),
        ];

        for template in templates {
            server.reset().await;
            mount_template_at_height(&server, 123, template).await;
            assert!(matches!(
                validator(&server).validate(&request(9_999, 10_000)).await,
                GameValidation::Unavailable(UnavailableReason::DataUnavailable(_))
            ));
        }
    }

    #[tokio::test]
    async fn ready_requires_all_mandatory_fields() {
        let server = MockServer::start().await;
        for missing in ["canonicalBlockHash", "claimRoot"] {
            server.reset().await;
            let mut data = ready_data(B256::repeat_byte(0xaa));
            data.as_object_mut().unwrap().remove(missing);
            mount_response(&server, data).await;
            assert!(matches!(
                validator(&server).validate(&request(0, 10_000)).await,
                GameValidation::Unavailable(UnavailableReason::DataUnavailable(_))
            ));
        }
    }

    #[tokio::test]
    async fn root_query_obeys_configured_timeout() {
        let server = MockServer::start().await;
        mount_template_at_height(
            &server,
            123,
            ResponseTemplate::new(200).set_delay(Duration::from_millis(100)).set_body_json(
                serde_json::json!({
                    "code": 0,
                    "message": "ok",
                    "data": ready_data(B256::repeat_byte(0xaa))
                }),
            ),
        )
        .await;
        let client = TzRootClient::new_with_timeout(
            server.uri().parse().unwrap(),
            TEST_CHAIN_ID,
            Duration::from_millis(10),
        )
        .unwrap();

        assert!(client.query(123).await.unwrap_err().to_string().contains("request"));
    }

    #[tokio::test]
    async fn matching_chain_id_is_accepted() {
        let server = MockServer::start().await;
        mount_response(
            &server,
            serde_json::json!({
                "height": 123,
                "chainId": TEST_CHAIN_ID,
                "status": "ready",
                "canonicalBlockHash": B256::repeat_byte(0x11),
                "claimRoot": B256::repeat_byte(0xaa)
            }),
        )
        .await;
        assert_eq!(validator(&server).validate(&request(0, 10_000)).await, GameValidation::Valid);
    }

    #[tokio::test]
    async fn mismatched_chain_id_is_rejected_not_challenged() {
        // A checkpoint that belongs to a different chain must NOT be trusted: reject as
        // Unavailable (retry/alert) rather than silently passing or wrongly challenging (spec
        // §7.3).
        let server = MockServer::start().await;
        mount_response(
            &server,
            serde_json::json!({
                "height": 123,
                "chainId": TEST_CHAIN_ID + 1,
                "status": "ready",
                "canonicalBlockHash": B256::repeat_byte(0x11),
                "claimRoot": B256::repeat_byte(0xaa)
            }),
        )
        .await;
        assert!(matches!(
            validator(&server).validate(&request(0, 10_000)).await,
            GameValidation::Unavailable(UnavailableReason::DataUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn zero_chain_id_is_rejected() {
        let server = MockServer::start().await;
        mount_response(
            &server,
            serde_json::json!({
                "height": 123,
                "chainId": 0,
                "status": "ready",
                "canonicalBlockHash": B256::repeat_byte(0x11),
                "claimRoot": B256::repeat_byte(0xaa)
            }),
        )
        .await;
        assert!(matches!(
            validator(&server).validate(&request(0, 10_000)).await,
            GameValidation::Unavailable(UnavailableReason::DataUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn non_tip_failures_never_default_to_invalid() {
        let server = MockServer::start().await;
        for status in ["capacity_unavailable", "no_base_snapshot", "history_pruned", "failed"] {
            server.reset().await;
            mount_response(&server, serde_json::json!({ "height": 123, "status": status })).await;
            assert!(matches!(
                validator(&server).validate(&request(9_999, 10_000)).await,
                GameValidation::Unavailable(UnavailableReason::DataUnavailable(_))
            ));
        }
    }
}
