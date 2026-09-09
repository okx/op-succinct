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

use super::{
    claim::claim_root,
    error::WbError,
    tree_adapter::{root_from_frontier, TREE_DEPTH},
    types::{
        CheckpointV2, CheckpointV2Envelope, HistoricalInclusionProof, TreeBoundaryWitness,
        WithdrawRecord,
    },
};

const WB_TIMEOUT: Duration = Duration::from_secs(30);
const SUPPORTED_SCHEMA_VERSION: u16 = 2;
// Numeric business error codes in the witness-builder's unified `{code, message, data}` envelope.
// There is NO `name` field; classification is by these numeric codes plus a joint
// `(endpoint, HTTP status, code, message prefix)` validation that fails closed on any mismatch.
const CODE_INVALID_REQUEST: i32 = 11001;
const CODE_PROTOCOL_NOT_ACCEPTED: i32 = 11002;
const CODE_CHECKPOINT_NOT_FOUND: i32 = 11003;
const CODE_WITHDRAWAL_NOT_FOUND: i32 = 11004;
const CODE_RECORD_NOT_IN_CHECKPOINT: i32 = 11005;
const CODE_NOT_READY: i32 = 11006;
const CODE_STORE_CORRUPT: i32 = 11008;
const CODE_ROOT_NOT_FOUND: i32 = 11009;

/// Which endpoint a request targeted, so an error code can be validated against the endpoint's
/// allowed set and mapped to the semantically-correct [`WbError`].
#[derive(Clone, Copy)]
enum WbEndpoint {
    Checkpoint,
    Boundary,
    Record,
    Proof,
}

/// The witness-builder's unified error envelope. Only `code` and `message` are needed to classify;
/// `data` is present on the wire but not consulted here.
#[derive(Deserialize)]
struct ErrEnvelope {
    #[serde(default)]
    code: Option<i32>,
    #[serde(default)]
    message: Option<String>,
}

// Real WB v2 routes verified against tradezone `feature/witness-builder-withdraw-v1` @ bb695f3a
// (`crates/chain/src/rpc/handlers/{zkvm_snapshot,witness}.rs`). Record is a PATH param
// (`{recordHash}`); the others take query params.
const ROUTE_CHECKPOINT: &str = "chain/dex_state_snapshot";
// NOTE: witness.rs registers `query_tree_boundary`; its exact URL path was not capturable from the
// clone's OpenAPI attrs — confirm against the running WB. Grouped under `chain/witness/`.
const ROUTE_BOUNDARY: &str = "chain/witness/tree-boundary";
const ROUTE_RECORD_PREFIX: &str = "chain/witness/withdrawals/"; // + {recordHash}
const ROUTE_PROOF: &str = "chain/witness/withdrawal-proof";

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

    pub fn new_with_timeout(
        mut base: Url,
        chain_id: u64,
        timeout: Duration,
    ) -> Result<Self, WbError> {
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
        let http = reqwest::Client::builder().timeout(timeout).build().map_err(|e| {
            WbError::permanent_transport(format!("failed to build HTTP client: {e}"))
        })?;
        Ok(Self { base, http, chain_id })
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: WbEndpoint,
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
        if status.is_success() {
            let env: ApiEnvelope<T> = resp
                .json()
                .await
                .map_err(|e| WbError::permanent_transport(format!("invalid JSON: {e}")))?;
            if env.code != 0 {
                // A 2xx that still carries a business error code is a protocol inconsistency.
                return Err(Self::classify(endpoint, status, env.code, &env.message));
            }
            return env.data.ok_or(WbError::CheckpointNotFound);
        }
        // Non-2xx: parse the unified `{code, message, data}` envelope BEFORE trusting the HTTP
        // status (never blanket-map "any 4xx" to InvalidRequest); then classify by the joint tuple.
        let body = resp.text().await.unwrap_or_default();
        Err(match serde_json::from_str::<ErrEnvelope>(&body) {
            Ok(env) => match env.code {
                Some(code) => {
                    Self::classify(endpoint, status, code, env.message.as_deref().unwrap_or(""))
                }
                // Parsed JSON without a numeric code is not a WB error envelope ⇒ fail closed.
                None => Self::unparsed_error_status(status),
            },
            // Unparseable / empty / non-envelope body.
            Err(_) => Self::unparsed_error_status(status),
        })
    }

    /// Classify a witness-builder error response by the joint tuple `(endpoint, HTTP status,
    /// numeric code, message prefix)`. Any of: a code outside the endpoint's allowed set, an
    /// HTTP-status/code disagreement, or a message-prefix/code conflict is a [`WbError::Protocol`]
    /// (fail-closed) — never a normal wait/retry.
    fn classify(
        endpoint: WbEndpoint,
        status: reqwest::StatusCode,
        code: i32,
        message: &str,
    ) -> WbError {
        // 1. The code must be legitimate for this endpoint (per-endpoint allowed sets).
        let allowed: &[i32] = match endpoint {
            WbEndpoint::Proof => &[
                CODE_INVALID_REQUEST,
                CODE_WITHDRAWAL_NOT_FOUND,
                CODE_RECORD_NOT_IN_CHECKPOINT,
                CODE_NOT_READY,
                CODE_STORE_CORRUPT,
                CODE_ROOT_NOT_FOUND,
            ],
            WbEndpoint::Checkpoint | WbEndpoint::Boundary => {
                &[CODE_INVALID_REQUEST, CODE_CHECKPOINT_NOT_FOUND, CODE_NOT_READY, CODE_STORE_CORRUPT]
            }
            WbEndpoint::Record => {
                &[CODE_INVALID_REQUEST, CODE_WITHDRAWAL_NOT_FOUND, CODE_NOT_READY, CODE_STORE_CORRUPT]
            }
        };
        if !allowed.contains(&code) {
            return WbError::Protocol;
        }
        // 2. The code determines the expected HTTP status and the mapped error.
        let (expected_status, err): (u16, WbError) = match code {
            CODE_INVALID_REQUEST => (400, WbError::InvalidRequest),
            CODE_CHECKPOINT_NOT_FOUND => (404, WbError::CheckpointNotFound),
            CODE_WITHDRAWAL_NOT_FOUND => (404, WbError::WithdrawalNotFound),
            CODE_RECORD_NOT_IN_CHECKPOINT => (404, WbError::RecordNotInCheckpoint),
            CODE_NOT_READY => (409, WbError::NotReady),
            CODE_STORE_CORRUPT => (500, WbError::WitnessStoreCorrupt),
            CODE_ROOT_NOT_FOUND => (404, WbError::RootNotFound),
            // Unreachable given the allowed-set gate above; fail closed defensively.
            _ => return WbError::Protocol,
        };
        // 3. HTTP status must agree with the code.
        if status.as_u16() != expected_status {
            return WbError::Protocol;
        }
        // 4. If the message begins with a recognizable variant token, it must name THIS code (a
        //    token naming a different code is a conflict). An unrecognized/empty message is not.
        if let Some(prefix_code) = Self::code_for_message_prefix(message) {
            if prefix_code != code {
                return WbError::Protocol;
            }
        }
        err
    }

    /// If a message begins with a known witness-builder error-kind token, return the numeric code
    /// that token implies (used only to detect code↔prefix conflicts).
    fn code_for_message_prefix(message: &str) -> Option<i32> {
        match message.split([':', ' ']).next().unwrap_or("") {
            "InvalidRequest" => Some(CODE_INVALID_REQUEST),
            "ProtocolNotAccepted" => Some(CODE_PROTOCOL_NOT_ACCEPTED),
            "CheckpointNotFound" => Some(CODE_CHECKPOINT_NOT_FOUND),
            "WithdrawalNotFound" => Some(CODE_WITHDRAWAL_NOT_FOUND),
            "RecordNotInCheckpoint" => Some(CODE_RECORD_NOT_IN_CHECKPOINT),
            "NotReady" => Some(CODE_NOT_READY),
            "StoreCorrupt" => Some(CODE_STORE_CORRUPT),
            "RootNotFound" => Some(CODE_ROOT_NOT_FOUND),
            _ => None,
        }
    }

    /// A non-2xx response whose body is not a witness-builder error envelope: a 5xx is a transient
    /// transport failure (retry with backoff); any other status (4xx/409) fails closed.
    fn unparsed_error_status(status: reqwest::StatusCode) -> WbError {
        if status.is_server_error() {
            WbError::transient_transport(format!("witness-builder HTTP {status}"))
        } else {
            WbError::Protocol
        }
    }

    /// Fetch the four-field checkpoint at `height` and its top-level `chainId` (R2 #1/#3).
    ///
    /// Sends BOTH `format=root` AND `schemaVersion=2` (R2 #1: omitting `schemaVersion` makes the WB
    /// default to v1). Parses the FLAT `SnapshotQueryResponse` (no nested `components`; the four
    /// roots + `chainId` are top-level per §R2.1-B), verifies `schemaVersion==2`, the top-level
    /// `chainId`, and that the four fields recompute to the advertised `claimRoot`. Returns a
    /// [`CheckpointV2Envelope`] so chainId is carried beside — never inside — the checkpoint body.
    pub async fn get_checkpoint_v2(&self, height: u64) -> Result<CheckpointV2Envelope, WbError> {
        let d: CheckpointDto = self
            .get(
                WbEndpoint::Checkpoint,
                ROUTE_CHECKPOINT,
                &[
                    ("height", height.to_string()),
                    ("format", "root".into()),
                    ("schemaVersion", "2".into()),
                ],
            )
            .await?;
        // status is snake_case (§R2.1-B): ready usable; running / above_local_tip ⇒ retryable.
        match d.status.as_deref() {
            Some("ready") => {}
            Some("running") | Some("above_local_tip") => return Err(WbError::NotReady),
            _ => return Err(WbError::CheckpointNotFound),
        }
        // R2 #1: a response without schemaVersion==2 is a v1 body — reject as unsupported.
        if d.schema_version != Some(SUPPORTED_SCHEMA_VERSION) {
            return Err(WbError::UnsupportedVersion);
        }
        // R2 #3: chainId is a bare top-level field (only populated for v2); guard it host-side.
        let chain_id = d.chain_id.ok_or(WbError::UnsupportedVersion)?;
        if chain_id == 0 || chain_id != self.chain_id {
            return Err(WbError::InvalidRequest);
        }
        let block_hash = d.canonical_block_hash.ok_or(WbError::WitnessStoreCorrupt)?;
        let app_hash = d.app_hash.ok_or(WbError::WitnessStoreCorrupt)?;
        let withdrawal_root = d.withdrawal_root.ok_or(WbError::WitnessStoreCorrupt)?;
        let force_root = d.force_root.ok_or(WbError::WitnessStoreCorrupt)?;
        let claim = d.claim_root.ok_or(WbError::WitnessStoreCorrupt)?;
        // The four flat fields MUST recompute to the advertised claimRoot.
        if claim_root(block_hash, app_hash, withdrawal_root, force_root) != claim {
            return Err(WbError::RootMismatch);
        }
        Ok(CheckpointV2Envelope {
            checkpoint: CheckpointV2 {
                schema_version: SUPPORTED_SCHEMA_VERSION,
                block_height: d.height,
                block_hash,
                app_hash,
                withdrawal_root,
                force_root,
                claim_root: claim,
            },
            chain_id,
        })
    }

    /// Fetch the tree boundary witness at `height`. Validates `len == popcount(count)` and, when
    /// declared roots are present, rebuilds them from the frontier and rejects on mismatch.
    pub async fn get_tree_boundary_witness(
        &self,
        height: u64,
    ) -> Result<TreeBoundaryWitness, WbError> {
        let d: BoundaryDto =
            self.get(WbEndpoint::Boundary, ROUTE_BOUNDARY, &[("height", height.to_string())]).await?;
        if d.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(WbError::UnsupportedVersion);
        }
        // R2 #2: TreeBoundaryResponse carries NO chainId; correctness is `len == popcount(count)`
        // + a successful inner-root rebuild via tz-witness (chainId is guarded on the checkpoint
        // top level only). `root_from_frontier` enforces the popcount invariant and rebuilds the
        // inner root through `tz_witness::merkle::inner_root`.
        let _w_inner = root_from_frontier(&d.withdrawal_active_branches, d.withdrawal_count)?;
        let _f_inner = root_from_frontier(&d.force_active_branches, d.force_count)?;
        Ok(TreeBoundaryWitness {
            schema_version: d.schema_version,
            block_height: d.block_height,
            block_hash: d.block_hash,
            withdrawal_count: d.withdrawal_count,
            withdrawal_active_branches: d.withdrawal_active_branches,
            force_count: d.force_count,
            force_active_branches: d.force_active_branches,
        })
    }

    /// Fetch the canonical Withdraw record for a record hash. The recordHash is a PATH param
    /// (`/chain/witness/withdrawals/{recordHash}`, §R2.1-D); the record fields are nested under
    /// `record.rawTradezoneWithdrawal`.
    pub async fn get_canonical_record(&self, record_hash: B256) -> Result<WithdrawRecord, WbError> {
        let route = format!("{ROUTE_RECORD_PREFIX}{record_hash:#x}");
        let d: LookupDto = self.get(WbEndpoint::Record, &route, &[]).await?;
        Ok(d.record.into_record())
    }

    /// Fetch the canonical block height at which the record for `record_hash` was included. The
    /// height is taken from the WB (never the caller); a zero/absent height means not-yet-included.
    pub async fn get_canonical_record_height(&self, record_hash: B256) -> Result<u64, WbError> {
        let route = format!("{ROUTE_RECORD_PREFIX}{record_hash:#x}");
        let d: LookupDto = self.get(WbEndpoint::Record, &route, &[]).await?;
        if d.canonical_block_height == 0 {
            return Err(WbError::WithdrawalNotFound);
        }
        Ok(d.canonical_block_height)
    }

    /// Fetch an inclusion proof addressed by `record_hash` and the exact `withdrawal_root`. The
    /// request carries only those two parameters; the successful response is not expected to carry
    /// a checkpoint height.
    pub async fn get_inclusion_proof(
        &self,
        record_hash: B256,
        withdrawal_root: B256,
    ) -> Result<HistoricalInclusionProof, WbError> {
        let d: ProofDto = self
            .get(
                WbEndpoint::Proof,
                ROUTE_PROOF,
                &[
                    ("recordHash", format!("{record_hash:#x}")),
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
    // Flat SnapshotQueryResponse (§R2.1-B): no nested `components`; four roots + chainId
    // top-level.
    #[serde(default)]
    schema_version: Option<u16>,
    #[serde(default)]
    chain_id: Option<u64>,
    height: u64,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    canonical_block_hash: Option<B256>,
    #[serde(default)]
    claim_root: Option<B256>,
    #[serde(default)]
    app_hash: Option<B256>,
    #[serde(default)]
    withdrawal_root: Option<B256>,
    #[serde(default)]
    force_root: Option<B256>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BoundaryDto {
    // TreeBoundaryResponse (§R2.1-C / R4): flat, NO chainId, NO declared root; DOES carry
    // `blockHash` between `blockHeight` and `withdrawalCount` (R4 MR102-R3-3 — previously
    // dropped).
    #[serde(default)]
    schema_version: u16,
    block_height: u64,
    // `blockHash` (camelCase); `B256`'s serde parses the `0x` hex string, same as
    // `canonical_block_hash`.
    block_hash: B256,
    #[serde(default)]
    withdrawal_count: u32,
    #[serde(default)]
    withdrawal_active_branches: Vec<B256>,
    #[serde(default)]
    force_count: u32,
    #[serde(default)]
    force_active_branches: Vec<B256>,
}

/// WithdrawalLookupResponse (§R2.1-D): record fields nested under `rawTradezoneWithdrawal`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LookupDto {
    #[serde(default)]
    canonical_block_height: u64,
    record: WithdrawRecordDto,
}

/// WithdrawRecordResponse (§R2.1-D). Hashes/addresses/amounts arrive as `0x`/decimal strings and
/// deserialize into alloy `B256`/`Address`/`U256` via their serde impls.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WithdrawRecordDto {
    version: u16,
    chain_id: u64,
    transaction_hash: B256,
    raw_tradezone_withdrawal: RawWithdrawalDto,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawWithdrawalDto {
    token_type: u8,
    token_address: Address,
    #[serde(default)]
    token_ids: Vec<U256>,
    #[serde(default)]
    amounts: Vec<U256>,
    from: Address,
    to: Address,
}

impl WithdrawRecordDto {
    /// Flatten the nested WB record into op-succinct's host-side [`WithdrawRecord`] (op-succinct
    /// carries record data but never re-encodes the leaf — the WB supplies recordHash/leafHash).
    fn into_record(self) -> WithdrawRecord {
        let raw = self.raw_tradezone_withdrawal;
        WithdrawRecord {
            version: self.version,
            chain_id: self.chain_id,
            transaction_hash: self.transaction_hash,
            token_type: raw.token_type,
            token_address: raw.token_address,
            token_ids: raw.token_ids,
            amounts: raw.amounts,
            from: raw.from,
            to: raw.to,
        }
    }
}

/// Withdrawal inclusion-proof response body. The root-addressed proof does not carry a checkpoint
/// height; the height needed for an on-chain prove call is sourced separately from the RootManager.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofDto {
    record: WithdrawRecordDto,
    record_hash: B256,
    leaf_hash: B256,
    canonical_block_height: u64,
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
                "claimRoot": claim, "canonicalBlockHash": bh, "appHash": ah,
                "withdrawalRoot": wr, "forceRoot": fr
            }))))
            .mount(&server)
            .await;
        let cp = client(&server, 196).get_checkpoint_v2(100).await.unwrap();
        assert_eq!(cp.chain_id, 196);
        assert_eq!(cp.checkpoint.withdrawal_root, wr);
        assert_eq!(cp.checkpoint.force_root, fr);
        assert_eq!(cp.checkpoint.claim_root, claim);
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
                "claimRoot": B256::repeat_byte(0xEE), // does not match the four flat fields
                "canonicalBlockHash": B256::repeat_byte(0x11), "appHash": B256::repeat_byte(0x22),
                "withdrawalRoot": B256::repeat_byte(0x33), "forceRoot": B256::repeat_byte(0x44)
            }))))
            .mount(&server)
            .await;
        assert!(matches!(
            client(&server, 196).get_checkpoint_v2(100).await,
            Err(WbError::RootMismatch)
        ));
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
        assert!(matches!(
            client(&server, 196).get_checkpoint_v2(100).await,
            Err(WbError::InvalidRequest)
        ));
    }

    #[tokio::test]
    async fn boundary_valid_popcount_maps_and_bad_length_is_corrupt() {
        // count=2 ⇒ popcount(2)=1 active branch. Provide 1 (valid) then 2 (invalid).
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/witness/tree-boundary"))
            .and(query_param("height", "50"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(serde_json::json!({
                "schemaVersion": 2, "blockHeight": 50, "blockHash": B256::repeat_byte(0xaa),
                "withdrawalCount": 2, "withdrawalActiveBranches": [B256::repeat_byte(0x11)],
                "forceCount": 0, "forceActiveBranches": []
            }))))
            .mount(&server)
            .await;
        let b = client(&server, 196).get_tree_boundary_witness(50).await.unwrap();
        assert_eq!(b.withdrawal_count, 2);
        assert_eq!(b.withdrawal_active_branches.len(), 1);
        assert!(b.force_active_branches.is_empty());

        let server2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/witness/tree-boundary"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(serde_json::json!({
                "schemaVersion": 2, "blockHeight": 50, "blockHash": B256::repeat_byte(0xaa),
                "withdrawalCount": 2,
                "withdrawalActiveBranches": [B256::repeat_byte(0x11), B256::repeat_byte(0x22)],
                "forceCount": 0, "forceActiveBranches": []
            }))))
            .mount(&server2)
            .await;
        assert!(matches!(
            client(&server2, 196).get_tree_boundary_witness(50).await,
            Err(WbError::WitnessStoreCorrupt)
        ));
    }

    #[tokio::test]
    async fn boundary_dto_preserves_block_hash() {
        // R4 C-pos (MR102-R3-3): the wire `blockHash` must survive into
        // `TreeBoundaryWitness.block_hash` (previously silently dropped). Uses the flat DTO shape
        // (`withdrawalCount`/`withdrawalActiveBranches`/…) the current `BoundaryDto` deserializes.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/witness/tree-boundary"))
            .and(query_param("height", "100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(serde_json::json!({
                "schemaVersion": 2, "blockHeight": 100,
                "blockHash": B256::repeat_byte(0x11),
                "withdrawalCount": 2, "withdrawalActiveBranches": [B256::repeat_byte(0x22)],
                "forceCount": 0, "forceActiveBranches": []
            }))))
            .mount(&server)
            .await;
        let w = client(&server, 196).get_tree_boundary_witness(100).await.unwrap();
        assert_eq!(w.block_hash, B256::repeat_byte(0x11));
        assert_eq!(w.block_height, 100);
        assert_eq!(w.withdrawal_count, 2);
        assert_eq!(w.withdrawal_active_branches.len(), 1); // popcount(2) == 1
    }

    #[tokio::test]
    async fn boundary_bad_force_popcount_is_corrupt() {
        // The force tree's active-branch count must equal popcount(count); a mismatch is a
        // fail-closed corruption signal. forceCount=2 ⇒ popcount(2)=1, but two branches are sent.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/witness/tree-boundary"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(serde_json::json!({
                "schemaVersion": 2, "blockHeight": 50, "blockHash": B256::repeat_byte(0xaa),
                "withdrawalCount": 0, "withdrawalActiveBranches": [],
                "forceCount": 2,
                "forceActiveBranches": [B256::repeat_byte(0x11), B256::repeat_byte(0x22)]
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
    async fn proof_request_is_root_addressed_no_checkpoint_height() {
        let server = MockServer::start().await;
        let rec = serde_json::json!({
            "version": 1, "chainId": 196, "transactionHash": B256::repeat_byte(0x01),
            "rawTradezoneWithdrawal": {
                "tokenType": 0, "tokenAddress": Address::ZERO, "tokenIds": [], "amounts": [],
                "from": Address::ZERO, "to": Address::ZERO
            }
        });
        let sibs: Vec<String> = (0..32).map(|_| format!("{:#x}", B256::ZERO)).collect();
        Mock::given(method("GET"))
            .and(path("/chain/witness/withdrawal-proof"))
            .and(query_param("recordHash", format!("{:#x}", B256::repeat_byte(0x01))))
            .and(query_param("withdrawalRoot", format!("{:#x}", B256::repeat_byte(0x33))))
            // No checkpointHeight query param is sent.
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(serde_json::json!({
                "record": rec, "recordHash": B256::repeat_byte(0x01), "leafHash": B256::repeat_byte(0x01),
                "canonicalBlockHeight": 10, "withdrawalRoot": B256::repeat_byte(0x33),
                "leafIndex": 0, "count": 1, "siblings": sibs
            }))))
            .mount(&server)
            .await;
        let p = client(&server, 196)
            .get_inclusion_proof(B256::repeat_byte(0x01), B256::repeat_byte(0x33))
            .await
            .unwrap();
        assert_eq!(p.count, 1);
        assert_eq!(p.withdrawal_root, B256::repeat_byte(0x33));
    }

    #[tokio::test]
    async fn proof_maps_and_bad_siblings_len_is_corrupt() {
        let server = MockServer::start().await;
        let rec = serde_json::json!({
            "version": 1, "chainId": 196, "transactionHash": B256::repeat_byte(0x01),
            "rawTradezoneWithdrawal": {
                "tokenType": 0, "tokenAddress": Address::ZERO, "tokenIds": [], "amounts": [],
                "from": Address::ZERO, "to": Address::ZERO
            }
        });
        let sibs: Vec<String> = (0..32).map(|_| format!("{:#x}", B256::ZERO)).collect();
        Mock::given(method("GET"))
            .and(path("/chain/witness/withdrawal-proof"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(serde_json::json!({
                "record": rec, "recordHash": B256::repeat_byte(0x01), "leafHash": B256::repeat_byte(0x01),
                "canonicalBlockHeight": 10, "withdrawalRoot": B256::repeat_byte(0x33),
                "leafIndex": 0, "count": 1, "siblings": sibs
            }))))
            .mount(&server)
            .await;
        let p = client(&server, 196)
            .get_inclusion_proof(B256::repeat_byte(0x01), B256::repeat_byte(0x33))
            .await
            .unwrap();
        assert_eq!(p.count, 1);
        assert_eq!(p.withdrawal_root, B256::repeat_byte(0x33));

        // Bad siblings length ⇒ corrupt.
        let server2 = MockServer::start().await;
        let short: Vec<String> = (0..31).map(|_| format!("{:#x}", B256::ZERO)).collect();
        Mock::given(method("GET"))
            .and(path("/chain/witness/withdrawal-proof"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(serde_json::json!({
                "record": rec, "recordHash": B256::repeat_byte(0x01), "leafHash": B256::repeat_byte(0x01),
                "canonicalBlockHeight": 10, "withdrawalRoot": B256::repeat_byte(0x33),
                "leafIndex": 0, "count": 1, "siblings": short
            }))))
            .mount(&server2)
            .await;
        assert!(matches!(
            client(&server2, 196)
                .get_inclusion_proof(B256::repeat_byte(0x01), B256::repeat_byte(0x33))
                .await,
            Err(WbError::WitnessStoreCorrupt)
        ));
        // Silence unused import warning when only some branches run.
        let _ = business_root(B256::ZERO, 0, WITHDRAWAL_TAG);
    }

    /// WB errors are classified by the numeric `code` over the unified `{code,message,data}`
    /// envelope (there is NO `name` field), with joint `(endpoint, status, code, prefix)`
    /// validation that fails closed on any mismatch.
    #[tokio::test]
    async fn wb_errors_classified_by_numeric_code_not_name() {
        let leaf = B256::repeat_byte(0x01);
        let root = B256::repeat_byte(0x33);

        // (1) 11009 on the proof endpoint, real envelope shape, HTTP 404 ⇒ RootNotFound.
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/witness/withdrawal-proof"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!(
                {"code": 11009, "message": "RootNotFound: 0x33", "data": null})))
            .mount(&s)
            .await;
        let e = client(&s, 196).get_inclusion_proof(leaf, root).await.unwrap_err();
        assert!(matches!(e, WbError::RootNotFound));
        assert!(!e.is_retryable(), "transport layer must not blanket-retry RootNotFound");

        // (2) 11006 NotReady arrives as HTTP 409 (not generic 4xx→InvalidRequest).
        let s2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/witness/withdrawal-proof"))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!(
                {"code": 11006, "message": "NotReady: rebuilding", "data": null})))
            .mount(&s2)
            .await;
        let e2 = client(&s2, 196).get_inclusion_proof(leaf, root).await.unwrap_err();
        assert!(matches!(e2, WbError::NotReady));
        assert!(e2.is_retryable());

        // (3) Joint-tuple mismatch: 11003 (a checkpoint code) on the PROOF endpoint ⇒ Protocol.
        let s3 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/witness/withdrawal-proof"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!(
                {"code": 11003, "message": "CheckpointNotFound: 9", "data": null})))
            .mount(&s3)
            .await;
        assert!(matches!(
            client(&s3, 196).get_inclusion_proof(leaf, root).await.unwrap_err(),
            WbError::Protocol
        ));

        // (4) Unknown / plain 404 (no envelope) ⇒ Protocol fail-closed, NOT CheckpointNotFound.
        let s4 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/witness/withdrawal-proof"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&s4)
            .await;
        let e4 = client(&s4, 196).get_inclusion_proof(leaf, root).await.unwrap_err();
        assert!(matches!(e4, WbError::Protocol));
        assert!(!e4.is_retryable());

        // (5) HTTP-status↔code disagreement: 11009 returned with HTTP 409 ⇒ Protocol.
        let s5 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/witness/withdrawal-proof"))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!(
                {"code": 11009, "message": "RootNotFound: 0x33", "data": null})))
            .mount(&s5)
            .await;
        assert!(matches!(
            client(&s5, 196).get_inclusion_proof(leaf, root).await.unwrap_err(),
            WbError::Protocol
        ));

        // (6) code↔message-prefix conflict: 11009 carrying a `NotReady:` message ⇒ Protocol.
        let s6 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/witness/withdrawal-proof"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!(
                {"code": 11009, "message": "NotReady: mislabelled", "data": null})))
            .mount(&s6)
            .await;
        assert!(matches!(
            client(&s6, 196).get_inclusion_proof(leaf, root).await.unwrap_err(),
            WbError::Protocol
        ));
    }

    /// A 500 carrying code 11008 is a permanent store-corruption (body parsed before status), while
    /// a plain 500 with no envelope stays a retryable transient transport error.
    #[tokio::test]
    async fn wb_500_store_corrupt_is_permanent_but_plain_5xx_is_transient() {
        let leaf = B256::repeat_byte(0x01);
        let root = B256::repeat_byte(0x33);

        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/witness/withdrawal-proof"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!(
                {"code": 11008, "message": "StoreCorrupt: dag", "data": null})))
            .mount(&s)
            .await;
        let e = client(&s, 196).get_inclusion_proof(leaf, root).await.unwrap_err();
        assert!(matches!(e, WbError::WitnessStoreCorrupt));
        assert!(!e.is_retryable(), "a store-corrupt 500 must not be retried");

        let s2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chain/witness/withdrawal-proof"))
            .respond_with(ResponseTemplate::new(500).set_body_string("upstream boom"))
            .mount(&s2)
            .await;
        assert!(client(&s2, 196).get_inclusion_proof(leaf, root).await.unwrap_err().is_retryable());
    }

    /// The record endpoint has its own allowed set: 11004 ⇒ WithdrawalNotFound, but a proof-only
    /// code such as 11009 here is a joint-tuple violation ⇒ Protocol fail-closed.
    #[tokio::test]
    async fn record_endpoint_numeric_codes_and_joint_validation() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/chain/witness/withdrawals/{:#x}", B256::repeat_byte(0x01))))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!(
                {"code": 11004, "message": "WithdrawalNotFound: 0x01", "data": null})))
            .mount(&s)
            .await;
        assert!(matches!(
            client(&s, 196).get_canonical_record(B256::repeat_byte(0x01)).await.unwrap_err(),
            WbError::WithdrawalNotFound
        ));

        let s2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/chain/witness/withdrawals/{:#x}", B256::repeat_byte(0x02))))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!(
                {"code": 11009, "message": "RootNotFound: x", "data": null})))
            .mount(&s2)
            .await;
        assert!(matches!(
            client(&s2, 196).get_canonical_record(B256::repeat_byte(0x02)).await.unwrap_err(),
            WbError::Protocol
        ));
    }
}
