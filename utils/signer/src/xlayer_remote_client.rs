use alloy_consensus::{Transaction, TxEnvelope};
use alloy_eips::Decodable2718;
use alloy_primitives::{Address, Bytes, U256};
use alloy_rpc_types_eth::TransactionRequest;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::time::Duration;
use lru::LruCache;
use tokio::sync::Mutex;
use tokio::time::sleep;

/// Custom error types for XLayer remote signer
#[derive(Debug, thiserror::Error)]
pub enum XLayerSignerError {
    #[error("HTTP request failed: status={status}, body={body}")]
    HttpError { status: u16, body: String },

    #[error("Signing request failed: status={status}, msg={msg}, detail={detail}")]
    SigningFailed {
        status: i32,
        msg: String,
        detail: String,
    },

    #[error("Transaction verification failed: {0}")]
    VerificationError(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Timeout waiting for signature result after {0} attempts")]
    SignatureTimeout(u32),

    #[error("Network error: {0}")]
    #[allow(dead_code)]
    NetworkError(String),

    #[error("Configuration error: {0}")]
    #[allow(dead_code)]
    ConfigError(String),
}

/// 4-byte selectors of the contract methods this client will sign for.
/// Calls with any other selector are rejected.
const METHOD_SIG_DGF_CREATE: &str = "0x82ecf2f6"; // DisputeGameFactory.create
const METHOD_SIG_PROVE: &str = "0x375bfa5d"; // OPSuccinctFaultDisputeGame.prove(bytes)
const METHOD_SIG_CHALLENGE: &str = "0xd2ef7398"; // OPSuccinctFaultDisputeGame.challenge()
const METHOD_SIG_RESOLVE: &str = "0x2810e1d6"; // OPSuccinctFaultDisputeGame.resolve()
const METHOD_SIG_CLAIM_CREDIT: &str = "0x60e27464"; // OPSuccinctFaultDisputeGame.claimCredit(address)

const MAX_SIGNING_RETRIES: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_secs(5);
const SIGN_RESULT_POLL_INTERVAL: Duration = Duration::from_secs(1);
const HTTP_STATUS_SUCCESS: u16 = 200;

/// Capacity of the LRU that remembers refOrderIDs issued by this client,
/// so a companion verify-server can answer asset-management callbacks.
const REF_ORDER_CACHE_CAPACITY: usize = 1000;

const REF_ORDER_ID_PREFIX: &str = "PROPOSER_TZ_";

/// Builds a refOrderID of the form `PROPOSER_TZ_{op}_{unix_ms}_{rand8hex}`.
/// The 32 bits of randomness come from a v4 UUID to avoid pulling in a
/// separate `rand` dependency.
fn generate_ref_order_id(op: OperateType) -> String {
    let ts_ms = chrono::Utc::now().timestamp_millis();
    let uuid = uuid::Uuid::new_v4();
    let rand_bytes = &uuid.as_bytes()[..4];
    format!(
        "{prefix}{op}_{ts}_{rand}",
        prefix = REF_ORDER_ID_PREFIX,
        op = op as i32,
        ts = ts_ms,
        rand = hex::encode(rand_bytes),
    )
}

/// Wire-level operation type recognised by the XLayer remote signer.
/// Variants are named after the contract method they cover; the integer
/// values are the on-the-wire IDs the service expects.
///
/// Do **not** renumber these without a coordinated change on the signing
/// service.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(i32)]
pub enum OperateType {
    /// `DisputeGameFactory.create`.
    Create = 20,
    /// `OPSuccinctFaultDisputeGame.resolve()`.
    Resolve = 22,
    /// `OPSuccinctFaultDisputeGame.claimCredit(address)`.
    ClaimCredit = 23,
    /// `OPSuccinctFaultDisputeGame.prove(bytes)`.
    Prove = 27,
    /// `OPSuccinctFaultDisputeGame.challenge()`.
    Challenge = 28,
}

/// XLayerSignRequest represents the signing request structure
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct XLayerSignRequest {
    user_id: i32,
    operate_type: i32,
    operate_address: String,
    symbol: i32,
    project_symbol: i32,
    ref_order_id: String,
    operate_symbol: i32,
    operate_amount: String,
    sys_from: i32,
    other_info: String,
    deposite_address: String,
    to_address: String,
    batch_id: i32,
}

/// XLayerSignResponse represents the signing response structure
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct XLayerSignResponse {
    #[allow(dead_code)]
    code: i32,
    data: String,
    detail_msg: Option<String>,
    msg: String,
    status: i32,
    success: bool,
}

/// XLayerQueryRequest represents the query request for signature result
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct XLayerQueryRequest {
    user_id: i32,
    order_id: String,
    project_symbol: i32,
}

/// Per-method business overlay decoded from calldata. Selectors that
/// carry no arguments (e.g. `resolve()`) produce an empty overlay.
/// Flattened into `XLayerOtherInfo`, so absent fields don't appear in
/// the JSON payload.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct MethodOverlay {
    // DisputeGameFactory.create(uint32, bytes32, bytes)
    #[serde(skip_serializing_if = "Option::is_none")]
    game_type: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_claim: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extra_data: Option<String>,
    // OPSuccinctFaultDisputeGame.claimCredit(address)
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient: Option<String>,
    // OPSuccinctFaultDisputeGame.prove(bytes)
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_bytes: Option<String>,
}

impl MethodOverlay {
    /// Dispatches on the calldata selector to the right decoder. Unknown
    /// selectors are rejected upstream in `detect_operate_type`; the
    /// fallback here only fires for empty calldata.
    fn from_calldata(data: &[u8]) -> Self {
        if data.len() < 4 {
            return Self::default();
        }
        let selector = format!("0x{}", hex::encode(&data[..4]));
        let args = &data[4..];
        match selector.as_str() {
            METHOD_SIG_DGF_CREATE => decode_create(args).unwrap_or_default(),
            METHOD_SIG_CLAIM_CREDIT => Self {
                recipient: extract_recipient(args),
                ..Self::default()
            },
            METHOD_SIG_PROVE => Self {
                proof_bytes: extract_prove_bytes(args),
                ..Self::default()
            },
            _ => Self::default(),
        }
    }
}

/// JSON payload of the remote signer's `otherInfo` field: tx-level
/// fields plus the per-method business overlay decoded from calldata.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct XLayerOtherInfo {
    contract_address: String,
    gas_limit: u64,
    gas_price: Option<String>,
    nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_fee_per_gas: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_priority_fee_per_gas: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(flatten)]
    overlay: MethodOverlay,
}

/// Decodes `DisputeGameFactory.create(uint32, bytes32, bytes)`. Returns
/// `None` if `args` is too short to hold the three head words; the
/// dynamic `extraData` tail is truncated rather than erroring when its
/// declared length runs off the end.
fn decode_create(args: &[u8]) -> Option<MethodOverlay> {
    if args.len() < 96 {
        tracing::warn!("Insufficient calldata for create()");
        return None;
    }
    let game_type = u32_from_word(&args[0..32]);
    let root_claim = hex_0x(&args[32..64]);
    let extra_data_offset = u64_from_word(&args[64..96]) as usize;
    let extra_data = decode_dyn_bytes(args, extra_data_offset)
        .unwrap_or_else(|| "0x".to_string());

    tracing::info!(
        game_type,
        %root_claim,
        %extra_data,
        "Parsed create() params"
    );
    Some(MethodOverlay {
        game_type: Some(game_type),
        root_claim: Some(root_claim),
        extra_data: Some(extra_data),
        ..MethodOverlay::default()
    })
}

/// Extracts the recipient from `claimCredit(address)` args — the
/// address sits in the low 20 bytes of the single 32-byte word.
fn extract_recipient(args: &[u8]) -> Option<String> {
    if args.len() < 32 {
        return None;
    }
    let recipient = hex_0x(&args[12..32]);
    tracing::info!(%recipient, "Parsed claimCredit() params");
    Some(recipient)
}

/// Extracts the inner payload from `prove(bytes)` args, stripping the
/// 32-byte offset + 32-byte length header.
fn extract_prove_bytes(args: &[u8]) -> Option<String> {
    if args.len() <= 64 {
        return None;
    }
    let length = u64_from_word(&args[32..64]) as usize;
    if args.len() < 64 + length {
        return None;
    }
    Some(hex_0x(&args[64..64 + length]))
}

/// Decodes an ABI dynamic `bytes` value at `offset` inside `args`. The
/// offset points at the length word; the payload follows. Truncates
/// rather than erroring when the declared length runs off the end.
fn decode_dyn_bytes(args: &[u8], offset: usize) -> Option<String> {
    let len_word = args.get(offset..offset.checked_add(32)?)?;
    let length = u64_from_word(len_word) as usize;
    let start = offset + 32;
    let end = start.saturating_add(length).min(args.len());
    Some(hex_0x(&args[start..end]))
}

/// Reads the low 4 bytes of an ABI 32-byte word as `uint32`.
fn u32_from_word(word: &[u8]) -> u32 {
    u32::from_be_bytes(word[28..32].try_into().expect("word is 32 bytes"))
}

/// Reads the low 8 bytes of an ABI 32-byte word as `u64`. Upper bytes
/// are ignored — ABI lengths and offsets that fit in 64 bits already
/// dwarf anything we'd actually try to allocate.
fn u64_from_word(word: &[u8]) -> u64 {
    u64::from_be_bytes(word[24..32].try_into().expect("word is 32 bytes"))
}

fn hex_0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// XLayerConfig contains configuration for XLayer remote signer
#[derive(Clone)]
pub struct XLayerConfig {
    pub endpoint: String,
    pub address: Address,
    pub user_id: i32,
    pub symbol: i32,
    pub project_symbol: i32,
    pub operate_symbol: i32,
    pub operate_amount: String,
    pub sys_from: i32,
    pub request_sign_uri: String,
    pub query_sign_uri: String,
    pub access_key: String,
    pub secret_key: String,
    pub timeout: Duration,
}

impl std::fmt::Debug for XLayerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XLayerConfig")
            .field("endpoint", &self.endpoint)
            .field("address", &self.address)
            .field("user_id", &self.user_id)
            .field("symbol", &self.symbol)
            .field("project_symbol", &self.project_symbol)
            .field("operate_symbol", &self.operate_symbol)
            .field("operate_amount", &self.operate_amount)
            .field("sys_from", &self.sys_from)
            .field("request_sign_uri", &self.request_sign_uri)
            .field("query_sign_uri", &self.query_sign_uri)
            .field("access_key", &"***REDACTED***")
            .field("secret_key", &"***REDACTED***")
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl Default for XLayerConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            address: Address::ZERO,
            user_id: 0,
            symbol: 2882,
            project_symbol: 3011,
            operate_symbol: 2,
            operate_amount: "0".to_string(),
            sys_from: 3,
            request_sign_uri: "/priapi/v1/assetonchain/ecology/ecologyOperate".to_string(),
            query_sign_uri: "/priapi/v1/assetonchain/ecology/querySignDataByOrderNo".to_string(),
            access_key: String::new(),
            secret_key: String::new(),
            timeout: Duration::from_secs(30),
        }
    }
}

/// Client for the XLayer remote signing service. Safe for concurrent
/// use — signing requests are serialized internally because the remote
/// service is not guaranteed to handle parallel calls for the same
/// operate address.
#[derive(Debug)]
pub struct XLayerRemoteClient {
    config: XLayerConfig,
    client: reqwest::Client,
    /// One in-flight signing request at a time.
    signing_lock: Mutex<()>,
    /// refOrderIDs issued by this client, queryable by a companion
    /// verify-server. Held behind its own mutex so callback lookups
    /// don't contend with the signing lock.
    ref_order_cache: Mutex<LruCache<String, ()>>,
}

impl XLayerRemoteClient {
    pub fn new(config: XLayerConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("Failed to create HTTP client");

        let cache = LruCache::new(
            NonZeroUsize::new(REF_ORDER_CACHE_CAPACITY)
                .expect("REF_ORDER_CACHE_CAPACITY must be > 0"),
        );

        Self {
            config,
            client,
            signing_lock: Mutex::new(()),
            ref_order_cache: Mutex::new(cache),
        }
    }

    /// Reports whether this client has issued the given `refOrderID`.
    /// Used by asset-management callbacks to vouch for a transfer
    /// initiated by the remote signer.
    pub async fn has_ref_order_id(&self, id: &str) -> bool {
        let mut cache = self.ref_order_cache.lock().await;
        cache.contains(id)
    }

    /// Signs `transaction_request` via the XLayer remote signer.
    /// Concurrent calls are serialized internally.
    pub async fn sign_transaction(
        &self,
        transaction_request: &TransactionRequest,
    ) -> Result<Bytes> {
        // Held across the POST, the poll loop, and signature verification.
        let _guard = self.signing_lock.lock().await;

        tracing::debug!(
            "Acquired signing lock: from={:?}, to={:?}, nonce={:?}",
            transaction_request.from,
            transaction_request.to,
            transaction_request.nonce
        );

        let operate_type = self.detect_operate_type(transaction_request)?;
        tracing::info!("Detected operate type: {:?}", operate_type);

        let other_info = self.build_other_info(transaction_request)?;

        // Register the refOrderID before sending so the verify-server can
        // answer asset-management callbacks even if the response is delayed
        // or lost.
        let ref_order_id = generate_ref_order_id(operate_type);
        {
            let mut cache = self.ref_order_cache.lock().await;
            cache.put(ref_order_id.clone(), ());
        }

        let to_address = transaction_request
            .to
            .and_then(|to| match to {
                alloy_primitives::TxKind::Call(addr) => Some(format!("{:?}", addr).to_lowercase()),
                alloy_primitives::TxKind::Create => None,
            })
            .unwrap_or_default();

        let operate_amount = transaction_request
            .value
            .map(|v| Self::convert_value_to_operate_amount(v))
            .unwrap_or_else(|| "0".to_string());

        let sign_request = XLayerSignRequest {
            user_id: self.config.user_id,
            operate_type: operate_type as i32,
            operate_address: format!("{:?}", self.config.address).to_lowercase(),
            symbol: self.config.symbol,
            project_symbol: self.config.project_symbol,
            ref_order_id: ref_order_id.clone(),
            operate_symbol: self.config.operate_symbol,
            operate_amount,
            sys_from: self.config.sys_from,
            other_info,
            deposite_address: to_address.clone(),
            to_address,
            batch_id: 0,
        };

        tracing::info!(
            "Sending sign request to remote signer: ref_order_id={}, operate_type={:?}",
            ref_order_id,
            operate_type
        );

        // Retry the "pending transaction" backoff error; let every other
        // error propagate immediately.
        for attempt in 0..=MAX_SIGNING_RETRIES {
            if attempt > 0 {
                tracing::warn!(
                    "Retrying after pending-tx error: attempt={}/{}",
                    attempt,
                    MAX_SIGNING_RETRIES
                );
                sleep(RETRY_DELAY).await;
            }

            match self.post_sign_request_and_wait_result(&sign_request, &transaction_request).await {
                Ok(signed_tx_bytes) => {
                    if attempt > 0 {
                        tracing::info!("Remote signing succeeded after retry: attempt={}", attempt);
                    }
                    return Ok(signed_tx_bytes);
                }
                Err(e) => {
                    let err_str = e.to_string();
                    // The remote can return either the Chinese or English wording.
                    let is_pending_tx_error = err_str.contains("未完成交易")
                        || err_str.contains("pending transaction")
                        || err_str.contains("相同地址有未完成交易")
                        || err_str.contains("has pending transactions");

                    if !is_pending_tx_error {
                        tracing::error!("Remote signing failed with non-retryable error: {}", e);
                        return Err(e);
                    }

                    if attempt == MAX_SIGNING_RETRIES {
                        tracing::error!(
                            "Remote signing failed after max retries: max_retries={}",
                            MAX_SIGNING_RETRIES
                        );
                        return Err(anyhow::anyhow!(
                            "Remote signing failed after {} retries (pending transaction): {}",
                            MAX_SIGNING_RETRIES,
                            e
                        ));
                    }

                    tracing::info!(
                        "Remote signer reported pending transaction, will retry: attempt={}/{}, next_retry_in={:?}",
                        attempt + 1,
                        MAX_SIGNING_RETRIES,
                        RETRY_DELAY
                    );
                }
            }
        }

        Err(anyhow::anyhow!("Unexpected: exhausted retry attempts"))
    }

    /// Maps the calldata selector to the wire-level `OperateType` the
    /// remote signer expects.
    fn detect_operate_type(
        &self,
        tx: &TransactionRequest,
    ) -> Result<OperateType> {
        let empty_bytes = Bytes::new();
        let data = tx.input.input().unwrap_or(&empty_bytes);
        if data.len() < 4 {
            return Err(anyhow::anyhow!("Transaction data too short to detect component type"));
        }

        let method_sig = format!("0x{}", hex::encode(&data[..4]));
        match method_sig.as_str() {
            METHOD_SIG_DGF_CREATE => Ok(OperateType::Create),
            METHOD_SIG_PROVE => Ok(OperateType::Prove),
            METHOD_SIG_CHALLENGE => Ok(OperateType::Challenge),
            METHOD_SIG_RESOLVE => Ok(OperateType::Resolve),
            METHOD_SIG_CLAIM_CREDIT => Ok(OperateType::ClaimCredit),
            _ => Err(anyhow::anyhow!(
                "Unknown method signature: refusing to sign transaction (method_sig={}, data_len={})",
                method_sig,
                data.len()
            )),
        }
    }

    /// Serializes the tx-level fields plus the per-method business
    /// overlay (game params, recipient, proof bytes) into the `otherInfo`
    /// JSON string.
    fn build_other_info(&self, tx: &TransactionRequest) -> Result<String> {
        let contract_address = match tx.to {
            Some(alloy_primitives::TxKind::Call(addr)) => format!("{:?}", addr),
            _ => String::new(),
        };
        let empty = Bytes::new();
        let data = tx.input.input().unwrap_or(&empty);

        let other_info = XLayerOtherInfo {
            contract_address,
            gas_limit: tx.gas.unwrap_or(0),
            gas_price: tx.gas_price.map(|gp| gp.to_string()),
            nonce: tx.nonce.unwrap_or(0),
            max_fee_per_gas: tx.max_fee_per_gas.map(|f| f.to_string()),
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas.map(|f| f.to_string()),
            data: Some(hex_0x(data)),
            value: tx.value.map(|v| v.to_string()),
            overlay: MethodOverlay::from_calldata(data),
        };

        serde_json::to_string(&other_info).context("Failed to serialize OtherInfo")
    }

    /// Converts a wei value to the `operateAmount` string the remote
    /// signer expects: zero is `"0"`, otherwise an ETH decimal with up to
    /// 18 fractional digits and trailing zeros / dots trimmed (e.g.
    /// `"1.5"`, `"0.001"`). Operates on the integer wei string directly
    /// so the output is exact for any U256.
    fn convert_value_to_operate_amount(value: U256) -> String {
        if value.is_zero() {
            return "0".to_string();
        }
        // Pad to ≥19 chars so the slice always has one integer digit
        // before the 18-digit fractional tail.
        let wei = value.to_string();
        let padded = if wei.len() < 19 {
            format!("{:0>19}", wei)
        } else {
            wei
        };
        let split = padded.len() - 18;
        let int_part = &padded[..split];
        let frac_part = padded[split..].trim_end_matches('0');
        if frac_part.is_empty() {
            int_part.to_string()
        } else {
            format!("{int_part}.{frac_part}")
        }
    }

    /// Posts the sign request, then polls until a signed transaction
    /// comes back or the poll budget is exhausted.
    async fn post_sign_request_and_wait_result(
        &self,
        request: &XLayerSignRequest,
        transaction_request: &TransactionRequest,
    ) -> Result<Bytes> {
        self.post_sign_request(request).await?;
        let result = self.wait_sign_result(&request.ref_order_id).await?;

        tracing::info!(
            "Received signing result: ref_order_id={}, status={}, success={}",
            request.ref_order_id,
            result.status,
            result.success
        );

        if !result.success || result.data.is_empty() {
            return Err(anyhow::anyhow!(
                "Signing failed: msg={}, detail={}",
                result.msg,
                result.detail_msg.unwrap_or_default()
            ));
        }

        let hex_data = result.data.trim_start_matches("0x");
        let signed_tx_bytes = hex::decode(hex_data)
            .context("Failed to decode signed transaction hex")?;
        self.verify_signed_transaction(&transaction_request, &signed_tx_bytes)?;

        Ok(Bytes::from(signed_tx_bytes))
    }

    async fn post_sign_request(&self, request: &XLayerSignRequest) -> Result<()> {
        let url = format!("{}{}", self.config.endpoint, self.config.request_sign_uri);

        // Key order must be canonical so the signature matches server-side.
        let payload = self.sorted_json_marshal(request)?;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse()?);
        self.add_auth_headers(&mut headers, &[], &payload)?;

        eprintln!("[xlayer] >>> POST {url}\n[xlayer]     body={payload}");

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .body(payload)
            .send()
            .await
            .context("Failed to send sign request")?;

        let status = response.status().as_u16();
        let resp_body = response.text().await.unwrap_or_default();
        eprintln!("[xlayer] <<< {status} {resp_body}");

        if status != HTTP_STATUS_SUCCESS {
            return Err(XLayerSignerError::HttpError {
                status,
                body: resp_body,
            }
            .into());
        }

        let sign_response: XLayerSignResponse = serde_json::from_str(&resp_body)
            .with_context(|| format!("Failed to parse sign response. Raw body: {resp_body}"))?;

        if !sign_response.success {
            return Err(XLayerSignerError::SigningFailed {
                status: sign_response.status,
                msg: sign_response.msg,
                detail: sign_response.detail_msg.unwrap_or_default(),
            }
            .into());
        }

        Ok(())
    }

    /// Polls the remote signer until it returns a signed transaction for
    /// `order_id` or the poll budget runs out (5 minutes).
    async fn wait_sign_result(&self, order_id: &str) -> Result<XLayerSignResponse> {
        let url = format!("{}{}", self.config.endpoint, self.config.query_sign_uri);

        let query_request = XLayerQueryRequest {
            user_id: self.config.user_id,
            order_id: order_id.to_string(),
            project_symbol: self.config.project_symbol,
        };

        let max_attempts = 300;
        for attempt in 0..max_attempts {
            sleep(SIGN_RESULT_POLL_INTERVAL).await;

            // GET requests sign the sorted URL-query *values*, not a body.
            let user_id_str = query_request.user_id.to_string();
            let project_symbol_str = query_request.project_symbol.to_string();
            let query_params: [(&str, &str); 3] = [
                ("userId", user_id_str.as_str()),
                ("orderId", query_request.order_id.as_str()),
                ("projectSymbol", project_symbol_str.as_str()),
            ];

            let mut headers = reqwest::header::HeaderMap::new();
            self.add_auth_headers(&mut headers, &query_params, "")?;

            eprintln!(
                "[xlayer] >>> GET {url} (attempt {}/{})\n[xlayer]     query={query_params:?}",
                attempt + 1,
                max_attempts,
            );

            let response = self
                .client
                .get(&url)
                .headers(headers)
                .query(&query_params)
                .send()
                .await
                .context("Failed to send query request")?;

            let status = response.status().as_u16();
            let body = response
                .text()
                .await
                .context("Failed to read query response body")?;
            eprintln!("[xlayer] <<< {status} {body}");

            if status != HTTP_STATUS_SUCCESS {
                continue;
            }

            let query_response: XLayerSignResponse = serde_json::from_str(&body)
                .with_context(|| format!("Failed to parse query response. Raw body: {body}"))?;

            // Done only when the response carries a non-empty signed tx.
            if query_response.success && !query_response.data.is_empty() {
                return Ok(query_response);
            }

            tracing::debug!(
                "Polling for sign result: attempt={}/{}, success={}, data_len={}",
                attempt + 1,
                max_attempts,
                query_response.success,
                query_response.data.len()
            );
        }

        Err(XLayerSignerError::SignatureTimeout(max_attempts).into())
    }

    /// Serializes `data` to JSON with all object keys sorted alphabetically.
    /// Key order is part of the canonical input the request signature is
    /// computed over.
    fn sorted_json_marshal<T: Serialize>(&self, data: &T) -> Result<String> {
        let json_value: serde_json::Value = serde_json::to_value(data)?;
        let sorted = Self::sort_json_keys(&json_value);
        serde_json::to_string(&sorted).context("Failed to serialize sorted JSON")
    }

    /// Recursively sorts the keys of every JSON object in `value`.
    fn sort_json_keys(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let mut sorted_map: Vec<_> = map.iter().collect();
                sorted_map.sort_by_key(|(k, _)| k.as_str());
                let sorted_obj: serde_json::Map<String, serde_json::Value> = sorted_map
                    .into_iter()
                    .map(|(k, v)| (k.clone(), Self::sort_json_keys(v)))
                    .collect();
                serde_json::Value::Object(sorted_obj)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(Self::sort_json_keys).collect())
            }
            _ => value.clone(),
        }
    }

    /// Attaches the `accessKey` and `sign` headers. If either credential
    /// is empty the call goes out unauthenticated.
    fn add_auth_headers(
        &self,
        headers: &mut reqwest::header::HeaderMap,
        query_params: &[(&str, &str)],
        body: &str,
    ) -> Result<()> {
        if self.config.access_key.is_empty() || self.config.secret_key.is_empty() {
            return Ok(());
        }
        headers.insert("accessKey", self.config.access_key.parse()?);
        let signature = self.generate_signature(query_params, body)?;
        headers.insert("sign", signature.parse()?);
        Ok(())
    }

    /// Computes the request signature: sort URL-query *values* lexically,
    /// concatenate with the body, SHA-256, hex-encode, AES-ECB-encrypt
    /// with the secret key, base64.
    fn generate_signature(&self, query_params: &[(&str, &str)], body: &str) -> Result<String> {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let mut values: Vec<&str> = query_params.iter().map(|(_, v)| *v).collect();
        values.sort();

        let mut content = String::new();
        for v in &values {
            content.push_str(v);
        }
        content.push_str(body);

        let hash = Sha256::digest(content.as_bytes());
        let hash_hex = hex::encode(hash);
        let encrypted = self.encrypt_aes_ecb(&hash_hex)?;
        Ok(base64::prelude::BASE64_STANDARD.encode(encrypted))
    }

    /// Encrypts data using AES-ECB with PKCS5 padding. Accepts 16/24/32-byte
    /// keys (AES-128/192/256).
    fn encrypt_aes_ecb(&self, plaintext: &str) -> Result<Vec<u8>> {
        use aes::cipher::generic_array::GenericArray;
        use aes::cipher::{BlockEncrypt, KeyInit};
        use aes::{Aes128, Aes192, Aes256};

        let key_bytes = self.config.secret_key.as_bytes();
        let padded = self.pkcs5_padding(plaintext.as_bytes(), 16);
        let mut encrypted = padded;

        match key_bytes.len() {
            16 => {
                let cipher = Aes128::new(GenericArray::from_slice(key_bytes));
                for chunk in encrypted.chunks_mut(16) {
                    cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
                }
            }
            24 => {
                let cipher = Aes192::new(GenericArray::from_slice(key_bytes));
                for chunk in encrypted.chunks_mut(16) {
                    cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
                }
            }
            32 => {
                let cipher = Aes256::new(GenericArray::from_slice(key_bytes));
                for chunk in encrypted.chunks_mut(16) {
                    cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
                }
            }
            n => {
                return Err(anyhow::anyhow!(
                    "Secret key must be 16, 24 or 32 bytes (AES-128/192/256), got {n}"
                ));
            }
        }

        Ok(encrypted)
    }

    /// PKCS#5 / PKCS#7 padding for AES-ECB block alignment.
    fn pkcs5_padding(&self, data: &[u8], block_size: usize) -> Vec<u8> {
        let padding = block_size - (data.len() % block_size);
        let mut result = data.to_vec();
        result.extend(vec![padding as u8; padding]);
        result
    }

    /// Sanity-checks the signed bytes the remote signer returned: the
    /// recovered signer must match `config.address`, and every header
    /// field the caller specified must round-trip identically.
    fn verify_signed_transaction(
        &self,
        original_tx: &TransactionRequest,
        signed_tx_bytes: &[u8],
    ) -> Result<()> {
        let tx_envelope = TxEnvelope::decode_2718(&mut &signed_tx_bytes[..])
            .context("Failed to decode signed transaction")?;
        let recovered_req: TransactionRequest = tx_envelope.clone().into();

        tracing::debug!(
            "Verifying signed transaction: type={:?}, from={:?}",
            tx_envelope.tx_type(),
            original_tx.from
        );

        // Without this signer-identity check a compromised or
        // misconfigured remote could return a transaction signed by some
        // other key and we'd happily broadcast it.
        let recovered_signer = recovered_req.from.ok_or_else(|| {
            XLayerSignerError::VerificationError(
                "Failed to recover signer from signed transaction".to_string(),
            )
        })?;
        if recovered_signer != self.config.address {
            return Err(XLayerSignerError::VerificationError(format!(
                "Signature verification failed: expected signer {:?}, recovered {:?}",
                self.config.address, recovered_signer
            ))
            .into());
        }

        match &tx_envelope {
            TxEnvelope::Eip1559(signed) => {
                if let Some(chain_id) = original_tx.chain_id {
                    if recovered_req.chain_id != Some(chain_id) {
                        return Err(anyhow::anyhow!(
                            "ChainId mismatch: expected {:?}, got {:?}",
                            chain_id,
                            recovered_req.chain_id
                        ));
                    }
                }

                if let Some(expected_from) = original_tx.from {
                    let actual_from = recovered_req.from;
                    if actual_from != Some(expected_from) {
                        return Err(anyhow::anyhow!(
                            "From mismatch: expected {:?}, got {:?}",
                            expected_from,
                            actual_from
                        ));
                    }
                }

                if let Some(nonce) = original_tx.nonce {
                    if signed.nonce() != nonce {
                        return Err(anyhow::anyhow!(
                            "Nonce mismatch: expected {}, got {}",
                            nonce,
                            signed.nonce()
                        ));
                    }
                }

                if let Some(to) = &original_tx.to {
                    match to {
                        alloy_primitives::TxKind::Call(addr) => {
                            if Some(*addr) != signed.to() {
                                return Err(XLayerSignerError::VerificationError(format!(
                                    "To address mismatch: expected {:?}, got {:?}",
                                    addr,
                                    signed.to()
                                ))
                                .into());
                            }
                        }
                        alloy_primitives::TxKind::Create => {
                            if signed.to().is_some() {
                                return Err(anyhow::anyhow!(
                                    "To address should be None for contract creation"
                                ));
                            }
                        }
                    }
                }

                if let Some(value) = original_tx.value {
                    if signed.value() != value {
                        return Err(anyhow::anyhow!(
                            "Value mismatch: expected {}, got {}",
                            value,
                            signed.value()
                        ));
                    }
                }

                if let Some(gas) = original_tx.gas {
                    if signed.gas_limit() != gas {
                        return Err(anyhow::anyhow!(
                            "Gas limit mismatch: expected {}, got {}",
                            gas,
                            signed.gas_limit()
                        ));
                    }
                }

                if let Some(max_fee) = original_tx.max_fee_per_gas {
                    if signed.max_fee_per_gas() != max_fee {
                        return Err(anyhow::anyhow!(
                            "Max fee per gas mismatch: expected {}, got {:?}",
                            max_fee,
                            signed.max_fee_per_gas()
                        ));
                    }
                }

                if let Some(max_priority_fee) = original_tx.max_priority_fee_per_gas {
                    if signed.max_priority_fee_per_gas() != Some(max_priority_fee) {
                        return Err(anyhow::anyhow!(
                            "Max priority fee per gas mismatch: expected {}, got {:?}",
                            max_priority_fee,
                            signed.max_priority_fee_per_gas()
                        ));
                    }
                }

                let empty_data = Bytes::new();
                let original_data = original_tx.input.input().unwrap_or(&empty_data);
                if signed.input() != original_data.as_ref() {
                    return Err(anyhow::anyhow!(
                        "Transaction data mismatch: expected {} bytes, got {} bytes",
                        original_data.len(),
                        signed.input().len()
                    ));
                }

                tracing::info!(
                    "Signed transaction verified successfully: nonce={}, to={:?}, value={}, gas={}, data_len={}",
                    signed.nonce(),
                    signed.to(),
                    signed.value(),
                    signed.gas_limit(),
                    signed.input().len()
                );
            }
            TxEnvelope::Legacy(signed) => {
                if let Some(chain_id) = original_tx.chain_id {
                    if recovered_req.chain_id != Some(chain_id) {
                        return Err(anyhow::anyhow!(
                            "ChainId mismatch: expected {:?}, got {:?}",
                            chain_id,
                            recovered_req.chain_id
                        ));
                    }
                }

                if let Some(expected_from) = original_tx.from {
                    let actual_from = recovered_req.from;
                    if actual_from != Some(expected_from) {
                        return Err(anyhow::anyhow!(
                            "From mismatch (legacy): expected {:?}, got {:?}",
                            expected_from,
                            actual_from
                        ));
                    }
                }

                if let Some(nonce) = original_tx.nonce {
                    if signed.nonce() != nonce {
                        return Err(anyhow::anyhow!(
                            "Nonce mismatch: expected {}, got {}",
                            nonce,
                            signed.nonce()
                        ));
                    }
                }

                let empty_data = Bytes::new();
                let original_data = original_tx.input.input().unwrap_or(&empty_data);
                if signed.input() != original_data.as_ref() {
                    return Err(anyhow::anyhow!(
                        "Transaction data mismatch for legacy tx"
                    ));
                }

                if let Some(gas_price) = original_tx.gas_price {
                    if signed.gas_price() != Some(gas_price) {
                        return Err(anyhow::anyhow!(
                            "Gas price mismatch (legacy): expected {}, got {:?}",
                            gas_price,
                            signed.gas_price()
                        ));
                    }
                }
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Unsupported transaction type: {:?}",
                    tx_envelope.tx_type()
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, Bytes, U256};
    use alloy_rpc_types_eth::TransactionRequest;
    use serde::Serialize;
    use std::time::Duration;

    /// `DisputeGameFactory.create` -> `OperateType::Create`.
    #[test]
    fn test_detect_create_operate_type() {
        let config = XLayerConfig::default();
        let client = XLayerRemoteClient::new(config);

        let data = hex::decode("82ecf2f6").unwrap();
        let mut tx = TransactionRequest::default();
        tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
        tx.to = Some(alloy_primitives::TxKind::Call(address!(
            "0000000000000000000000000000000000000001"
        )));

        let result = client.detect_operate_type(&tx);
        assert!(result.is_ok());
        let operate_type = result.unwrap();
        assert_eq!(operate_type as i32, OperateType::Create as i32);
    }

    /// `OPSuccinctFaultDisputeGame.challenge` -> `OperateType::Challenge`.
    #[test]
    fn test_detect_challenge_operate_type() {
        let config = XLayerConfig::default();
        let client = XLayerRemoteClient::new(config);

        let data = hex::decode("d2ef7398").unwrap();
        let mut tx = TransactionRequest::default();
        tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
        tx.to = Some(alloy_primitives::TxKind::Call(address!(
            "0000000000000000000000000000000000000002"
        )));

        let result = client.detect_operate_type(&tx);
        assert!(result.is_ok());
        let operate_type = result.unwrap();
        assert_eq!(operate_type as i32, OperateType::Challenge as i32);
    }

    /// `OPSuccinctFaultDisputeGame.resolve` -> `OperateType::Resolve`.
    #[test]
    fn test_detect_resolve_operate_type() {
        let config = XLayerConfig::default();
        let client = XLayerRemoteClient::new(config);

        let data = hex::decode("2810e1d6").unwrap();
        let mut tx = TransactionRequest::default();
        tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
        tx.to = Some(alloy_primitives::TxKind::Call(address!(
            "0000000000000000000000000000000000000002"
        )));

        let result = client.detect_operate_type(&tx);
        assert!(result.is_ok());
        let operate_type = result.unwrap();
        assert_eq!(operate_type as i32, OperateType::Resolve as i32);
    }

    /// `OPSuccinctFaultDisputeGame.claimCredit` -> `OperateType::ClaimCredit`.
    #[test]
    fn test_detect_claim_credit_operate_type() {
        let config = XLayerConfig::default();
        let client = XLayerRemoteClient::new(config);

        let data = hex::decode("60e27464").unwrap();
        let mut tx = TransactionRequest::default();
        tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
        tx.to = Some(alloy_primitives::TxKind::Call(address!(
            "0000000000000000000000000000000000000002"
        )));

        let result = client.detect_operate_type(&tx);
        assert!(result.is_ok());
        let operate_type = result.unwrap();
        assert_eq!(operate_type as i32, OperateType::ClaimCredit as i32);
    }

    /// `prove(bytes)` (selector 0x375bfa5d) -> `OperateType::Prove`.
    #[test]
    fn test_detect_prove_operate_type() {
        let config = XLayerConfig::default();
        let client = XLayerRemoteClient::new(config);

        let data = hex::decode("375bfa5d").unwrap();
        let mut tx = TransactionRequest::default();
        tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
        tx.to = Some(alloy_primitives::TxKind::Call(address!(
            "0000000000000000000000000000000000000002"
        )));

        let result = client.detect_operate_type(&tx);
        assert!(result.is_ok());
        let operate_type = result.unwrap();
        assert_eq!(operate_type as i32, OperateType::Prove as i32);
    }

    /// `resolveClaim` is no longer supported (not on `OPSuccinctFaultDisputeGame`).
    #[test]
    fn test_detect_resolve_claim_rejected() {
        let config = XLayerConfig::default();
        let client = XLayerRemoteClient::new(config);

        let data = hex::decode("03c2924d").unwrap();
        let mut tx = TransactionRequest::default();
        tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
        tx.to = Some(alloy_primitives::TxKind::Call(address!(
            "0000000000000000000000000000000000000002"
        )));

        let err = client.detect_operate_type(&tx).unwrap_err();
        assert!(err.to_string().contains("Unknown method signature"));
    }

    /// Test unknown method signature rejection
    #[test]
    fn test_detect_unknown_method() {
        let config = XLayerConfig::default();
        let client = XLayerRemoteClient::new(config);

        // Unknown method signature: 0xdeadbeef
        let data = hex::decode("deadbeef").unwrap();
        let mut tx = TransactionRequest::default();
        tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
        tx.to = Some(alloy_primitives::TxKind::Call(address!(
            "0000000000000000000000000000000000000002"
        )));

        let result = client.detect_operate_type(&tx);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unknown method signature"));
    }

    /// Test transaction data too short
    #[test]
    fn test_detect_data_too_short() {
        let config = XLayerConfig::default();
        let client = XLayerRemoteClient::new(config);

        // Only 2 bytes, less than 4 required for method signature
        let data = hex::decode("8282").unwrap();
        let mut tx = TransactionRequest::default();
        tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
        tx.to = Some(alloy_primitives::TxKind::Call(address!(
            "0000000000000000000000000000000000000002"
        )));

        let result = client.detect_operate_type(&tx);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Transaction data too short"));
    }

/// `operateAmount` must be an exact 18-decimal ETH string with trailing
    /// zeros and any trailing dot trimmed.
    #[test]
    fn test_convert_value_to_operate_amount() {
        // 0 wei
        assert_eq!(
            XLayerRemoteClient::convert_value_to_operate_amount(U256::ZERO),
            "0"
        );

        // 1 ETH = 10^18 wei -> "1"
        assert_eq!(
            XLayerRemoteClient::convert_value_to_operate_amount(U256::from(
                1_000_000_000_000_000_000u128
            )),
            "1"
        );

        // 2.5 ETH -> "2.5"
        assert_eq!(
            XLayerRemoteClient::convert_value_to_operate_amount(U256::from(
                2_500_000_000_000_000_000u128
            )),
            "2.5"
        );

        // Sub-ETH: 1 wei -> "0.000000000000000001"
        assert_eq!(
            XLayerRemoteClient::convert_value_to_operate_amount(U256::from(1u64)),
            "0.000000000000000001"
        );

        // 0.001 ETH -> "0.001"
        assert_eq!(
            XLayerRemoteClient::convert_value_to_operate_amount(U256::from(
                1_000_000_000_000_000u128
            )),
            "0.001"
        );

        // Large amount: 1000 ETH -> "1000"
        assert_eq!(
            XLayerRemoteClient::convert_value_to_operate_amount(U256::from(
                1_000_000_000_000_000_000_000u128
            )),
            "1000"
        );
    }

    /// Test JSON key sorting
    #[test]
    fn test_sort_json_keys() {
        #[derive(Serialize)]
        #[allow(dead_code)]
        struct TestData {
            z_field: String,
            a_field: String,
            m_field: String,
        }

        let data = TestData {
            z_field: "last".to_string(),
            a_field: "first".to_string(),
            m_field: "middle".to_string(),
        };

        let json_value: serde_json::Value = serde_json::to_value(data).unwrap();
        let sorted = XLayerRemoteClient::sort_json_keys(&json_value);
        let sorted_str = serde_json::to_string(&sorted).unwrap();

        // Keys should be in alphabetical order: a_field, m_field, z_field
        let a_pos = sorted_str.find("a_field").unwrap();
        let m_pos = sorted_str.find("m_field").unwrap();
        let z_pos = sorted_str.find("z_field").unwrap();

        assert!(a_pos < m_pos);
        assert!(m_pos < z_pos);
    }

    /// Test XLayerConfig Debug implementation (should redact secrets)
    #[test]
    fn test_config_debug_redacts_secrets() {
        let config = XLayerConfig {
            endpoint: "https://test.com".to_string(),
            address: address!("0000000000000000000000000000000000000001"),
            user_id: 123,
            symbol: 2882,
            project_symbol: 3011,
            operate_symbol: 2,
            operate_amount: "0".to_string(),
            sys_from: 3,
            request_sign_uri: "/sign".to_string(),
            query_sign_uri: "/query".to_string(),
            access_key: "secret-access-key".to_string(),
            secret_key: "super-secret-key".to_string(),
            timeout: Duration::from_secs(30),
        };

        let debug_str = format!("{:?}", config);

        // Should contain endpoint and address
        assert!(debug_str.contains("https://test.com"));
        assert!(debug_str.contains("0x0000000000000000000000000000000000000001"));

        // Should NOT contain actual secrets
        assert!(!debug_str.contains("secret-access-key"));
        assert!(!debug_str.contains("super-secret-key"));

        // Should contain redacted markers
        assert!(debug_str.contains("***REDACTED***"));
    }

    /// Builds a tx with the given calldata that the dispute-game contracts
    /// would produce, then returns the resulting `otherInfo` JSON.
    /// `nonce`/`gasLimit` are fixed across all OtherInfo tests so the
    /// expected JSON literals can be written by hand.
    fn build_other_info_for(client: &XLayerRemoteClient, calldata: Vec<u8>) -> String {
        let mut tx = TransactionRequest::default();
        tx.to = Some(alloy_primitives::TxKind::Call(address!(
            "1234567890123456789012345678901234567890"
        )));
        tx.gas = Some(200_000);
        tx.nonce = Some(42);
        tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(calldata));
        client.build_other_info(&tx).unwrap()
    }

    /// `DisputeGameFactory.create(uint32, bytes32, bytes)`. The serialized
    /// JSON must surface `gameType`/`rootClaim`/`extraData` and nothing
    /// else from the overlay layer.
    #[test]
    fn test_other_info_for_create() {
        let client = XLayerRemoteClient::new(XLayerConfig::default());

        let mut calldata = hex::decode("82ecf2f6").unwrap();
        calldata.extend_from_slice(&[0u8; 28]);
        calldata.extend_from_slice(&[0, 0, 0, 1]); // gameType = 1
        calldata.extend_from_slice(&[0x12u8; 32]); // rootClaim
        calldata.extend_from_slice(&[0u8; 24]);
        calldata.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0x60]); // extraData offset
        calldata.extend_from_slice(&[0u8; 24]);
        calldata.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 2]); // extraData length
        calldata.extend_from_slice(&[0xab, 0xcd]); // extraData payload

        let json = build_other_info_for(&client, calldata);
        assert_eq!(
            json,
            r#"{"contractAddress":"0x1234567890123456789012345678901234567890","gasLimit":200000,"gasPrice":null,"nonce":42,"data":"0x82ecf2f60000000000000000000000000000000000000000000000000000000000000001121212121212121212121212121212121212121212121212121212121212121200000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000002abcd","gameType":1,"rootClaim":"0x1212121212121212121212121212121212121212121212121212121212121212","extraData":"0xabcd"}"#,
        );
    }

    /// `OPSuccinctFaultDisputeGame.resolve()` — no calldata args, no overlay.
    #[test]
    fn test_other_info_for_resolve() {
        let client = XLayerRemoteClient::new(XLayerConfig::default());
        let json = build_other_info_for(&client, hex::decode("2810e1d6").unwrap());
        assert_eq!(
            json,
            r#"{"contractAddress":"0x1234567890123456789012345678901234567890","gasLimit":200000,"gasPrice":null,"nonce":42,"data":"0x2810e1d6"}"#,
        );
    }

    /// `OPSuccinctFaultDisputeGame.claimCredit(address)` — recipient comes
    /// from the low 20 bytes of the 32-byte word.
    #[test]
    fn test_other_info_for_claim_credit() {
        let client = XLayerRemoteClient::new(XLayerConfig::default());

        let mut calldata = hex::decode("60e27464").unwrap();
        calldata.extend_from_slice(&[0u8; 12]);
        calldata.extend_from_slice(
            &hex::decode("1234567890123456789012345678901234567890").unwrap(),
        );

        let json = build_other_info_for(&client, calldata);
        assert_eq!(
            json,
            r#"{"contractAddress":"0x1234567890123456789012345678901234567890","gasLimit":200000,"gasPrice":null,"nonce":42,"data":"0x60e274640000000000000000000000001234567890123456789012345678901234567890","recipient":"0x1234567890123456789012345678901234567890"}"#,
        );
    }

    /// `OPSuccinctFaultDisputeGame.prove(bytes)` — `proofBytes` is the
    /// inner payload only (ABI offset + length headers stripped).
    #[test]
    fn test_other_info_for_prove() {
        let client = XLayerRemoteClient::new(XLayerConfig::default());

        let mut calldata = hex::decode("375bfa5d").unwrap();
        calldata.extend_from_slice(&[0u8; 24]);
        calldata.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0x20]); // offset = 32
        calldata.extend_from_slice(&[0u8; 24]);
        calldata.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0x04]); // length = 4
        calldata.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let json = build_other_info_for(&client, calldata);
        assert_eq!(
            json,
            r#"{"contractAddress":"0x1234567890123456789012345678901234567890","gasLimit":200000,"gasPrice":null,"nonce":42,"data":"0x375bfa5d00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000004deadbeef","proofBytes":"0xdeadbeef"}"#,
        );
    }

    /// `OPSuccinctFaultDisputeGame.challenge()` — no calldata args, no overlay.
    #[test]
    fn test_other_info_for_challenge() {
        let client = XLayerRemoteClient::new(XLayerConfig::default());
        let json = build_other_info_for(&client, hex::decode("d2ef7398").unwrap());
        assert_eq!(
            json,
            r#"{"contractAddress":"0x1234567890123456789012345678901234567890","gasLimit":200000,"gasPrice":null,"nonce":42,"data":"0xd2ef7398"}"#,
        );
    }

    /// Fixed-input regression for the signature algorithm. The output is the
    /// canonical base64 the remote signer expects for these inputs; any change
    /// here means our request bodies will no longer authenticate.
    #[test]
    fn test_generate_signature_fixed_vector() {
        let mut config = XLayerConfig::default();
        config.secret_key = "12doxpwjkengkjna".to_string(); // 16-byte AES-128 key
        let client = XLayerRemoteClient::new(config);

        let params: [(&str, &str); 3] = [
            ("0", "0x07f67d4195bc9940f07eb901ef18f1e9e4af12d7"),
            ("1", "127"),
            ("2", "true"),
        ];
        let body = "{\"testBOdy\":45251}";

        let signature = client.generate_signature(&params, body).unwrap();

        assert_eq!(
            signature,
            "si/fTWlDg6+V9OFOM3CictCuqtGfUjKZ3keGLwxM/walrXtQaN8K/PnGTvFvc4q6pb/80HtZIy+hjeugAx8VPLmIXmKpJ5H4mbGEVQe7bk4="
        );
    }

    /// Confirms that the `k256` feature on `alloy-rpc-types-eth` is
    /// enabled and `From<TxEnvelope> for TransactionRequest` populates
    /// `from` via ECDSA recovery. The `from` checks inside
    /// `verify_signed_transaction` rely on this — without the feature
    /// they silently degrade to no-ops.
    #[test]
    fn test_envelope_into_request_recovers_from() {
        use alloy_consensus::{SignableTransaction, TxEip1559};
        use alloy_eips::Encodable2718;
        use alloy_signer::SignerSync;
        use alloy_signer_local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let expected_from = signer.address();

        let tx = TxEip1559 {
            chain_id: 11_155_111,
            nonce: 1,
            gas_limit: 21_000,
            max_fee_per_gas: 20_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: alloy_primitives::TxKind::Call(address!(
                "1234567890123456789012345678901234567890"
            )),
            value: U256::ZERO,
            access_list: Default::default(),
            input: Bytes::new(),
        };
        let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
        let envelope = TxEnvelope::Eip1559(tx.into_signed(signature));

        let raw = envelope.encoded_2718();
        let decoded = TxEnvelope::decode_2718(&mut raw.as_slice()).unwrap();
        let recovered_req: TransactionRequest = decoded.into();

        assert_eq!(recovered_req.from, Some(expected_from));
    }

    /// refOrderID shape: `PROPOSER_TZ_{operateType}_{ms}_{8 hex}`.
    #[test]
    fn test_generate_ref_order_id_shape() {
        let id = generate_ref_order_id(OperateType::Create);
        // Prefix
        assert!(
            id.starts_with("PROPOSER_TZ_"),
            "expected PROPOSER_TZ_ prefix, got: {id}"
        );
        // Three underscore-separated chunks after the prefix:
        //   operateType, timestamp, random
        let tail = id.trim_start_matches("PROPOSER_TZ_");
        let parts: Vec<&str> = tail.split('_').collect();
        assert_eq!(parts.len(), 3, "expected op_ts_rand, got: {id}");
        assert_eq!(parts[0], "20"); // OperateType::Create == 20
        assert!(parts[1].parse::<i64>().is_ok(), "timestamp not numeric: {id}");
        assert_eq!(parts[2].len(), 8, "rand must be 8 hex chars: {id}");
        assert!(parts[2].chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Two consecutive calls must produce distinct IDs even with timestamps in
    /// the same millisecond — the random suffix is what saves us.
    #[test]
    fn test_generate_ref_order_id_unique() {
        let a = generate_ref_order_id(OperateType::Resolve);
        let b = generate_ref_order_id(OperateType::Resolve);
        assert_ne!(a, b);
    }

    /// `has_ref_order_id` round-trip: an ID becomes known once it's recorded,
    /// and remains unknown otherwise. This is what the verify server relies
    /// on to answer asset-management callbacks.
    #[tokio::test]
    async fn test_has_ref_order_id_roundtrip() {
        let client = XLayerRemoteClient::new(XLayerConfig::default());

        let id = generate_ref_order_id(OperateType::Create);
        assert!(!client.has_ref_order_id(&id).await);

        {
            let mut cache = client.ref_order_cache.lock().await;
            cache.put(id.clone(), ());
        }

        assert!(client.has_ref_order_id(&id).await);
        assert!(!client.has_ref_order_id("totally-unrelated-id").await);
    }

}
