use alloy_consensus::{Transaction, TxEnvelope};
use alloy_eips::Decodable2718;
use alloy_primitives::{Address, Bytes, U256};
use alloy_rpc_types_eth::TransactionRequest;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;

/// Contract method signatures (4-byte selectors)
const METHOD_SIG_DGF_CREATE: &str = "0x82ecf2f6"; // DisputeGameFactory.create
const METHOD_SIG_PROVE: &str = "0x0e5d7305"; // FaultDisputeGame.prove
const METHOD_SIG_CHALLENGE: &str = "0xd2ef7398"; // FaultDisputeGame.challenge
const METHOD_SIG_RESOLVE: &str = "0x2810e1d6"; // FaultDisputeGame.resolve
const METHOD_SIG_CLAIM_CREDIT: &str = "0x60e27464"; // FaultDisputeGame.claimCredit

/// Retry configuration constants
const MAX_SIGNING_RETRIES: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_secs(5);
const SIGN_RESULT_POLL_INTERVAL: Duration = Duration::from_secs(1);
const HTTP_STATUS_SUCCESS: u16 = 200;

/// OperateType represents the operation type for XLayer remote signer
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(i32)]
pub enum OperateType {
    Proposer = 20,
    ChallengerProve = 24,
    ChallengerChallenge = 25,
    ChallengerResolve = 22,
    ChallengerClaimCredit = 23,
}

/// ComponentRole represents the role/type of blockchain component
#[derive(Debug, Clone, PartialEq)]
enum ComponentRole {
    Proposer,
    Challenger,
    Unknown,
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

/// XLayerOtherInfo contains transaction parameters for OtherInfo field
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct XLayerOtherInfo {
    contract_address: String,
    gas_limit: u64,
    gas_price: Option<String>,
    nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    blob_versioned_hashes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_fee_per_blob_gas: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_fee_per_gas: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_priority_fee_per_gas: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    // Business parameters for Proposer
    #[serde(skip_serializing_if = "Option::is_none")]
    game_type: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_claim: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extra_data: Option<String>,
    // Business parameters for Challenger
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_to_resolve: Option<u64>,
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

/// XLayerRemoteClient is the client for XLayer remote signing service
#[derive(Debug)]
pub struct XLayerRemoteClient {
    config: XLayerConfig,
    client: reqwest::Client,
}

impl XLayerRemoteClient {
    /// Creates a new XLayer remote signing client
    pub fn new(config: XLayerConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    /// Signs a transaction using XLayer remote signing service
    pub async fn sign_transaction(
        &self,
        transaction_request: &TransactionRequest,
        _filled_tx_bytes: Bytes,
    ) -> Result<Bytes> {
        tracing::debug!(
            "Starting XLayer remote signing for transaction: from={:?}, to={:?}, nonce={:?}",
            transaction_request.from,
            transaction_request.to,
            transaction_request.nonce
        );

        // Detect component type and determine operate type
        let (component_role, operate_type) = self.detect_component_and_operate_type(transaction_request)?;

        tracing::info!(
            "Detected component role: {:?}, operate type: {:?}",
            component_role,
            operate_type
        );

        // Build OtherInfo JSON
        let other_info = self.build_other_info(transaction_request)?;

        // Generate unique order ID
        let ref_order_id = uuid::Uuid::new_v4().to_string();

        // Prepare signing request
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

        // Retry logic for pending transaction errors
        for attempt in 0..=MAX_SIGNING_RETRIES {
            if attempt > 0 {
                tracing::warn!(
                    "Retrying remote signing after pending transaction error: attempt={}/{}",
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

    /// Detects component role and corresponding operate type
    fn detect_component_and_operate_type(
        &self,
        tx: &TransactionRequest,
    ) -> Result<(ComponentRole, OperateType)> {
        // Extract method signature
        let empty_bytes = Bytes::new();
        let data = tx.input.input().unwrap_or(&empty_bytes);
        if data.len() < 4 {
            return Err(anyhow::anyhow!("Transaction data too short to detect component type"));
        }

        let method_sig = format!("0x{}", hex::encode(&data[..4]));

        // Detect based on method signature
        match method_sig.as_str() {
            METHOD_SIG_DGF_CREATE => Ok((ComponentRole::Proposer, OperateType::Proposer)),
            METHOD_SIG_PROVE => Ok((ComponentRole::Challenger, OperateType::ChallengerProve)),
            METHOD_SIG_CHALLENGE => Ok((ComponentRole::Challenger, OperateType::ChallengerChallenge)),
            METHOD_SIG_RESOLVE => Ok((ComponentRole::Challenger, OperateType::ChallengerResolve)),
            METHOD_SIG_CLAIM_CREDIT => Ok((ComponentRole::Challenger, OperateType::ChallengerClaimCredit)),
            _ => Err(anyhow::anyhow!(
                "Unknown component type: refusing to sign transaction (method_sig={}, data_len={})",
                method_sig,
                data.len()
            )),
        }
    }

    /// Builds OtherInfo JSON string with business parameters
    fn build_other_info(&self, tx: &TransactionRequest) -> Result<String> {
        let contract_address = tx
            .to
            .and_then(|to| match to {
                alloy_primitives::TxKind::Call(addr) => Some(format!("{:?}", addr)),
                alloy_primitives::TxKind::Create => None,
            })
            .unwrap_or_default();

        let empty_bytes = Bytes::new();
        let data = tx.input.input().unwrap_or(&empty_bytes);
        
        // Parse business parameters based on method signature
        let (game_type, root_claim, extra_data, recipient, claim_index, num_to_resolve) = 
            if data.len() >= 4 {
                self.parse_business_params(data)?
            } else {
                (None, None, None, None, None, None)
            };

        let other_info = XLayerOtherInfo {
            contract_address,
            gas_limit: tx.gas.unwrap_or(0),
            gas_price: tx.gas_price.map(|gp| gp.to_string()),
            nonce: tx.nonce.unwrap_or(0),
            blob_versioned_hashes: tx.blob_versioned_hashes.as_ref().map(|hashes| {
                hashes.iter().map(|h| format!("{:?}", h)).collect()
            }),
            max_fee_per_blob_gas: tx.max_fee_per_blob_gas.map(|f| f.to_string()),
            max_fee_per_gas: tx.max_fee_per_gas.map(|f| f.to_string()),
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas.map(|f| f.to_string()),
            data: Some(format!("0x{}", hex::encode(data))),
            value: tx.value.map(|v| v.to_string()),
            // Business parameters
            game_type,
            root_claim,
            extra_data,
            recipient,
            claim_index,
            num_to_resolve,
        };

        serde_json::to_string(&other_info).context("Failed to serialize OtherInfo")
    }

    /// Parses business parameters from transaction data based on method signature
    fn parse_business_params(
        &self,
        data: &Bytes,
    ) -> Result<(Option<u32>, Option<String>, Option<String>, Option<String>, Option<u64>, Option<u64>)> {
        if data.len() < 4 {
            return Ok((None, None, None, None, None, None));
        }

        let method_sig = format!("0x{}", hex::encode(&data[..4]));
        let params_data = &data[4..];

        match method_sig.as_str() {
            METHOD_SIG_DGF_CREATE => {
                // DisputeGameFactory.create(uint32 _gameType, bytes32 _rootClaim, bytes calldata _extraData)
                if params_data.len() < 96 {
                    tracing::warn!("Insufficient data for create method");
                    return Ok((None, None, None, None, None, None));
                }

                // Parse gameType (uint32, but padded to 32 bytes)
                let game_type = u32::from_be_bytes([
                    params_data[28],
                    params_data[29],
                    params_data[30],
                    params_data[31],
                ]);

                // Parse rootClaim (bytes32, next 32 bytes)
                let root_claim = format!("0x{}", hex::encode(&params_data[32..64]));

                // Parse extraData (dynamic bytes)
                // The offset to extraData is at bytes 64-96
                let extra_data_offset = u64::from_be_bytes([
                    params_data[88],
                    params_data[89],
                    params_data[90],
                    params_data[91],
                    params_data[92],
                    params_data[93],
                    params_data[94],
                    params_data[95],
                ]) as usize;

                let extra_data = if extra_data_offset < params_data.len() {
                    // Read length of extraData (32 bytes at offset)
                    if extra_data_offset + 32 <= params_data.len() {
                        let length = u64::from_be_bytes([
                            params_data[extra_data_offset + 24],
                            params_data[extra_data_offset + 25],
                            params_data[extra_data_offset + 26],
                            params_data[extra_data_offset + 27],
                            params_data[extra_data_offset + 28],
                            params_data[extra_data_offset + 29],
                            params_data[extra_data_offset + 30],
                            params_data[extra_data_offset + 31],
                        ]) as usize;

                        let data_start = extra_data_offset + 32;
                        if data_start + length <= params_data.len() {
                            format!("0x{}", hex::encode(&params_data[data_start..data_start + length]))
                        } else {
                            format!("0x{}", hex::encode(&params_data[data_start..]))
                        }
                    } else {
                        format!("0x{}", hex::encode(&params_data[extra_data_offset..]))
                    }
                } else {
                    "0x".to_string()
                };

                tracing::info!(
                    "Parsed Proposer params: gameType={}, rootClaim={}, extraData={}",
                    game_type,
                    root_claim,
                    extra_data
                );

                Ok((Some(game_type), Some(root_claim), Some(extra_data), None, None, None))
            }
            METHOD_SIG_CLAIM_CREDIT => {
                // FaultDisputeGame.claimCredit(address _recipient)
                if params_data.len() >= 32 {
                    let recipient = format!("0x{}", hex::encode(&params_data[12..32]));
                    tracing::info!("Parsed ClaimCredit params: recipient={}", recipient);
                    Ok((None, None, None, Some(recipient), None, None))
                } else {
                    Ok((None, None, None, None, None, None))
                }
            }
            METHOD_SIG_PROVE | METHOD_SIG_CHALLENGE | METHOD_SIG_RESOLVE => {
                // These methods have parameters but they are not critical business params
                // prove(bytes calldata proofBytes) - proof data is in calldata
                // challenge() - no params
                // resolve() - no params
                tracing::debug!("Method {} has no critical business params to parse", method_sig);
                Ok((None, None, None, None, None, None))
            }
            _ => {
                tracing::debug!("Unknown method signature for param parsing: {}", method_sig);
                Ok((None, None, None, None, None, None))
            }
        }
    }

    /// Converts value to operate amount string
    fn convert_value_to_operate_amount(value: U256) -> String {
        if value.is_zero() {
            "0".to_string()
        } else {
            // Convert to ETH (divide by 10^18)
            let eth_value = value / U256::from(1_000_000_000_000_000_000u128);
            eth_value.to_string()
        }
    }

    /// Posts sign request and waits for result
    async fn post_sign_request_and_wait_result(
        &self,
        request: &XLayerSignRequest,
        transaction_request: &TransactionRequest,
    ) -> Result<Bytes> {
        // 1. Send signing request
        self.post_sign_request(request).await?;

        // 2. Wait for signing result
        let result = self.wait_sign_result(&request.ref_order_id).await?;

        tracing::info!(
            "Received signing result from remote signer: ref_order_id={}, status={}, success={}",
            request.ref_order_id,
            result.status,
            result.success
        );

        // 3. Parse signed transaction hex
        if !result.success || result.data.is_empty() {
            return Err(anyhow::anyhow!(
                "Signing failed: msg={}, detail={}",
                result.msg,
                result.detail_msg.unwrap_or_default()
            ));
        }

        // Remove "0x" prefix if present
        let hex_data = result.data.trim_start_matches("0x");
        let signed_tx_bytes = hex::decode(hex_data)
            .context("Failed to decode signed transaction hex")?;

        // 4. Verify signed transaction
        self.verify_signed_transaction(&transaction_request, &signed_tx_bytes)?;

        Ok(Bytes::from(signed_tx_bytes))
    }

    /// Posts signing request to remote signer
    async fn post_sign_request(&self, request: &XLayerSignRequest) -> Result<()> {
        let url = format!("{}{}", self.config.endpoint, self.config.request_sign_uri);

        // Serialize request with sorted keys (important for signature verification)
        let payload = self.sorted_json_marshal(request)?;

        // Calculate signature
        let signature = self.calculate_signature(&payload)?;

        // Build headers
        let timestamp = chrono::Utc::now().timestamp_millis().to_string();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse()?);
        headers.insert("FIX-ACCESS-KEY", self.config.access_key.parse()?);
        headers.insert("FIX-SIGNATURE", signature.parse()?);
        headers.insert("FIX-TIMESTAMP", timestamp.parse()?);

        tracing::debug!("Posting sign request to: {}", url);

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .body(payload)
            .send()
            .await
            .context("Failed to send sign request")?;

        if response.status().as_u16() != HTTP_STATUS_SUCCESS {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "HTTP error: status={}, body={}",
                status,
                body
            ));
        }

        let sign_response: XLayerSignResponse = response
            .json()
            .await
            .context("Failed to parse sign response")?;

        if !sign_response.success {
            return Err(anyhow::anyhow!(
                "Sign request failed: msg={}, detail={}",
                sign_response.msg,
                sign_response.detail_msg.unwrap_or_default()
            ));
        }

        Ok(())
    }

    /// Waits for signing result by polling
    async fn wait_sign_result(&self, order_id: &str) -> Result<XLayerSignResponse> {
        let url = format!("{}{}", self.config.endpoint, self.config.query_sign_uri);

        let query_request = XLayerQueryRequest {
            user_id: self.config.user_id,
            order_id: order_id.to_string(),
            project_symbol: self.config.project_symbol,
        };

        // Poll for result
        let max_attempts = 60; // 60 seconds timeout
        for attempt in 0..max_attempts {
            sleep(SIGN_RESULT_POLL_INTERVAL).await;

            let payload = self.sorted_json_marshal(&query_request)?;
            let signature = self.calculate_signature(&payload)?;

            let timestamp = chrono::Utc::now().timestamp_millis().to_string();
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert("Content-Type", "application/json".parse()?);
            headers.insert("FIX-ACCESS-KEY", self.config.access_key.parse()?);
            headers.insert("FIX-SIGNATURE", signature.parse()?);
            headers.insert("FIX-TIMESTAMP", timestamp.parse()?);

            let response = self
                .client
                .post(&url)
                .headers(headers)
                .body(payload)
                .send()
                .await
                .context("Failed to send query request")?;

            if response.status().as_u16() != HTTP_STATUS_SUCCESS {
                continue;
            }

            let query_response: XLayerSignResponse = response
                .json()
                .await
                .context("Failed to parse query response")?;

            // Check if signing is complete
            if query_response.success && !query_response.data.is_empty() {
                return Ok(query_response);
            }

            // Check for error conditions
            if !query_response.success && !query_response.msg.contains("查询不到") {
                return Err(anyhow::anyhow!(
                    "Query failed: msg={}, detail={}",
                    query_response.msg,
                    query_response.detail_msg.unwrap_or_default()
                ));
            }

            tracing::debug!("Polling for sign result: attempt={}/{}", attempt + 1, max_attempts);
        }

        Err(anyhow::anyhow!("Timeout waiting for signing result"))
    }

    /// Serializes JSON with sorted keys (required for signature calculation)
    fn sorted_json_marshal<T: Serialize>(&self, data: &T) -> Result<String> {
        let json_value: serde_json::Value = serde_json::to_value(data)?;
        let sorted = Self::sort_json_keys(&json_value);
        serde_json::to_string(&sorted).context("Failed to serialize sorted JSON")
    }

    /// Recursively sorts JSON keys
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

    /// Calculates HMAC-SHA256 signature
    fn calculate_signature(&self, payload: &str) -> Result<String> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(self.config.secret_key.as_bytes())
            .context("Invalid secret key")?;
        mac.update(payload.as_bytes());
        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }

    /// Verifies the signed transaction returned by remote signer
    fn verify_signed_transaction(
        &self,
        original_tx: &TransactionRequest,
        signed_tx_bytes: &[u8],
    ) -> Result<()> {
        // Decode signed transaction
        let tx_envelope = TxEnvelope::decode_2718(&mut &signed_tx_bytes[..])
            .context("Failed to decode signed transaction")?;

        tracing::debug!(
            "Verifying signed transaction: type={:?}, from={:?}",
            tx_envelope.tx_type(),
            original_tx.from
        );

        // Verify basic fields
        match &tx_envelope {
            TxEnvelope::Eip1559(signed) => {
                // Verify nonce
                if let Some(nonce) = original_tx.nonce {
                    if signed.nonce() != nonce {
                        return Err(anyhow::anyhow!(
                            "Nonce mismatch: expected {}, got {}",
                            nonce,
                            signed.nonce()
                        ));
                    }
                }

                // Verify to address
                if let Some(to) = &original_tx.to {
                    match to {
                        alloy_primitives::TxKind::Call(addr) => {
                            if Some(*addr) != signed.to() {
                                return Err(anyhow::anyhow!(
                                    "To address mismatch: expected {:?}, got {:?}",
                                    addr,
                                    signed.to()
                                ));
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

                // Verify value
                if let Some(value) = original_tx.value {
                    if signed.value() != value {
                        return Err(anyhow::anyhow!(
                            "Value mismatch: expected {}, got {}",
                            value,
                            signed.value()
                        ));
                    }
                }

                // Verify gas limit
                if let Some(gas) = original_tx.gas {
                    if signed.gas_limit() != gas {
                        return Err(anyhow::anyhow!(
                            "Gas limit mismatch: expected {}, got {}",
                            gas,
                            signed.gas_limit()
                        ));
                    }
                }

                // Verify data
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
                // Similar verification for legacy transactions
                if let Some(nonce) = original_tx.nonce {
                    if signed.nonce() != nonce {
                        return Err(anyhow::anyhow!(
                            "Nonce mismatch: expected {}, got {}",
                            nonce,
                            signed.nonce()
                        ));
                    }
                }

                // Verify other fields...
                let empty_data = Bytes::new();
                let original_data = original_tx.input.input().unwrap_or(&empty_data);
                if signed.input() != original_data.as_ref() {
                    return Err(anyhow::anyhow!(
                        "Transaction data mismatch for legacy tx"
                    ));
                }
            }
            TxEnvelope::Eip4844(signed) => {
                // Verify blob transaction basic fields
                if let Some(nonce) = original_tx.nonce {
                    if signed.nonce() != nonce {
                        return Err(anyhow::anyhow!(
                            "Nonce mismatch in blob tx: expected {}, got {}",
                            nonce,
                            signed.nonce()
                        ));
                    }
                }

                // Verify to address
                if let Some(to) = &original_tx.to {
                    match to {
                        alloy_primitives::TxKind::Call(addr) => {
                            if Some(*addr) != signed.to() {
                                return Err(anyhow::anyhow!(
                                    "To address mismatch in blob tx"
                                ));
                            }
                        }
                        _ => {}
                    }
                }

                // Verify value
                if let Some(value) = original_tx.value {
                    if signed.value() != value {
                        return Err(anyhow::anyhow!(
                            "Value mismatch in blob tx"
                        ));
                    }
                }

                tracing::info!(
                    "Blob transaction verified successfully: nonce={}, to={:?}",
                    signed.nonce(),
                    signed.to()
                );
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

    /// Test component detection for Proposer (DisputeGameFactory.create)
    #[test]
    fn test_detect_proposer_component() {
        let config = XLayerConfig::default();
        let client = XLayerRemoteClient::new(config);

        // DisputeGameFactory.create method signature: 0x82ecf2f6
        let data = hex::decode("82ecf2f6").unwrap();
        let mut tx = TransactionRequest::default();
        tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
        tx.to = Some(alloy_primitives::TxKind::Call(address!(
            "0000000000000000000000000000000000000001"
        )));

        let result = client.detect_component_and_operate_type(&tx);
        assert!(result.is_ok());
        let (component, operate_type) = result.unwrap();
        assert_eq!(component, ComponentRole::Proposer);
        assert_eq!(operate_type as i32, OperateType::Proposer as i32);
    }

    /// Test component detection for Challenger (prove)
    #[test]
    fn test_detect_challenger_prove() {
        let config = XLayerConfig::default();
        let client = XLayerRemoteClient::new(config);

        // FaultDisputeGame.prove method signature: 0x0e5d7305
        let data = hex::decode("0e5d7305").unwrap();
        let mut tx = TransactionRequest::default();
        tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
        tx.to = Some(alloy_primitives::TxKind::Call(address!(
            "0000000000000000000000000000000000000002"
        )));

        let result = client.detect_component_and_operate_type(&tx);
        assert!(result.is_ok());
        let (component, operate_type) = result.unwrap();
        assert_eq!(component, ComponentRole::Challenger);
        assert_eq!(operate_type as i32, OperateType::ChallengerProve as i32);
    }

    /// Test component detection for Challenger (challenge)
    #[test]
    fn test_detect_challenger_challenge() {
        let config = XLayerConfig::default();
        let client = XLayerRemoteClient::new(config);

        // FaultDisputeGame.challenge method signature: 0xd2ef7398
        let data = hex::decode("d2ef7398").unwrap();
        let mut tx = TransactionRequest::default();
        tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
        tx.to = Some(alloy_primitives::TxKind::Call(address!(
            "0000000000000000000000000000000000000002"
        )));

        let result = client.detect_component_and_operate_type(&tx);
        assert!(result.is_ok());
        let (component, operate_type) = result.unwrap();
        assert_eq!(component, ComponentRole::Challenger);
        assert_eq!(operate_type as i32, OperateType::ChallengerChallenge as i32);
    }

    /// Test component detection for Challenger (resolve)
    #[test]
    fn test_detect_challenger_resolve() {
        let config = XLayerConfig::default();
        let client = XLayerRemoteClient::new(config);

        // FaultDisputeGame.resolve method signature: 0x2810e1d6
        let data = hex::decode("2810e1d6").unwrap();
        let mut tx = TransactionRequest::default();
        tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
        tx.to = Some(alloy_primitives::TxKind::Call(address!(
            "0000000000000000000000000000000000000002"
        )));

        let result = client.detect_component_and_operate_type(&tx);
        assert!(result.is_ok());
        let (component, operate_type) = result.unwrap();
        assert_eq!(component, ComponentRole::Challenger);
        assert_eq!(operate_type as i32, OperateType::ChallengerResolve as i32);
    }

    /// Test component detection for Challenger (claimCredit)
    #[test]
    fn test_detect_challenger_claim_credit() {
        let config = XLayerConfig::default();
        let client = XLayerRemoteClient::new(config);

        // FaultDisputeGame.claimCredit method signature: 0x60e27464
        let data = hex::decode("60e27464").unwrap();
        let mut tx = TransactionRequest::default();
        tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));
        tx.to = Some(alloy_primitives::TxKind::Call(address!(
            "0000000000000000000000000000000000000002"
        )));

        let result = client.detect_component_and_operate_type(&tx);
        assert!(result.is_ok());
        let (component, operate_type) = result.unwrap();
        assert_eq!(component, ComponentRole::Challenger);
        assert_eq!(
            operate_type as i32,
            OperateType::ChallengerClaimCredit as i32
        );
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

        let result = client.detect_component_and_operate_type(&tx);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unknown component type"));
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

        let result = client.detect_component_and_operate_type(&tx);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Transaction data too short"));
    }

    /// Test OtherInfo building
    #[test]
    fn test_build_other_info() {
        let config = XLayerConfig::default();
        let client = XLayerRemoteClient::new(config);

        let mut tx = TransactionRequest::default();
        tx.to = Some(alloy_primitives::TxKind::Call(address!(
            "1234567890123456789012345678901234567890"
        )));
        tx.gas = Some(200000);
        tx.gas_price = Some(20000000000);
        tx.nonce = Some(42);
        tx.max_fee_per_gas = Some(30000000000);
        tx.max_priority_fee_per_gas = Some(2000000000);
        tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(
            hex::decode("82ecf2f6").unwrap(),
        ));
        tx.value = Some(U256::from(1000000000000000000u128));

        let result = client.build_other_info(&tx);
        assert!(result.is_ok());

        let other_info = result.unwrap();
        assert!(other_info.contains("contractAddress"));
        assert!(other_info.contains("gasLimit"));
        assert!(other_info.contains("nonce"));
        assert!(other_info.contains("\"nonce\":42"));
        assert!(other_info.contains("\"gasLimit\":200000"));
    }

    /// Test value conversion to operate amount
    #[test]
    fn test_convert_value_to_operate_amount() {
        // 0 wei
        assert_eq!(
            XLayerRemoteClient::convert_value_to_operate_amount(U256::ZERO),
            "0"
        );

        // 1 ETH = 10^18 wei
        assert_eq!(
            XLayerRemoteClient::convert_value_to_operate_amount(U256::from(
                1_000_000_000_000_000_000u128
            )),
            "1"
        );

        // 2.5 ETH (should round down to 2)
        assert_eq!(
            XLayerRemoteClient::convert_value_to_operate_amount(U256::from(
                2_500_000_000_000_000_000u128
            )),
            "2"
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

    /// Test business parameter parsing for DisputeGameFactory.create
    #[test]
    fn test_parse_proposer_create_params() {
        let config = XLayerConfig::default();
        let client = XLayerRemoteClient::new(config);

        // DisputeGameFactory.create(uint32 gameType, bytes32 rootClaim, bytes extraData)
        // Method sig: 0x82ecf2f6
        // gameType: 1 (padded to 32 bytes)
        // rootClaim: 0x1234...00 (32 bytes)
        // extraData offset: 96 (0x60)
        // extraData length: 2
        // extraData: 0xabcd
        let mut data = Vec::new();
        data.extend_from_slice(&hex::decode("82ecf2f6").unwrap()); // method sig

        // gameType = 1 (padded to 32 bytes)
        data.extend_from_slice(&[0u8; 28]);
        data.extend_from_slice(&[0, 0, 0, 1]);

        // rootClaim (32 bytes)
        data.extend_from_slice(&[0x12u8; 32]);

        // extraData offset = 96 (0x60)
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0x60]);

        // extraData length = 2
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 2]);

        // extraData = 0xabcd
        data.extend_from_slice(&[0xab, 0xcd]);

        let result = client.parse_business_params(&Bytes::from(data));
        assert!(result.is_ok());

        let (game_type, root_claim, extra_data, _, _, _) = result.unwrap();
        assert_eq!(game_type, Some(1));
        assert!(root_claim.is_some());
        assert!(extra_data.is_some());
        assert_eq!(extra_data.unwrap(), "0xabcd");
    }

    /// Test business parameter parsing for claimCredit
    #[test]
    fn test_parse_challenger_claim_credit_params() {
        let config = XLayerConfig::default();
        let client = XLayerRemoteClient::new(config);

        // FaultDisputeGame.claimCredit(address _recipient)
        // Method sig: 0x60e27464
        // recipient: 0x1234567890123456789012345678901234567890
        let mut data = Vec::new();
        data.extend_from_slice(&hex::decode("60e27464").unwrap()); // method sig

        // address (20 bytes, padded to 32 bytes)
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(
            &hex::decode("1234567890123456789012345678901234567890").unwrap(),
        );

        let result = client.parse_business_params(&Bytes::from(data));
        assert!(result.is_ok());

        let (_, _, _, recipient, _, _) = result.unwrap();
        assert!(recipient.is_some());
        assert_eq!(
            recipient.unwrap(),
            "0x1234567890123456789012345678901234567890"
        );
    }

    /// Test OtherInfo includes business parameters
    #[test]
    fn test_other_info_with_business_params() {
        let config = XLayerConfig::default();
        let client = XLayerRemoteClient::new(config);

        // Build a create() transaction
        let mut tx = TransactionRequest::default();
        tx.to = Some(alloy_primitives::TxKind::Call(address!(
            "1234567890123456789012345678901234567890"
        )));
        tx.gas = Some(200000);
        tx.nonce = Some(42);

        // DisputeGameFactory.create with simple params
        let mut data = Vec::new();
        data.extend_from_slice(&hex::decode("82ecf2f6").unwrap());
        data.extend_from_slice(&[0u8; 28]);
        data.extend_from_slice(&[0, 0, 0, 1]); // gameType = 1
        data.extend_from_slice(&[0x12u8; 32]); // rootClaim
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0x60]); // offset
        data.extend_from_slice(&[0u8; 32]); // length = 0
        tx.input = alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data));

        let result = client.build_other_info(&tx);
        assert!(result.is_ok());

        let other_info = result.unwrap();
        assert!(other_info.contains("gameType"));
        assert!(other_info.contains("rootClaim"));
        assert!(other_info.contains("extraData"));
    }
}
