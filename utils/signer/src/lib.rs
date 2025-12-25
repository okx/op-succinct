use std::{str::FromStr, sync::Arc};

use alloy_consensus::TxEnvelope;
use alloy_eips::Decodable2718;
use alloy_network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy_primitives::{Address, Bytes, TxKind};
use alloy_provider::{Provider, ProviderBuilder, Web3Signer};
use alloy_rpc_types_eth::{TransactionReceipt, TransactionRequest};
use alloy_signer::Signer as AlloySigner;
use alloy_signer_gcp::{GcpKeyRingRef, GcpSigner, KeySpecifier};
use alloy_signer_local::PrivateKeySigner;
use alloy_transport_http::reqwest::Url;
use anyhow::{Context, Result};
use gcloud_sdk::{
    google::cloud::kms::v1::key_management_service_client::KeyManagementServiceClient, GoogleApi,
};
use tokio::{sync::Mutex, time::Duration};

pub mod xlayer_remote_client;
pub use xlayer_remote_client::{XLayerConfig, XLayerRemoteClient};

pub const NUM_CONFIRMATIONS: u64 = 3;
pub const TIMEOUT_SECONDS: u64 = 60;

#[derive(Clone, Debug)]
/// The type of signer to use for signing transactions.
pub enum Signer {
    /// The signer URL and address.
    Web3Signer(Url, Address),
    /// The local signer.
    LocalSigner(PrivateKeySigner),
    /// Cloud HSM signer using Google.
    CloudHsmSigner(GcpSigner),
    /// XLayer remote signer using remote asset management service.
    XLayerRemoteSigner(Arc<XLayerRemoteClient>, Address),
}

impl Signer {
    pub fn address(&self) -> Address {
        match self {
            Signer::Web3Signer(_, address) => *address,
            Signer::LocalSigner(signer) => signer.address(),
            Signer::CloudHsmSigner(signer) => signer.address(),
            Signer::XLayerRemoteSigner(_, address) => *address,
        }
    }

    /// Creates a new Web3 signer with the given URL and address.
    pub fn new_web3_signer(url: Url, address: Address) -> Self {
        Signer::Web3Signer(url, address)
    }

    /// Creates a new local signer from a private key string.
    pub fn new_local_signer(private_key_str: &str) -> Result<Self> {
        let private_key =
            PrivateKeySigner::from_str(private_key_str).context("Failed to parse private key")?;
        Ok(Signer::LocalSigner(private_key))
    }

    /// Creates a new XLayer remote signer from configuration.
    pub fn new_xlayer_remote_signer(config: XLayerConfig) -> Self {
        let address = config.address;
        let client = XLayerRemoteClient::new(config);
        Signer::XLayerRemoteSigner(Arc::new(client), address)
    }

    pub async fn from_env() -> Result<Self> {
        // Check for XLayer remote signer first (highest priority for production)
        if let Ok(enabled) = std::env::var("XLAYER_SIGNER_ENABLED") {
            if enabled.to_lowercase() == "true" {
                let config = XLayerConfig {
                    endpoint: std::env::var("XLAYER_SIGNER_ENDPOINT")
                        .context("XLAYER_SIGNER_ENDPOINT is required when XLAYER_SIGNER_ENABLED=true")?,
                    address: Address::from_str(&std::env::var("XLAYER_SIGNER_ADDRESS")
                        .context("XLAYER_SIGNER_ADDRESS is required when XLAYER_SIGNER_ENABLED=true")?)
                        .context("Failed to parse XLAYER_SIGNER_ADDRESS")?,
                    user_id: std::env::var("XLAYER_USER_ID")
                        .unwrap_or_else(|_| "0".to_string())
                        .parse()
                        .context("Failed to parse XLAYER_USER_ID")?,
                    symbol: std::env::var("XLAYER_SYMBOL")
                        .unwrap_or_else(|_| "2882".to_string())
                        .parse()
                        .context("Failed to parse XLAYER_SYMBOL")?,
                    project_symbol: std::env::var("XLAYER_PROJECT_SYMBOL")
                        .unwrap_or_else(|_| "3011".to_string())
                        .parse()
                        .context("Failed to parse XLAYER_PROJECT_SYMBOL")?,
                    operate_symbol: std::env::var("XLAYER_OPERATE_SYMBOL")
                        .unwrap_or_else(|_| "2".to_string())
                        .parse()
                        .context("Failed to parse XLAYER_OPERATE_SYMBOL")?,
                    operate_amount: std::env::var("XLAYER_OPERATE_AMOUNT")
                        .unwrap_or_else(|_| "0".to_string()),
                    sys_from: std::env::var("XLAYER_SYS_FROM")
                        .unwrap_or_else(|_| "3".to_string())
                        .parse()
                        .context("Failed to parse XLAYER_SYS_FROM")?,
                    request_sign_uri: std::env::var("XLAYER_REQUEST_SIGN_URI")
                        .unwrap_or_else(|_| "/priapi/v1/assetonchain/ecology/ecologyOperate".to_string()),
                    query_sign_uri: std::env::var("XLAYER_QUERY_SIGN_URI")
                        .unwrap_or_else(|_| "/priapi/v1/assetonchain/ecology/querySignDataByOrderNo".to_string()),
                    access_key: std::env::var("XLAYER_ACCESS_KEY")
                        .context("XLAYER_ACCESS_KEY is required when XLAYER_SIGNER_ENABLED=true")?,
                    secret_key: std::env::var("XLAYER_SECRET_KEY")
                        .context("XLAYER_SECRET_KEY is required when XLAYER_SIGNER_ENABLED=true")?,
                    timeout: Duration::from_secs(
                        std::env::var("XLAYER_TIMEOUT")
                            .unwrap_or_else(|_| "30".to_string())
                            .parse()
                            .context("Failed to parse XLAYER_TIMEOUT")?
                    ),
                };

                tracing::info!(
                    "Initialized XLayer remote signer: endpoint={}, address={:?}",
                    config.endpoint,
                    config.address
                );

                return Ok(Signer::new_xlayer_remote_signer(config));
            }
        }

        if let (Ok(project_id), Ok(location), Ok(keyring_name)) = (
            std::env::var("GOOGLE_PROJECT_ID"),
            std::env::var("GOOGLE_LOCATION"),
            std::env::var("GOOGLE_KEYRING"),
        ) {
            let key_name = std::env::var("HSM_KEY_NAME").expect("HSM_KEY_NAME");
            let key_version =
                std::env::var("HSM_KEY_VERSION").unwrap_or("1".to_string()).parse()?;

            let keyring = GcpKeyRingRef::new(&project_id, &location, &keyring_name);

            let key_specifier = KeySpecifier::new(keyring, &key_name, key_version);

            let client = GoogleApi::from_function(
                KeyManagementServiceClient::new,
                "https://cloudkms.googleapis.com",
                None,
            )
            .await?;
            let signer = GcpSigner::new(client, key_specifier, None).await?;

            Ok(Signer::CloudHsmSigner(signer))
        } else if let (Ok(signer_url_str), Ok(signer_address_str)) =
            (std::env::var("SIGNER_URL"), std::env::var("SIGNER_ADDRESS"))
        {
            let signer_url = Url::parse(&signer_url_str).context("Failed to parse SIGNER_URL")?;
            let signer_address =
                Address::from_str(&signer_address_str).context("Failed to parse SIGNER_ADDRESS")?;
            Ok(Signer::new_web3_signer(signer_url, signer_address))
        } else if let Ok(private_key_str) = std::env::var("PRIVATE_KEY") {
            Signer::new_local_signer(&private_key_str)
        } else {
            anyhow::bail!(
                "None of the required signer configurations are set in environment:\n\
                - For XLayer Remote Signer: XLAYER_SIGNER_ENABLED=true, XLAYER_SIGNER_ENDPOINT, XLAYER_SIGNER_ADDRESS, XLAYER_ACCESS_KEY, XLAYER_SECRET_KEY\n\
                - For Cloud HSM: GOOGLE_PROJECT_ID, GOOGLE_LOCATION, GOOGLE_KEYRING\n\
                - For Web3Signer: SIGNER_URL and SIGNER_ADDRESS\n\
                - For Local: PRIVATE_KEY"
            )
        }
    }

    /// Sends a transaction request, signed by the configured `signer`.
    pub async fn send_transaction_request(
        &self,
        l1_rpc: Url,
        mut transaction_request: TransactionRequest,
    ) -> Result<TransactionReceipt> {
        match self {
            Signer::XLayerRemoteSigner(client, signer_address) => {
                // Set the from address to the signer address.
                transaction_request.set_from(*signer_address);

                // Fill the transaction request with all of the relevant gas and nonce information.
                let provider = ProviderBuilder::new().network::<Ethereum>().connect_http(l1_rpc.clone());
                let filled_tx = provider.fill(transaction_request.clone()).await?;

                // Extract filled transaction bytes for reference
                let filled_tx_bytes = {
                    let mut tx = filled_tx.as_builder().unwrap().clone();
                    tx.normalize_data();
                    // This is just for logging/debugging, not used in signing
                    Bytes::new()
                };

                // Sign the transaction using XLayer remote signer
                tracing::info!("Signing transaction with XLayer remote signer");
                let signed_tx_bytes = client
                    .sign_transaction(&transaction_request, filled_tx_bytes)
                    .await
                    .context("XLayer remote signing failed")?;

                // Decode signed transaction
                let tx_envelope = TxEnvelope::decode_2718(&mut signed_tx_bytes.as_ref())
                    .context("Failed to decode signed transaction")?;

                // Send the signed transaction
                let receipt = provider
                    .send_tx_envelope(tx_envelope)
                    .await
                    .context("Failed to send XLayer-signed transaction")?
                    .with_required_confirmations(NUM_CONFIRMATIONS)
                    .with_timeout(Some(Duration::from_secs(TIMEOUT_SECONDS)))
                    .get_receipt()
                    .await?;

                tracing::info!("XLayer-signed transaction confirmed: tx_hash={:?}", receipt.transaction_hash);
                Ok(receipt)
            }
            Signer::Web3Signer(signer_url, signer_address) => {
                // Set the from address to the signer address.
                transaction_request.set_from(*signer_address);

                // Fill the transaction request with all of the relevant gas and nonce information.
                let provider = ProviderBuilder::new().network::<Ethereum>().connect_http(l1_rpc);
                let filled_tx = provider.fill(transaction_request).await?;

                // Sign the transaction request using the Web3Signer.
                let web3_provider =
                    ProviderBuilder::new().network::<Ethereum>().connect_http(signer_url.clone());
                let signer = Web3Signer::new(web3_provider.clone(), *signer_address);

                let mut tx = filled_tx.as_builder().unwrap().clone();
                tx.normalize_data();

                let raw: Bytes =
                    signer.provider().client().request("eth_signTransaction", (tx,)).await?;

                let tx_envelope = TxEnvelope::decode_2718(&mut raw.as_ref()).unwrap();

                let receipt = provider
                    .send_tx_envelope(tx_envelope)
                    .await
                    .context("Failed to send transaction")?
                    .with_required_confirmations(NUM_CONFIRMATIONS)
                    .with_timeout(Some(Duration::from_secs(TIMEOUT_SECONDS)))
                    .get_receipt()
                    .await?;

                Ok(receipt)
            }
            Signer::LocalSigner(private_key) => {
                let provider = ProviderBuilder::new()
                    .network::<Ethereum>()
                    .wallet(EthereumWallet::new(private_key.clone()))
                    .connect_http(l1_rpc);

                // Ensure the request has a `from` address so the wallet filler can sign it.
                transaction_request.set_from(private_key.address());
                if transaction_request.to.is_none() {
                    // NOTE(fakedev9999): Anvil's wallet filler insists on a `to` field even for
                    // deployments. Mark the request as contract creation so it can be signed.
                    transaction_request.to = Some(TxKind::Create);
                }

                let receipt = provider
                    .send_transaction(transaction_request)
                    .await
                    .context("Failed to send transaction")?
                    .with_required_confirmations(NUM_CONFIRMATIONS)
                    .with_timeout(Some(Duration::from_secs(TIMEOUT_SECONDS)))
                    .get_receipt()
                    .await?;

                Ok(receipt)
            }
            Signer::CloudHsmSigner(signer) => {
                // Set the from address to HSM address
                transaction_request.set_from(signer.address());
                if transaction_request.to.is_none() {
                    // NOTE(fakedev9999): Anvil's wallet filler insists on a `to` field even for
                    // deployments. Mark the request as contract creation so it can be signed.
                    transaction_request.to = Some(TxKind::Create);
                }

                let wallet = EthereumWallet::new(signer.clone());
                let provider = ProviderBuilder::new()
                    .network::<Ethereum>()
                    .wallet(wallet)
                    .connect_http(l1_rpc);

                let receipt = provider
                    .send_transaction(transaction_request)
                    .await
                    .context("Failed to send KMS-signed transaction")?
                    .with_required_confirmations(NUM_CONFIRMATIONS)
                    .with_timeout(Some(Duration::from_secs(TIMEOUT_SECONDS)))
                    .get_receipt()
                    .await?;

                Ok(receipt)
            }
        }
    }
}

/// Wrapper around Signer that provides thread-safe transaction sending.
/// Transactions are serialized via a Mutex to prevent nonce conflicts.
#[derive(Clone, Debug)]
pub struct SignerLock {
    inner: Arc<Mutex<Signer>>,
    cached_address: Address,
}

impl SignerLock {
    /// Creates a new SignerLock wrapping the given Signer.
    pub fn new(signer: Signer) -> Self {
        let cached_address = signer.address();
        SignerLock { inner: Arc::new(Mutex::new(signer)), cached_address }
    }

    /// Creates a SignerLock from environment variables.
    pub async fn from_env() -> Result<Self> {
        Ok(SignerLock::new(Signer::from_env().await?))
    }

    /// Returns the address of the signer without acquiring a lock.
    pub fn address(&self) -> Address {
        self.cached_address
    }

    /// Sends a transaction request, signed by the configured signer.
    /// Transactions are serialized via a Mutex to prevent nonce conflicts.
    pub async fn send_transaction_request(
        &self,
        l1_rpc: Url,
        transaction_request: TransactionRequest,
    ) -> Result<TransactionReceipt> {
        let signer = self.inner.lock().await;
        signer.send_transaction_request(l1_rpc, transaction_request).await
    }
}

#[cfg(test)]
mod tests {
    use alloy_eips::BlockId;
    use alloy_primitives::{address, U256};
    use op_succinct_host_utils::OPSuccinctL2OutputOracle::OPSuccinctL2OutputOracleInstance as OPSuccinctL2OOContract;

    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_send_transaction_request_web3() {
        let proposer_signer = SignerLock::new(Signer::new_web3_signer(
            "http://localhost:9000".parse().unwrap(),
            "0x9b3F173823E944d183D532ed236Ee3B83Ef15E1d".parse().unwrap(),
        ));

        let provider = ProviderBuilder::new()
            .network::<Ethereum>()
            .connect_http("http://localhost:8545".parse().unwrap());

        let l2oo_contract = OPSuccinctL2OOContract::new(
            address!("0xDafA1019F21AB8B27b319B1085f93673F02A69B7"),
            provider.clone(),
        );

        let latest_header = provider.get_block(BlockId::latest()).await.unwrap().unwrap();

        let transaction_request = l2oo_contract
            .checkpointBlockHash(U256::from(latest_header.header.number))
            .into_transaction_request();

        let receipt = proposer_signer
            .send_transaction_request("http://localhost:8545".parse().unwrap(), transaction_request)
            .await
            .unwrap();

        println!("Signed transaction receipt: {receipt:?}");
    }

    #[tokio::test]
    #[ignore]
    // This test is meant to be ran locally to test various signers implementations,
    // depending of the envvars set.
    async fn test_send_transaction_request() {
        dotenv::dotenv().ok();

        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install default crypto provider");
        let signer = SignerLock::from_env().await.unwrap();

        println!("Signer: {}", signer.address());

        let transaction_request = TransactionRequest::default()
            .to(Address::from([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
            ]))
            .value(U256::from(100000u64))
            .from(signer.address());
        let receipt = signer
            .send_transaction_request("http://localhost:8545".parse().unwrap(), transaction_request)
            .await
            .unwrap();
        println!("Signed transaction receipt: {receipt:?}");
    }
}
