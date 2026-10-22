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

pub mod kms;
pub mod xlayer_remote_client;
#[cfg(feature = "xlayer-verify")]
pub mod xlayer_verify_server;
pub use xlayer_remote_client::{XLayerConfig, XLayerRemoteClient};

pub const NUM_CONFIRMATIONS: u64 = 3;
pub const TIMEOUT_SECONDS: u64 = 60;

/// Resolve the XLayer remote signer secret key from either KMS (when
/// `ENABLE_KMS=true`) or the `XLAYER_SECRET_KEY` env var.
fn resolve_xlayer_secret_key() -> Result<String> {
    if kms::is_kms_enabled() {
        let key_name = std::env::var("KMS_SECRET_KEY_NAME")
            .context("KMS_SECRET_KEY_NAME is required when ENABLE_KMS=true")?;
        tracing::info!(kms_key = %key_name, "Fetching XLayer secret_key from KMS");
        kms::fetch_secret(&key_name).context("failed to fetch XLAYER secret_key from KMS")
    } else {
        std::env::var("XLAYER_SECRET_KEY")
            .context("XLAYER_SECRET_KEY is required when XLAYER_SIGNER_ENABLED=true")
    }
}

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

    /// Resolves the refOrderId lookup endpoint address of this signer.
    ///
    /// Returns `Ok(None)` when this is not an XLayer signer, and when it is an
    /// XLayer signer with no lookup address configured. Returns
    /// `Ok(Some((addr, client)))` when the configured address parses. Returns
    /// `Err` when an address IS configured but cannot be parsed: the caller
    /// must stop startup rather than run without the lookup endpoint that the
    /// asset-management callback depends on.
    pub fn xlayer_verify_target(
        &self,
    ) -> Result<Option<(std::net::SocketAddr, Arc<XLayerRemoteClient>)>> {
        match self {
            Signer::XLayerRemoteSigner(client, _) => {
                let addr = client.verify_addr();
                if addr.is_empty() {
                    return Ok(None);
                }
                match addr.parse::<std::net::SocketAddr>() {
                    Ok(sock) => Ok(Some((sock, client.clone()))),
                    Err(e) => {
                        Err(anyhow::anyhow!("invalid XLAYER_SIGNER_VERIFY_ADDR '{addr}': {e}"))
                    }
                }
            }
            _ => Ok(None),
        }
    }

    pub async fn from_env() -> Result<Self> {
        // Check for XLayer remote signer first (highest priority for production)
        if let Ok(enabled) = std::env::var("XLAYER_SIGNER_ENABLED") {
            if enabled.to_lowercase() == "true" {
                // The refOrderId prefix is mandatory for the remote signer: the
                // verify endpoint and the asset-management side both key on it,
                // so a missing or malformed value must stop the process rather
                // than produce orders nobody can look up.
                let ref_order_prefix = std::env::var("XLAYER_SIGNER_REF_ORDER_PREFIX").context(
                    "XLAYER_SIGNER_REF_ORDER_PREFIX is required when XLAYER_SIGNER_ENABLED=true",
                )?;
                xlayer_remote_client::validate_ref_order_prefix(&ref_order_prefix)?;
                let verify_addr = std::env::var("XLAYER_SIGNER_VERIFY_ADDR").unwrap_or_default();

                let config = XLayerConfig {
                    endpoint: std::env::var("XLAYER_SIGNER_ENDPOINT").context(
                        "XLAYER_SIGNER_ENDPOINT is required when XLAYER_SIGNER_ENABLED=true",
                    )?,
                    address: Address::from_str(&std::env::var("XLAYER_SIGNER_ADDRESS").context(
                        "XLAYER_SIGNER_ADDRESS is required when XLAYER_SIGNER_ENABLED=true",
                    )?)
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
                    request_sign_uri: std::env::var("XLAYER_REQUEST_SIGN_URI").unwrap_or_else(
                        |_| "/priapi/v1/assetonchain/ecology/ecologyOperate".to_string(),
                    ),
                    query_sign_uri: std::env::var("XLAYER_QUERY_SIGN_URI").unwrap_or_else(|_| {
                        "/priapi/v1/assetonchain/ecology/querySignDataByOrderNo".to_string()
                    }),
                    access_key: std::env::var("XLAYER_ACCESS_KEY")
                        .context("XLAYER_ACCESS_KEY is required when XLAYER_SIGNER_ENABLED=true")?,
                    secret_key: resolve_xlayer_secret_key()?,
                    timeout: Duration::from_secs(
                        std::env::var("XLAYER_TIMEOUT")
                            .unwrap_or_else(|_| "30".to_string())
                            .parse()
                            .context("Failed to parse XLAYER_TIMEOUT")?,
                    ),
                    ref_order_prefix,
                    verify_addr,
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

    /// Sends a transaction request, signed by the configured `signer`, using the default
    /// confirmation timeout of [`TIMEOUT_SECONDS`].
    pub async fn send_transaction_request(
        &self,
        l1_rpc: Url,
        transaction_request: TransactionRequest,
    ) -> Result<TransactionReceipt> {
        self.send_transaction_request_with_timeout(l1_rpc, transaction_request, TIMEOUT_SECONDS)
            .await
    }

    /// Sends a transaction request, signed by the configured `signer`, with a caller-supplied
    /// confirmation timeout (in seconds).
    pub async fn send_transaction_request_with_timeout(
        &self,
        l1_rpc: Url,
        mut transaction_request: TransactionRequest,
        timeout_secs: u64,
    ) -> Result<TransactionReceipt> {
        match self {
            Signer::XLayerRemoteSigner(client, signer_address) => {
                // Set the from address to the signer address.
                transaction_request.set_from(*signer_address);

                // Fill the transaction request with all of the relevant gas and nonce information.
                let provider =
                    ProviderBuilder::new().network::<Ethereum>().connect_http(l1_rpc.clone());
                let filled_tx = provider.fill(transaction_request).await?;

                tracing::info!("Signing transaction with XLayer remote signer");
                let signed_tx_bytes = client
                    .sign_transaction(filled_tx.as_builder().unwrap())
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
                    .with_timeout(Some(Duration::from_secs(timeout_secs)))
                    .get_receipt()
                    .await?;

                tracing::info!(
                    "XLayer-signed transaction confirmed: tx_hash={:?}",
                    receipt.transaction_hash
                );
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
                    .with_timeout(Some(Duration::from_secs(timeout_secs)))
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
                    .with_timeout(Some(Duration::from_secs(timeout_secs)))
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
                    .with_timeout(Some(Duration::from_secs(timeout_secs)))
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

    /// Sends a transaction request, signed by the configured signer, using the default
    /// confirmation timeout of [`TIMEOUT_SECONDS`]. Transactions are serialized via a Mutex
    /// to prevent nonce conflicts.
    pub async fn send_transaction_request(
        &self,
        l1_rpc: Url,
        transaction_request: TransactionRequest,
    ) -> Result<TransactionReceipt> {
        let signer = self.inner.lock().await;
        signer.send_transaction_request(l1_rpc, transaction_request).await
    }

    /// Sends a transaction request with a caller-supplied confirmation timeout (in seconds).
    /// Transactions are serialized via a Mutex to prevent nonce conflicts.
    pub async fn send_transaction_request_with_timeout(
        &self,
        l1_rpc: Url,
        transaction_request: TransactionRequest,
        timeout_secs: u64,
    ) -> Result<TransactionReceipt> {
        let signer = self.inner.lock().await;
        signer
            .send_transaction_request_with_timeout(l1_rpc, transaction_request, timeout_secs)
            .await
    }

    /// Pre-binds the refOrderId lookup listener (when one is configured) and
    /// spawns a task that serves it.
    ///
    /// Returns `Err` when the configured address cannot be parsed or cannot be
    /// bound — the caller must stop startup rather than run without an
    /// endpoint the asset-management callback depends on. A successful no-op
    /// for signers that do not serve a lookup endpoint, and for an XLayer
    /// signer whose lookup address is unset.
    #[cfg(feature = "xlayer-verify")]
    pub async fn maybe_spawn_xlayer_verify_server(&self) -> Result<()> {
        let target = {
            let signer = self.inner.lock().await;
            signer.xlayer_verify_target()?
        };
        if let Some((addr, client)) = target {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tokio::spawn(async move {
                if let Err(e) =
                    crate::xlayer_verify_server::serve_from_listener(listener, client).await
                {
                    tracing::warn!("refOrderId lookup endpoint exited: {e}.");
                }
            });
        }
        Ok(())
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

    /// A signer that is not an XLayer remote signer must not expose a lookup
    /// target, and asking it to start the endpoint must be a successful no-op
    /// so a non-XLayer deployment is never blocked at startup.
    #[cfg(feature = "xlayer-verify")]
    #[tokio::test]
    async fn test_maybe_spawn_xlayer_verify_server_non_xlayer_is_noop() {
        let signers = [
            Signer::LocalSigner(PrivateKeySigner::random()),
            Signer::new_web3_signer(
                "http://localhost:9000".parse().unwrap(),
                Address::from([0x11u8; 20]),
            ),
        ];

        for signer in signers {
            let lock = SignerLock::new(signer);
            assert!(lock.inner.lock().await.xlayer_verify_target().unwrap().is_none());
            lock.maybe_spawn_xlayer_verify_server().await.unwrap();
            assert!(lock.inner.lock().await.xlayer_verify_target().unwrap().is_none());
        }
    }

    /// A disabled lookup endpoint (empty address) is a successful no-op: no
    /// listener, no error, so both services keep working without one.
    #[cfg(feature = "xlayer-verify")]
    #[tokio::test]
    async fn test_maybe_spawn_xlayer_verify_server_disabled_addr_is_noop() {
        let mut config = XLayerConfig::default();
        config.verify_addr = String::new();
        let lock = SignerLock::new(Signer::new_xlayer_remote_signer(config));

        lock.maybe_spawn_xlayer_verify_server().await.unwrap();
    }

    /// A configured address that cannot be parsed must stop startup: the
    /// caller propagates the error instead of running without the lookup
    /// endpoint the asset-management callback depends on.
    #[cfg(feature = "xlayer-verify")]
    #[tokio::test]
    async fn test_maybe_spawn_invalid_addr_is_fatal() {
        let mut config = XLayerConfig::default();
        config.verify_addr = "definitely-not-a-socket-addr".to_string();
        let lock = SignerLock::new(Signer::new_xlayer_remote_signer(config));

        let err = lock
            .maybe_spawn_xlayer_verify_server()
            .await
            .expect_err("unparseable address must stop startup");
        assert!(err.to_string().contains("invalid XLAYER_SIGNER_VERIFY_ADDR"), "got: {err}");
    }

    /// A lookup address that is already in use must stop startup rather than
    /// leave the service running with a silently unreachable callback endpoint.
    #[cfg(feature = "xlayer-verify")]
    #[tokio::test]
    async fn test_maybe_spawn_bind_failure_port_occupied() {
        let occupant = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = occupant.local_addr().unwrap().port();

        let mut config = XLayerConfig::default();
        config.verify_addr = format!("127.0.0.1:{port}");
        let lock = SignerLock::new(Signer::new_xlayer_remote_signer(config));

        let result = lock.maybe_spawn_xlayer_verify_server().await;
        assert!(result.is_err(), "binding to an occupied port must fail");

        // Keep the occupant alive until the assertion above has run, so the
        // port really is occupied for the whole bind attempt.
        drop(occupant);
    }

    /// The lookup endpoint is only exposed for a parseable, non-empty address;
    /// an address that cannot be parsed is reported as an error instead of a
    /// silently disabled endpoint.
    #[test]
    fn test_xlayer_verify_target_respects_configured_address() {
        let mut config = XLayerConfig::default();
        // An unset address means "endpoint not configured", not a failure.
        assert!(Signer::new_xlayer_remote_signer(config.clone())
            .xlayer_verify_target()
            .expect("unset address must not be an error")
            .is_none());

        // An address that is set but cannot be parsed is an error.
        config.verify_addr = "definitely-not-a-socket-addr".to_string();
        let result = Signer::new_xlayer_remote_signer(config.clone()).xlayer_verify_target();
        assert!(result.is_err(), "unparseable address must be reported as an error");

        config.verify_addr = "127.0.0.1:9191".to_string();
        let target = Signer::new_xlayer_remote_signer(config).xlayer_verify_target();
        let (addr, _client) = target.expect("parseable address must yield a target").unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:9191");
    }

    /// A configured but unparseable lookup address must surface as an error
    /// carrying the variable name, so startup can stop with an actionable
    /// message rather than running without the lookup endpoint.
    #[test]
    fn test_xlayer_verify_target_invalid_address_returns_err() {
        let mut config = XLayerConfig::default();
        config.verify_addr = "definitely-not-a-socket-addr".to_string();
        let signer = Signer::new_xlayer_remote_signer(config);
        let result = signer.xlayer_verify_target();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid XLAYER_SIGNER_VERIFY_ADDR"));
    }

    /// An empty address means "endpoint disabled" and must stay a successful
    /// no-op, so a deployment that does not want the lookup endpoint is not
    /// forced to configure one.
    #[test]
    fn test_xlayer_verify_target_empty_addr_returns_ok_none() {
        let mut config = XLayerConfig::default();
        config.verify_addr = "".to_string();
        let signer = Signer::new_xlayer_remote_signer(config);
        assert!(signer
            .xlayer_verify_target()
            .expect("empty address must not be an error")
            .is_none());
    }

    /// The pre-bound listener really serves the documented lookup contract on
    /// a live socket, answering over HTTP for the same client instance that
    /// would otherwise sign — so a callback can be answered before any signing
    /// request has been made.
    #[cfg(feature = "xlayer-verify")]
    #[tokio::test]
    async fn test_maybe_spawn_bound_listener_answers_lookup_over_http() {
        let port = reserve_loopback_port().await;
        let mut config = XLayerConfig::default();
        config.verify_addr = format!("127.0.0.1:{port}");
        let client = Arc::new(XLayerRemoteClient::new(config));
        let id = "CHALLENGER_TZ_99_9999_ffffffff";
        client.seed_ref_order_id(id).await;

        let lock = SignerLock::new(Signer::XLayerRemoteSigner(
            Arc::clone(&client),
            Address::from([0x22u8; 20]),
        ));
        lock.maybe_spawn_xlayer_verify_server().await.unwrap();

        let (status, code, msg) = lookup("127.0.0.1", port, id).await;
        assert_eq!(status, 200);
        assert_eq!(code, 0);
        assert_eq!(msg, "success");

        let (status, code, msg) = lookup("127.0.0.1", port, "CHALLENGER_TZ_00_0000_00000000").await;
        assert_eq!(status, 200);
        assert_eq!(code, 1);
        assert_eq!(msg, "not found");
    }

    /// Reserves a loopback port by binding and immediately releasing it, so a
    /// test can configure a known address for the pre-binding startup path.
    #[cfg(feature = "xlayer-verify")]
    async fn reserve_loopback_port() -> u16 {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        port
    }

    /// Performs one lookup call against a running endpoint and returns the
    /// documented `(status, code, msg)` triple from the response envelope.
    /// Retries until the serving task has accepted its first connection,
    /// bounded by a deadline — a readiness signal rather than a fixed sleep.
    #[cfg(feature = "xlayer-verify")]
    async fn lookup(host: &str, port: u16, id: &str) -> (u16, i64, String) {
        let url = format!("http://{host}:{port}/signer/get?refOrderId={id}");
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match reqwest::get(&url).await {
                Ok(response) => {
                    let body = response.text().await.unwrap();
                    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
                    return (
                        parsed["status"].as_u64().unwrap() as u16,
                        parsed["code"].as_i64().unwrap(),
                        parsed["msg"].as_str().unwrap().to_string(),
                    );
                }
                Err(error) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "the lookup endpoint never became reachable: {error}"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
    }
}
