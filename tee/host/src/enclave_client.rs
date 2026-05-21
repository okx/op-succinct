//! HTTP client to the enclave over vsock (prod) or TCP (dev).
//!
//! Single keep-alive connection wrapped in a Mutex; reconnects once on send error.
//! Mirrors the transport pattern from `tradezone/crates/chain/src/tee/host_task_manager.rs`
//! (`connect_enclave_http` / `reconnect_enclave_cli`).

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::{self, SendRequest};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::sync::Mutex;

use rkyv::rancor::Error as RkyvError;
use xlayer_tee_types::{content_type, paths, ErrorResponse, TaskStateView};

use crate::config::EnclaveConfig;
use crate::error::{Error, Result};

pub struct EnclaveClient {
    config: EnclaveConfig,
    sender: Arc<Mutex<SendRequest<Full<Bytes>>>>,
}

impl EnclaveClient {
    pub async fn connect(config: EnclaveConfig) -> anyhow::Result<Self> {
        let sender = open_connection(&config).await?;
        Ok(Self { config, sender: Arc::new(Mutex::new(sender)) })
    }

    pub async fn post_range(
        &self,
        task_id: &str,
        chain_id: u64,
        verifying_contract: &str,
        body: Bytes,
    ) -> Result<()> {
        let task_id = task_id.to_string();
        let chain_id_hdr = chain_id.to_string();
        let verifying_contract = verifying_contract.to_string();
        let body = body.clone();
        let resp = self
            .send_with_retry(|| {
                Request::builder()
                    .method("POST")
                    .uri(paths::TASKS_RANGE)
                    .header("host", "enclave")
                    .header(paths::HEADER_TASK_ID, &task_id)
                    .header("x-eip712-chain-id", &chain_id_hdr)
                    .header("x-eip712-verifying-contract", &verifying_contract)
                    .header("content-type", content_type::OCTET_STREAM)
                    .body(Full::new(body.clone()))
            })
            .await?;
        ensure_success(resp).await
    }

    pub async fn get_task(&self, task_id: &str) -> Result<TaskStateView> {
        let path = format!("/tasks/{}", task_id);
        let resp = self
            .send_with_retry(|| {
                Request::builder()
                    .method("GET")
                    .uri(&path)
                    .header("host", "enclave")
                    .body(Full::new(Bytes::new()))
            })
            .await?;
        decode_rkyv::<TaskStateView>(resp).await
    }

    pub async fn delete_task(&self, task_id: &str) -> Result<()> {
        let path = format!("/tasks/{}", task_id);
        let resp = self
            .send_with_retry(|| {
                Request::builder()
                    .method("DELETE")
                    .uri(&path)
                    .header("host", "enclave")
                    .body(Full::new(Bytes::new()))
            })
            .await?;
        ensure_success(resp).await
    }

    /// DELETE with exponential backoff (1s, 2s) up to 3 attempts. Reconnects
    /// between attempts so a restarted enclave is recovered transparently.
    pub async fn delete_task_with_retry(&self, task_id: &str) -> Result<()> {
        const MAX_ATTEMPTS: u8 = 3;
        let mut last_err: Option<Error> = None;
        for attempt in 0u8..MAX_ATTEMPTS {
            if attempt > 0 {
                let delay = Duration::from_secs(1u64 << (attempt - 1));
                tokio::time::sleep(delay).await;
            }
            match self.delete_task(task_id).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::warn!(attempt, error = %e, task_id, "enclave DELETE failed");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| Error::Internal(
            "no DELETE attempts made".into()
        )))
    }

    pub async fn get_attestation(&self) -> Result<Bytes> {
        let resp = self
            .send_with_retry(|| {
                Request::builder()
                    .method("GET")
                    .uri("/attestation")
                    .header("host", "enclave")
                    .body(Full::new(Bytes::new()))
            })
            .await?;
        if !resp.status().is_success() {
            return Err(parse_error_body(resp).await);
        }
        collect_body(resp).await
    }

    pub async fn get_health(&self) -> Result<serde_json::Value> {
        let resp = self
            .send_with_retry(|| {
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .header("host", "enclave")
                    .body(Full::new(Bytes::new()))
            })
            .await?;
        decode_json(resp).await
    }

    async fn send_with_retry<F>(&self, build: F) -> Result<Response<hyper::body::Incoming>>
    where
        F: Fn() -> std::result::Result<Request<Full<Bytes>>, hyper::http::Error>,
    {
        let timeout = Duration::from_secs(self.config.request_timeout_secs);
        for attempt in 0u8..2 {
            let req = build().map_err(|e| Error::Internal(e.to_string()))?;
            let send = async {
                let mut sender = self.sender.lock().await;
                sender.send_request(req).await
            };
            match tokio::time::timeout(timeout, send).await {
                Ok(Ok(resp)) => return Ok(resp),
                Ok(Err(e)) if attempt == 0 => {
                    tracing::warn!(error = %e, "enclave send failed, reconnecting");
                    self.reconnect().await
                        .map_err(|re| Error::Internal(format!("reconnect: {re}")))?;
                }
                Ok(Err(e)) => return Err(Error::Internal(format!("enclave send: {e}"))),
                Err(_) => return Err(Error::Internal(format!(
                    "enclave request timed out after {}s", timeout.as_secs()
                ))),
            }
        }
        Err(Error::Internal("enclave unreachable after retry".into()))
    }

    async fn reconnect(&self) -> anyhow::Result<()> {
        let new_sender = open_connection(&self.config).await?;
        *self.sender.lock().await = new_sender;
        Ok(())
    }
}

async fn ensure_success(resp: Response<hyper::body::Incoming>) -> Result<()> {
    if resp.status().is_success() {
        return Ok(());
    }
    Err(parse_error_body(resp).await)
}

async fn decode_json<T: serde::de::DeserializeOwned>(
    resp: Response<hyper::body::Incoming>,
) -> Result<T> {
    if !resp.status().is_success() {
        return Err(parse_error_body(resp).await);
    }
    let body = collect_body(resp).await?;
    serde_json::from_slice(&body)
        .map_err(|e| Error::Internal(format!("enclave JSON decode: {e}")))
}

/// Decode an rkyv-encoded body. Copies into an 8-byte aligned buffer because
/// hyper's `Bytes` is not aligned but rkyv validation requires it.
async fn decode_rkyv<T>(resp: Response<hyper::body::Incoming>) -> Result<T>
where
    T: rkyv::Archive,
    T::Archived: for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, RkyvError>>
        + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<RkyvError>>,
{
    if !resp.status().is_success() {
        return Err(parse_error_body(resp).await);
    }
    let body = collect_body(resp).await?;
    let mut aligned = rkyv::util::AlignedVec::<8>::with_capacity(body.len());
    aligned.extend_from_slice(&body);
    rkyv::from_bytes::<T, RkyvError>(&aligned[..])
        .map_err(|e| Error::Internal(format!("enclave rkyv decode: {e}")))
}

async fn collect_body(resp: Response<hyper::body::Incoming>) -> Result<Bytes> {
    resp.into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .map_err(|e| Error::Internal(format!("read body: {e}")))
}

async fn parse_error_body(resp: Response<hyper::body::Incoming>) -> Error {
    let status = resp.status();
    let body = match collect_body(resp).await {
        Ok(b) => b,
        Err(e) => return e,
    };
    match serde_json::from_slice::<ErrorResponse>(&body) {
        Ok(er) => Error::Enclave { kind: er.error_kind, message: er.message },
        Err(_) => Error::Internal(format!(
            "enclave HTTP {} body: {}",
            status,
            String::from_utf8_lossy(&body)
        )),
    }
}

async fn open_connection(config: &EnclaveConfig) -> anyhow::Result<SendRequest<Full<Bytes>>> {
    #[cfg(all(target_os = "linux", feature = "vsock"))]
    let io = {
        use tokio_vsock::{VsockAddr, VsockStream};
        let stream = VsockStream::connect(VsockAddr::new(config.vsock_cid, config.vsock_port))
            .await
            .with_context(|| format!(
                "vsock connect cid={} port={}", config.vsock_cid, config.vsock_port
            ))?;
        tracing::info!(cid = config.vsock_cid, port = config.vsock_port, "vsock connected");
        TokioIo::new(stream)
    };

    #[cfg(not(all(target_os = "linux", feature = "vsock")))]
    let io = {
        use tokio::net::TcpStream;
        let stream = TcpStream::connect(&config.tcp_addr)
            .await
            .with_context(|| format!("tcp connect {}", config.tcp_addr))?;
        tracing::info!(addr = %config.tcp_addr, "tcp connected");
        TokioIo::new(stream)
    };

    let (sender, conn) = http1::handshake(io).await.context("http1 handshake")?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::warn!(error = %e, "enclave connection driver exited");
        }
    });
    Ok(sender)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use axum::{routing::delete, Router};
    use axum::http::StatusCode;

    /// Spawn an axum mock on an ephemeral TCP port. Returns the addr and a
    /// shared call counter the test can inspect.
    async fn spawn_flaky_delete(fail_first_n: usize) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let app = Router::new().route(
            "/tasks/{task_id}",
            delete(move || {
                let c = c.clone();
                async move {
                    let n = c.fetch_add(1, Ordering::SeqCst);
                    if n < fail_first_n {
                        StatusCode::INTERNAL_SERVER_ERROR
                    } else {
                        StatusCode::OK
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        (addr, counter)
    }

    fn cfg_for(addr: std::net::SocketAddr) -> EnclaveConfig {
        EnclaveConfig {
            vsock_cid: 0,
            vsock_port: 0,
            tcp_addr: addr.to_string(),
            request_timeout_secs: 5,
        }
    }

    #[tokio::test]
    async fn delete_with_retry_eventually_succeeds() {
        let (addr, counter) = spawn_flaky_delete(2).await;
        let client = EnclaveClient::connect(cfg_for(addr)).await.unwrap();
        client.delete_task_with_retry("test-id").await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 3, "fail x2 then success");
    }

    #[tokio::test]
    async fn delete_with_retry_returns_err_after_all_attempts() {
        // 5 failures > MAX_ATTEMPTS, so all 3 attempts fail.
        let (addr, counter) = spawn_flaky_delete(5).await;
        let client = EnclaveClient::connect(cfg_for(addr)).await.unwrap();
        let result = client.delete_task_with_retry("test-id").await;
        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 3, "exactly MAX_ATTEMPTS calls");
    }
}
