#[cfg(all(feature = "vsock", not(target_os = "linux")))]
compile_error!("xlayer-tee-host: vsock feature requires target_os = linux");

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use rkyv::util::AlignedVec;
use tokio::sync::Mutex;
use tracing;

#[cfg(not(feature = "vsock"))]
use tokio::net::TcpStream;

use xlayer_tee_types::{
    task::{ArchivedDeleteTaskResponse, ArchivedTaskStateView},
    wire, DeleteTaskResponse, ErrorKind, ErrorResponse, TaskStateView,
};

use crate::{config::HostConfig, error::HostError};

type SendRequest = hyper::client::conn::http1::SendRequest<Full<Bytes>>;

pub struct EnclaveClient {
    sender: Mutex<Option<SendRequest>>,
    config: Arc<HostConfig>,
}

impl EnclaveClient {
    pub fn new(config: Arc<HostConfig>) -> Self {
        Self { sender: Mutex::new(None), config }
    }

    async fn connect(&self) -> Result<SendRequest, HostError> {
        #[cfg(not(feature = "vsock"))]
        let stream = {
            let addr = &self.config.enclave.tcp_addr;
            TcpStream::connect(addr)
                .await
                .map_err(|e| HostError::EnclaveUnreachable(format!("TCP connect {addr}: {e}")))?
        };

        #[cfg(feature = "vsock")]
        let stream = {
            let cid = self.config.enclave.vsock_cid;
            let port = self.config.enclave.vsock_port;
            let vsock_addr = tokio_vsock::VsockAddr::new(cid, port);
            tokio_vsock::VsockStream::connect(vsock_addr).await.map_err(|e| {
                HostError::EnclaveUnreachable(format!("vsock connect cid={cid} port={port}: {e}"))
            })?
        };

        let io = TokioIo::new(stream);
        let (sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| HostError::EnclaveUnreachable(format!("handshake: {e}")))?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::warn!(error = %e, "enclave connection closed");
            }
        });

        Ok(sender)
    }

    async fn execute_request(
        &self,
        method: &str,
        uri: &str,
        headers: Vec<(&str, &str)>,
        body: Bytes,
    ) -> Result<(u16, Vec<u8>), HostError> {
        let timeout = Duration::from_secs(self.config.enclave.request_timeout_secs);
        let max_attempts = 3u32;
        let mut last_err = HostError::Internal("no attempts made".to_string());

        for attempt in 0..max_attempts {
            if attempt > 0 {
                let backoff = Duration::from_secs(1 << (attempt - 1));
                tracing::warn!(
                    attempt,
                    backoff_ms = backoff.as_millis(),
                    "retrying enclave request"
                );
                tokio::time::sleep(backoff).await;
            }

            let mut guard = self.sender.lock().await;

            let need_reconnect = match &*guard {
                None => true,
                Some(s) => s.is_closed(),
            };

            if need_reconnect {
                match self.connect().await {
                    Ok(s) => {
                        *guard = Some(s);
                    }
                    Err(e) => {
                        *guard = None;
                        last_err = e;
                        drop(guard);
                        continue;
                    }
                }
            }

            let sender = guard.as_mut().unwrap();

            let mut builder = Request::builder().method(method).uri(uri);
            for (k, v) in &headers {
                builder = builder.header(*k, *v);
            }
            let req = builder
                .body(Full::new(body.clone()))
                .map_err(|e| HostError::Internal(format!("build request: {e}")))?;

            let result = tokio::time::timeout(timeout, sender.send_request(req)).await;
            drop(guard);

            match result {
                Ok(Ok(resp)) => {
                    let status = resp.status().as_u16();
                    let body_bytes = resp
                        .into_body()
                        .collect()
                        .await
                        .map_err(|e| HostError::Internal(format!("read body: {e}")))?
                        .to_bytes()
                        .to_vec();
                    return Ok((status, body_bytes));
                }
                Ok(Err(e)) => {
                    tracing::warn!(attempt, error = %e, "enclave request failed");
                    last_err = HostError::EnclaveUnreachable(format!("request error: {e}"));
                    let mut guard = self.sender.lock().await;
                    *guard = None;
                }
                Err(_) => {
                    tracing::warn!(
                        attempt,
                        timeout_secs = timeout.as_secs(),
                        "enclave request timed out"
                    );
                    last_err = HostError::EnclaveUnreachable(format!(
                        "request timed out after {timeout:?}"
                    ));
                    let mut guard = self.sender.lock().await;
                    *guard = None;
                }
            }
        }

        Err(last_err)
    }

    pub async fn post_range_task(
        &self,
        task_id: &str,
        witness_body: &[u8],
    ) -> Result<(), HostError> {
        let (status, body) = self
            .execute_request(
                "POST",
                wire::TASKS_RANGE,
                vec![(wire::HEADER_TASK_ID, task_id), ("content-type", wire::OCTET_STREAM)],
                Bytes::copy_from_slice(witness_body),
            )
            .await?;

        if status == 200 {
            return Ok(());
        }

        let body_str = String::from_utf8_lossy(&body);
        parse_error_response(status, &body_str)
    }

    pub async fn get_task(&self, task_id: &str) -> Result<TaskStateView, HostError> {
        let uri = wire::task_path(task_id);
        let (status, body) = self.execute_request("GET", &uri, vec![], Bytes::new()).await?;

        if status == 200 {
            return decode_task_state_view(&body);
        }

        let body_str = String::from_utf8_lossy(&body);
        Err(parse_enclave_error(status, &body_str))
    }

    pub async fn delete_task(&self, task_id: &str) -> Result<DeleteTaskResponse, HostError> {
        let uri = wire::task_path(task_id);
        let (status, body) = self.execute_request("DELETE", &uri, vec![], Bytes::new()).await?;

        if status == 200 {
            return decode_delete_task_response(&body);
        }

        let body_str = String::from_utf8_lossy(&body);
        Err(parse_enclave_error(status, &body_str))
    }

    pub async fn get_attestation(&self) -> Result<Vec<u8>, HostError> {
        let (status, body) =
            self.execute_request("GET", wire::ATTESTATION, vec![], Bytes::new()).await?;

        if status == 200 {
            return Ok(body);
        }

        let body_str = String::from_utf8_lossy(&body);
        Err(parse_enclave_error(status, &body_str))
    }
}

fn decode_task_state_view(raw: &[u8]) -> Result<TaskStateView, HostError> {
    let mut aligned = AlignedVec::<8>::new();
    aligned.extend_from_slice(raw);
    let archived = rkyv::access::<ArchivedTaskStateView, rkyv::rancor::Error>(&aligned)
        .map_err(|e| HostError::Internal(format!("rkyv access: {e}")))?;
    rkyv::deserialize::<TaskStateView, rkyv::rancor::Error>(archived)
        .map_err(|e| HostError::Internal(format!("rkyv deserialize: {e}")))
}

fn decode_delete_task_response(raw: &[u8]) -> Result<DeleteTaskResponse, HostError> {
    let mut aligned = AlignedVec::<8>::new();
    aligned.extend_from_slice(raw);
    let archived = rkyv::access::<ArchivedDeleteTaskResponse, rkyv::rancor::Error>(&aligned)
        .map_err(|e| HostError::Internal(format!("rkyv access: {e}")))?;
    rkyv::deserialize::<DeleteTaskResponse, rkyv::rancor::Error>(archived)
        .map_err(|e| HostError::Internal(format!("rkyv deserialize: {e}")))
}

fn parse_error_response(status: u16, body: &str) -> Result<(), HostError> {
    Err(parse_enclave_error(status, body))
}

fn parse_enclave_error(status: u16, body: &str) -> HostError {
    match serde_json::from_str::<ErrorResponse>(body) {
        Ok(err_resp) => {
            HostError::EnclaveError { kind: err_resp.error_kind, message: err_resp.message }
        }
        Err(_) => {
            if status == 429 {
                HostError::EnclaveError {
                    kind: ErrorKind::TooManyTasks,
                    message: format!("enclave returned 429: {body}"),
                }
            } else {
                HostError::Internal(format!("enclave returned {status}: {body}"))
            }
        }
    }
}
