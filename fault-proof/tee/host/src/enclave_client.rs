#[cfg(all(feature = "vsock", not(target_os = "linux")))]
compile_error!("xlayer-tee-host: vsock feature requires target_os = linux");

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
#[cfg(not(all(target_os = "linux", feature = "vsock")))]
use tokio::net::TcpStream;

use crate::{config::EnclaveConfig, error::HostError};
use xlayer_tee_types::{
    wire, CreateTaskResponse, DeleteTaskResponse, ErrorKind, ErrorResponse, TaskStateView,
};

const MAX_RETRIES: usize = 3;
const BACKOFF: [u64; 2] = [1, 2];

pub struct EnclaveClient {
    config: EnclaveConfig,
    sender: tokio::sync::Mutex<Option<SendRequest<Full<Bytes>>>>,
}

impl EnclaveClient {
    pub fn new(config: EnclaveConfig) -> Self {
        Self { config, sender: tokio::sync::Mutex::new(None) }
    }

    async fn connect(config: &EnclaveConfig) -> Result<SendRequest<Full<Bytes>>, HostError> {
        #[cfg(all(target_os = "linux", feature = "vsock"))]
        {
            let addr = tokio_vsock::VsockAddr::new(config.vsock_cid, config.vsock_port);
            let stream = tokio_vsock::VsockStream::connect(addr)
                .await
                .map_err(|e| HostError::EnclaveUnreachable(format!("vsock connect: {e}")))?;
            let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .map_err(|e| HostError::EnclaveUnreachable(format!("handshake: {e}")))?;
            tokio::spawn(conn);
            Ok(sender)
        }
        #[cfg(not(all(target_os = "linux", feature = "vsock")))]
        {
            let stream = TcpStream::connect(&config.tcp_addr)
                .await
                .map_err(|e| HostError::EnclaveUnreachable(format!("tcp connect: {e}")))?;
            let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .map_err(|e| HostError::EnclaveUnreachable(format!("handshake: {e}")))?;
            tokio::spawn(conn);
            Ok(sender)
        }
    }

    async fn ensure_sender(&self) -> Result<(), HostError> {
        let mut guard = self.sender.lock().await;
        if guard.as_ref().is_none_or(|s| s.is_closed()) {
            let sender = Self::connect(&self.config).await?;
            *guard = Some(sender);
        }
        Ok(())
    }

    async fn send_request(
        &self,
        request: hyper::Request<Full<Bytes>>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, HostError> {
        let mut guard = self.sender.lock().await;
        let sender =
            guard.as_mut().ok_or_else(|| HostError::EnclaveUnreachable("no connection".into()))?;
        sender
            .send_request(request)
            .await
            .map_err(|e| HostError::EnclaveUnreachable(format!("send: {e}")))
    }

    async fn call_with_retry(
        &self,
        build_request: impl Fn() -> hyper::Request<Full<Bytes>>,
    ) -> Result<(hyper::StatusCode, Bytes), HostError> {
        let timeout = Duration::from_secs(self.config.request_timeout_secs);
        let mut last_error = HostError::EnclaveUnreachable("no attempt made".into());

        for attempt in 0..MAX_RETRIES {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_secs(BACKOFF[attempt - 1])).await;
                *self.sender.lock().await = None;
            }
            if let Err(e) = self.ensure_sender().await {
                last_error = e;
                continue;
            }
            let req = build_request();
            match tokio::time::timeout(timeout, self.send_request(req)).await {
                Ok(Ok(resp)) => {
                    let status = resp.status();
                    let body = http_body_util::BodyExt::collect(resp.into_body())
                        .await
                        .map_err(|e| HostError::EnclaveUnreachable(format!("read body: {e}")))?
                        .to_bytes();
                    return Ok((status, body));
                }
                Ok(Err(e)) => last_error = e,
                Err(_) => last_error = HostError::EnclaveUnreachable("request timed out".into()),
            }
        }
        Err(last_error)
    }

    fn decode_create_task_response(bytes: &[u8]) -> Result<CreateTaskResponse, HostError> {
        let mut aligned = rkyv::util::AlignedVec::<8>::new();
        aligned.extend_from_slice(bytes);
        let archived = rkyv::access::<
            <CreateTaskResponse as rkyv::Archive>::Archived,
            rkyv::rancor::Error,
        >(&aligned)
        .map_err(|e| HostError::Internal(format!("rkyv access: {e}")))?;
        rkyv::deserialize::<CreateTaskResponse, rkyv::rancor::Error>(archived)
            .map_err(|e| HostError::Internal(format!("rkyv deserialize: {e}")))
    }

    fn decode_task_state_view(bytes: &[u8]) -> Result<TaskStateView, HostError> {
        let mut aligned = rkyv::util::AlignedVec::<8>::new();
        aligned.extend_from_slice(bytes);
        let archived = rkyv::access::<
            <TaskStateView as rkyv::Archive>::Archived,
            rkyv::rancor::Error,
        >(&aligned)
        .map_err(|e| HostError::Internal(format!("rkyv access: {e}")))?;
        rkyv::deserialize::<TaskStateView, rkyv::rancor::Error>(archived)
            .map_err(|e| HostError::Internal(format!("rkyv deserialize: {e}")))
    }

    fn decode_delete_task_response(bytes: &[u8]) -> Result<DeleteTaskResponse, HostError> {
        let mut aligned = rkyv::util::AlignedVec::<8>::new();
        aligned.extend_from_slice(bytes);
        let archived = rkyv::access::<
            <DeleteTaskResponse as rkyv::Archive>::Archived,
            rkyv::rancor::Error,
        >(&aligned)
        .map_err(|e| HostError::Internal(format!("rkyv access: {e}")))?;
        rkyv::deserialize::<DeleteTaskResponse, rkyv::rancor::Error>(archived)
            .map_err(|e| HostError::Internal(format!("rkyv deserialize: {e}")))
    }

    fn parse_error_response(body: &[u8]) -> Option<ErrorResponse> {
        serde_json::from_slice(body).ok()
    }

    fn map_status_to_error(status: hyper::StatusCode, body: &Bytes) -> HostError {
        if let Some(err_resp) = Self::parse_error_response(body) {
            return HostError::EnclaveError { kind: err_resp.error_kind, message: err_resp.message };
        }
        match status.as_u16() {
            429 => HostError::EnclaveError {
                kind: ErrorKind::TooManyTasks,
                message: "enclave at capacity".into(),
            },
            404 => HostError::EnclaveError {
                kind: ErrorKind::TaskUnknown,
                message: "task not found in enclave".into(),
            },
            _ => HostError::EnclaveError {
                kind: ErrorKind::InternalEnclave,
                message: format!("HTTP {status}"),
            },
        }
    }

    pub async fn post_range(
        &self,
        task_id: &str,
        body: Arc<Bytes>,
    ) -> Result<CreateTaskResponse, HostError> {
        let task_id_owned = task_id.to_string();
        let body_clone = body.clone();
        let (status, resp_body) = self
            .call_with_retry(|| {
                hyper::Request::builder()
                    .method(hyper::Method::POST)
                    .uri(wire::TASKS_RANGE)
                    .header(wire::HEADER_TASK_ID, &task_id_owned)
                    .header("content-type", wire::OCTET_STREAM)
                    .body(Full::new(Bytes::copy_from_slice(&body_clone)))
                    .expect("build request")
            })
            .await?;
        if !status.is_success() {
            return Err(Self::map_status_to_error(status, &resp_body));
        }
        Self::decode_create_task_response(&resp_body)
    }

    pub async fn get_task(&self, task_id: &str) -> Result<TaskStateView, HostError> {
        let path = wire::task_path(task_id);
        let (status, body) = self
            .call_with_retry(|| {
                hyper::Request::builder()
                    .method(hyper::Method::GET)
                    .uri(&path)
                    .header("accept", wire::JSON)
                    .body(Full::new(Bytes::new()))
                    .expect("build request")
            })
            .await?;
        if !status.is_success() {
            return Err(Self::map_status_to_error(status, &body));
        }
        Self::decode_task_state_view(&body)
    }

    pub async fn delete_task(&self, task_id: &str) -> Result<DeleteTaskResponse, HostError> {
        let path = wire::task_path(task_id);
        let (status, body) = self
            .call_with_retry(|| {
                hyper::Request::builder()
                    .method(hyper::Method::DELETE)
                    .uri(&path)
                    .body(Full::new(Bytes::new()))
                    .expect("build request")
            })
            .await?;
        if !status.is_success() {
            return Err(Self::map_status_to_error(status, &body));
        }
        Self::decode_delete_task_response(&body)
    }

    pub async fn get_attestation(&self) -> Result<String, HostError> {
        let (status, body) = self
            .call_with_retry(|| {
                hyper::Request::builder()
                    .method(hyper::Method::GET)
                    .uri(wire::ATTESTATION)
                    .body(Full::new(Bytes::new()))
                    .expect("build request")
            })
            .await?;
        if !status.is_success() {
            return Err(Self::map_status_to_error(status, &body));
        }
        String::from_utf8(body.to_vec())
            .map_err(|e| HostError::Internal(format!("attestation not utf8: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_status_429_returns_too_many_tasks() {
        let err = EnclaveClient::map_status_to_error(
            hyper::StatusCode::from_u16(429).unwrap(),
            &Bytes::new(),
        );
        assert!(err.is_too_many_tasks());
    }

    #[test]
    fn map_status_404_returns_task_unknown() {
        let err = EnclaveClient::map_status_to_error(hyper::StatusCode::NOT_FOUND, &Bytes::new());
        assert!(err.is_task_unknown());
    }

    #[test]
    fn parse_error_response_from_json() {
        let json =
            serde_json::to_vec(&ErrorResponse::new(ErrorKind::ClaimMismatch, "mismatch")).unwrap();
        let parsed = EnclaveClient::parse_error_response(&json).unwrap();
        assert_eq!(parsed.error_kind, ErrorKind::ClaimMismatch);
        assert_eq!(parsed.message, "mismatch");
    }

    #[test]
    fn parse_error_response_returns_none_for_invalid() {
        assert!(EnclaveClient::parse_error_response(b"not json").is_none());
    }

    #[test]
    fn map_status_with_json_error_body() {
        let json =
            serde_json::to_vec(&ErrorResponse::new(ErrorKind::InvalidWitness, "bad witness"))
                .unwrap();
        let err =
            EnclaveClient::map_status_to_error(hyper::StatusCode::BAD_REQUEST, &Bytes::from(json));
        match err {
            HostError::EnclaveError { kind, message } => {
                assert_eq!(kind, ErrorKind::InvalidWitness);
                assert_eq!(message, "bad witness");
            }
            other => panic!("expected EnclaveError, got {other:?}"),
        }
    }
}
