use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::error::HostError;

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self { code: 0, message: "ok".to_string(), data: Some(data) }
    }

    pub fn from_error(err: &HostError) -> Self {
        Self { code: err.code(), message: err.message(), data: None }
    }
}

impl<T: Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> Response {
        let body = serde_json::to_string(&self).unwrap_or_else(|e| {
            format!(r#"{{"code":20001,"message":"serialization error: {e}"}}"#)
        });
        (StatusCode::OK, [("content-type", "application/json")], body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_response_serializes_correctly() {
        #[derive(Serialize)]
        struct TaskId {
            #[serde(rename = "taskId")]
            task_id: String,
        }
        let resp = ApiResponse::ok(TaskId { task_id: "abc-123".into() });
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""code":0"#));
        assert!(json.contains(r#""message":"ok""#));
        assert!(json.contains(r#""taskId":"abc-123""#));
    }

    #[test]
    fn error_response_omits_data() {
        let err = HostError::EmptyBody;
        let resp = ApiResponse::<()>::from_error(&err);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""code":10001"#));
        assert!(json.contains(r#""message":"empty witness body""#));
        assert!(!json.contains(r#""data""#), "data should be omitted when None");
    }

    #[test]
    fn error_response_preserves_code_from_host_error() {
        let cases: Vec<(HostError, i32)> = vec![
            (HostError::TaskNotFound("x".into()), 10004),
            (HostError::EnclaveUnreachable("down".into()), 20001),
            (HostError::Internal("bad".into()), 20001),
        ];
        for (err, expected_code) in cases {
            let resp = ApiResponse::<()>::from_error(&err);
            assert_eq!(resp.code, expected_code);
        }
    }
}
