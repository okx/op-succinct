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
        Self { code: 0, message: "ok".into(), data: Some(data) }
    }

    pub fn from_error(err: &HostError) -> Self {
        Self { code: err.code(), message: err.to_string(), data: None }
    }
}

impl<T: Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> Response {
        let body = serde_json::to_string(&self).expect("ApiResponse serialization");
        (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "application/json")], body)
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Serialize)]
    struct TestData {
        task_id: String,
    }

    #[test]
    fn ok_response_serializes_correctly() {
        let resp = ApiResponse::ok(TestData { task_id: "abc".into() });
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"code\":0"));
        assert!(json.contains("\"message\":\"ok\""));
        assert!(json.contains("\"task_id\":\"abc\""));
    }

    #[test]
    fn error_response_has_null_data() {
        let resp = ApiResponse::<()>::from_error(&HostError::EmptyBody);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"code\":10001"));
        assert!(json.contains("\"message\":\"empty witness body\""));
        assert!(!json.contains("\"data\""));
    }

    #[test]
    fn task_not_found_includes_id_in_message() {
        let resp = ApiResponse::<()>::from_error(&HostError::TaskNotFound("test-123".into()));
        assert_eq!(resp.code, 10004);
        assert!(resp.message.contains("test-123"));
    }
}
