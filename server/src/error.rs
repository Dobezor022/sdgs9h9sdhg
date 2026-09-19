use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("{1}")]
    Public(StatusCode, &'static str),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}
impl ApiError {
    pub fn bad(code: &'static str) -> Self { Self::Public(StatusCode::BAD_REQUEST, code) }
    pub fn unauthorized(code: &'static str) -> Self { Self::Public(StatusCode::UNAUTHORIZED, code) }
    pub fn forbidden(code: &'static str) -> Self { Self::Public(StatusCode::FORBIDDEN, code) }
    pub fn not_found(code: &'static str) -> Self { Self::Public(StatusCode::NOT_FOUND, code) }
    pub fn conflict(code: &'static str) -> Self { Self::Public(StatusCode::CONFLICT, code) }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::Public(status, code) => (status, Json(json!({"error":{"code":code}}))).into_response(),
            ApiError::Internal(error) => {
                eprintln!("fedmes internal error: {error:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error":{"code":"internal_error"}}))).into_response()
            }
        }
    }
}
pub type ApiResult<T> = Result<T, ApiError>;
