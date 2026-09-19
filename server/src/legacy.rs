use crate::{auth, error::{ApiError, ApiResult}, AppState};
use axum::{extract::State, http::{HeaderMap, StatusCode}};

pub async fn opaque_public() -> ApiResult<StatusCode> {
    Err(ApiError::Public(StatusCode::NOT_IMPLEMENTED, "opaque_rust_provider_required"))
}

pub async fn opaque_any(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let _ = auth::authenticate(&state, &headers, false).await?;
    Err(ApiError::Public(StatusCode::NOT_IMPLEMENTED, "opaque_rust_provider_required"))
}

pub async fn opaque_ready(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let _ = auth::authenticate(&state, &headers, true).await?;
    Err(ApiError::Public(StatusCode::NOT_IMPLEMENTED, "opaque_rust_provider_required"))
}

pub async fn migration(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let _ = auth::authenticate(&state, &headers, true).await?;
    Err(ApiError::Public(StatusCode::CONFLICT, "legacy_crypto_migration_not_required_on_2_0_1"))
}
