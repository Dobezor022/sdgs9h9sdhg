use crate::{blind, device_links, legacy, messaging, provisioning, ratchet, security, AppState};
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde_json::json;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/api/v1/provisioning/redeem", post(provisioning::redeem))
        .route("/api/v1/provisioning/bootstrap-commit", post(provisioning::bootstrap_commit))
        .route("/api/v1/auth/challenge", post(provisioning::challenge))
        .route("/api/v1/auth/session", post(provisioning::session))
        .route("/api/v1/auth/validate", get(messaging::validate))
        .route("/api/v1/devices/encryption-key", put(messaging::register_encryption_key))
        .route("/api/v1/chats", get(messaging::list_chats))
        .route("/api/v1/chats/:chat/devices", get(messaging::list_devices))
        .route("/api/v3/chats/:chat/crypto-sequence", post(messaging::reserve_sequence))
        .route("/api/v3/chats/:chat/crypto-sequence/lease", post(messaging::reserve_sequence_lease))
        .route("/api/v1/chats/:chat/messages", get(messaging::list_messages).post(messaging::create_message))
        .route("/api/v1/chats/:chat/envelope-repair", get(messaging::list_envelope_repair_messages))
        .route("/api/v1/chats/:chat/messages/:message", put(messaging::update_message).delete(messaging::delete_message))
        .route("/api/v1/chats/:chat/messages/:message/envelopes", put(messaging::add_envelopes))
        .route("/api/v1/chats/:chat/receipts", post(messaging::receipts))
        .route("/api/v1/chats/:chat/read-cursor", put(messaging::read_cursor))
        .route("/api/v1/chats/:chat/typing", put(messaging::set_typing).get(messaging::list_typing))
        .route("/api/v1/chats/:chat/pin/:message", put(messaging::pin))
        .route("/api/v1/chats/:chat/pin", delete(messaging::unpin))
        .route("/api/v1/chats/:chat/media/:media", put(messaging::upload_media).get(messaging::download_media).delete(messaging::delete_media).layer(DefaultBodyLimit::max(260 * 1024 * 1024)))
        .route("/api/v1/presence/heartbeat", post(messaging::heartbeat))
        .route("/api/v1/presence", get(messaging::presence))
        .route("/api/v1/events", get(messaging::events))
        .route("/api/v1/events/current", get(messaging::events_current))
        .route("/api/v1/device-links", post(device_links::create))
        .route("/api/v1/device-links/:id/status", post(device_links::status))
        .route("/api/v1/device-links/:id/cancel", post(device_links::cancel))
        .route("/api/v1/device-links/:id/complete", post(device_links::complete))
        .route("/api/v1/device-links/:id/preview", post(device_links::preview))
        .route("/api/v1/device-links/:id/approve", post(device_links::approve))
        .route("/api/v1/account/devices", get(device_links::list_devices))
        .route("/api/v1/account/devices/:device", delete(device_links::revoke_device))
        .route("/api/v1/account/devices/terminate-others", post(device_links::terminate_others))
        .route("/api/v1/account/device", delete(device_links::revoke_current))
        .route("/api/v2/security/state", get(security::state))
        .route("/api/v2/security/vault", get(security::get_vault).put(security::put_vault))
        .route("/api/v2/security/recovery-package", get(security::get_recovery).put(security::put_recovery))
        .route("/api/v2/security/recovery/complete", post(security::complete_recovery))
        .route("/api/v2/security/device-requests", get(security::list_device_requests))
        .route("/api/v2/security/device-requests/:id", get(security::get_device_request))
        .route("/api/v2/security/device-requests/:id/approve", post(security::approve_device))
        .route("/api/v2/security/device-requests/:id/reject", post(security::reject_device))
        .route("/api/v2/security/device-requests/:id/package", get(security::package))
        .route("/api/v2/security/device-requests/:id/complete", post(security::complete_device))
        .route("/api/v2/security/devices/:id", delete(security::revoke_device))
        .route("/api/v2/security/migrations", get(security::migrations))
        .route("/api/v3/crypto/ratchet/bundle", put(ratchet::put_bundle))
        .route("/api/v3/crypto/ratchet/claim", post(ratchet::claim))
        .route("/api/v3/crypto/ratchet/envelopes", post(ratchet::put_envelopes).get(ratchet::list_envelopes))
        .route("/api/v3/crypto/megolm/reserve", post(ratchet::reserve_group))
        .route("/api/v3/crypto/megolm/sessions", post(ratchet::put_group))
        .route("/api/v3/crypto/megolm/packages", get(ratchet::list_packages))
        .route("/api/v3/crypto/megolm/packages/consume", post(ratchet::consume_package))
        .route("/api/v4/object/route", put(blind::register_route))
        .route("/api/v4/object", post(blind::put_object).get(blind::pull_objects))
        .route("/api/v4/object/:id", delete(blind::ack_object))
        .route("/api/v4/stream", get(blind::stream_down).post(blind::stream_up))
        // OPAQUE is intentionally fail-closed until a Rust RFC9807 provider is interoperability-tested.
        .route("/api/v3/auth/opaque/login/start", post(legacy::opaque_public))
        .route("/api/v3/auth/opaque/login/finish", post(legacy::opaque_public))
        .route("/api/v3/auth/opaque/registration/start", post(legacy::opaque_ready))
        .route("/api/v3/auth/opaque/registration/finish", post(legacy::opaque_ready))
        .route("/api/v3/auth/opaque/password-change/start", post(legacy::opaque_ready))
        .route("/api/v3/auth/opaque/password-change/finish", post(legacy::opaque_ready))
        .route("/api/v3/security/opaque-recovery-package", get(legacy::opaque_any).put(legacy::opaque_ready))
        // 1.x ciphertext migration endpoints remain fail-closed. A 3.0.0 fresh/schema-14 database does not need them.
        .route("/api/v3/security/migrations", post(legacy::migration))
        .route("/api/v3/security/migrations/:id", get(legacy::migration))
        .route("/api/v3/security/migrations/:id/messages", get(legacy::migration))
        .route("/api/v3/security/migrations/:id/messages/:message", put(legacy::migration))
        .route("/api/v3/security/migrations/:id/messages/:message/replacement", get(legacy::migration))
        .route("/api/v3/security/migrations/:id/messages/:message/verify", post(legacy::migration))
        .route("/api/v3/security/migrations/:id/media", get(legacy::migration))
        .route("/api/v3/security/migrations/:id/media/:media", put(legacy::migration))
        .route("/api/v3/security/migrations/:id/media/:media/staged", get(legacy::migration))
        .route("/api/v3/security/migrations/:id/media/:media/verify", post(legacy::migration))
        .route("/api/v3/security/migrations/:id/complete", post(legacy::migration))
        .route("/api/v3/security/legacy-fmk/retire", post(legacy::migration))
        .layer(DefaultBodyLimit::max(18 * 1024 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn live() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status":"ok","server":"rust","version":crate::VERSION,"build":crate::VERSION_CODE})))
}

async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.ping().await {
        Ok(()) => (StatusCode::OK, Json(json!({"status":"ready","schema":14,"server":"rust","version":crate::VERSION,"build":crate::VERSION_CODE,"protocol_generation":crate::PROTOCOL_GENERATION,"security_epoch":crate::SECURITY_EPOCH,"event_sequence":state.events.current()}))),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"status":"unavailable"}))),
    }
}

async fn security_headers(req: Request, next: Next) -> Response<Body> {
    let request_id = uuid::Uuid::new_v4().to_string();
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"));
    headers.insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000; includeSubDomains"));
    headers.insert(axum::http::HeaderName::from_static("x-frame-options"), HeaderValue::from_static("DENY"));
    if let Ok(value) = HeaderValue::from_str(&request_id) { headers.insert("x-fedmes-request-id", value); }
    response
}
