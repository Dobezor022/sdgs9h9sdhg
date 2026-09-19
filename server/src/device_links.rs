use crate::{auth, error::{ApiError, ApiResult}, util, AppState, PROTOCOL_GENERATION};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Duration;
use openssl::{
    encrypt::Encrypter,
    hash::MessageDigest,
    pkey::PKey,
    rsa::Padding,
};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::{json, Value};

const REQUEST_TTL_MINUTES: i64 = 2;
const RESULT_TTL_MINUTES: i64 = 10;
const SESSION_TTL_MINUTES: i64 = 15;

#[derive(Deserialize)]
struct PublicKeyInput {
    algorithm: String,
    public_key_spki: String,
}

#[derive(Deserialize)]
pub struct CreateRequest {
    version: i64,
    display_name: String,
    platform: String,
    identity: PublicKeyInput,
    encryption: PublicKeyInput,
}

#[derive(Deserialize)]
pub struct SecretRequest {
    version: i64,
    secret: String,
}

#[derive(Deserialize)]
pub struct ApproveRequest {
    version: i64,
    secret: String,
    signature: String,
}

#[derive(Clone)]
struct LinkRecord {
    id: String,
    identity_algorithm: String,
    identity_public_key: Vec<u8>,
    identity_fingerprint: Vec<u8>,
    encryption_algorithm: String,
    encryption_public_key: Vec<u8>,
    encryption_fingerprint: Vec<u8>,
    display_name: String,
    platform: String,
    created_at: String,
    expires_at: String,
    approved_at: Option<String>,
    approved_by_device_id: Option<String>,
    username: Option<String>,
    linked_device_id: Option<String>,
    linked_session_id: Option<String>,
    encrypted_session_token: Option<Vec<u8>>,
    session_expires_at: Option<String>,
    result_expires_at: Option<String>,
    consumed_at: Option<String>,
    cancelled_at: Option<String>,
}

fn parse_secret(value: &str) -> ApiResult<Vec<u8>> {
    let raw = util::decode_b64url(value.trim(), 64)?;
    if raw.len() != 32 || util::b64url(&raw) != value.trim() {
        return Err(ApiError::bad("invalid_device_link_secret"));
    }
    Ok(util::sha256(&raw).to_vec())
}

fn state_of(link: &LinkRecord) -> &'static str {
    let now = util::now();
    if link.cancelled_at.is_some() { return "cancelled"; }
    if link.consumed_at.is_some() { return "consumed"; }
    if link.approved_at.is_some() {
        if link.result_expires_at.as_deref().and_then(|v| util::parse_ts(v).ok()).map(|t| t > now).unwrap_or(false) {
            return "approved";
        }
        return "expired";
    }
    if util::parse_ts(&link.expires_at).map(|t| t <= now).unwrap_or(true) { "expired" } else { "pending" }
}

async fn load_link(state: &AppState, id: String, digest: Vec<u8>) -> ApiResult<LinkRecord> {
    state.db.run(move |c| {
        Ok(c.query_row(
            "SELECT id,identity_algorithm,identity_public_key_spki,identity_fingerprint,\
                    encryption_algorithm,encryption_public_key_spki,encryption_fingerprint,\
                    display_name,platform,created_at,expires_at,approved_at,approved_by_device_id,\
                    username,linked_device_id,linked_session_id,encrypted_session_token,\
                    session_expires_at,result_expires_at,consumed_at,cancelled_at \
             FROM device_link_requests WHERE id=?1 AND secret_digest=?2",
            rusqlite::params![id, digest],
            |r| Ok(LinkRecord {
                id: r.get(0)?, identity_algorithm: r.get(1)?, identity_public_key: r.get(2)?, identity_fingerprint: r.get(3)?,
                encryption_algorithm: r.get(4)?, encryption_public_key: r.get(5)?, encryption_fingerprint: r.get(6)?,
                display_name: r.get(7)?, platform: r.get(8)?, created_at: r.get(9)?, expires_at: r.get(10)?,
                approved_at: r.get(11)?, approved_by_device_id: r.get(12)?, username: r.get(13)?,
                linked_device_id: r.get(14)?, linked_session_id: r.get(15)?, encrypted_session_token: r.get(16)?,
                session_expires_at: r.get(17)?, result_expires_at: r.get(18)?, consumed_at: r.get(19)?, cancelled_at: r.get(20)?,
            }),
        ).optional()?)
    }).await.map_err(ApiError::Internal)?.ok_or_else(|| ApiError::not_found("device_link_not_found"))
}

pub async fn create(State(state): State<AppState>, Json(req): Json<CreateRequest>) -> ApiResult<(StatusCode, Json<Value>)> {
    let display_name = req.display_name.trim().to_owned();
    let platform = req.platform.trim().to_ascii_lowercase();
    if req.version != 1 || display_name.is_empty() || display_name.len() > 64 || !matches!(platform.as_str(), "windows" | "linux" | "macos") {
        return Err(ApiError::bad("invalid_device_link"));
    }
    let identity = STANDARD.decode(req.identity.public_key_spki).map_err(|_| ApiError::bad("invalid_identity_key"))?;
    let encryption = STANDARD.decode(req.encryption.public_key_spki).map_err(|_| ApiError::bad("invalid_encryption_key"))?;
    if !auth::validate_identity_key(&req.identity.algorithm, &identity) { return Err(ApiError::bad("invalid_identity_key")); }
    if !auth::validate_encryption_key(&req.encryption.algorithm, &encryption) { return Err(ApiError::bad("invalid_encryption_key")); }

    let secret_raw = util::random_bytes(32);
    let secret = util::b64url(&secret_raw);
    let digest = util::sha256(&secret_raw).to_vec();
    let identity_fp = util::sha256(&identity).to_vec();
    let encryption_fp = util::sha256(&encryption).to_vec();
    let id = uuid::Uuid::new_v4().to_string();
    let now = util::now();
    let created = util::ts(now);
    let expires = util::ts(now + Duration::minutes(REQUEST_TTL_MINUTES));
    let db_id = id.clone();
    let id_alg = req.identity.algorithm;
    let enc_alg = req.encryption.algorithm;
    let db_created = created.clone();
    let db_expires = expires.clone();

    state.db.run(move |c| {
        let duplicate: i64 = c.query_row(
            "SELECT COUNT(*) FROM provisioning_devices WHERE public_key_fingerprint=?1 AND revoked_at IS NULL",
            [&identity_fp], |r| r.get(0))?;
        if duplicate != 0 { anyhow::bail!("conflict"); }
        c.execute(
            "INSERT INTO device_link_requests(id,secret_digest,identity_algorithm,identity_public_key_spki,identity_fingerprint,\
             encryption_algorithm,encryption_public_key_spki,encryption_fingerprint,display_name,platform,created_at,expires_at)\
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            rusqlite::params![db_id,digest,id_alg,identity,identity_fp,enc_alg,encryption,encryption_fp,display_name,platform,db_created,db_expires])?;
        Ok(())
    }).await.map_err(|e| if e.to_string().contains("conflict") || e.to_string().contains("UNIQUE") { ApiError::conflict("device_link_conflict") } else { ApiError::Internal(e) })?;

    let payload = format!("fedmes://link-device?v=1&id={}&secret={}", id, secret);
    let png = util::render_qr_png(payload.as_bytes(), 512).map_err(ApiError::Internal)?;
    Ok((StatusCode::CREATED, Json(json!({
        "version": 1,
        "link_id": id,
        "secret": secret,
        "qr_payload": payload,
        "qr_png_base64": STANDARD.encode(png),
        "expires_at": expires
    }))))
}

pub async fn status(State(state): State<AppState>, Path(id): Path<String>, Json(req): Json<SecretRequest>) -> ApiResult<Json<Value>> {
    if req.version != 1 { return Err(ApiError::bad("invalid_request")); }
    let digest = parse_secret(&req.secret)?;
    let link = load_link(&state, id, digest).await?;
    let current = state_of(&link);
    let mut out = json!({"version":1,"status":current,"expires_at":link.expires_at});
    if current == "approved" {
        out["username"] = json!(link.username);
        out["device_id"] = json!(link.linked_device_id);
        out["session_id"] = json!(link.linked_session_id);
        out["encrypted_session_token"] = json!(link.encrypted_session_token.as_deref().map(|v| STANDARD.encode(v)).unwrap_or_default());
        out["session_expires_at"] = json!(link.session_expires_at);
        out["result_expires_at"] = json!(link.result_expires_at);
        if let (Some(device), Some(user)) = (link.linked_device_id.clone(), link.username.clone()) {
            let sec = state.db.run(move |c| Ok(c.query_row(
                "SELECT security_state FROM provisioning_devices WHERE id=?1 AND username=?2",
                rusqlite::params![device,user], |r| r.get::<_,String>(0)).optional()?)).await.map_err(ApiError::Internal)?;
            out["authentication_state"] = json!(sec.unwrap_or_else(|| "REVOKED".into()));
        }
    }
    Ok(Json(out))
}

pub async fn preview(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(req): Json<SecretRequest>) -> ApiResult<Json<Value>> {
    let _ = auth::authenticate(&state, &headers, true).await?;
    if req.version != 1 { return Err(ApiError::bad("invalid_request")); }
    let digest = parse_secret(&req.secret)?;
    let link = load_link(&state, id, digest).await?;
    if state_of(&link) != "pending" { return Err(ApiError::Public(StatusCode::GONE, "device_link_unavailable")); }
    Ok(Json(json!({
        "version":1,"link_id":link.id,"display_name":link.display_name,"platform":link.platform,
        "identity_fingerprint":hex::encode(link.identity_fingerprint),
        "encryption_fingerprint":hex::encode(link.encryption_fingerprint),"expires_at":link.expires_at
    })))
}

pub async fn approve(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(req): Json<ApproveRequest>) -> ApiResult<(StatusCode, Json<Value>)> {
    let principal = auth::authenticate(&state, &headers, true).await?;
    if req.version != 1 { return Err(ApiError::bad("invalid_request")); }
    let digest = parse_secret(&req.secret)?;
    let signature = STANDARD.decode(req.signature).map_err(|_| ApiError::unauthorized("invalid_device_signature"))?;
    if signature.is_empty() || signature.len() > 512 { return Err(ApiError::unauthorized("invalid_device_signature")); }
    let link = load_link(&state, id.clone(), digest.clone()).await?;

    let device_id_for_key = principal.device_id.clone();
    let (approver_algorithm, approver_key) = state.db.run(move |c| {
        Ok(c.query_row(
            "SELECT key_algorithm,public_key_spki FROM provisioning_devices WHERE id=?1 AND revoked_at IS NULL",
            [device_id_for_key], |r| Ok((r.get::<_,String>(0)?, r.get::<_,Vec<u8>>(1)?))).optional()?)
    }).await.map_err(ApiError::Internal)?.ok_or_else(|| ApiError::unauthorized("session_invalid"))?;
    let canonical = format!("fedmes-device-link-approval-v1\n{}\n{}\n{}\n{}\n{}",
        id, req.secret.trim(), principal.device_id, hex::encode(&link.identity_fingerprint), hex::encode(&link.encryption_fingerprint));
    if !auth::verify_signature(&approver_algorithm, &approver_key, canonical.as_bytes(), &signature) {
        return Err(ApiError::unauthorized("invalid_device_signature"));
    }

    if state_of(&link) == "approved" && link.username.as_deref() == Some(&principal.username) && link.approved_by_device_id.as_deref() == Some(&principal.device_id) {
        let device = account_device_json(&state, principal.username, principal.device_id, link.linked_device_id.unwrap_or_default()).await?;
        return Ok((StatusCode::OK, Json(json!({"version":1,"device":device,"history_sync_required":true}))));
    }
    if state_of(&link) != "pending" { return Err(ApiError::Public(StatusCode::GONE, "device_link_unavailable")); }

    let pkey = PKey::public_key_from_der(&link.encryption_public_key).map_err(|e| ApiError::Internal(e.into()))?;
    let mut encrypter = Encrypter::new(&pkey).map_err(|e| ApiError::Internal(e.into()))?;
    encrypter.set_rsa_padding(Padding::PKCS1_OAEP).map_err(|e| ApiError::Internal(e.into()))?;
    encrypter.set_rsa_oaep_md(MessageDigest::sha256()).map_err(|e| ApiError::Internal(e.into()))?;
    encrypter.set_rsa_mgf1_md(MessageDigest::sha256()).map_err(|e| ApiError::Internal(e.into()))?;
    let raw_token = util::random_bytes(32);
    let token_digest = util::sha256(&raw_token).to_vec();
    let mut encrypted_token = vec![0u8; encrypter.encrypt_len(&raw_token).map_err(|e| ApiError::Internal(e.into()))?];
    let n = encrypter.encrypt(&raw_token, &mut encrypted_token).map_err(|e| ApiError::Internal(e.into()))?;
    encrypted_token.truncate(n);

    let now = util::now();
    let now_s = util::ts(now);
    let session_expires = util::ts(now + Duration::minutes(SESSION_TTL_MINUTES));
    let result_expires = util::ts(now + Duration::minutes(RESULT_TTL_MINUTES));
    let proposed_device_id = uuid::Uuid::new_v4().to_string();
    let invitation_id = uuid::Uuid::new_v4().to_string();
    let session_id = uuid::Uuid::new_v4().to_string();
    let username = principal.username.clone();
    let approver_id = principal.device_id.clone();
    let link_id = id.clone();
    let link_for_db = link.clone();
    let digest_for_db = digest.clone();
    let actual_device_id = state.db.run(move |c| {
        let tx = c.transaction()?;
        let fresh: i64 = tx.query_row(
            "SELECT COUNT(*) FROM device_link_requests WHERE id=?1 AND secret_digest=?2 AND approved_at IS NULL AND cancelled_at IS NULL AND expires_at>?3",
            rusqlite::params![link_id,digest_for_db,now_s], |r| r.get(0))?;
        if fresh != 1 { anyhow::bail!("unavailable"); }
        let vault_revision: i64 = tx.query_row("SELECT COALESCE(vault_revision,0) FROM account_security_state WHERE username=?1", [&username], |r| r.get(0)).optional()?.unwrap_or(0);
        let security_state = if vault_revision > 0 { "AUTHENTICATED_NO_KEYS" } else { "READY" };

        // Preserve device identity across an explicit revoke/re-link when the exact same
        // signing and encryption keys return for the same account. This mirrors the
        // 2.0.0 Go server and avoids violating the UNIQUE identity fingerprint constraint.
        let existing: Option<(String,String,Option<String>,Vec<u8>)> = tx.query_row(
            "SELECT d.id,d.username,d.revoked_at,k.fingerprint FROM provisioning_devices d JOIN device_encryption_keys k ON k.device_id=d.id WHERE d.public_key_fingerprint=?1",
            [&link_for_db.identity_fingerprint],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).optional()?;
        let linked_device_id = if let Some((existing_id, existing_username, revoked_at, existing_encryption_fp)) = existing {
            if revoked_at.is_none() || existing_username != username || existing_encryption_fp != link_for_db.encryption_fingerprint {
                anyhow::bail!("device_link_conflict");
            }
            tx.execute(
                "UPDATE provisioning_sessions SET revoked_at=?1 WHERE device_id=?2 AND revoked_at IS NULL",
                rusqlite::params![now_s,existing_id],
            )?;
            tx.execute(
                "UPDATE provisioning_devices SET revoked_at=NULL,display_name=?1,platform=?2,last_seen_at=?3,approved_by_device_id=?4,approved_at=NULL,security_state=?5 WHERE id=?6 AND revoked_at IS NOT NULL",
                rusqlite::params![link_for_db.display_name,link_for_db.platform,now_s,approver_id,security_state,existing_id],
            )?;
            existing_id
        } else {
            tx.execute(
                "INSERT INTO provisioning_invitations(id,username,token_digest,created_at,expires_at,redeemed_at,redeemed_by_device_id) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params![invitation_id,username,digest_for_db,link_for_db.created_at,link_for_db.expires_at,now_s,proposed_device_id])?;
            tx.execute(
                "INSERT INTO provisioning_devices(id,username,invitation_id,key_algorithm,public_key_spki,public_key_fingerprint,bound_at,display_name,platform,last_seen_at,approved_by_device_id,security_state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?7,?10,?11)",
                rusqlite::params![proposed_device_id,username,invitation_id,link_for_db.identity_algorithm,link_for_db.identity_public_key,link_for_db.identity_fingerprint,now_s,link_for_db.display_name,link_for_db.platform,approver_id,security_state])?;
            tx.execute(
                "INSERT INTO device_encryption_keys(device_id,algorithm,public_key_spki,fingerprint,registered_at) VALUES(?1,?2,?3,?4,?5)",
                rusqlite::params![proposed_device_id,link_for_db.encryption_algorithm,link_for_db.encryption_public_key,link_for_db.encryption_fingerprint,now_s])?;
            proposed_device_id
        };
        tx.execute(
            "INSERT INTO device_keys(device_id,purpose,algorithm,public_key_spki,fingerprint,created_at,revoked_at) VALUES(?1,'signing',?2,?3,?4,?5,NULL) ON CONFLICT(device_id,purpose) DO UPDATE SET algorithm=excluded.algorithm,public_key_spki=excluded.public_key_spki,fingerprint=excluded.fingerprint,created_at=excluded.created_at,revoked_at=NULL",
            rusqlite::params![linked_device_id,link_for_db.identity_algorithm,link_for_db.identity_public_key,link_for_db.identity_fingerprint,now_s])?;
        tx.execute(
            "INSERT INTO device_keys(device_id,purpose,algorithm,public_key_spki,fingerprint,created_at,revoked_at) VALUES(?1,'key_agreement',?2,?3,?4,?5,NULL) ON CONFLICT(device_id,purpose) DO UPDATE SET algorithm=excluded.algorithm,public_key_spki=excluded.public_key_spki,fingerprint=excluded.fingerprint,created_at=excluded.created_at,revoked_at=NULL",
            rusqlite::params![linked_device_id,link_for_db.encryption_algorithm,link_for_db.encryption_public_key,link_for_db.encryption_fingerprint,now_s])?;

        if vault_revision > 0 {
            let mut request_digest_input = Vec::with_capacity(link_id.len() + 1 + link_for_db.identity_fingerprint.len() + 1 + link_for_db.encryption_fingerprint.len());
            request_digest_input.extend_from_slice(link_id.as_bytes());
            request_digest_input.push(0);
            request_digest_input.extend_from_slice(&link_for_db.identity_fingerprint);
            request_digest_input.push(0);
            request_digest_input.extend_from_slice(&link_for_db.encryption_fingerprint);
            let request_digest = util::sha256(&request_digest_input).to_vec();
            let request_expires = util::ts(util::now() + Duration::hours(24));
            tx.execute(
                "INSERT INTO device_provisioning_requests(id,username,target_device_id,request_digest,protocol_version,requested_at,expires_at,display_name,platform,network_hint) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'')",
                rusqlite::params![link_id,username,linked_device_id,request_digest,PROTOCOL_GENERATION,now_s,request_expires,link_for_db.display_name,link_for_db.platform])?;
        } else {
            tx.execute("UPDATE account_security_state SET last_ready_device_id=?1,updated_at=?2 WHERE username=?3", rusqlite::params![linked_device_id,now_s,username])?;
        }
        tx.execute("INSERT INTO provisioning_sessions(id,device_id,token_digest,issued_at,expires_at,protocol_version,authentication_method) VALUES(?1,?2,?3,?4,?5,?6,'device-link')",
            rusqlite::params![session_id,linked_device_id,token_digest,now_s,session_expires,PROTOCOL_GENERATION])?;
        let changed = tx.execute(
            "UPDATE device_link_requests SET approved_at=?1,approved_by_device_id=?2,username=?3,linked_device_id=?4,linked_session_id=?5,encrypted_session_token=?6,session_expires_at=?7,result_expires_at=?8 WHERE id=?9 AND secret_digest=?10 AND approved_at IS NULL AND cancelled_at IS NULL",
            rusqlite::params![now_s,approver_id,username,linked_device_id,session_id,encrypted_token,session_expires,result_expires,link_id,digest_for_db])?;
        if changed != 1 { anyhow::bail!("unavailable"); }
        tx.commit()?;
        Ok(linked_device_id)
    }).await.map_err(|e| {
        let text=e.to_string();
        if text.contains("unavailable") { ApiError::Public(StatusCode::GONE, "device_link_unavailable") }
        else if text.contains("device_link_conflict") || text.contains("UNIQUE") || text.contains("unique") { ApiError::conflict("device_link_conflict") }
        else { ApiError::Internal(e) }
    })?;

    state.events.bump();
    let device = account_device_json(&state, principal.username, principal.device_id, actual_device_id).await?;
    Ok((StatusCode::CREATED, Json(json!({"version":1,"device":device,"history_sync_required":true}))))
}

async fn account_device_json(state: &AppState, username: String, current: String, target: String) -> ApiResult<Value> {
    state.db.run(move |c| {
        Ok(c.query_row(
            "SELECT id,display_name,platform,bound_at,last_seen_at,COALESCE(approved_by_device_id,''),public_key_fingerprint FROM provisioning_devices WHERE id=?1 AND username=?2 AND revoked_at IS NULL",
            rusqlite::params![target,username], |r| {
                let id: String = r.get(0)?; let fp: Vec<u8> = r.get(6)?;
                Ok(json!({"id":id,"display_name":r.get::<_,String>(1)?,"platform":r.get::<_,String>(2)?,"bound_at":r.get::<_,String>(3)?,"last_seen_at":r.get::<_,Option<String>>(4)?,"current":id==current,"approved_by_device_id":r.get::<_,String>(5)?,"identity_fingerprint":hex::encode(fp)}))
            }).optional()?)
    }).await.map_err(ApiError::Internal)?.ok_or_else(|| ApiError::not_found("device_not_found"))
}

pub async fn cancel(State(state): State<AppState>, Path(id): Path<String>, Json(req): Json<SecretRequest>) -> ApiResult<StatusCode> {
    if req.version != 1 { return Err(ApiError::bad("invalid_request")); }
    let digest = parse_secret(&req.secret)?; let now = util::ts(util::now());
    let n = state.db.run(move |c| Ok(c.execute("UPDATE device_link_requests SET cancelled_at=?1 WHERE id=?2 AND secret_digest=?3 AND approved_at IS NULL AND cancelled_at IS NULL AND expires_at>?1", rusqlite::params![now,id,digest])?)).await.map_err(ApiError::Internal)?;
    if n != 1 { return Err(ApiError::conflict("device_link_used")); }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn complete(State(state): State<AppState>, Path(id): Path<String>, Json(req): Json<SecretRequest>) -> ApiResult<StatusCode> {
    if req.version != 1 { return Err(ApiError::bad("invalid_request")); }
    let digest = parse_secret(&req.secret)?; let now = util::ts(util::now());
    let n = state.db.run(move |c| Ok(c.execute("UPDATE device_link_requests SET consumed_at=?1,encrypted_session_token=NULL WHERE id=?2 AND secret_digest=?3 AND approved_at IS NOT NULL AND consumed_at IS NULL AND result_expires_at>?1", rusqlite::params![now,id,digest])?)).await.map_err(ApiError::Internal)?;
    if n != 1 { return Err(ApiError::conflict("device_link_used")); }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_devices(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let p = auth::authenticate(&state, &headers, true).await?;
    let user = p.username; let current = p.device_id;
    let devices = state.db.run(move |c| {
        let mut stmt = c.prepare("SELECT id,display_name,platform,bound_at,last_seen_at,COALESCE(approved_by_device_id,''),public_key_fingerprint FROM provisioning_devices WHERE username=?1 AND revoked_at IS NULL ORDER BY CASE WHEN id=?2 THEN 0 ELSE 1 END,COALESCE(last_seen_at,bound_at) DESC")?;
        let rows = stmt.query_map(rusqlite::params![user,current], |r| {
            let id: String = r.get(0)?; let fp: Vec<u8> = r.get(6)?;
            Ok(json!({"id":id,"display_name":r.get::<_,String>(1)?,"platform":r.get::<_,String>(2)?,"bound_at":r.get::<_,String>(3)?,"last_seen_at":r.get::<_,Option<String>>(4)?,"current":id==current,"approved_by_device_id":r.get::<_,String>(5)?,"identity_fingerprint":hex::encode(fp)}))
        })?.collect::<Result<Vec<_>,_>>()?;
        Ok(rows)
    }).await.map_err(ApiError::Internal)?;
    Ok(Json(json!({"version":1,"devices":devices})))
}

async fn revoke_impl(state: &AppState, username: String, device_id: String) -> ApiResult<()> {
    let now = util::ts(util::now());
    let n = state.db.run(move |c| {
        let tx = c.transaction()?;
        let n = tx.execute("UPDATE provisioning_devices SET revoked_at=?1,security_state='REVOKED' WHERE id=?2 AND username=?3 AND revoked_at IS NULL", rusqlite::params![now,device_id,username])?;
        if n == 1 {
            tx.execute("UPDATE provisioning_sessions SET revoked_at=?1 WHERE device_id=?2 AND revoked_at IS NULL", rusqlite::params![now,device_id])?;
            tx.execute("UPDATE provisioning_challenges SET consumed_at=?1 WHERE device_id=?2 AND consumed_at IS NULL", rusqlite::params![now,device_id])?;
            tx.execute("UPDATE device_keys SET revoked_at=?1 WHERE device_id=?2 AND revoked_at IS NULL", rusqlite::params![now,device_id])?;
            tx.execute("UPDATE device_certificates SET revoked_at=?1 WHERE subject_device_id=?2 AND revoked_at IS NULL", rusqlite::params![now,device_id])?;
            tx.execute("UPDATE ratchet_device_bundles SET revoked_at=?1 WHERE device_id=?2 AND revoked_at IS NULL", rusqlite::params![now,device_id])?;
        }
        tx.commit()?; Ok(n)
    }).await.map_err(ApiError::Internal)?;
    if n != 1 { return Err(ApiError::not_found("device_not_found")); }
    state.events.bump(); Ok(())
}

pub async fn revoke_device(State(state): State<AppState>, headers: HeaderMap, Path(device_id): Path<String>) -> ApiResult<StatusCode> {
    let p = auth::authenticate(&state, &headers, true).await?;
    if p.device_id == device_id { return Err(ApiError::conflict("current_device")); }
    revoke_impl(&state, p.username, device_id).await?; Ok(StatusCode::NO_CONTENT)
}

pub async fn terminate_others(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let p = auth::authenticate(&state, &headers, true).await?;
    let user = p.username; let current = p.device_id; let now = util::ts(util::now());
    state.db.run(move |c| {
        let tx = c.transaction()?;
        let mut stmt = tx.prepare("SELECT id FROM provisioning_devices WHERE username=?1 AND id<>?2 AND revoked_at IS NULL")?;
        let ids = stmt.query_map(rusqlite::params![user,current], |r| r.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?;
        drop(stmt);
        for id in ids {
            tx.execute("UPDATE provisioning_devices SET revoked_at=?1,security_state='REVOKED' WHERE id=?2", rusqlite::params![now,id])?;
            tx.execute("UPDATE provisioning_sessions SET revoked_at=?1 WHERE device_id=?2 AND revoked_at IS NULL", rusqlite::params![now,id])?;
            tx.execute("UPDATE provisioning_challenges SET consumed_at=?1 WHERE device_id=?2 AND consumed_at IS NULL", rusqlite::params![now,id])?;
            tx.execute("UPDATE device_keys SET revoked_at=?1 WHERE device_id=?2 AND revoked_at IS NULL", rusqlite::params![now,id])?;
            tx.execute("UPDATE device_certificates SET revoked_at=?1 WHERE subject_device_id=?2 AND revoked_at IS NULL", rusqlite::params![now,id])?;
            tx.execute("UPDATE ratchet_device_bundles SET revoked_at=?1 WHERE device_id=?2 AND revoked_at IS NULL", rusqlite::params![now,id])?;
        }
        tx.commit()?; Ok(())
    }).await.map_err(ApiError::Internal)?;
    state.events.bump(); Ok(StatusCode::NO_CONTENT)
}

pub async fn revoke_current(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let p = auth::authenticate(&state, &headers, false).await?;
    revoke_impl(&state, p.username, p.device_id).await?; Ok(StatusCode::NO_CONTENT)
}
