use crate::{auth::{self,Principal}, error::{ApiError,ApiResult}, util, AppState};
use axum::{
    body::Body,
    extract::{Path, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::{STANDARD,URL_SAFE_NO_PAD},Engine as _};
use chrono::Duration;
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::{json,Value};
use std::path::PathBuf;
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio_util::io::ReaderStream;

#[derive(Deserialize)] pub struct EncryptionKeyRequest{version:i64,algorithm:String,public_key_spki:String}
#[derive(Deserialize,Clone)] pub struct Envelope{device_id:String,algorithm:String,ciphertext:String}
#[derive(Deserialize,Clone)] pub struct RatchetEnvelope{recipient_device_id:String,sender_curve25519_key:String,session_id:String,message_type:i64,ciphertext:String,ciphertext_sha256:String}
#[derive(Deserialize,Clone)] pub struct MessageWrite{version:i64,id:String,ciphertext:String,nonce:String,aad:String,#[serde(default)]crypto_version:i64,#[serde(default)]room_key_version:i64,#[serde(default)]aad_version:i64,#[serde(default)]crypto_sequence:i64,#[serde(default)]encryption_algorithm:String,#[serde(default)]message_type:String,#[serde(default)]sequence_request_id:String,#[serde(default)]envelopes:Vec<Envelope>,#[serde(default)]ratchet_envelopes:Vec<RatchetEnvelope>}
#[derive(Deserialize)] pub struct SequenceRequest{version:i64,request_id:String,message_id:String}
#[derive(Deserialize)] pub struct SequenceLeaseRequest{version:i64,items:Vec<SequenceLeaseItemRequest>}
#[derive(Deserialize)] pub struct SequenceLeaseItemRequest{request_id:String,message_id:String}
#[derive(Deserialize)] pub struct ReceiptRequest{version:i64,#[serde(default)]delivered_message_ids:Vec<String>,#[serde(default)]read_message_ids:Vec<String>}
#[derive(Deserialize)] pub struct ReadCursorRequest{version:i64,max_read_sequence:i64}
#[derive(Deserialize)] pub struct TypingRequest{version:i64,typing:bool}
#[derive(Deserialize)] pub struct HeartbeatRequest{version:i64,show_exact:bool}
#[derive(Deserialize,Default)] pub struct MessageQuery{after:Option<i64>,before:Option<i64>,limit:Option<i64>,scope:Option<String>}
#[derive(Deserialize,Default)] pub struct EventQuery{after:Option<i64>,timeout_ms:Option<u64>}

async fn member(state:&AppState,p:&Principal,chat:&str)->ApiResult<()> {
    let c=chat.to_string(); let u=p.username.clone();
    let ok=state.db.run(move|db|Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM chat_members WHERE chat_id=?1 AND username=?2)",rusqlite::params![c,u],|r|r.get::<_,i64>(0))?==1)).await.map_err(ApiError::Internal)?;
    if !ok{return Err(ApiError::not_found("chat_not_found"));} Ok(())
}

pub async fn validate(State(state):State<AppState>,headers:HeaderMap)->ApiResult<Response>{
    let p=auth::authenticate(&state,&headers,false).await?;
    let user_header=HeaderValue::from_str(&p.username).map_err(|e|ApiError::Internal(e.into()))?;
    let device_header=HeaderValue::from_str(&p.device_id).map_err(|e|ApiError::Internal(e.into()))?;
    let mut response=Json(json!({"version":1,"username":p.username,"device_id":p.device_id,"authentication_state":p.security_state})).into_response();
    response.headers_mut().insert("x-fedmes-user",user_header);
    response.headers_mut().insert("x-fedmes-device",device_header);
    Ok(response)
}

pub async fn register_encryption_key(State(state):State<AppState>,headers:HeaderMap,Json(req):Json<EncryptionKeyRequest>)->ApiResult<StatusCode>{
    let p=auth::authenticate(&state,&headers,true).await?; if req.version!=1{return Err(ApiError::bad("invalid_request"));}
    let key=STANDARD.decode(&req.public_key_spki).map_err(|_|ApiError::bad("invalid_encryption_key"))?;
    if !auth::validate_encryption_key(&req.algorithm,&key){return Err(ApiError::bad("invalid_encryption_key"));}
    let fp=util::sha256(&key).to_vec(); let did=p.device_id; let algo=req.algorithm; let now=util::ts(util::now());
    state.db.run(move|c|{
        let existing=c.query_row("SELECT algorithm,public_key_spki FROM device_encryption_keys WHERE device_id=?1",[&did],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?))).optional()?;
        if let Some((a,k))=existing { if a!=algo || k!=key {anyhow::bail!("key_replacement")}; return Ok(()); }
        c.execute("INSERT INTO device_encryption_keys(device_id,algorithm,public_key_spki,fingerprint,registered_at) VALUES(?1,?2,?3,?4,?5)",rusqlite::params![did,algo,key,fp,now])?; Ok(())
    }).await.map_err(|e|if e.to_string()=="key_replacement"{ApiError::conflict("encryption_key_replacement_requires_new_qr")}else{ApiError::Internal(e)})?;
    state.events.bump(); Ok(StatusCode::NO_CONTENT)
}

pub async fn list_chats(State(state):State<AppState>,headers:HeaderMap)->ApiResult<Json<Value>>{
    let p=auth::authenticate(&state,&headers,true).await?; let user=p.username;
    let chats=state.db.run(move|c|{
        let mut st=c.prepare(r#"SELECT c.id,c.kind,c.title,COALESCE(MAX(m.sequence),0),MAX(m.created_at),COALESCE(pm.message_id,''),
        (SELECT COUNT(*) FROM messages um WHERE um.chat_id=c.id AND um.deleted_at IS NULL AND um.sender_username<>?1 AND um.sequence>COALESCE((SELECT max_read_sequence FROM chat_read_cursors WHERE chat_id=c.id AND username=?1),0) AND NOT EXISTS(SELECT 1 FROM message_user_deletions d WHERE d.message_id=um.id AND d.username=?1))
        FROM chats c JOIN chat_members me ON me.chat_id=c.id LEFT JOIN messages m ON m.chat_id=c.id AND m.deleted_at IS NULL LEFT JOIN pinned_messages pm ON pm.chat_id=c.id WHERE me.username=?1 GROUP BY c.id,c.kind,c.title ORDER BY COALESCE(MAX(m.sequence),0) DESC,CASE c.kind WHEN 'favorites' THEN 0 WHEN 'family' THEN 1 ELSE 2 END,c.title"#)?;
        let mut rows=st.query([&user])?; let mut out=Vec::new();
        while let Some(r)=rows.next()? { let id:String=r.get(0)?; let mut ms=c.prepare("SELECT username FROM chat_members WHERE chat_id=?1 ORDER BY username")?; let members=ms.query_map([&id],|x|x.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?; out.push(json!({"id":id,"kind":r.get::<_,String>(1)?,"title":r.get::<_,String>(2)?,"members":members,"last_sequence":r.get::<_,i64>(3)?,"last_message_at":r.get::<_,Option<String>>(4)?,"pinned_message_id":r.get::<_,String>(5)?,"unread_count":r.get::<_,i64>(6)?})); }
        Ok(out)
    }).await.map_err(ApiError::Internal)?; Ok(Json(json!({"version":1,"chats":chats})))
}

pub async fn list_devices(State(state):State<AppState>,headers:HeaderMap,Path(chat):Path<String>)->ApiResult<Json<Value>>{
    let p=auth::authenticate(&state,&headers,true).await?; member(&state,&p,&chat).await?; let cid=chat;
    let devices=state.db.run(move|c|{let mut st=c.prepare(r#"SELECT d.id,d.username,d.key_algorithm,d.public_key_spki,COALESCE(k.algorithm,''),k.public_key_spki,COALESCE(r.bundle_version,0) FROM provisioning_devices d JOIN chat_members cm ON cm.username=d.username LEFT JOIN device_encryption_keys k ON k.device_id=d.id LEFT JOIN ratchet_device_bundles r ON r.device_id=d.id AND r.revoked_at IS NULL WHERE cm.chat_id=?1 AND d.revoked_at IS NULL AND d.security_state='READY' ORDER BY d.username,d.bound_at"#)?; let rows=st.query_map([&cid],|r|{let ik:Vec<u8>=r.get(3)?; let ek:Option<Vec<u8>>=r.get(5)?; Ok(json!({"id":r.get::<_,String>(0)?,"username":r.get::<_,String>(1)?,"identity_algorithm":r.get::<_,String>(2)?,"identity_public_key_spki":STANDARD.encode(ik),"encryption_algorithm":r.get::<_,String>(4)?,"encryption_public_key_spki":ek.map(|v|STANDARD.encode(v)).unwrap_or_default(),"ratchet_bundle_version":r.get::<_,i64>(6)?}))})?.collect::<Result<Vec<_>,_>>()?;Ok(rows)}).await.map_err(ApiError::Internal)?;
    Ok(Json(json!({"version":1,"devices":devices})))
}

pub async fn reserve_sequence(State(state):State<AppState>,headers:HeaderMap,Path(chat):Path<String>,Json(req):Json<SequenceRequest>)->ApiResult<Json<Value>>{
    let p=auth::authenticate(&state,&headers,true).await?; member(&state,&p,&chat).await?;
    if req.version!=2 || req.request_id.len()<16 || req.request_id.len()>128 || !util::canonical_uuid(&req.message_id){return Err(ApiError::bad("invalid_sequence_reservation"));}
    let cid=chat.clone();let did=p.device_id.clone();let rid=req.request_id.clone();let mid=req.message_id.clone();let now=util::now();let now_s=util::ts(now);let exp=util::ts(now+Duration::minutes(10));
    let (seq,replayed)=state.db.run(move|c|{let tx=c.transaction()?; let old=tx.query_row("SELECT crypto_sequence,message_id,chat_id,sender_device_id FROM message_sequence_reservations WHERE request_id=?1",[&rid],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?))).optional()?; if let Some((s,m,ch,d))=old{if m!=mid||ch!=cid||d!=did{anyhow::bail!("replay")};return Ok((s,true));}
        let next=tx.query_row("SELECT next_sequence FROM room_device_sequence_state WHERE chat_id=?1 AND device_id=?2",rusqlite::params![cid,did],|r|r.get::<_,i64>(0)).optional()?.unwrap_or(1);
        tx.execute("INSERT INTO room_device_sequence_state(chat_id,device_id,next_sequence,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(chat_id,device_id) DO UPDATE SET next_sequence=excluded.next_sequence,updated_at=excluded.updated_at",rusqlite::params![cid,did,next+1,now_s])?;
        tx.execute("INSERT INTO message_sequence_reservations(request_id,message_id,chat_id,sender_device_id,crypto_sequence,created_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",rusqlite::params![rid,mid,cid,did,next,now_s,exp])?;tx.commit()?;Ok((next,false))}).await.map_err(|e|if e.to_string()=="replay"{ApiError::conflict("sequence_reservation_replay")}else{ApiError::Internal(e)})?;
    Ok(Json(json!({"version":2,"message_id":req.message_id,"crypto_sequence":seq,"replayed":replayed})))
}

pub async fn reserve_sequence_lease(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat): Path<String>,
    Json(req): Json<SequenceLeaseRequest>,
) -> ApiResult<Json<Value>> {
    let principal = auth::authenticate(&state, &headers, true).await?;
    member(&state, &principal, &chat).await?;
    if req.version != 1 || req.items.is_empty() || req.items.len() > 16 {
        return Err(ApiError::bad("invalid_sequence_lease"));
    }
    let mut request_ids = std::collections::HashSet::with_capacity(req.items.len());
    let mut message_ids = std::collections::HashSet::with_capacity(req.items.len());
    for item in &req.items {
        if item.request_id.len() < 16 || item.request_id.len() > 128 || !util::canonical_uuid(&item.message_id)
            || !request_ids.insert(item.request_id.clone()) || !message_ids.insert(item.message_id.clone()) {
            return Err(ApiError::bad("invalid_sequence_lease"));
        }
    }
    let chat_id = chat.clone();
    let device_id = principal.device_id.clone();
    let input = req.items.into_iter().map(|item| (item.request_id, item.message_id)).collect::<Vec<_>>();
    let now = util::now();
    let created_at = util::ts(now);
    let expires_at = util::ts(now + Duration::minutes(10));
    let leased = state.db.run(move |conn| {
        let tx = conn.transaction()?;
        let start = tx.query_row(
            "SELECT next_sequence FROM room_device_sequence_state WHERE chat_id=?1 AND device_id=?2",
            rusqlite::params![chat_id, device_id],
            |row| row.get::<_, i64>(0),
        ).optional()?.unwrap_or(1);
        let mut output = Vec::with_capacity(input.len());
        for (index, (request_id, message_id)) in input.into_iter().enumerate() {
            let sequence = start + index as i64;
            tx.execute(
                "INSERT INTO message_sequence_reservations(request_id,message_id,chat_id,sender_device_id,crypto_sequence,created_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params![request_id, message_id, chat_id, device_id, sequence, created_at, expires_at],
            )?;
            output.push((request_id, message_id, sequence));
        }
        let next = start + output.len() as i64;
        tx.execute(
            "INSERT INTO room_device_sequence_state(chat_id,device_id,next_sequence,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(chat_id,device_id) DO UPDATE SET next_sequence=excluded.next_sequence,updated_at=excluded.updated_at",
            rusqlite::params![chat_id, device_id, next, created_at],
        )?;
        tx.commit()?;
        Ok(output)
    }).await.map_err(|error| {
        let text = error.to_string();
        if text.contains("UNIQUE") || text.contains("unique") { ApiError::conflict("sequence_lease_conflict") } else { ApiError::Internal(error) }
    })?;
    let items = leased.into_iter().map(|(request_id, message_id, crypto_sequence)| {
        json!({"request_id":request_id,"message_id":message_id,"crypto_sequence":crypto_sequence})
    }).collect::<Vec<_>>();
    Ok(Json(json!({"version":1,"items":items})))
}

fn validate_message(req: &MessageWrite) -> ApiResult<(Vec<u8>, Vec<u8>)> {
    if !util::canonical_uuid(&req.id) { return Err(ApiError::bad("invalid_message_id")); }
    let cipher = STANDARD.decode(&req.ciphertext).map_err(|_| ApiError::bad("invalid_message"))?;
    let nonce = STANDARD.decode(&req.nonce).map_err(|_| ApiError::bad("invalid_message"))?;
    if cipher.len() < 16 || cipher.len() > 1_048_576 || nonce.len() != 12 || req.aad.is_empty() || req.aad.len() > 2048 {
        return Err(ApiError::bad("invalid_message"));
    }
    Ok((cipher, nonce))
}

fn canonical_message_aad_v2(
    chat_id: &str,
    username: &str,
    device_id: &str,
    message_id: &str,
    message_type: &str,
    crypto_sequence: i64,
    room_key_version: i64,
) -> String {
    format!(
        "fedmes-message-v2\n{}\n{}\n{}\n{}\n{}\n{}\n{}\naad-v2",
        chat_id, message_id, username, device_id, message_type, crypto_sequence, room_key_version,
    )
}

fn message_type_from_aad(aad: &str) -> &str {
    let mut parts = aad.split('\n');
    if parts.next() != Some("fedmes-message-v2") { return "legacy"; }
    let _chat_id = parts.next();
    let _message_id = parts.next();
    let _username = parts.next();
    let _device_id = parts.next();
    match parts.next() {
        Some(value) if !value.is_empty() => value,
        _ => "legacy",
    }
}

fn validate_envelope_targets_tx(
    tx: &rusqlite::Transaction<'_>,
    chat_id: &str,
    sender_device_id: Option<&str>,
    envelopes: &[Envelope],
) -> anyhow::Result<()> {
    if envelopes.len() > 64 { anyhow::bail!("invalid_envelopes"); }
    if sender_device_id.is_some() && envelopes.is_empty() { anyhow::bail!("invalid_envelopes"); }
    let mut seen = std::collections::HashSet::with_capacity(envelopes.len());
    let mut sender_present = sender_device_id.is_none();
    for envelope in envelopes {
        if envelope.algorithm != "rsa-oaep-sha256" || !seen.insert(envelope.device_id.as_str()) {
            anyhow::bail!("invalid_envelopes");
        }
        let ciphertext = STANDARD.decode(&envelope.ciphertext).map_err(|_| anyhow::anyhow!("invalid_envelopes"))?;
        if ciphertext.len() < 256 || ciphertext.len() > 1024 { anyhow::bail!("invalid_envelopes"); }
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM provisioning_devices d JOIN chat_members cm ON cm.username=d.username JOIN device_encryption_keys k ON k.device_id=d.id WHERE cm.chat_id=?1 AND d.id=?2 AND d.revoked_at IS NULL",
            rusqlite::params![chat_id, envelope.device_id],
            |row| row.get(0),
        )?;
        if count != 1 { anyhow::bail!("invalid_envelopes"); }
        if sender_device_id == Some(envelope.device_id.as_str()) { sender_present = true; }
    }
    if !sender_present { anyhow::bail!("invalid_envelopes"); }
    Ok(())
}

fn validate_ratchet_envelopes_tx(
    tx: &rusqlite::Transaction<'_>,
    chat_id: &str,
    envelopes: &[RatchetEnvelope],
) -> anyhow::Result<()> {
    if envelopes.is_empty() || envelopes.len() > 64 { anyhow::bail!("invalid_ratchet_envelopes"); }
    let mut seen = std::collections::HashSet::with_capacity(envelopes.len());
    for envelope in envelopes {
        if envelope.recipient_device_id.is_empty()
            || envelope.sender_curve25519_key.len() < 32 || envelope.sender_curve25519_key.len() > 128
            || envelope.session_id.len() < 16 || envelope.session_id.len() > 256
            || !matches!(envelope.message_type, 0 | 1)
            || !seen.insert(envelope.recipient_device_id.as_str())
        {
            anyhow::bail!("invalid_ratchet_envelopes");
        }
        let ciphertext = URL_SAFE_NO_PAD.decode(&envelope.ciphertext)
            .map_err(|_| anyhow::anyhow!("invalid_ratchet_envelopes"))?;
        let digest = hex::decode(&envelope.ciphertext_sha256)
            .map_err(|_| anyhow::anyhow!("invalid_ratchet_envelopes"))?;
        if ciphertext.len() < 16 || ciphertext.len() > 1_048_576 || digest.len() != 32
            || util::sha256(&ciphertext).as_slice() != digest.as_slice()
        {
            anyhow::bail!("invalid_ratchet_envelopes");
        }
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM provisioning_devices d JOIN chat_members m ON m.username=d.username JOIN ratchet_device_bundles b ON b.device_id=d.id AND b.revoked_at IS NULL WHERE d.id=?1 AND m.chat_id=?2 AND d.revoked_at IS NULL AND d.security_state='READY'",
            rusqlite::params![envelope.recipient_device_id, chat_id],
            |row| row.get(0),
        )?;
        if count != 1 { anyhow::bail!("invalid_ratchet_envelopes"); }
    }
    let expected: i64 = tx.query_row(
        "SELECT COUNT(*) FROM provisioning_devices d JOIN chat_members m ON m.username=d.username JOIN ratchet_device_bundles b ON b.device_id=d.id AND b.revoked_at IS NULL WHERE m.chat_id=?1 AND d.revoked_at IS NULL AND d.security_state='READY'",
        [chat_id],
        |row| row.get(0),
    )?;
    if seen.len() as i64 != expected { anyhow::bail!("invalid_ratchet_envelopes"); }
    Ok(())
}

fn validate_crypto_v2_tx(
    tx: &rusqlite::Transaction<'_>,
    req: &MessageWrite,
    chat_id: &str,
    username: &str,
    device_id: &str,
    now: &str,
) -> anyhow::Result<()> {
    if req.crypto_version != 2 || req.aad_version != 2 || req.room_key_version <= 0
        || req.crypto_sequence <= 0 || req.sequence_request_id.len() < 16 || req.sequence_request_id.len() > 128
        || req.message_type.is_empty() || req.message_type.len() > 64
    {
        anyhow::bail!("crypto_v2");
    }
    let reservation: Option<(String, String, String, i64, String, Option<String>)> = tx.query_row(
        "SELECT message_id,chat_id,sender_device_id,crypto_sequence,expires_at,consumed_at FROM message_sequence_reservations WHERE request_id=?1",
        [&req.sequence_request_id],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
    ).optional()?;
    let Some((reserved_message, reserved_chat, reserved_device, reserved_sequence, expires_at, consumed_at)) = reservation else {
        anyhow::bail!("sequence");
    };
    if consumed_at.is_some() || expires_at.as_str() <= now || reserved_message != req.id || reserved_chat != chat_id
        || reserved_device != device_id || reserved_sequence != req.crypto_sequence
    {
        anyhow::bail!("sequence");
    }
    let expected_aad = canonical_message_aad_v2(
        chat_id, username, device_id, &req.id, &req.message_type, req.crypto_sequence, req.room_key_version,
    );
    if req.aad != expected_aad { anyhow::bail!("aad"); }
    if !req.envelopes.is_empty() { validate_envelope_targets_tx(tx, chat_id, None, &req.envelopes)?; }
    let kind: String = tx.query_row("SELECT kind FROM chats WHERE id=?1", [chat_id], |row| row.get(0))?;
    match kind.as_str() {
        "family" => {
            if req.encryption_algorithm != "fedmes-megolm-v1" || !req.ratchet_envelopes.is_empty() {
                anyhow::bail!("crypto_v2");
            }
            let active: i64 = tx.query_row(
                "SELECT COUNT(*) FROM megolm_group_sessions WHERE chat_id=?1 AND room_key_version=?2 AND retired_at IS NULL",
                rusqlite::params![chat_id, req.room_key_version],
                |row| row.get(0),
            )?;
            if active != 1 { anyhow::bail!("group_key"); }
        }
        "direct" | "favorites" => {
            if req.encryption_algorithm != "fedmes-olm-v1" { anyhow::bail!("crypto_v2"); }
            validate_ratchet_envelopes_tx(tx, chat_id, &req.ratchet_envelopes)?;
        }
        _ => anyhow::bail!("crypto_v2"),
    }
    Ok(())
}

pub async fn create_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat): Path<String>,
    Json(req): Json<MessageWrite>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let principal = auth::authenticate(&state, &headers, true).await?;
    member(&state, &principal, &chat).await?;
    let (cipher, nonce) = validate_message(&req)?;
    let crypto_version = if req.crypto_version == 0 && req.version == 1 { 1 } else { req.crypto_version };
    if crypto_version < 1 { return Err(ApiError::bad("message_rejected")); }
    let now = util::ts(util::now());
    let response_created_at = now.clone();
    let chat_id = chat.clone();
    let username = principal.username.clone();
    let device_id = principal.device_id.clone();
    let request = req.clone();
    let created = state.db.run(move |conn| {
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let minimum_crypto: i64 = tx.query_row(
            "SELECT minimum_crypto_version FROM account_security_state WHERE username=?1",
            [&username], |row| row.get(0),
        )?;
        if crypto_version < minimum_crypto { anyhow::bail!("downgrade"); }
        let room_key_version;
        let aad_version;
        let encryption_algorithm;
        let crypto_sequence;
        if crypto_version == 1 {
            validate_envelope_targets_tx(&tx, &chat_id, Some(&device_id), &request.envelopes)?;
            if !request.ratchet_envelopes.is_empty() { anyhow::bail!("crypto_v1"); }
            room_key_version = 1;
            aad_version = 1;
            encryption_algorithm = "fedmes-aes256gcm-rsa-oaep-v1".to_owned();
            crypto_sequence = 0;
        } else if crypto_version == 2 {
            validate_crypto_v2_tx(&tx, &request, &chat_id, &username, &device_id, &now)?;
            room_key_version = request.room_key_version;
            aad_version = request.aad_version;
            encryption_algorithm = request.encryption_algorithm.clone();
            crypto_sequence = request.crypto_sequence;
        } else {
            anyhow::bail!("crypto_version");
        }
        let hash = util::sha256(&cipher).to_vec();
        tx.execute(
            "INSERT INTO messages(id,chat_id,sender_username,sender_device_id,ciphertext,nonce,aad,created_at,crypto_version,room_key_version,aad_version,encryption_algorithm,ciphertext_sha256,crypto_sequence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            rusqlite::params![request.id,chat_id,username,device_id,cipher,nonce,request.aad,now,crypto_version,room_key_version,aad_version,encryption_algorithm,hash,crypto_sequence],
        )?;
        let message_sequence = tx.last_insert_rowid();
        for envelope in &request.envelopes {
            let bytes = STANDARD.decode(&envelope.ciphertext).map_err(|_| anyhow::anyhow!("invalid_envelopes"))?;
            tx.execute(
                "INSERT INTO message_envelopes(message_id,device_id,algorithm,ciphertext) VALUES(?1,?2,?3,?4)",
                rusqlite::params![request.id,envelope.device_id,envelope.algorithm,bytes],
            )?;
        }
        for envelope in &request.ratchet_envelopes {
            let bytes = URL_SAFE_NO_PAD.decode(&envelope.ciphertext).map_err(|_| anyhow::anyhow!("invalid_ratchet_envelopes"))?;
            let digest = hex::decode(&envelope.ciphertext_sha256).map_err(|_| anyhow::anyhow!("invalid_ratchet_envelopes"))?;
            tx.execute(
                "INSERT INTO ratchet_message_envelopes(message_id,recipient_device_id,sender_curve25519_key,session_id,message_type,ciphertext,ciphertext_sha256,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                rusqlite::params![request.id,envelope.recipient_device_id,envelope.sender_curve25519_key,envelope.session_id,envelope.message_type,bytes,digest,now],
            )?;
        }
        if crypto_version >= 2 {
            let consumed = tx.execute(
                "UPDATE message_sequence_reservations SET consumed_at=?1 WHERE request_id=?2 AND consumed_at IS NULL",
                rusqlite::params![now,request.sequence_request_id],
            )?;
            if consumed != 1 { anyhow::bail!("sequence"); }
        }
        tx.commit()?;
        Ok(message_sequence)
    }).await.map_err(|error| {
        let text = error.to_string();
        if text.contains("UNIQUE") || text.contains("unique") { ApiError::conflict("message_exists") }
        else if matches!(text.as_str(), "sequence"|"aad"|"crypto_v1"|"crypto_v2"|"crypto_version"|"downgrade"|"group_key"|"invalid_envelopes"|"invalid_ratchet_envelopes") { ApiError::bad("message_rejected") }
        else { ApiError::Internal(error) }
    })?;
    state.events.bump();
    let envelope_device_ids = req.envelopes.iter().map(|e|e.device_id.clone())
        .chain(req.ratchet_envelopes.iter().map(|e|e.recipient_device_id.clone())).collect::<Vec<_>>();
    Ok((StatusCode::CREATED, Json(json!({"version":crypto_version,"message":{
        "sequence":created,"id":req.id,"chat_id":chat,"sender_username":principal.username,
        "sender_device_id":principal.device_id,"ciphertext":req.ciphertext,"nonce":req.nonce,"aad":req.aad,
        "crypto_version":crypto_version,"room_key_version":if crypto_version==1{1}else{req.room_key_version},
        "aad_version":if crypto_version==1{1}else{req.aad_version},"crypto_sequence":if crypto_version==1{0}else{req.crypto_sequence},
        "encryption_algorithm":if crypto_version==1{"fedmes-aes256gcm-rsa-oaep-v1"}else{req.encryption_algorithm.as_str()},
        "message_type":req.message_type,"created_at":response_created_at,"envelope_device_ids":envelope_device_ids,
        "recipient_count":0,"delivered_count":0,"read_count":0
    }}))))
}

pub async fn update_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((chat, message)): Path<(String,String)>,
    Json(req): Json<MessageWrite>,
) -> ApiResult<StatusCode> {
    let principal = auth::authenticate(&state, &headers, true).await?;
    member(&state, &principal, &chat).await?;
    if message != req.id { return Err(ApiError::bad("message_id_mismatch")); }
    let (cipher, nonce) = validate_message(&req)?;
    let now = util::ts(util::now());
    let chat_id = chat;
    let username = principal.username;
    let device_id = principal.device_id;
    state.db.run(move |conn| {
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: Option<(String,i64)> = tx.query_row(
            "SELECT sender_username,crypto_version FROM messages WHERE id=?1 AND chat_id=?2 AND deleted_at IS NULL",
            rusqlite::params![req.id,chat_id],
            |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional()?;
        let Some((sender,current_crypto)) = current else { anyhow::bail!("notfound"); };
        if sender != username { anyhow::bail!("forbidden"); }

        let (crypto_version, room_key_version, aad_version, crypto_sequence, encryption_algorithm) = if current_crypto <= 1 {
            if req.version != 1 { anyhow::bail!("metadata"); }
            validate_envelope_targets_tx(&tx, &chat_id, Some(&device_id), &req.envelopes)?;
            if !req.ratchet_envelopes.is_empty() { anyhow::bail!("metadata"); }
            (1_i64, 1_i64, 1_i64, 0_i64, "fedmes-aes256gcm-rsa-oaep-v1".to_owned())
        } else {
            if req.crypto_version != 2 { anyhow::bail!("metadata"); }
            validate_crypto_v2_tx(&tx, &req, &chat_id, &username, &device_id, &now)?;
            (2_i64, req.room_key_version, req.aad_version, req.crypto_sequence, req.encryption_algorithm.clone())
        };

        let hash = util::sha256(&cipher).to_vec();
        let changed = tx.execute(
            "UPDATE messages SET sender_device_id=?1,ciphertext=?2,nonce=?3,aad=?4,edited_at=?5,crypto_version=?6,room_key_version=?7,aad_version=?8,crypto_sequence=?9,encryption_algorithm=?10,ciphertext_sha256=?11 WHERE id=?12 AND chat_id=?13 AND sender_username=?14 AND deleted_at IS NULL",
            rusqlite::params![device_id,cipher,nonce,req.aad,now,crypto_version,room_key_version,aad_version,crypto_sequence,encryption_algorithm,hash,req.id,chat_id,username],
        )?;
        if changed != 1 { anyhow::bail!("forbidden"); }
        tx.execute("DELETE FROM message_envelopes WHERE message_id=?1", [&req.id])?;
        tx.execute("DELETE FROM ratchet_message_envelopes WHERE message_id=?1", [&req.id])?;
        for envelope in &req.envelopes {
            let bytes=STANDARD.decode(&envelope.ciphertext).map_err(|_|anyhow::anyhow!("invalid_envelopes"))?;
            tx.execute("INSERT INTO message_envelopes(message_id,device_id,algorithm,ciphertext) VALUES(?1,?2,?3,?4)", rusqlite::params![req.id,envelope.device_id,envelope.algorithm,bytes])?;
        }
        for envelope in &req.ratchet_envelopes {
            let bytes=URL_SAFE_NO_PAD.decode(&envelope.ciphertext).map_err(|_|anyhow::anyhow!("invalid_ratchet_envelopes"))?;
            let digest=hex::decode(&envelope.ciphertext_sha256).map_err(|_|anyhow::anyhow!("invalid_ratchet_envelopes"))?;
            tx.execute("INSERT INTO ratchet_message_envelopes(message_id,recipient_device_id,sender_curve25519_key,session_id,message_type,ciphertext,ciphertext_sha256,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)", rusqlite::params![req.id,envelope.recipient_device_id,envelope.sender_curve25519_key,envelope.session_id,envelope.message_type,bytes,digest,now])?;
        }
        if crypto_version >= 2 {
            let consumed=tx.execute("UPDATE message_sequence_reservations SET consumed_at=?1 WHERE request_id=?2 AND consumed_at IS NULL", rusqlite::params![now,req.sequence_request_id])?;
            if consumed!=1 { anyhow::bail!("sequence"); }
        }
        tx.commit()?;
        Ok(())
    }).await.map_err(|error| match error.to_string().as_str() {
        "notfound" => ApiError::not_found("message_not_found"),
        "forbidden" => ApiError::forbidden("message_update_forbidden"),
        "sequence"|"aad"|"metadata"|"crypto_v2"|"group_key"|"invalid_envelopes"|"invalid_ratchet_envelopes" => ApiError::bad("message_rejected"),
        _ => ApiError::Internal(error),
    })?;
    state.events.bump();
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)] pub struct EnvelopeBatch{version:i64,envelopes:Vec<Envelope>}
pub async fn add_envelopes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((chat,message)): Path<(String,String)>,
    Json(req): Json<EnvelopeBatch>,
) -> ApiResult<StatusCode> {
    let principal = auth::authenticate(&state,&headers,true).await?;
    member(&state,&principal,&chat).await?;
    if req.version!=1 || req.envelopes.is_empty() || req.envelopes.len()>64 { return Err(ApiError::bad("invalid_envelopes")); }
    let chat_id=chat;
    let message_id=message;
    let username=principal.username;
    state.db.run(move|conn| {
        let tx=conn.transaction()?;
        let owner=tx.query_row(
            "SELECT sender_username FROM messages WHERE id=?1 AND chat_id=?2 AND deleted_at IS NULL",
            rusqlite::params![message_id,chat_id], |r|r.get::<_,String>(0),
        ).optional()?;
        let Some(owner)=owner else { anyhow::bail!("notfound"); };
        validate_envelope_targets_tx(&tx,&chat_id,None,&req.envelopes)?;
        if owner!=username {
            for envelope in &req.envelopes {
                let target_username=tx.query_row(
                    "SELECT username FROM provisioning_devices WHERE id=?1 AND revoked_at IS NULL",
                    [&envelope.device_id], |r|r.get::<_,String>(0),
                ).optional()?;
                if target_username.as_deref()!=Some(username.as_str()) { anyhow::bail!("forbidden"); }
            }
        }
        for envelope in &req.envelopes {
            let bytes=STANDARD.decode(&envelope.ciphertext).map_err(|_|anyhow::anyhow!("invalid_envelopes"))?;
            tx.execute(
                "INSERT INTO message_envelopes(message_id,device_id,algorithm,ciphertext) VALUES(?1,?2,?3,?4) ON CONFLICT(message_id,device_id) DO NOTHING",
                rusqlite::params![message_id,envelope.device_id,envelope.algorithm,bytes],
            )?;
        }
        tx.commit()?;
        Ok(())
    }).await.map_err(|error| match error.to_string().as_str() {
        "forbidden" => ApiError::forbidden("envelope_update_forbidden"),
        "notfound" => ApiError::not_found("message_not_found"),
        "invalid_envelopes" => ApiError::bad("invalid_envelopes"),
        _ => ApiError::Internal(error),
    })?;
    state.events.bump();
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat): Path<String>,
    Query(query): Query<MessageQuery>,
) -> ApiResult<Json<Value>> {
    let principal = auth::authenticate(&state, &headers, true).await?;
    member(&state, &principal, &chat).await?;
    let after = query.after.unwrap_or(0).max(0);
    let before = query.before.unwrap_or(0).max(0);
    if after > 0 && before > 0 { return Err(ApiError::bad("invalid_message_cursor")); }
    let limit = query.limit.unwrap_or(100).clamp(1, 200);
    load_messages(&state, &principal, chat, after, before, limit, false).await
}

pub async fn list_envelope_repair_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat): Path<String>,
    Query(query): Query<MessageQuery>,
) -> ApiResult<Json<Value>> {
    let principal = auth::authenticate(&state, &headers, true).await?;
    member(&state, &principal, &chat).await?;
    let before = query.before.unwrap_or(0).max(0);
    let limit = query.limit.unwrap_or(200).clamp(1, 200);
    load_messages(&state, &principal, chat, 0, before, limit, true).await
}

async fn load_messages(
    state: &AppState,
    principal: &Principal,
    chat: String,
    after: i64,
    before: i64,
    limit: i64,
    owned_repair: bool,
) -> ApiResult<Json<Value>> {
    let chat_id = chat.clone();
    let username = principal.username.clone();
    let device_id = principal.device_id.clone();
    let (messages, has_more_before) = state.db.run(move |conn| {
        let mut sql = String::from(r#"
            SELECT
                m.sequence,m.id,m.sender_username,m.sender_device_id,
                m.ciphertext,m.nonce,m.aad,m.created_at,m.edited_at,
                m.crypto_version,m.room_key_version,m.aad_version,m.crypto_sequence,m.encryption_algorithm,
                e.device_id,e.algorithm,e.ciphertext,
                r.recipient_device_id,r.sender_curve25519_key,r.session_id,r.message_type,r.ciphertext,r.ciphertext_sha256,
                COALESCE((SELECT group_concat(all_env.device_id, ',') FROM message_envelopes all_env WHERE all_env.message_id=m.id),''),
                (SELECT COUNT(*) FROM chat_members cm WHERE cm.chat_id=m.chat_id AND cm.username<>m.sender_username),
                (SELECT COUNT(*) FROM chat_read_cursors crc WHERE crc.chat_id=m.chat_id AND crc.username<>m.sender_username AND crc.max_read_sequence>=m.sequence),
                (SELECT COUNT(*) FROM chat_read_cursors crc WHERE crc.chat_id=m.chat_id AND crc.username<>m.sender_username AND crc.max_read_sequence>=m.sequence)
            FROM messages m
            LEFT JOIN message_envelopes e ON e.message_id=m.id AND e.device_id=?1
            LEFT JOIN ratchet_message_envelopes r ON r.message_id=m.id AND r.recipient_device_id=?1
            WHERE m.chat_id=?2 AND m.deleted_at IS NULL
        "#);
        if owned_repair {
            sql.push_str(" AND e.device_id IS NOT NULL");
        }
        sql.push_str(" AND NOT EXISTS(SELECT 1 FROM message_user_deletions d WHERE d.message_id=m.id AND d.username=?3)");

        let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![
            Box::new(device_id.clone()),
            Box::new(chat_id.clone()),
            Box::new(username.clone()),
        ];
        if after > 0 {
            sql.push_str(" AND m.sequence>?4 ORDER BY m.sequence ASC LIMIT ?5");
            params.push(Box::new(after));
            params.push(Box::new(limit));
        } else if before > 0 {
            sql.push_str(" AND m.sequence<?4 ORDER BY m.sequence DESC LIMIT ?5");
            params.push(Box::new(before));
            params.push(Box::new(limit));
        } else {
            sql.push_str(" ORDER BY m.sequence DESC LIMIT ?4");
            params.push(Box::new(limit));
        }
        let refs = params.iter().map(|value| value.as_ref()).collect::<Vec<&dyn rusqlite::ToSql>>();
        let mut statement = conn.prepare(&sql)?;
        let mut rows = statement.query(refs.as_slice())?;
        let mut output = Vec::new();
        while let Some(row) = rows.next()? {
            let sequence: i64 = row.get(0)?;
            let id: String = row.get(1)?;
            let sender_username: String = row.get(2)?;
            let sender_device_id: String = row.get(3)?;
            let ciphertext: Vec<u8> = row.get(4)?;
            let nonce: Vec<u8> = row.get(5)?;
            let aad: String = row.get(6)?;
            let created_at: String = row.get(7)?;
            let edited_at: Option<String> = row.get(8)?;
            let crypto_version: i64 = row.get(9)?;
            let room_key_version: i64 = row.get(10)?;
            let aad_version: i64 = row.get(11)?;
            let crypto_sequence: i64 = row.get(12)?;
            let encryption_algorithm: String = row.get(13)?;

            let envelope = match row.get::<_, Option<String>>(14)? {
                Some(target) => Some(json!({
                    "device_id": target,
                    "algorithm": row.get::<_, String>(15)?,
                    "ciphertext": STANDARD.encode(row.get::<_, Vec<u8>>(16)?),
                })),
                None => None,
            };
            let ratchet_envelope = match row.get::<_, Option<String>>(17)? {
                Some(target) => Some(json!({
                    "recipient_device_id": target,
                    "sender_curve25519_key": row.get::<_, String>(18)?,
                    "session_id": row.get::<_, String>(19)?,
                    "message_type": row.get::<_, i64>(20)?,
                    "ciphertext": URL_SAFE_NO_PAD.encode(row.get::<_, Vec<u8>>(21)?),
                    "ciphertext_sha256": hex::encode(row.get::<_, Vec<u8>>(22)?),
                })),
                None => None,
            };
            let envelope_csv: String = row.get(23)?;
            let envelope_device_ids = if envelope_csv.is_empty() {
                Vec::<String>::new()
            } else {
                envelope_csv.split(',').map(ToOwned::to_owned).collect::<Vec<_>>()
            };
            let recipient_count: i64 = row.get(24)?;
            let delivered_count: i64 = row.get(25)?;
            let read_count: i64 = row.get(26)?;
            let message_type = if crypto_version >= 2 {
                message_type_from_aad(&aad).to_owned()
            } else {
                "legacy".to_owned()
            };
            output.push(json!({
                "sequence": sequence,
                "id": id,
                "chat_id": chat_id,
                "sender_username": sender_username,
                "sender_device_id": sender_device_id,
                "ciphertext": STANDARD.encode(ciphertext),
                "nonce": STANDARD.encode(nonce),
                "aad": aad,
                "created_at": created_at,
                "edited_at": edited_at,
                "crypto_version": crypto_version,
                "room_key_version": room_key_version,
                "aad_version": aad_version,
                "crypto_sequence": crypto_sequence,
                "encryption_algorithm": encryption_algorithm,
                "message_type": message_type,
                "envelope": envelope,
                "ratchet_envelope": ratchet_envelope,
                "envelope_device_ids": envelope_device_ids,
                "recipient_count": recipient_count,
                "delivered_count": delivered_count,
                "read_count": read_count,
            }));
        }
        drop(rows);
        drop(statement);
        if before > 0 || after == 0 { output.reverse(); }
        let oldest = output.first().and_then(|value| value.get("sequence")).and_then(Value::as_i64).unwrap_or(0);
        let has_more = if oldest > 0 {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM messages m WHERE m.chat_id=?1 AND m.sequence<?2 AND m.deleted_at IS NULL AND NOT EXISTS(SELECT 1 FROM message_user_deletions d WHERE d.message_id=m.id AND d.username=?3))",
                rusqlite::params![chat_id, oldest, username],
                |row| row.get::<_, i64>(0),
            )? == 1
        } else { false };
        Ok((output, has_more))
    }).await.map_err(ApiError::Internal)?;
    Ok(Json(json!({"version":1,"messages":messages,"has_more_before":has_more_before})))
}

pub async fn delete_message(State(state):State<AppState>,headers:HeaderMap,Path((chat,message)):Path<(String,String)>,Query(q):Query<MessageQuery>)->ApiResult<StatusCode>{
    let p=auth::authenticate(&state,&headers,true).await?;member(&state,&p,&chat).await?;let scope=q.scope.unwrap_or_else(||"me".into());if scope!="me"&&scope!="everyone"{return Err(ApiError::bad("invalid_delete_scope"));}let now=util::ts(util::now());let u=p.username;let cid=chat;let mid=message;
    let changed=state.db.run(move|c|{if scope=="everyone"{Ok(c.execute("UPDATE messages SET deleted_at=?1 WHERE id=?2 AND chat_id=?3 AND sender_username=?4 AND deleted_at IS NULL",rusqlite::params![now,mid,cid,u])?)}else{Ok(c.execute("INSERT OR IGNORE INTO message_user_deletions(message_id,username,deleted_at) SELECT id,?1,?2 FROM messages WHERE id=?3 AND chat_id=?4",rusqlite::params![u,now,mid,cid])?)} }).await.map_err(ApiError::Internal)?;if changed==0{return Err(ApiError::not_found("message_not_found"));}state.events.bump();Ok(StatusCode::NO_CONTENT)
}

pub async fn receipts(State(state):State<AppState>,headers:HeaderMap,Path(chat):Path<String>,Json(req):Json<ReceiptRequest>)->ApiResult<StatusCode>{let p=auth::authenticate(&state,&headers,true).await?;member(&state,&p,&chat).await?;if req.version!=1||req.delivered_message_ids.len()>200||req.read_message_ids.len()>200{return Err(ApiError::bad("invalid_receipts"));}let now=util::ts(util::now());let user=p.username;let cid=chat;state.db.run(move|c|{let tx=c.transaction()?;for id in req.delivered_message_ids{tx.execute("INSERT INTO message_receipts(message_id,username,delivered_at) SELECT id,?1,?2 FROM messages WHERE id=?3 AND chat_id=?4 ON CONFLICT(message_id,username) DO UPDATE SET delivered_at=COALESCE(message_receipts.delivered_at,excluded.delivered_at)",rusqlite::params![user,now,id,cid])?;}for id in req.read_message_ids{tx.execute("INSERT INTO message_receipts(message_id,username,delivered_at,read_at) SELECT id,?1,?2,?2 FROM messages WHERE id=?3 AND chat_id=?4 ON CONFLICT(message_id,username) DO UPDATE SET delivered_at=COALESCE(message_receipts.delivered_at,excluded.delivered_at),read_at=COALESCE(message_receipts.read_at,excluded.read_at)",rusqlite::params![user,now,id,cid])?;}tx.commit()?;Ok(())}).await.map_err(ApiError::Internal)?;state.events.bump();Ok(StatusCode::NO_CONTENT)}

pub async fn read_cursor(State(state):State<AppState>,headers:HeaderMap,Path(chat):Path<String>,Json(req):Json<ReadCursorRequest>)->ApiResult<Json<Value>>{let p=auth::authenticate(&state,&headers,true).await?;member(&state,&p,&chat).await?;if req.version!=1||req.max_read_sequence<=0{return Err(ApiError::bad("invalid_read_cursor"));}let cid=chat;let user=p.username;let requested=req.max_read_sequence;let now=util::ts(util::now());let accepted=state.db.run(move|c|{let clamped=c.query_row("SELECT COALESCE(MAX(sequence),0) FROM messages WHERE chat_id=?1 AND sequence<=?2 AND deleted_at IS NULL",rusqlite::params![cid,requested],|r|r.get::<_,i64>(0))?;if clamped==0{anyhow::bail!("invalid")};c.execute("INSERT INTO chat_read_cursors(chat_id,username,max_read_sequence,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(chat_id,username) DO UPDATE SET max_read_sequence=MAX(chat_read_cursors.max_read_sequence,excluded.max_read_sequence),updated_at=CASE WHEN excluded.max_read_sequence>chat_read_cursors.max_read_sequence THEN excluded.updated_at ELSE chat_read_cursors.updated_at END",rusqlite::params![cid,user,clamped,now])?;Ok(clamped)}).await.map_err(|e|if e.to_string()=="invalid"{ApiError::bad("invalid_read_cursor")}else{ApiError::Internal(e)})?;state.events.bump();Ok(Json(json!({"version":1,"max_read_sequence":accepted})))}

pub async fn set_typing(State(state):State<AppState>,headers:HeaderMap,Path(chat):Path<String>,Json(req):Json<TypingRequest>)->ApiResult<StatusCode>{let p=auth::authenticate(&state,&headers,true).await?;member(&state,&p,&chat).await?;if req.version!=1{return Err(ApiError::bad("invalid_typing"));}let cid=chat;let user=p.username;let now=util::now();let updated=util::ts(now);let exp=util::ts(now+Duration::seconds(6));state.db.run(move|c|{if req.typing{c.execute("INSERT INTO typing_state(chat_id,username,expires_at,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(chat_id,username) DO UPDATE SET expires_at=excluded.expires_at,updated_at=excluded.updated_at",rusqlite::params![cid,user,exp,updated])?;}else{c.execute("DELETE FROM typing_state WHERE chat_id=?1 AND username=?2",rusqlite::params![cid,user])?;}Ok(())}).await.map_err(ApiError::Internal)?;state.events.bump();Ok(StatusCode::NO_CONTENT)}

pub async fn list_typing(State(state):State<AppState>,headers:HeaderMap,Path(chat):Path<String>)->ApiResult<Json<Value>>{let p=auth::authenticate(&state,&headers,true).await?;member(&state,&p,&chat).await?;let cid=chat;let user=p.username;let now=util::ts(util::now());let values=state.db.run(move|c|{let mut s=c.prepare("SELECT username FROM typing_state WHERE chat_id=?1 AND username<>?2 AND expires_at>?3 ORDER BY username")?;let rows=s.query_map(rusqlite::params![cid,user,now],|r|Ok(json!({"username":r.get::<_,String>(0)?})))?.collect::<Result<Vec<_>,_>>()?;Ok(rows)}).await.map_err(ApiError::Internal)?;Ok(Json(json!({"version":1,"typing":values})))}

pub async fn pin(State(state):State<AppState>,headers:HeaderMap,Path((chat,message)):Path<(String,String)>)->ApiResult<StatusCode>{let p=auth::authenticate(&state,&headers,true).await?;member(&state,&p,&chat).await?;let now=util::ts(util::now());let user=p.username;state.db.run(move|c|{let exists=c.query_row("SELECT EXISTS(SELECT 1 FROM messages WHERE id=?1 AND chat_id=?2 AND deleted_at IS NULL)",rusqlite::params![message,chat],|r|r.get::<_,i64>(0))?;if exists!=1{anyhow::bail!("notfound")};c.execute("INSERT INTO pinned_messages(chat_id,message_id,pinned_by,pinned_at) VALUES(?1,?2,?3,?4) ON CONFLICT(chat_id) DO UPDATE SET message_id=excluded.message_id,pinned_by=excluded.pinned_by,pinned_at=excluded.pinned_at",rusqlite::params![chat,message,user,now])?;Ok(())}).await.map_err(|e|if e.to_string()=="notfound"{ApiError::not_found("message_not_found")}else{ApiError::Internal(e)})?;state.events.bump();Ok(StatusCode::NO_CONTENT)}
pub async fn unpin(State(state):State<AppState>,headers:HeaderMap,Path(chat):Path<String>)->ApiResult<StatusCode>{let p=auth::authenticate(&state,&headers,true).await?;member(&state,&p,&chat).await?;state.db.run(move|c|{c.execute("DELETE FROM pinned_messages WHERE chat_id=?1",[chat])?;Ok(())}).await.map_err(ApiError::Internal)?;state.events.bump();Ok(StatusCode::NO_CONTENT)}

pub async fn heartbeat(State(state):State<AppState>,headers:HeaderMap,Json(req):Json<HeartbeatRequest>)->ApiResult<StatusCode>{let p=auth::authenticate(&state,&headers,true).await?;if req.version!=1{return Err(ApiError::bad("invalid_request"));}let now=util::ts(util::now());let u=p.username;let exact=if req.show_exact{1}else{0};state.db.run(move|c|{c.execute("UPDATE presence SET last_seen_at=?1,show_exact=?2,updated_at=?1 WHERE username=?3",rusqlite::params![now,exact,u])?;Ok(())}).await.map_err(ApiError::Internal)?;Ok(StatusCode::NO_CONTENT)}

pub async fn presence(State(state):State<AppState>,headers:HeaderMap)->ApiResult<Json<Value>>{let p=auth::authenticate(&state,&headers,true).await?;let viewer=p.username;let now=util::now();let list=state.db.run(move|c|{let mut s=c.prepare("SELECT username,last_seen_at,show_exact FROM presence ORDER BY username")?;let mut rows=s.query([])?;let mut out=Vec::new();while let Some(r)=rows.next()?{let u:String=r.get(0)?;let last:Option<String>=r.get(1)?;let exact:i64=r.get(2)?;let parsed=last.as_deref().and_then(|x|util::parse_ts(x).ok());let online=parsed.map(|t|(now-t).num_seconds()<=45).unwrap_or(false);let category=if online{"online"}else if let Some(t)=parsed{let d=(now.date_naive()-t.date_naive()).num_days();if d==0{"today"}else if d==1{"yesterday"}else if d<=7{"recently"}else{"long_ago"}}else{"long_ago"};out.push(json!({"username":u,"online":online,"last_seen_at":if exact==1||u==viewer{last}else{None},"show_exact":exact==1,"last_seen_category":category}));}Ok(out)}).await.map_err(ApiError::Internal)?;Ok(Json(json!({"version":1,"presence":list})))}

pub async fn events(State(state):State<AppState>,headers:HeaderMap,Query(q):Query<EventQuery>)->ApiResult<Json<Value>>{
    let _=auth::authenticate(&state,&headers,true).await?;
    let after=q.after.unwrap_or(0).max(0);
    let current=state.events.current();
    // A persisted client cursor can be ahead after a VM snapshot restore or wall-clock
    // correction. Return immediately and force a snapshot refresh instead of long-polling
    // forever against a sequence the process can never reach in reasonable time.
    if after>current {
        return Ok(Json(json!({"version":1,"sequence":current,"changed":true,"reset":true,"server_time_ms":chrono::Utc::now().timestamp_millis()})));
    }
    // Backward-compatible long poll with an explicit bounded timeout. 30 s remains the default.
    let timeout_ms=q.timeout_ms.unwrap_or(30_000).clamp(1_000,45_000);
    let seq=state.events.wait_after(after,std::time::Duration::from_millis(timeout_ms)).await;
    Ok(Json(json!({"version":1,"sequence":seq,"changed":seq!=after,"reset":false,"server_time_ms":chrono::Utc::now().timestamp_millis()})))
}

pub async fn events_current(State(state):State<AppState>,headers:HeaderMap)->ApiResult<Json<Value>>{
    let _=auth::authenticate(&state,&headers,true).await?;
    Ok(Json(json!({"version":1,"sequence":state.events.current(),"server_time_ms":chrono::Utc::now().timestamp_millis()})))
}

fn media_path(root:&PathBuf,id:&str)->PathBuf{root.join(format!("{}.blob",id))}
pub async fn upload_media(
    State(state): State<AppState>,
    Path((chat, id)): Path<(String, String)>,
    request: Request,
) -> ApiResult<StatusCode> {
    let p = auth::authenticate(&state, request.headers(), true).await?;
    member(&state, &p, &chat).await?;
    if !util::canonical_uuid(&id) {
        return Err(ApiError::bad("invalid_media"));
    }
    let content_type = request.headers().get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok()).unwrap_or("");
    if !content_type.to_ascii_lowercase().starts_with("application/octet-stream") {
        return Err(ApiError::Public(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type"));
    }
    const MAX_MEDIA_BYTES: u64 = 256 * 1024 * 1024;
    if request.headers().get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v == 0 || v > MAX_MEDIA_BYTES)
        .unwrap_or(false)
    {
        return Err(ApiError::bad("invalid_media"));
    }

    tokio::fs::create_dir_all(&state.config.media_dir).await.map_err(|e| ApiError::Internal(e.into()))?;
    let path = media_path(&state.config.media_dir, &id);
    if tokio::fs::try_exists(&path).await.map_err(|e| ApiError::Internal(e.into()))? {
        return Err(ApiError::conflict("media_exists"));
    }
    let tmp = state.config.media_dir.join(format!(".{}.{}.part", id, uuid::Uuid::new_v4()));
    let raw_file = tokio::fs::OpenOptions::new().write(true).create_new(true).open(&tmp).await
        .map_err(|e| ApiError::Internal(e.into()))?;
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await
            .map_err(|e| ApiError::Internal(e.into()))?;
    }

    // Large encrypted media is written through a bounded userspace buffer. This avoids one
    // filesystem write per HTTP frame without ever buffering the whole object in RAM.
    let mut file = BufWriter::with_capacity(512 * 1024, raw_file);
    let mut body = request.into_body();
    let mut total: u64 = 0;
    let mut hasher = Sha256::new();
    let write_result: Result<(), ApiError> = async {
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| ApiError::Internal(anyhow::anyhow!("media body: {e}")))?;
            if let Ok(data) = frame.into_data() {
                if data.is_empty() { continue; }
                total = total.saturating_add(data.len() as u64);
                if total > MAX_MEDIA_BYTES { return Err(ApiError::bad("media_too_large")); }
                hasher.update(&data);
                file.write_all(&data).await.map_err(|e| ApiError::Internal(e.into()))?;
            }
        }
        if total == 0 { return Err(ApiError::bad("invalid_media")); }
        file.flush().await.map_err(|e| ApiError::Internal(e.into()))?;
        // Ciphertext bytes are durable before the database row becomes reachable. sync_data is
        // enough here because the final filename is committed atomically below.
        file.get_ref().sync_data().await.map_err(|e| ApiError::Internal(e.into()))?;
        Ok(())
    }.await;
    drop(file);
    if let Err(error) = write_result {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(error);
    }
    // Never use rename() as create-if-absent here: on Unix it can replace an existing
    // destination. A hard link in the same directory is atomic and fails when the final
    // object already exists, so two concurrent uploads cannot overwrite one another.
    match tokio::fs::hard_link(&tmp, &path).await {
        Ok(()) => { let _ = tokio::fs::remove_file(&tmp).await; }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(ApiError::conflict("media_exists"));
        }
        Err(error) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(ApiError::Internal(error.into()));
        }
    }

    let hash = hasher.finalize().to_vec();
    let now = util::ts(util::now());
    let cid = chat;
    let mid = id.clone();
    let user = p.username;
    let did = p.device_id;
    let size = total as i64;
    let insert = match state.db.run(move |c| {
        let changed = c.execute(
            "INSERT INTO media_objects(id,chat_id,uploader_username,uploader_device_id,blob_name,size_bytes,sha256_digest,created_at,crypto_version,encryption_algorithm,ciphertext_sha256) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,2,'fedmes-blob-v2',?7) ON CONFLICT(id) DO NOTHING",
            rusqlite::params![mid,cid,user,did,format!("{}.blob",mid),size,hash,now])?;
        Ok(changed)
    }).await {
        Ok(value) => value,
        Err(error) => {
            // A successful atomic link followed by a database failure must not leave an orphaned
            // ciphertext object behind. The DB remains the source of truth for blob reachability.
            let _ = tokio::fs::remove_file(&path).await;
            return Err(ApiError::Internal(error));
        }
    };
    if insert != 1 {
        let _ = tokio::fs::remove_file(&path).await;
        return Err(ApiError::conflict("media_exists"));
    }
    state.events.bump();
    Ok(StatusCode::CREATED)
}

pub async fn download_media(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((chat, id)): Path<(String, String)>,
) -> ApiResult<Response> {
    let p = auth::authenticate(&state, &headers, true).await?;
    member(&state, &p, &chat).await?;
    let cid = chat;
    let mid = id.clone();
    let expected_size = state.db.run(move |c| {
        Ok(c.query_row(
            "SELECT size_bytes FROM media_objects WHERE id=?1 AND chat_id=?2 AND deleted_at IS NULL",
            rusqlite::params![mid,cid], |r| r.get::<_,i64>(0)).optional()?)
    }).await.map_err(ApiError::Internal)?.ok_or_else(|| ApiError::not_found("media_not_found"))?;
    let file = tokio::fs::File::open(media_path(&state.config.media_dir, &id)).await
        .map_err(|_| ApiError::not_found("media_not_found"))?;
    let meta = file.metadata().await.map_err(|_| ApiError::not_found("media_not_found"))?;
    if meta.len() != expected_size as u64 { return Err(ApiError::Internal(anyhow::anyhow!("media size mismatch"))); }
    let stream = ReaderStream::with_capacity(file, 512 * 1024);
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    if let Ok(value) = HeaderValue::from_str(&expected_size.to_string()) {
        response.headers_mut().insert(header::CONTENT_LENGTH, value);
    }
    Ok(response)
}

pub async fn delete_media(State(state):State<AppState>,headers:HeaderMap,Path((chat,id)):Path<(String,String)>)->ApiResult<StatusCode>{let p=auth::authenticate(&state,&headers,true).await?;member(&state,&p,&chat).await?;let cid=chat;let mid=id.clone();let now=util::ts(util::now());let n=state.db.run(move|c|Ok(c.execute("UPDATE media_objects SET deleted_at=?1 WHERE id=?2 AND chat_id=?3 AND deleted_at IS NULL",rusqlite::params![now,mid,cid])?)).await.map_err(ApiError::Internal)?;if n==0{return Err(ApiError::not_found("media_not_found"));}let _=tokio::fs::remove_file(media_path(&state.config.media_dir,&id)).await;state.events.bump();Ok(StatusCode::NO_CONTENT)}
