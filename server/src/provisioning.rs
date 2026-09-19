use crate::{auth, error::{ApiError,ApiResult}, util, AppState};
use axum::{extract::State, http::{HeaderMap,StatusCode}, Json};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Duration;
use rusqlite::OptionalExtension;
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};

#[derive(Deserialize)] struct PublicKeyInput{algorithm:String,public_key_spki:String}
#[derive(Deserialize)] pub struct RedeemRequest{version:i64,idempotency_key:Option<String>,username:String,device:PublicKeyInput,encryption:PublicKeyInput,token:String}
#[derive(Deserialize)] pub struct ChallengeRequest{version:i64,username:String,device:PublicKeyInput,purpose:String}
#[derive(Deserialize)] pub struct SessionRequest{version:i64,username:String,device_id:String,challenge_id:String,nonce:String,purpose:String,signature:String}
#[derive(Deserialize)] pub struct BootstrapCommitRequest{version:i64,signature:String}
#[derive(Serialize)] struct DeviceView<'a>{id:&'a str,username:&'a str,key_algorithm:&'a str,key_fingerprint:String,bound_by_invitation_id:&'a str,bound_at:&'a str}

pub async fn redeem(State(state):State<AppState>,Json(req):Json<RedeemRequest>)->ApiResult<(StatusCode,Json<Value>)>{
    if req.version!=3 || !util::valid_user(&req.username) { return Err(ApiError::bad("invalid_request")); }
    let token=util::decode_b64url(&req.token,64).map_err(|_|ApiError::bad("invalid_invitation_token"))?;
    if token.len()!=32 { return Err(ApiError::bad("invalid_invitation_token")); }
    let identity=STANDARD.decode(&req.device.public_key_spki).map_err(|_|ApiError::bad("invalid_device_key"))?;
    let encryption=STANDARD.decode(&req.encryption.public_key_spki).map_err(|_|ApiError::bad("invalid_encryption_key"))?;
    if !auth::validate_identity_key(&req.device.algorithm,&identity){return Err(ApiError::bad("invalid_device_key"));}
    if !auth::validate_encryption_key(&req.encryption.algorithm,&encryption){return Err(ApiError::bad("invalid_encryption_key"));}
    let idem=req.idempotency_key.clone().unwrap_or_else(||util::b64url(&util::random_bytes(32)));
    if idem.len()<16 || idem.len()>128 { return Err(ApiError::bad("invalid_request")); }

    let token_digest=util::sha256(&token).to_vec();
    let identity_fp=util::sha256(&identity).to_vec();
    let identity_fp_hex=hex::encode(&identity_fp);
    let enc_fp=util::sha256(&encryption).to_vec();
    let request_digest=auth::request_digest(&[req.username.as_bytes(),&token_digest,&identity_fp,&enc_fp]).to_vec();
    let now=util::now();
    let now_s=util::ts(now);
    let session_exp=util::ts(now+Duration::minutes(15));
    let device_id=uuid::Uuid::new_v4().to_string();
    let session_id=uuid::Uuid::new_v4().to_string();
    let session_token=util::random_token();
    let sess_raw=util::decode_b64url(&session_token,64)?;
    let sess_digest=util::sha256(&sess_raw).to_vec();

    let db_username=req.username.clone();
    let db_key_algo=req.device.algorithm.clone();
    let db_enc_algo=req.encryption.algorithm.clone();
    let db_device_id=device_id.clone();
    let db_session_id=session_id.clone();
    let db_now=now_s.clone();
    let db_session_exp=session_exp.clone();
    let out=state.db.run(move|c|{
        let tx=c.transaction()?;
        let invitation=tx.query_row("SELECT id,username,created_at,expires_at,redeemed_at FROM provisioning_invitations WHERE token_digest=?1",[&token_digest],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,Option<String>>(4)?))).optional()?;
        let Some((invite_id,invite_user,created_at,expires_at,redeemed_at))=invitation else{anyhow::bail!("invalid_invitation_token")};
        if invite_user!=db_username { anyhow::bail!("invitation_user_mismatch"); }
        if redeemed_at.is_some() { anyhow::bail!("invitation_used"); }
        if util::parse_ts(&expires_at)?<=util::now() { anyhow::bail!("invitation_expired"); }
        let ready:i64=tx.query_row("SELECT COUNT(*) FROM provisioning_devices WHERE username=?1 AND revoked_at IS NULL AND security_state='READY'",[&db_username],|r|r.get(0))?;
        let security_state=if ready==0{"REGISTRATION_PENDING"}else{"AUTHENTICATED_NO_KEYS"};
        tx.execute("INSERT INTO provisioning_devices(id,username,invitation_id,key_algorithm,public_key_spki,public_key_fingerprint,bound_at,display_name,platform,security_state) VALUES(?1,?2,?3,?4,?5,?6,?7,'Android','android',?8)",rusqlite::params![db_device_id,db_username,invite_id,db_key_algo,identity,identity_fp,db_now,security_state])?;
        tx.execute("INSERT INTO device_encryption_keys(device_id,algorithm,public_key_spki,fingerprint,registered_at) VALUES(?1,?2,?3,?4,?5)",rusqlite::params![db_device_id,db_enc_algo,encryption,enc_fp,db_now])?;
        tx.execute("INSERT INTO device_keys(device_id,purpose,algorithm,public_key_spki,fingerprint,created_at) VALUES(?1,'signing',?2,?3,?4,?5)",rusqlite::params![db_device_id,db_key_algo,identity,identity_fp,db_now])?;
        tx.execute("INSERT INTO device_keys(device_id,purpose,algorithm,public_key_spki,fingerprint,created_at) VALUES(?1,'key_agreement',?2,?3,?4,?5)",rusqlite::params![db_device_id,db_enc_algo,encryption,enc_fp,db_now])?;
        tx.execute("INSERT INTO provisioning_sessions(id,device_id,token_digest,issued_at,expires_at,protocol_version,authentication_method) VALUES(?1,?2,?3,?4,?5,4,'device_signature')",rusqlite::params![db_session_id,db_device_id,sess_digest,db_now,db_session_exp])?;
        let changed=tx.execute("UPDATE provisioning_invitations SET redeemed_at=?1,redeemed_by_device_id=?2 WHERE id=?3 AND redeemed_at IS NULL",rusqlite::params![db_now,db_device_id,invite_id])?;
        if changed!=1 { anyhow::bail!("invitation_used"); }
        tx.execute("INSERT OR IGNORE INTO account_security_state(username,state,protocol_version,crypto_version,vault_revision,updated_at) VALUES(?1,'READY',4,2,0,?2)",rusqlite::params![db_username,db_now])?;
        if ready == 0 {
            tx.execute("UPDATE account_security_state SET state='REGISTRATION_PENDING',protocol_version=MAX(protocol_version,4),crypto_version=MAX(crypto_version,2),updated_at=?1 WHERE username=?2",rusqlite::params![db_now,db_username])?;
        } else {
            tx.execute("UPDATE account_security_state SET state='AUTHENTICATED_NO_KEYS',updated_at=?1 WHERE username=?2",rusqlite::params![db_now,db_username])?;
            let rid=uuid::Uuid::new_v4().to_string();
            let expires_req=util::ts(util::now()+Duration::minutes(15));
            tx.execute("INSERT INTO device_provisioning_requests(id,username,target_device_id,request_digest,protocol_version,requested_at,expires_at,display_name,platform,network_hint) VALUES(?1,?2,?3,?4,4,?5,?6,'Android','android','')",rusqlite::params![rid,db_username,db_device_id,request_digest,db_now,expires_req])?;
        }
        tx.execute("INSERT INTO security_audit_events(event_id,username,device_id,event_type,outcome,protocol_version,occurred_at,metadata) VALUES(?1,?2,?3,'device.registration','success',4,?4,'{}')",rusqlite::params![uuid::Uuid::new_v4().to_string(),db_username,db_device_id,db_now])?;
        tx.commit()?;
        Ok((invite_id,created_at,expires_at,security_state.to_string()))
    }).await.map_err(map_db_error)?;
    state.events.bump();
    let (invite_id,created_at,expires_at,security_state)=out;
    let _ = (created_at, expires_at);
    Ok((StatusCode::CREATED,Json(json!({
        "version":3,
        "device":{"id":device_id,"username":req.username,"key_algorithm":req.device.algorithm,"key_fingerprint":identity_fp_hex,"bound_by_invitation_id":invite_id,"bound_at":now_s},
        "session":{"id":session_id,"token":session_token,"issued_at":now_s,"expires_at":session_exp},
        "authentication_state":security_state
    }))))
}

fn map_db_error(e:anyhow::Error)->ApiError{
    let s=e.to_string();
    match s.as_str(){
        "invalid_invitation_token"=>ApiError::bad("invalid_invitation_token"),
        "invitation_user_mismatch"=>ApiError::bad("invitation_user_mismatch"),
        "invitation_used"=>ApiError::conflict("invitation_used"),
        "invitation_expired"=>ApiError::Public(StatusCode::GONE,"invitation_expired"),
        "challenge_used"=>ApiError::conflict("challenge_used"),
        _=>ApiError::Internal(e),
    }
}

pub async fn bootstrap_commit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<BootstrapCommitRequest>,
) -> ApiResult<Json<Value>> {
    if req.version != 1 { return Err(ApiError::bad("invalid_request")); }
    let principal = auth::authenticate(&state, &headers, false).await?;
    if principal.security_state != "REGISTRATION_PENDING" {
        if principal.security_state == "READY" {
            return Ok(Json(json!({"version":1,"authentication_state":"READY"})));
        }
        return Err(ApiError::conflict("bootstrap_not_pending"));
    }
    let signature = STANDARD.decode(&req.signature).map_err(|_| ApiError::unauthorized("invalid_signature"))?;
    if signature.is_empty() || signature.len() > 256 { return Err(ApiError::unauthorized("invalid_signature")); }
    let device_id = principal.device_id.clone();
    let username = principal.username.clone();
    let key = state.db.run({
        let device_id = device_id.clone();
        move |conn| {
            Ok(conn.query_row(
                "SELECT key_algorithm,public_key_spki FROM provisioning_devices WHERE id=?1 AND revoked_at IS NULL",
                [&device_id],
                |row| Ok((row.get::<_,String>(0)?, row.get::<_,Vec<u8>>(1)?)),
            ).optional()?)
        }
    }).await.map_err(ApiError::Internal)?.ok_or_else(|| ApiError::unauthorized("device_not_found"))?;
    let payload = auth::canonical_bootstrap_payload(&state.config.public_url, &username, &device_id, &principal.session_id);
    if !auth::verify_signature(&key.0, &key.1, &payload, &signature) {
        return Err(ApiError::unauthorized("invalid_signature"));
    }
    let now = util::ts(util::now());
    let commit_device = device_id.clone();
    let commit_user = username.clone();
    state.db.run(move |conn| {
        let tx = conn.transaction()?;
        let current = tx.query_row(
            "SELECT security_state FROM provisioning_devices WHERE id=?1 AND username=?2 AND revoked_at IS NULL",
            rusqlite::params![commit_device, commit_user],
            |row| row.get::<_,String>(0),
        ).optional()?.ok_or_else(|| anyhow::anyhow!("notfound"))?;
        if current == "READY" { tx.commit()?; return Ok(()); }
        if current != "REGISTRATION_PENDING" { anyhow::bail!("state"); }
        let ready_count:i64 = tx.query_row(
            "SELECT COUNT(*) FROM provisioning_devices WHERE username=?1 AND id<>?2 AND revoked_at IS NULL AND security_state='READY'",
            rusqlite::params![commit_user, commit_device], |row| row.get(0),
        )?;
        if ready_count != 0 { anyhow::bail!("closed"); }
        tx.execute(
            "UPDATE provisioning_devices SET security_state='READY',approved_at=COALESCE(approved_at,?1) WHERE id=?2 AND username=?3 AND security_state='REGISTRATION_PENDING'",
            rusqlite::params![now, commit_device, commit_user],
        )?;
        // Abandoned first-device registrations never become trusted later. Once one bootstrap
        // commits, all sibling REGISTRATION_PENDING devices are revoked atomically.
        tx.execute(
            "UPDATE provisioning_devices SET security_state='REVOKED',revoked_at=COALESCE(revoked_at,?1) WHERE username=?2 AND id<>?3 AND security_state='REGISTRATION_PENDING' AND revoked_at IS NULL",
            rusqlite::params![now, commit_user, commit_device],
        )?;
        tx.execute(
            "UPDATE provisioning_sessions SET revoked_at=COALESCE(revoked_at,?1) WHERE device_id IN (SELECT id FROM provisioning_devices WHERE username=?2 AND id<>?3 AND security_state='REVOKED') AND revoked_at IS NULL",
            rusqlite::params![now, commit_user, commit_device],
        )?;
        tx.execute(
            "UPDATE account_security_state SET state='READY',protocol_version=MAX(protocol_version,4),crypto_version=MAX(crypto_version,2),last_ready_device_id=?1,updated_at=?2 WHERE username=?3",
            rusqlite::params![commit_device, now, commit_user],
        )?;
        tx.execute(
            "INSERT INTO security_audit_events(event_id,username,device_id,event_type,outcome,protocol_version,occurred_at,metadata) VALUES(?1,?2,?3,'device.bootstrap_commit','success',4,?4,'{}')",
            rusqlite::params![uuid::Uuid::new_v4().to_string(), commit_user, commit_device, now],
        )?;
        tx.commit()?;
        Ok(())
    }).await.map_err(|error| match error.to_string().as_str() {
        "notfound" => ApiError::unauthorized("device_not_found"),
        "state" => ApiError::conflict("bootstrap_not_pending"),
        "closed" => ApiError::conflict("bootstrap_closed"),
        _ => ApiError::Internal(error),
    })?;
    state.events.bump();
    Ok(Json(json!({"version":1,"authentication_state":"READY"})))
}

pub async fn challenge(State(state):State<AppState>,headers:HeaderMap,Json(req):Json<ChallengeRequest>)->ApiResult<(StatusCode,Json<Value>)>{
    if req.version!=1 || req.purpose!="session.refresh" || !util::valid_user(&req.username){return Err(ApiError::bad("invalid_request"));}
    let der=STANDARD.decode(&req.device.public_key_spki).map_err(|_|ApiError::bad("invalid_device_key"))?;
    if !auth::validate_identity_key(&req.device.algorithm,&der){return Err(ApiError::bad("invalid_device_key"));}
    let fp=util::sha256(&der).to_vec(); let username=req.username.clone();
    let device_id=state.db.run(move|c|Ok(c.query_row("SELECT id FROM provisioning_devices WHERE username=?1 AND public_key_fingerprint=?2 AND revoked_at IS NULL",rusqlite::params![username,fp],|r|r.get::<_,String>(0)).optional()?)).await.map_err(ApiError::Internal)?.ok_or_else(||ApiError::unauthorized("device_not_found"))?;
    let audience=headers.get("host").and_then(|v|v.to_str().ok()).unwrap_or_default().to_string(); if audience.is_empty(){return Err(ApiError::bad("invalid_request"));}
    let id=uuid::Uuid::new_v4().to_string(); let nonce=util::random_token(); let nonce_raw=util::decode_b64url(&nonce,64)?; let digest=util::sha256(&nonce_raw).to_vec();
    let created=util::now(); let expires=created+Duration::seconds(10); let created_s=util::ts(created); let expires_s=util::ts(expires); let purpose=req.purpose.clone(); let did=device_id.clone(); let cid=id.clone(); let aud=audience.clone();
    state.db.run(move|c|{c.execute("INSERT INTO provisioning_challenges(id,device_id,nonce_digest,audience,purpose,created_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",rusqlite::params![cid,did,digest,aud,purpose,created_s,expires_s])?;Ok(())}).await.map_err(ApiError::Internal)?;
    Ok((StatusCode::CREATED,Json(json!({"version":1,"challenge":{"id":id,"device_id":device_id,"audience":audience,"purpose":"session.refresh","nonce":nonce,"expires_at":util::ts(expires)}}))))
}

pub async fn session(State(state):State<AppState>,headers:HeaderMap,Json(req):Json<SessionRequest>)->ApiResult<(StatusCode,Json<Value>)>{
    if req.version!=1 || req.purpose!="session.refresh" || !util::valid_user(&req.username){return Err(ApiError::bad("invalid_request"));}
    let audience=headers.get("host").and_then(|v|v.to_str().ok()).unwrap_or_default().to_string();
    if audience.is_empty(){return Err(ApiError::bad("invalid_request"));}
    let username=req.username.clone(); let did=req.device_id.clone(); let cid=req.challenge_id.clone();
    let row=state.db.run(move|c|Ok(c.query_row("SELECT ch.nonce_digest,ch.audience,ch.purpose,ch.expires_at,ch.consumed_at,d.key_algorithm,d.public_key_spki,d.security_state FROM provisioning_challenges ch JOIN provisioning_devices d ON d.id=ch.device_id WHERE ch.id=?1 AND d.id=?2 AND d.username=?3 AND d.revoked_at IS NULL",rusqlite::params![cid,did,username],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,String>(5)?,r.get::<_,Vec<u8>>(6)?,r.get::<_,String>(7)?))).optional()?)).await.map_err(ApiError::Internal)?.ok_or_else(||ApiError::unauthorized("challenge_not_found"))?;
    if row.4.is_some(){return Err(ApiError::conflict("challenge_used"));}
    if util::parse_ts(&row.3).map_err(ApiError::Internal)?<=util::now(){return Err(ApiError::unauthorized("challenge_expired"));}
    if row.1!=audience || row.2!=req.purpose{return Err(ApiError::unauthorized("challenge_context"));}
    let nonce=util::decode_b64url(&req.nonce,64)?;
    if &util::sha256(&nonce)[..]!=row.0.as_slice(){return Err(ApiError::unauthorized("challenge_context"));}
    let signature=STANDARD.decode(&req.signature).map_err(|_|ApiError::unauthorized("invalid_signature"))?;
    let payload=auth::canonical_auth_payload(&audience,&req.username,&req.device_id,&req.challenge_id,&req.purpose,&req.nonce);
    if !auth::verify_signature(&row.5,&row.6,&payload,&signature){return Err(ApiError::unauthorized("invalid_signature"));}
    let sid=uuid::Uuid::new_v4().to_string(); let token=util::random_token(); let raw=util::decode_b64url(&token,64)?; let digest=util::sha256(&raw).to_vec();
    let issued=util::now(); let exp=issued+Duration::minutes(15); let issued_s=util::ts(issued); let exp_s=util::ts(exp);
    let db_issued=issued_s.clone(); let db_exp=exp_s.clone(); let cid2=req.challenge_id.clone(); let did2=req.device_id.clone(); let sid2=sid.clone();
    state.db.run(move|c|{let tx=c.transaction()?;let changed=tx.execute("UPDATE provisioning_challenges SET consumed_at=?1 WHERE id=?2 AND consumed_at IS NULL",rusqlite::params![db_issued,cid2])?;if changed!=1{anyhow::bail!("challenge_used")};tx.execute("INSERT INTO provisioning_sessions(id,device_id,token_digest,issued_at,expires_at,protocol_version,authentication_method) VALUES(?1,?2,?3,?4,?5,4,'device_signature')",rusqlite::params![sid2,did2,digest,db_issued,db_exp])?;tx.commit()?;Ok(())}).await.map_err(map_db_error)?;
    Ok((StatusCode::CREATED,Json(json!({"version":1,"device":{"id":req.device_id,"username":req.username,"key_algorithm":row.5,"key_fingerprint":hex::encode(util::sha256(&row.6)),"bound_by_invitation_id":"","bound_at":issued_s},"session":{"id":sid,"token":token,"issued_at":issued_s,"expires_at":exp_s},"authentication_state":row.7}))))
}

