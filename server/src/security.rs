use crate::{auth, error::{ApiError,ApiResult}, util, AppState};
use axum::{extract::{Path,State}, http::{HeaderMap,StatusCode}, Json};
use base64::{engine::general_purpose::STANDARD,Engine as _};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::{json,Value};

#[derive(Deserialize)]pub struct VaultWrite{version:i64,expected_previous_revision:i64,vault_version:i64,crypto_version:i64,aad_version:i64,nonce:String,ciphertext:String,ciphertext_sha256:String,access_verifier:String}
#[derive(Deserialize)]pub struct RecoveryWrite{version:i64,id:String,vault_revision:i64,package_version:i64,crypto_version:i64,aad_version:i64,kdf_name:String,kdf_parameters:String,salt:String,nonce:String,ciphertext:String,ciphertext_sha256:String}
#[derive(Deserialize)]pub struct CompleteRecovery{version:i64,vault_revision:i64,access_verifier:String}
#[derive(Deserialize)]pub struct VersionOnly{version:i64}
#[derive(Deserialize)]pub struct ApproveDevice{version:i64,certificate_id:String,certificate_version:i64,certificate_payload:String,certificate_signature:String,signature_algorithm:String,encrypted_package:String,nonce:String,aad_version:i64,package_version:i64,request_signature:String}

pub async fn state(State(state):State<AppState>,headers:HeaderMap)->ApiResult<Json<Value>>{let p=auth::authenticate(&state,&headers,false).await?;let u=p.username.clone();let did=p.device_id.clone();let row=state.db.run(move|c|Ok(c.query_row("SELECT s.protocol_version,s.crypto_version,s.vault_revision,s.recovery_configured,s.opaque_enrolled,d.security_state FROM account_security_state s JOIN provisioning_devices d ON d.username=s.username WHERE s.username=?1 AND d.id=?2",rusqlite::params![u,did],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?,r.get::<_,i64>(4)?,r.get::<_,String>(5)?)))?)).await.map_err(ApiError::Internal)?;Ok(Json(json!({"version":3,"security":{"username":p.username,"device_id":p.device_id,"state":row.5,"protocol_version":row.0,"crypto_version":row.1,"vault_revision":row.2,"recovery_configured":row.3==1,"opaque_enrolled":false,"opaque_available":false}})))}

pub async fn get_vault(State(state):State<AppState>,headers:HeaderMap)->ApiResult<Json<Value>>{let p=auth::authenticate(&state,&headers,false).await?;let u=p.username;let row=state.db.run(move|c|Ok(c.query_row("SELECT revision,vault_version,crypto_version,aad_version,nonce,ciphertext,ciphertext_sha256 FROM encrypted_key_vaults WHERE username=?1 ORDER BY revision DESC LIMIT 1",[u],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,Vec<u8>>(5)?,r.get::<_,Vec<u8>>(6)?))).optional()?)).await.map_err(ApiError::Internal)?.ok_or_else(||ApiError::not_found("security_record_not_found"))?;if util::sha256(&row.5).as_slice()!=row.6.as_slice(){return Err(ApiError::conflict("vault_hash_mismatch"));}Ok(Json(json!({"version":3,"revision":row.0,"vault_version":row.1,"crypto_version":row.2,"aad_version":row.3,"nonce":STANDARD.encode(row.4),"ciphertext":STANDARD.encode(row.5),"ciphertext_sha256":hex::encode(row.6)})))}

pub async fn put_vault(State(state):State<AppState>,headers:HeaderMap,Json(req):Json<VaultWrite>)->ApiResult<(StatusCode,Json<Value>)>{let p=auth::authenticate(&state,&headers,true).await?;if req.version!=3||req.expected_previous_revision<0{return Err(ApiError::bad("invalid_request"));}let nonce=STANDARD.decode(&req.nonce).map_err(|_|ApiError::bad("invalid_request"))?;let ciphertext=STANDARD.decode(&req.ciphertext).map_err(|_|ApiError::bad("invalid_request"))?;let hash=hex::decode(&req.ciphertext_sha256).map_err(|_|ApiError::bad("invalid_request"))?;let verifier=STANDARD.decode(&req.access_verifier).map_err(|_|ApiError::bad("invalid_request"))?;if nonce.len()<12||nonce.len()>24||ciphertext.len()<16||ciphertext.len()>16*1024*1024||hash.len()!=32||verifier.len()!=32||util::sha256(&ciphertext).as_slice()!=hash.as_slice(){return Err(ApiError::conflict("vault_hash_mismatch"));}let u=p.username;let did=p.device_id;let now=util::ts(util::now());let prev=req.expected_previous_revision;let vv=req.vault_version;let cv=req.crypto_version;let av=req.aad_version;let hash_out=hash.clone();let nonce_out=nonce.clone();let cipher_out=ciphertext.clone();let next=state.db.run(move|c|{let tx=c.transaction()?;let current=tx.query_row("SELECT vault_revision FROM account_security_state WHERE username=?1",[&u],|r|r.get::<_,i64>(0))?;if current!=prev{anyhow::bail!("revision")};let next=current+1;tx.execute("INSERT INTO encrypted_key_vaults(username,revision,vault_version,crypto_version,aad_version,nonce,ciphertext,ciphertext_sha256,access_verifier,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)",rusqlite::params![u,next,vv,cv,av,nonce,ciphertext,hash,verifier,now])?;tx.execute("UPDATE account_security_state SET vault_revision=?1,protocol_version=MAX(protocol_version,3),crypto_version=MAX(crypto_version,?2),updated_at=?3,last_ready_device_id=?4 WHERE username=?5",rusqlite::params![next,cv,now,did,u])?;tx.commit()?;Ok(next)}).await.map_err(|e|if e.to_string()=="revision"{ApiError::conflict("vault_revision_conflict")}else{ApiError::Internal(e)})?;state.events.bump();Ok((StatusCode::CREATED,Json(json!({"version":3,"revision":next,"vault_version":vv,"crypto_version":cv,"aad_version":av,"nonce":STANDARD.encode(nonce_out),"ciphertext":STANDARD.encode(cipher_out),"ciphertext_sha256":hex::encode(hash_out)}))))}

pub async fn get_recovery(State(state):State<AppState>,headers:HeaderMap)->ApiResult<Json<Value>>{let p=auth::authenticate(&state,&headers,false).await?;let u=p.username;let r=state.db.run(move|c|Ok(c.query_row("SELECT id,vault_revision,package_version,crypto_version,aad_version,kdf_name,kdf_parameters,salt,nonce,ciphertext,ciphertext_sha256 FROM recovery_packages WHERE username=?1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1",[u],|x|Ok((x.get::<_,String>(0)?,x.get::<_,i64>(1)?,x.get::<_,i64>(2)?,x.get::<_,i64>(3)?,x.get::<_,i64>(4)?,x.get::<_,String>(5)?,x.get::<_,String>(6)?,x.get::<_,Vec<u8>>(7)?,x.get::<_,Vec<u8>>(8)?,x.get::<_,Vec<u8>>(9)?,x.get::<_,Option<Vec<u8>>>(10)?))).optional()?)).await.map_err(ApiError::Internal)?.ok_or_else(||ApiError::not_found("security_record_not_found"))?;let h=r.10.unwrap_or_else(||util::sha256(&r.9).to_vec());if util::sha256(&r.9).as_slice()!=h.as_slice(){return Err(ApiError::conflict("recovery_package_invalid"));}Ok(Json(json!({"version":3,"id":r.0,"vault_revision":r.1,"package_version":r.2,"crypto_version":r.3,"aad_version":r.4,"kdf_name":r.5,"kdf_parameters":r.6,"salt":STANDARD.encode(r.7),"nonce":STANDARD.encode(r.8),"ciphertext":STANDARD.encode(r.9),"ciphertext_sha256":hex::encode(h)})))}

pub async fn put_recovery(State(state):State<AppState>,headers:HeaderMap,Json(req):Json<RecoveryWrite>)->ApiResult<(StatusCode,Json<Value>)>{let p=auth::authenticate(&state,&headers,true).await?;if req.version!=3||!util::canonical_uuid(&req.id)||req.vault_revision<=0{return Err(ApiError::bad("invalid_request"));}let salt=STANDARD.decode(&req.salt).map_err(|_|ApiError::bad("invalid_request"))?;let nonce=STANDARD.decode(&req.nonce).map_err(|_|ApiError::bad("invalid_request"))?;let cipher=STANDARD.decode(&req.ciphertext).map_err(|_|ApiError::bad("invalid_request"))?;let hash=hex::decode(&req.ciphertext_sha256).map_err(|_|ApiError::bad("invalid_request"))?;if salt.len()<16||salt.len()>64||nonce.len()<12||nonce.len()>24||cipher.len()<16||cipher.len()>1024*1024||hash.len()!=32||util::sha256(&cipher).as_slice()!=hash.as_slice(){return Err(ApiError::bad("recovery_package_invalid"));}let u=p.username;let now=util::ts(util::now());let id=req.id.clone();let vr=req.vault_revision;let pv=req.package_version;let cv=req.crypto_version;let av=req.aad_version;let kn=req.kdf_name.clone();let kp=req.kdf_parameters.clone();let salt2=salt.clone();let nonce2=nonce.clone();let cipher2=cipher.clone();let hash2=hash.clone();state.db.run(move|c|{let tx=c.transaction()?;let current=tx.query_row("SELECT vault_revision FROM account_security_state WHERE username=?1",[&u],|r|r.get::<_,i64>(0))?;if current!=vr{anyhow::bail!("revision")};tx.execute("UPDATE recovery_packages SET revoked_at=?1 WHERE username=?2 AND revoked_at IS NULL",rusqlite::params![now,u])?;tx.execute("INSERT INTO recovery_packages(id,username,vault_revision,package_version,crypto_version,aad_version,kdf_name,kdf_parameters,salt,nonce,ciphertext,created_at,ciphertext_sha256) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",rusqlite::params![id,u,vr,pv,cv,av,kn,kp,salt,nonce,cipher,now,hash])?;tx.execute("UPDATE account_security_state SET recovery_configured=1,updated_at=?1 WHERE username=?2",rusqlite::params![now,u])?;tx.commit()?;Ok(())}).await.map_err(|e|if e.to_string()=="revision"{ApiError::conflict("recovery_package_revision_mismatch")}else{ApiError::Internal(e)})?;state.events.bump();Ok((StatusCode::CREATED,Json(json!({"version":3,"id":req.id,"vault_revision":vr,"package_version":pv,"crypto_version":cv,"aad_version":av,"kdf_name":req.kdf_name,"kdf_parameters":req.kdf_parameters,"salt":STANDARD.encode(salt2),"nonce":STANDARD.encode(nonce2),"ciphertext":STANDARD.encode(cipher2),"ciphertext_sha256":hex::encode(hash2)}))))}

pub async fn complete_recovery(State(state):State<AppState>,headers:HeaderMap,Json(req):Json<CompleteRecovery>)->ApiResult<StatusCode>{let p=auth::authenticate(&state,&headers,false).await?;if req.version!=3||req.vault_revision<=0{return Err(ApiError::bad("invalid_request"));}let verifier=STANDARD.decode(&req.access_verifier).map_err(|_|ApiError::bad("invalid_request"))?;if verifier.len()!=32{return Err(ApiError::bad("invalid_request"));}let u=p.username;let did=p.device_id;let now=util::ts(util::now());let vr=req.vault_revision;let n=state.db.run(move|c|{let expected=c.query_row("SELECT access_verifier FROM encrypted_key_vaults WHERE username=?1 AND revision=?2",rusqlite::params![u,vr],|r|r.get::<_,Option<Vec<u8>>>(0)).optional()?.flatten();if expected.as_deref()!=Some(verifier.as_slice()){anyhow::bail!("verifier")};c.execute("UPDATE provisioning_devices SET security_state='READY',approved_at=COALESCE(approved_at,?1) WHERE id=?2 AND username=?3 AND revoked_at IS NULL",rusqlite::params![now,did,u])?;c.execute("UPDATE account_security_state SET state='READY',updated_at=?1,last_ready_device_id=?2 WHERE username=?3",rusqlite::params![now,did,u])?;Ok(1)}).await.map_err(|e|if e.to_string()=="verifier"{ApiError::forbidden("recovery_key_invalid")}else{ApiError::Internal(e)})?;if n==0{return Err(ApiError::forbidden("recovery_failed"));}state.events.bump();Ok(StatusCode::NO_CONTENT)}

pub async fn list_device_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let principal = auth::authenticate(&state, &headers, true).await?;
    let username = principal.username;
    let now = util::ts(util::now());
    let list = state.db.run(move |conn| {
        let mut statement = conn.prepare(
            "SELECT r.id,r.username,r.target_device_id,r.display_name,r.platform,r.network_hint,r.protocol_version,r.requested_at,r.expires_at,\
                    r.approved_at,r.approved_by_device_id,r.rejected_at,r.completed_at,\
                    signing.algorithm,signing.public_key_spki,signing.fingerprint,\
                    agreement.algorithm,agreement.public_key_spki,agreement.fingerprint \
             FROM device_provisioning_requests r \
             JOIN device_keys signing ON signing.device_id=r.target_device_id AND signing.purpose='signing' \
             JOIN device_keys agreement ON agreement.device_id=r.target_device_id AND agreement.purpose='key_agreement' \
             WHERE r.username=?1 AND r.expires_at>?2 AND r.approved_at IS NULL AND r.rejected_at IS NULL AND r.completed_at IS NULL \
             ORDER BY r.requested_at"
        )?;
        let rows = statement.query_map(rusqlite::params![username, now], |row| {
            let signing_key: Vec<u8> = row.get(14)?;
            let signing_fp: Vec<u8> = row.get(15)?;
            let agreement_key: Vec<u8> = row.get(17)?;
            let agreement_fp: Vec<u8> = row.get(18)?;
            Ok(json!({
                "id":row.get::<_,String>(0)?,
                "username":row.get::<_,String>(1)?,
                "target_device_id":row.get::<_,String>(2)?,
                "display_name":row.get::<_,String>(3)?,
                "platform":row.get::<_,String>(4)?,
                "network_hint":row.get::<_,String>(5)?,
                "protocol_version":row.get::<_,i64>(6)?,
                "requested_at":row.get::<_,String>(7)?,
                "expires_at":row.get::<_,String>(8)?,
                "approved_at":row.get::<_,Option<String>>(9)?,
                "approved_by_device_id":row.get::<_,Option<String>>(10)?,
                "rejected_at":row.get::<_,Option<String>>(11)?,
                "completed_at":row.get::<_,Option<String>>(12)?,
                "signing_algorithm":row.get::<_,String>(13)?,
                "signing_public_key_spki":STANDARD.encode(signing_key),
                "signing_fingerprint":hex::encode(signing_fp),
                "key_agreement_algorithm":row.get::<_,String>(16)?,
                "key_agreement_public_key":STANDARD.encode(agreement_key),
                "key_agreement_fingerprint":hex::encode(agreement_fp)
            }))
        })?.collect::<Result<Vec<_>,_>>()?;
        Ok(rows)
    }).await.map_err(ApiError::Internal)?;
    Ok(Json(json!({"version":3,"requests":list})))
}

pub async fn get_device_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let principal = auth::authenticate(&state, &headers, false).await?;
    let username = principal.username;
    let device_id = principal.device_id;
    let row = state.db.run(move |conn| {
        Ok(conn.query_row(
            "SELECT r.id,r.username,r.target_device_id,r.display_name,r.platform,r.network_hint,r.protocol_version,r.requested_at,r.expires_at,\
                    r.approved_at,r.approved_by_device_id,r.rejected_at,r.completed_at,\
                    signing.algorithm,signing.public_key_spki,signing.fingerprint,\
                    agreement.algorithm,agreement.public_key_spki,agreement.fingerprint \
             FROM device_provisioning_requests r \
             JOIN device_keys signing ON signing.device_id=r.target_device_id AND signing.purpose='signing' \
             JOIN device_keys agreement ON agreement.device_id=r.target_device_id AND agreement.purpose='key_agreement' \
             WHERE r.id=?1 AND r.username=?2 AND r.target_device_id=?3",
            rusqlite::params![id, username, device_id],
            |r| Ok((
                r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,String>(2)?,
                r.get::<_,String>(3)?, r.get::<_,String>(4)?, r.get::<_,String>(5)?, r.get::<_,i64>(6)?,
                r.get::<_,String>(7)?, r.get::<_,String>(8)?, r.get::<_,Option<String>>(9)?,
                r.get::<_,Option<String>>(10)?, r.get::<_,Option<String>>(11)?, r.get::<_,Option<String>>(12)?,
                r.get::<_,String>(13)?, r.get::<_,Vec<u8>>(14)?, r.get::<_,Vec<u8>>(15)?,
                r.get::<_,String>(16)?, r.get::<_,Vec<u8>>(17)?, r.get::<_,Vec<u8>>(18)?,
            )),
        ).optional()?)
    }).await.map_err(ApiError::Internal)?
      .ok_or_else(|| ApiError::not_found("device_request_not_found"))?;
    Ok(Json(json!({"version":3,"request":{
        "id":row.0,"username":row.1,"target_device_id":row.2,"display_name":row.3,"platform":row.4,
        "network_hint":row.5,"protocol_version":row.6,"requested_at":row.7,"expires_at":row.8,
        "approved_at":row.9,"approved_by_device_id":row.10,"rejected_at":row.11,"completed_at":row.12,
        "signing_algorithm":row.13,"signing_public_key_spki":STANDARD.encode(row.14),"signing_fingerprint":hex::encode(row.15),
        "key_agreement_algorithm":row.16,"key_agreement_public_key":STANDARD.encode(row.17),"key_agreement_fingerprint":hex::encode(row.18)
    }})))
}

pub async fn reject_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<VersionOnly>,
) -> ApiResult<StatusCode> {
    let principal = auth::authenticate(&state, &headers, true).await?;
    if req.version != 3 {
        return Err(ApiError::bad("invalid_request"));
    }
    let username = principal.username;
    let current_device_id = principal.device_id;
    let now = util::ts(util::now());
    state.db.run(move |c| {
        let tx = c.transaction()?;
        let target: Option<String> = tx.query_row(
            "SELECT target_device_id FROM device_provisioning_requests WHERE id=?1 AND username=?2",
            rusqlite::params![id, username],
            |r| r.get(0),
        ).optional()?;
        let Some(target_device_id) = target else { anyhow::bail!("notfound"); };
        if target_device_id == current_device_id { anyhow::bail!("forbidden"); }
        let changed = tx.execute(
            "UPDATE device_provisioning_requests SET rejected_at=?1 WHERE id=?2 AND username=?3 AND approved_at IS NULL AND rejected_at IS NULL AND completed_at IS NULL",
            rusqlite::params![now, id, username],
        )?;
        if changed != 1 { anyhow::bail!("conflict"); }
        tx.execute(
            "UPDATE provisioning_devices SET security_state='REVOKED',revoked_at=?1 WHERE id=?2 AND username=?3 AND revoked_at IS NULL",
            rusqlite::params![now, target_device_id, username],
        )?;
        tx.execute(
            "UPDATE provisioning_sessions SET revoked_at=?1 WHERE device_id=?2 AND revoked_at IS NULL",
            rusqlite::params![now, target_device_id],
        )?;
        tx.execute(
            "UPDATE provisioning_challenges SET consumed_at=?1 WHERE device_id=?2 AND consumed_at IS NULL",
            rusqlite::params![now, target_device_id],
        )?;
        tx.execute(
            "UPDATE device_certificates SET revoked_at=?1 WHERE subject_device_id=?2 AND revoked_at IS NULL",
            rusqlite::params![now, target_device_id],
        )?;
        tx.commit()?;
        Ok(())
    }).await.map_err(|e| match e.to_string().as_str() {
        "notfound" => ApiError::not_found("device_request_not_found"),
        "forbidden" => ApiError::forbidden("device_request_forbidden"),
        "conflict" => ApiError::conflict("device_request_conflict"),
        _ => ApiError::Internal(e),
    })?;
    state.events.bump();
    Ok(StatusCode::NO_CONTENT)
}

pub async fn approve_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ApproveDevice>,
) -> ApiResult<StatusCode> {
    let principal = auth::authenticate(&state, &headers, true).await?;
    if req.version != 3
        || !util::canonical_uuid(&req.certificate_id)
        || req.certificate_version < 1 || req.certificate_version > 64
        || req.aad_version < 1 || req.aad_version > 64
        || req.package_version < 1 || req.package_version > 64
    {
        return Err(ApiError::bad("invalid_request"));
    }

    let certificate = STANDARD.decode(&req.certificate_payload)
        .map_err(|_| ApiError::bad("invalid_certificate"))?;
    let certificate_signature = STANDARD.decode(&req.certificate_signature)
        .map_err(|_| ApiError::unauthorized("invalid_certificate_signature"))?;
    let encrypted_package = STANDARD.decode(&req.encrypted_package)
        .map_err(|_| ApiError::bad("invalid_provisioning_package"))?;
    let nonce = STANDARD.decode(&req.nonce)
        .map_err(|_| ApiError::bad("invalid_nonce"))?;
    let request_signature = STANDARD.decode(&req.request_signature)
        .map_err(|_| ApiError::unauthorized("invalid_device_signature"))?;

    if !(32..=16 * 1024).contains(&certificate.len())
        || !(32..=2048).contains(&certificate_signature.len())
        || !(48..=1024 * 1024).contains(&encrypted_package.len())
        || !(12..=24).contains(&nonce.len())
        || !(32..=2048).contains(&request_signature.len())
    {
        return Err(ApiError::bad("invalid_request"));
    }

    let username = principal.username.clone();
    let approver_id = principal.device_id.clone();
    let request_id = id.clone();
    let now_dt = util::now();

    let context = state.db.run({
        let username = username.clone();
        let approver_id = approver_id.clone();
        let request_id = request_id.clone();
        move |conn| {
            let request = conn.query_row(
                "SELECT r.target_device_id,r.expires_at,r.approved_at,r.approved_by_device_id,r.rejected_at,r.completed_at,signing.fingerprint,agreement.fingerprint \
                 FROM device_provisioning_requests r \
                 JOIN device_keys signing ON signing.device_id=r.target_device_id AND signing.purpose='signing' \
                 JOIN device_keys agreement ON agreement.device_id=r.target_device_id AND agreement.purpose='key_agreement' \
                 WHERE r.id=?1 AND r.username=?2",
                rusqlite::params![request_id, username],
                |row| Ok((
                    row.get::<_,String>(0)?, row.get::<_,String>(1)?, row.get::<_,Option<String>>(2)?,
                    row.get::<_,Option<String>>(3)?, row.get::<_,Option<String>>(4)?, row.get::<_,Option<String>>(5)?,
                    row.get::<_,Vec<u8>>(6)?, row.get::<_,Vec<u8>>(7)?,
                )),
            ).optional()?;
            let approver = conn.query_row(
                "SELECT key_algorithm,public_key_spki FROM provisioning_devices WHERE id=?1 AND username=?2 AND revoked_at IS NULL AND security_state='READY'",
                rusqlite::params![approver_id, username],
                |row| Ok((row.get::<_,String>(0)?, row.get::<_,Vec<u8>>(1)?)),
            ).optional()?;
            Ok((request, approver))
        }
    }).await.map_err(ApiError::Internal)?;

    let Some((target_id, expires_at, approved_at, approved_by, rejected_at, completed_at, signing_fp, agreement_fp)) = context.0
        else { return Err(ApiError::not_found("device_request_not_found")); };
    let Some((approver_algorithm, approver_public_key)) = context.1
        else { return Err(ApiError::unauthorized("session_invalid")); };

    if target_id == approver_id { return Err(ApiError::forbidden("device_request_scope")); }
    if rejected_at.is_some() || completed_at.is_some() { return Err(ApiError::conflict("device_request_closed")); }
    if util::parse_ts(&expires_at).map_err(ApiError::Internal)? <= now_dt {
        return Err(ApiError::Public(StatusCode::GONE, "device_request_expired"));
    }
    if req.signature_algorithm != approver_algorithm
        || !auth::verify_signature(&approver_algorithm, &approver_public_key, &certificate, &certificate_signature)
    {
        return Err(ApiError::unauthorized("invalid_certificate_signature"));
    }
    if signing_fp.len() != 32 || agreement_fp.len() != 32 {
        return Err(ApiError::conflict("device_request_invalid"));
    }

    let package_hash = util::sha256(&encrypted_package);
    let certificate_hash = util::sha256(&certificate);
    let canonical = format!(
        "fedmes-device-approval-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        request_id,
        approver_id,
        target_id,
        hex::encode(&signing_fp),
        hex::encode(&agreement_fp),
        req.package_version,
        hex::encode(package_hash),
        hex::encode(certificate_hash),
    ).into_bytes();
    if !auth::verify_signature(&approver_algorithm, &approver_public_key, &canonical, &request_signature) {
        return Err(ApiError::unauthorized("invalid_device_signature"));
    }

    if approved_at.is_some() {
        return if approved_by.as_deref() == Some(approver_id.as_str()) {
            Ok(StatusCode::NO_CONTENT)
        } else {
            Err(ApiError::conflict("device_request_already_approved"))
        };
    }

    let now = util::ts(now_dt);
    let certificate_id = req.certificate_id;
    let certificate_version = req.certificate_version;
    let signature_algorithm = req.signature_algorithm;
    let aad_version = req.aad_version;
    let package_version = req.package_version;
    state.db.run(move |conn| {
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE device_provisioning_requests SET approved_at=?1,approved_by_device_id=?2 \
             WHERE id=?3 AND username=?4 AND target_device_id=?5 AND approved_at IS NULL AND rejected_at IS NULL AND completed_at IS NULL AND expires_at>?1",
            rusqlite::params![now, approver_id, request_id, username, target_id],
        )?;
        if changed != 1 { anyhow::bail!("conflict"); }
        tx.execute(
            "INSERT INTO device_provisioning_packages(request_id,target_device_id,encrypted_package,nonce,aad_version,package_version,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![request_id, target_id, encrypted_package, nonce, aad_version, package_version, now],
        )?;
        tx.execute(
            "INSERT INTO device_certificates(id,username,subject_device_id,issuer_device_id,certificate_version,certificate_payload,signature_algorithm,signature,issued_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            rusqlite::params![certificate_id, username, target_id, approver_id, certificate_version, certificate, signature_algorithm, certificate_signature, now],
        )?;
        tx.execute(
            "UPDATE provisioning_devices SET security_state='KEY_TRANSFER_PENDING',approved_by_device_id=?1,approved_at=?2 WHERE id=?3 AND username=?4 AND revoked_at IS NULL",
            rusqlite::params![approver_id, now, target_id, username],
        )?;
        tx.commit()?;
        Ok(())
    }).await.map_err(|error| {
        if error.to_string() == "conflict" { ApiError::conflict("device_request_conflict") } else { ApiError::Internal(error) }
    })?;
    state.events.bump();
    Ok(StatusCode::NO_CONTENT)
}

pub async fn package(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let principal = auth::authenticate(&state, &headers, false).await?;
    let device_id = principal.device_id;
    let request_id = id.clone();
    let row = state.db.run(move |conn| {
        Ok(conn.query_row(
            "SELECT p.target_device_id,p.encrypted_package,p.nonce,p.aad_version,p.package_version,p.created_at,p.consumed_at,\
                    cert.id,cert.certificate_payload,cert.signature,cert.signature_algorithm,cert.issuer_device_id \
             FROM device_provisioning_packages p \
             JOIN device_provisioning_requests r ON r.id=p.request_id \
             JOIN device_certificates cert ON cert.subject_device_id=p.target_device_id AND cert.issuer_device_id=r.approved_by_device_id \
             WHERE p.request_id=?1 AND p.target_device_id=?2 AND r.rejected_at IS NULL",
            rusqlite::params![request_id, device_id],
            |x| Ok((
                x.get::<_,String>(0)?, x.get::<_,Vec<u8>>(1)?, x.get::<_,Vec<u8>>(2)?,
                x.get::<_,i64>(3)?, x.get::<_,i64>(4)?, x.get::<_,String>(5)?, x.get::<_,Option<String>>(6)?,
                x.get::<_,String>(7)?, x.get::<_,Vec<u8>>(8)?, x.get::<_,Vec<u8>>(9)?,
                x.get::<_,String>(10)?, x.get::<_,String>(11)?,
            )),
        ).optional()?)
    }).await.map_err(ApiError::Internal)?
      .ok_or_else(|| ApiError::not_found("device_package_not_found"))?;

    Ok(Json(json!({
        "version":3,
        "request_id":id,
        "target_device_id":row.0,
        "encrypted_package":STANDARD.encode(row.1),
        "nonce":STANDARD.encode(row.2),
        "aad_version":row.3,
        "package_version":row.4,
        "created_at":row.5,
        "consumed_at":row.6,
        "certificate_id":row.7,
        "certificate_payload":STANDARD.encode(row.8),
        "certificate_signature":STANDARD.encode(row.9),
        "signature_algorithm":row.10,
        "issuer_device_id":row.11
    })))
}

pub async fn complete_device(State(state):State<AppState>,headers:HeaderMap,Path(id):Path<String>,Json(req):Json<CompleteRecovery>)->ApiResult<StatusCode>{let p=auth::authenticate(&state,&headers,false).await?;if req.version!=3{return Err(ApiError::bad("invalid_request"));}let verifier=STANDARD.decode(req.access_verifier).map_err(|_|ApiError::bad("invalid_request"))?;if verifier.len()!=32{return Err(ApiError::bad("invalid_request"));}let u=p.username;let did=p.device_id;let now=util::ts(util::now());let rid=id;let vr=req.vault_revision;state.db.run(move|c|{let expected=c.query_row("SELECT access_verifier FROM encrypted_key_vaults WHERE username=?1 AND revision=?2",rusqlite::params![u,vr],|r|r.get::<_,Option<Vec<u8>>>(0)).optional()?.flatten();if expected.as_deref()!=Some(verifier.as_slice()){anyhow::bail!("verifier")};let tx=c.transaction()?;let n=tx.execute("UPDATE device_provisioning_requests SET completed_at=?1 WHERE id=?2 AND username=?3 AND target_device_id=?4 AND approved_at IS NOT NULL AND completed_at IS NULL",rusqlite::params![now,rid,u,did])?;if n!=1{anyhow::bail!("notfound")};tx.execute("UPDATE device_provisioning_packages SET consumed_at=?1 WHERE request_id=?2 AND consumed_at IS NULL",rusqlite::params![now,rid])?;tx.execute("UPDATE provisioning_devices SET security_state='READY',approved_at=?1 WHERE id=?2",rusqlite::params![now,did])?;tx.execute("UPDATE account_security_state SET state='READY',updated_at=?1,last_ready_device_id=?2 WHERE username=?3",rusqlite::params![now,did,u])?;tx.commit()?;Ok(())}).await.map_err(|e|match e.to_string().as_str(){"verifier"=>ApiError::forbidden("vault_verifier_mismatch"),"notfound"=>ApiError::not_found("device_request_not_found"),_=>ApiError::Internal(e)})?;state.events.bump();Ok(StatusCode::NO_CONTENT)}

pub async fn revoke_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let principal = auth::authenticate(&state, &headers, true).await?;
    if id == principal.device_id {
        return Err(ApiError::conflict("cannot_revoke_current_device"));
    }
    let username = principal.username;
    let target_device_id = id;
    let now = util::ts(util::now());
    state.db.run(move |c| {
        let tx = c.transaction()?;
        let row: Option<Option<String>> = tx.query_row(
            "SELECT revoked_at FROM provisioning_devices WHERE id=?1 AND username=?2",
            rusqlite::params![target_device_id, username],
            |r| r.get(0),
        ).optional()?;
        let Some(revoked_at) = row else { anyhow::bail!("notfound"); };
        if revoked_at.is_some() {
            tx.commit()?;
            return Ok(());
        }
        tx.execute(
            "UPDATE provisioning_devices SET revoked_at=?1,security_state='REVOKED' WHERE id=?2 AND username=?3 AND revoked_at IS NULL",
            rusqlite::params![now, target_device_id, username],
        )?;
        tx.execute(
            "UPDATE provisioning_sessions SET revoked_at=?1 WHERE device_id=?2 AND revoked_at IS NULL",
            rusqlite::params![now, target_device_id],
        )?;
        tx.execute(
            "UPDATE provisioning_challenges SET consumed_at=?1 WHERE device_id=?2 AND consumed_at IS NULL",
            rusqlite::params![now, target_device_id],
        )?;
        tx.execute(
            "UPDATE device_certificates SET revoked_at=?1 WHERE subject_device_id=?2 AND revoked_at IS NULL",
            rusqlite::params![now, target_device_id],
        )?;
        tx.commit()?;
        Ok(())
    }).await.map_err(|e| if e.to_string()=="notfound" {
        ApiError::not_found("device_not_found")
    } else {
        ApiError::Internal(e)
    })?;
    state.events.bump();
    Ok(StatusCode::NO_CONTENT)
}

pub async fn migrations(State(state):State<AppState>,headers:HeaderMap)->ApiResult<Json<Value>>{let p=auth::authenticate(&state,&headers,true).await?;let u=p.username;let list=state.db.run(move|c|{let mut s=c.prepare("SELECT id,kind,source_version,target_version,state,last_sequence,processed_count,verified_count,failure_code,updated_at,completed_at FROM crypto_migrations WHERE username=?1 ORDER BY updated_at DESC")?;let rows=s.query_map([u],|r|Ok(json!({"id":r.get::<_,String>(0)?,"kind":r.get::<_,String>(1)?,"source_version":r.get::<_,i64>(2)?,"target_version":r.get::<_,i64>(3)?,"state":r.get::<_,String>(4)?,"last_sequence":r.get::<_,i64>(5)?,"processed_count":r.get::<_,i64>(6)?,"verified_count":r.get::<_,i64>(7)?,"failure_code":r.get::<_,Option<String>>(8)?,"updated_at":r.get::<_,String>(9)?,"completed_at":r.get::<_,Option<String>>(10)?})))?.collect::<Result<Vec<_>,_>>()?;Ok(rows)}).await.map_err(ApiError::Internal)?;Ok(Json(json!({"version":3,"migrations":list})))}
