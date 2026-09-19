use crate::{error::{ApiError,ApiResult}, util, AppState};
use axum::http::HeaderMap;
use openssl::{hash::MessageDigest, nid::Nid, pkey::{Id,PKey,Public}, sign::Verifier};
use rusqlite::OptionalExtension;
use serde::Serialize;
use sha2::{Digest,Sha256};

#[derive(Clone,Debug,Serialize)]
pub struct Principal { pub username:String, pub device_id:String, pub session_id:String, pub security_state:String }

pub async fn authenticate(state:&AppState, headers:&HeaderMap, ready:bool)->ApiResult<Principal>{
    let value=headers.get(axum::http::header::AUTHORIZATION).and_then(|v|v.to_str().ok()).ok_or_else(||ApiError::unauthorized("missing_session"))?;
    let raw=value.strip_prefix("Bearer ").ok_or_else(||ApiError::unauthorized("invalid_session"))?;
    let bytes=util::decode_b64url(raw,64).map_err(|_|ApiError::unauthorized("invalid_session"))?;
    if bytes.len()!=32 || util::b64url(&bytes)!=raw { return Err(ApiError::unauthorized("invalid_session")); }
    let digest=util::sha256(&bytes).to_vec();
    let now=util::ts(util::now());
    let principal=state.db.run(move |c|{
        let row=c.query_row("SELECT d.username,d.id,s.id,d.security_state FROM provisioning_sessions s JOIN provisioning_devices d ON d.id=s.device_id WHERE s.token_digest=?1 AND s.revoked_at IS NULL AND d.revoked_at IS NULL AND s.expires_at>?2",rusqlite::params![digest,now],|r|Ok(Principal{username:r.get(0)?,device_id:r.get(1)?,session_id:r.get(2)?,security_state:r.get(3)?})).optional()?;
        Ok(row)
    }).await.map_err(ApiError::Internal)?.ok_or_else(||ApiError::unauthorized("invalid_session"))?;
    if ready && principal.security_state!="READY" { return Err(ApiError::forbidden("device_not_ready")); }
    Ok(principal)
}

pub fn verify_signature(algorithm:&str, public_der:&[u8], payload:&[u8], signature:&[u8])->bool{
    let key = match PKey::public_key_from_der(public_der) { Ok(key) => key, Err(_) => return false };
    match algorithm {
        "ed25519" if key.id()==Id::ED25519 => {
            let Ok(mut v)=Verifier::new_without_digest(&key) else { return false; };
            v.verify_oneshot(signature,payload).unwrap_or(false)
        }
        "ecdsa-p256-sha256" if is_p256_key(&key) => {
            let Ok(mut v)=Verifier::new(MessageDigest::sha256(),&key) else { return false; };
            v.update(payload).is_ok() && v.verify(signature).unwrap_or(false)
        }
        _=>false,
    }
}

pub fn validate_identity_key(algorithm:&str, der:&[u8])->bool{
    if der.len()<32 || der.len()>512 {return false;}
    let Ok(key)=PKey::public_key_from_der(der) else {return false;};
    let canonical=key.public_key_to_der().ok();
    if canonical.as_deref()!=Some(der){return false;}
    match algorithm {
        "ed25519" => key.id()==Id::ED25519,
        "ecdsa-p256-sha256" => is_p256_key(&key),
        _ => false,
    }
}
fn is_p256_key(key:&PKey<Public>)->bool {
    if key.id()!=Id::EC { return false; }
    key.ec_key().ok().and_then(|ec| ec.group().curve_name()) == Some(Nid::X9_62_PRIME256V1)
}
pub fn validate_encryption_key(algorithm:&str, der:&[u8])->bool{
    if algorithm!="rsa-oaep-sha256" || der.len()<256 || der.len()>1024 {return false;}
    let Ok(key)=PKey::public_key_from_der(der) else {return false;};
    if key.id()!=Id::RSA {return false;}
    let Ok(rsa)=key.rsa() else {return false;};
    rsa.size()>=384 && rsa.size()<=1024 && rsa.e().to_dec_str().map(|v|v.to_string()=="65537").unwrap_or(false)
}

pub fn canonical_auth_payload(audience:&str, username:&str, device_id:&str, challenge_id:&str, purpose:&str, nonce:&str)->Vec<u8>{
    format!("fedmes-device-auth-v1\n{audience}\n{username}\n{device_id}\n{challenge_id}\n{purpose}\n{nonce}").into_bytes()
}
pub fn canonical_bootstrap_payload(server_url:&str, username:&str, device_id:&str, session_id:&str)->Vec<u8>{
    format!("fedmes-bootstrap-commit-v1\n{server_url}\n{username}\n{device_id}\n{session_id}").into_bytes()
}
pub fn request_digest(parts:&[&[u8]])->[u8;32]{ let mut h=Sha256::new(); for p in parts {h.update(p);} h.finalize().into() }
