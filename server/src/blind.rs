use crate::{auth, error::{ApiError, ApiResult}, util, AppState};
use axum::{
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Duration;
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::sync::{broadcast, Mutex};
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

const DEFAULT_OBJECT_TTL: i64 = 72 * 60 * 60;
const MAX_OBJECT_TTL: i64 = 7 * 24 * 60 * 60;
const MAX_ROUTE_LIFE: i64 = 30 * 24 * 60 * 60;
const DEFAULT_MAX_OBJECT: i64 = 2 * 1024 * 1024;
const DEFAULT_MAX_PENDING: i64 = 512;
const MAX_FRAME: usize = 256 * 1024;

#[derive(Default)]
pub struct StreamBroker {
    routes: Mutex<HashMap<[u8; 32], broadcast::Sender<Vec<u8>>>>,
}
impl StreamBroker {
    async fn sender(&self, key: [u8;32]) -> broadcast::Sender<Vec<u8>> {
        let mut guard = self.routes.lock().await;
        guard.entry(key).or_insert_with(|| broadcast::channel(256).0).clone()
    }
}

#[derive(Deserialize)] pub struct RouteRequest {
    version:i64, route_digest:String, generation:i64,
    #[serde(default)] lifetime_seconds:i64,
    #[serde(default)] max_object_bytes:i64,
    #[serde(default)] max_pending_objects:i64,
}
#[derive(Deserialize)] pub struct ObjectWrite {
    version:i64, object_id:String, length_class:i64, ciphertext:String,
    #[serde(default)] lifetime_seconds:i64,
}
#[derive(Deserialize,Default)] pub struct PullQuery { limit:Option<i64> }

fn parse_digest(value:&str)->ApiResult<[u8;32]> {
    let bytes=URL_SAFE_NO_PAD.decode(value).map_err(|_|ApiError::bad("invalid_route_digest"))?;
    bytes.try_into().map_err(|_|ApiError::bad("invalid_route_digest"))
}
fn capability(headers:&HeaderMap)->ApiResult<([u8;32],[u8;32])> {
    let raw=headers.get("x-object-capability").and_then(|v|v.to_str().ok()).ok_or_else(||ApiError::unauthorized("missing_capability"))?;
    let decoded=util::decode_b64url(raw,64)?;
    if decoded.len()!=32 || util::b64url(&decoded)!=raw { return Err(ApiError::unauthorized("invalid_capability")); }
    let mut cap=[0u8;32]; cap.copy_from_slice(&decoded);
    Ok((cap,util::sha256(&decoded)))
}
async fn active_route(state:&AppState,digest:[u8;32])->ApiResult<(i64,i64,String)> {
    let d=digest.to_vec(); let now=util::ts(util::now());
    state.db.run(move|c|Ok(c.query_row("SELECT max_object_bytes,max_pending_objects,expires_at FROM blind_routes WHERE route_digest=?1 AND revoked_at IS NULL AND expires_at>?2",rusqlite::params![d,now],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?)).await.map_err(ApiError::Internal)?.ok_or_else(||ApiError::not_found("route_not_found"))
}

pub async fn register_route(State(state):State<AppState>,headers:HeaderMap,Json(req):Json<RouteRequest>)->ApiResult<Json<Value>> {
    let _=auth::authenticate(&state,&headers,true).await?;
    if req.version!=1 || req.generation<=0 { return Err(ApiError::bad("invalid_request")); }
    let digest=parse_digest(&req.route_digest)?;
    let life=if req.lifetime_seconds<=0 {86400} else {req.lifetime_seconds};
    if !(60..=MAX_ROUTE_LIFE).contains(&life) { return Err(ApiError::bad("invalid_lifetime")); }
    let max_obj=if req.max_object_bytes<=0 {DEFAULT_MAX_OBJECT}else{req.max_object_bytes};
    let max_pending=if req.max_pending_objects<=0 {DEFAULT_MAX_PENDING}else{req.max_pending_objects};
    if !(1024..=8*1024*1024).contains(&max_obj) || !(1..=4096).contains(&max_pending) {return Err(ApiError::bad("invalid_limits"));}
    let now=util::now(); let now_s=util::ts(now); let expires=util::ts(now+Duration::seconds(life));
    let d=digest.to_vec(); let generation=req.generation; let exp_out=expires.clone();
    state.db.run(move|c|{c.execute(r#"INSERT INTO blind_routes(route_digest,generation,created_at,expires_at,max_object_bytes,max_pending_objects,revoked_at)
        VALUES(?1,?2,?3,?4,?5,?6,NULL)
        ON CONFLICT(route_digest) DO UPDATE SET generation=MAX(blind_routes.generation,excluded.generation),
        expires_at=CASE WHEN excluded.expires_at>blind_routes.expires_at THEN excluded.expires_at ELSE blind_routes.expires_at END,
        max_object_bytes=excluded.max_object_bytes,max_pending_objects=excluded.max_pending_objects,revoked_at=NULL"#,
        rusqlite::params![d,generation,now_s,expires,max_obj,max_pending])?;Ok(())}).await.map_err(ApiError::Internal)?;
    Ok(Json(json!({"version":1,"status":"ok","expires_at":exp_out})))
}

pub async fn put_object(State(state):State<AppState>,headers:HeaderMap,Json(req):Json<ObjectWrite>)->ApiResult<(StatusCode,Json<Value>)> {
    if req.version!=1 || !(1..=16).contains(&req.length_class) || req.object_id.len()<20 || req.object_id.len()>64 || !req.object_id.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_'||b==b'-') {return Err(ApiError::bad("invalid_request"));}
    let (_,digest)=capability(&headers)?; let (max_bytes,max_pending,route_expiry)=active_route(&state,digest).await?;
    let ct=util::decode_b64url(&req.ciphertext,8*1024*1024)?; if ct.len()<16 || ct.len() as i64>max_bytes{return Err(ApiError::bad("object_too_large"));}
    let d=digest.to_vec(); let now=util::now(); let now_s=util::ts(now); let requested=if req.lifetime_seconds<=0{DEFAULT_OBJECT_TTL}else{req.lifetime_seconds.clamp(60,MAX_OBJECT_TTL)};
    let route_exp=util::parse_ts(&route_expiry).map_err(ApiError::Internal)?; let exp=std::cmp::min(now+Duration::seconds(requested),route_exp); let exp_s=util::ts(exp); let oid=req.object_id.clone(); let cls=req.length_class; let hash=util::sha256(&ct).to_vec();
    let oid_out=oid.clone(); let exp_out=exp_s.clone();
    state.db.run(move|c|{let tx=c.transaction()?;tx.execute("DELETE FROM blind_objects WHERE expires_at<=?1",[&now_s])?;let pending:i64=tx.query_row("SELECT COUNT(*) FROM blind_objects WHERE route_digest=?1 AND expires_at>?2",rusqlite::params![d,now_s],|r|r.get(0))?;if pending>=max_pending{anyhow::bail!("queue_full")};tx.execute("INSERT INTO blind_objects(object_id,route_digest,length_class,ciphertext,ciphertext_sha256,created_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",rusqlite::params![oid,d,cls,ct,hash,now_s,exp_s])?;tx.commit()?;Ok(())}).await.map_err(|e|if e.to_string()=="queue_full"{ApiError::Public(StatusCode::TOO_MANY_REQUESTS,"route_queue_full")}else if e.to_string().to_lowercase().contains("unique"){ApiError::conflict("object_exists")}else{ApiError::Internal(e)})?;
    state.events.bump(); Ok((StatusCode::CREATED,Json(json!({"version":1,"object_id":oid_out,"expires_at":exp_out}))))
}

pub async fn pull_objects(State(state):State<AppState>,headers:HeaderMap,Query(q):Query<PullQuery>)->ApiResult<Json<Value>> {
    let (_,digest)=capability(&headers)?; let _=active_route(&state,digest).await?; let limit=q.limit.unwrap_or(64).clamp(1,256); let d=digest.to_vec(); let now=util::ts(util::now());
    let list=state.db.run(move|c|{c.execute("DELETE FROM blind_objects WHERE expires_at<=?1",[&now])?;let mut s=c.prepare("SELECT object_id,length_class,ciphertext FROM blind_objects WHERE route_digest=?1 AND expires_at>?2 ORDER BY created_at,object_id LIMIT ?3")?;let rows=s.query_map(rusqlite::params![d,now,limit],|r|{let ct:Vec<u8>=r.get(2)?;Ok(json!({"object_id":r.get::<_,String>(0)?,"length_class":r.get::<_,i64>(1)?,"ciphertext":util::b64url(&ct)}))})?.collect::<Result<Vec<_>,_>>()?;Ok(rows)}).await.map_err(ApiError::Internal)?;
    Ok(Json(json!({"version":1,"objects":list})))
}

pub async fn ack_object(State(state):State<AppState>,headers:HeaderMap,Path(id):Path<String>)->ApiResult<StatusCode> {
    let (_,digest)=capability(&headers)?; let _=active_route(&state,digest).await?; let d=digest.to_vec();
    let n=state.db.run(move|c|Ok(c.execute("DELETE FROM blind_objects WHERE object_id=?1 AND route_digest=?2",rusqlite::params![id,d])?)).await.map_err(ApiError::Internal)?;
    if n==0{return Err(ApiError::not_found("object_not_found"));} Ok(StatusCode::NO_CONTENT)
}

pub async fn stream_down(State(state):State<AppState>,headers:HeaderMap)->ApiResult<Response> {
    let (_,digest)=capability(&headers)?; let _=active_route(&state,digest).await?; let tx=state.streams.sender(digest).await; let rx=tx.subscribe();
    let stream=BroadcastStream::new(rx).filter_map(|item| match item { Ok(frame)=>{let mut out=Vec::with_capacity(frame.len()+4);out.extend_from_slice(&(frame.len() as u32).to_be_bytes());out.extend_from_slice(&frame);Some(Ok::<Bytes,std::convert::Infallible>(Bytes::from(out)))},Err(_)=>None });
    let mut response=Response::new(Body::from_stream(stream));
    response.headers_mut().insert(axum::http::header::CONTENT_TYPE,HeaderValue::from_static("application/octet-stream"));
    response.headers_mut().insert(axum::http::header::CACHE_CONTROL,HeaderValue::from_static("no-store"));
    Ok(response)
}

pub async fn stream_up(State(state):State<AppState>,headers:HeaderMap,body:Body)->ApiResult<impl IntoResponse> {
    let (_,digest)=capability(&headers)?; let _=active_route(&state,digest).await?; let tx=state.streams.sender(digest).await; let mut stream=body.into_data_stream(); let mut buffer=Vec::<u8>::with_capacity(64*1024);
    while let Some(chunk)=stream.next().await { let chunk=chunk.map_err(|_|ApiError::bad("invalid_stream"))?; buffer.extend_from_slice(&chunk); if buffer.len()>2*MAX_FRAME+4{return Err(ApiError::bad("stream_buffer_exceeded"));}
        loop { if buffer.len()<4{break;} let prefix: [u8;4] = buffer[0..4].try_into().map_err(|_|ApiError::bad("invalid_frame"))?; let n=u32::from_be_bytes(prefix) as usize; if n==0||n>MAX_FRAME{return Err(ApiError::bad("invalid_frame"));} if buffer.len()<4+n{break;} let frame=buffer[4..4+n].to_vec(); buffer.drain(..4+n); let _=tx.send(frame); }
    }
    if !buffer.is_empty(){return Err(ApiError::bad("truncated_frame"));}
    Ok(StatusCode::NO_CONTENT)
}
