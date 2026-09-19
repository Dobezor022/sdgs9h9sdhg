use anyhow::{bail, Context, Result};
use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::Parser;
use fedmes_server::{util, VERSION};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::{collections::HashMap, path::{Path, PathBuf}, sync::{Arc, Mutex}};
use tokio_util::io::ReaderStream;

type HmacSha256 = Hmac<Sha256>;
const TICKET_TTL: i64 = 180;

#[derive(Parser)]
#[command(name="fedmes-update-server", version=VERSION)]
struct Args {
    #[arg(long,default_value="127.0.0.1:8010")] addr:String,
    #[arg(long,default_value="/var/lib/fedmes/updates/releases.json")] manifest:PathBuf,
    #[arg(long="files-dir",default_value="/var/lib/fedmes/updates/files")] files_dir:PathBuf,
    #[arg(long="ticket-key",default_value="/etc/fedmes/update-ticket.key")] ticket_key:PathBuf,
}
#[derive(Clone)] struct App{manifest:PathBuf,files:PathBuf,key:Arc<Vec<u8>>,used:Arc<Mutex<HashMap<String,i64>>>}
#[derive(Deserialize,Clone)] struct Release{version_name:String,version_code:i64,minimum_supported_code:i64,file_name:String,sha256:String,size_bytes:i64,notes:String,published_at:String}
#[derive(Deserialize)] struct Manifest{schema:i64,releases:HashMap<String,Release>}
#[derive(Serialize,Deserialize)] struct Claims{v:i64,p:String,c:i64,s:String,u:String,d:String,e:i64,n:String}
#[derive(Deserialize)] struct Check{platform:String,version_name:String,version_code:i64}
#[derive(Deserialize)] struct Download{version:i64,ticket:String}

#[tokio::main]
async fn main(){if let Err(e)=run().await{eprintln!("FedMes Update Server error: {e:#}");std::process::exit(1)}}
async fn run()->Result<()> {
    let a=Args::parse();
    let text=tokio::fs::read_to_string(&a.ticket_key).await.context("read update ticket key")?;
    let key=hex::decode(text.trim()).context("ticket key hex")?; if key.len()!=32{bail!("ticket key must be 32 bytes");}
    let state=App{manifest:a.manifest,files:a.files_dir,key:Arc::new(key),used:Arc::new(Mutex::new(HashMap::new()))};
    let app=Router::new().route("/health",get(health)).route("/api/v1/updates/check",get(check)).route("/api/v1/updates/download",post(download)).with_state(state);
    let listener=tokio::net::TcpListener::bind(&a.addr).await?;
    eprintln!("FedMes Rust Update Server {VERSION} listening on {}",a.addr);
    axum::serve(listener,app).await?; Ok(())
}
async fn health()->impl IntoResponse{Json(json!({"status":"ok","version":VERSION,"protocol":2,"server":"rust"}))}
fn identity(h:&HeaderMap)->Result<(String,String),StatusCode>{
    let bearer=h.get(header::AUTHORIZATION).and_then(|x|x.to_str().ok()).unwrap_or("");
    let user=h.get("x-fedmes-authenticated-user").and_then(|x|x.to_str().ok()).unwrap_or("").trim();
    let dev=h.get("x-fedmes-authenticated-device").and_then(|x|x.to_str().ok()).unwrap_or("").trim();
    if !bearer.starts_with("Bearer ")||bearer[7..].trim().len()<16||user.is_empty()||dev.is_empty(){Err(StatusCode::UNAUTHORIZED)}else{Ok((user.to_owned(),dev.to_owned()))}
}
async fn manifest(path:&Path)->Result<Manifest>{let b=tokio::fs::read(path).await?;let m:Manifest=serde_json::from_slice(&b)?;if m.schema!=2{bail!("manifest schema must be 2")};Ok(m)}
fn platform(v:&str)->bool{matches!(v,"android-normal"|"android-huawei"|"windows-x64")}
fn valid_sha(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn safe_name(s:&str)->bool{!s.is_empty()&&s.len()<=200&&s.bytes().all(|b|b.is_ascii_alphanumeric()||b"._-".contains(&b))&&!s.contains("..")&&!s.contains('/')&&!s.contains('\\')}
fn api_error(status:StatusCode,code:&'static str)->Response{(status,Json(json!({"error":{"code":code}}))).into_response()}
async fn check(State(st):State<App>,h:HeaderMap,Query(q):Query<Check>)->Response{
    let (u,d)=match identity(&h){Ok(v)=>v,Err(s)=>return api_error(s,"update_auth_required")};
    let p=q.platform.trim().to_ascii_lowercase(); if !platform(&p)||q.version_name.len()>64||q.version_code<0{return api_error(StatusCode::BAD_REQUEST,"invalid_update_request")}
    let m=match manifest(&st.manifest).await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"update_manifest_unavailable")};
    let r=match m.releases.get(&p){Some(v)=>v.clone(),None=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"release_not_configured")};
    if !valid_sha(&r.sha256)||!safe_name(&r.file_name)||r.version_code<=0||r.minimum_supported_code>r.version_code{return api_error(StatusCode::SERVICE_UNAVAILABLE,"update_manifest_invalid")}
    let available=q.version_code<r.version_code;
    let mut latest=json!({"version_name":r.version_name,"version_code":r.version_code,"minimum_supported_code":r.minimum_supported_code,"sha256":r.sha256,"size_bytes":r.size_bytes,"notes":r.notes,"published_at":r.published_at});
    if available{match issue_ticket(&st,&p,&r,&u,&d){Ok(t)=>{latest["download_method"]=json!("POST");latest["download_path"]=json!("/api/v1/updates/download");latest["download_ticket"]=json!(t);latest["ticket_expires_in_seconds"]=json!(TICKET_TTL)},Err(_)=>return api_error(StatusCode::INTERNAL_SERVER_ERROR,"update_ticket_failed")}}
    Json(json!({"version":2,"platform":p,"current_version":q.version_name,"current_code":q.version_code,"update_available":available,"required":q.version_code<r.minimum_supported_code,"latest":latest})).into_response()
}
fn issue_ticket(st:&App,p:&str,r:&Release,u:&str,d:&str)->Result<String>{
    let claims=Claims{v:1,p:p.to_owned(),c:r.version_code,s:r.sha256.clone(),u:u.to_owned(),d:d.to_owned(),e:chrono::Utc::now().timestamp()+TICKET_TTL,n:util::b64url(&util::random_bytes(18))};
    let enc=URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);let mut mac=HmacSha256::new_from_slice(&st.key)?;mac.update(enc.as_bytes());Ok(format!("{}.{}",enc,URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())))
}
fn consume_ticket(st:&App,ticket:&str,u:&str,d:&str)->Result<Claims>{
    let (a,b)=ticket.split_once('.').context("ticket format")?;let sig=URL_SAFE_NO_PAD.decode(b)?;let mut mac=HmacSha256::new_from_slice(&st.key)?;mac.update(a.as_bytes());mac.verify_slice(&sig)?;
    let c:Claims=serde_json::from_slice(&URL_SAFE_NO_PAD.decode(a)?)?;let now=chrono::Utc::now().timestamp();if c.v!=1||!platform(&c.p)||!valid_sha(&c.s)||c.u!=u||c.d!=d||c.e<now||c.e>now+TICKET_TTL+15{bail!("invalid claims")}
    let mut used=st.used.lock().map_err(|_|anyhow::anyhow!("ticket mutex poisoned"))?;used.retain(|_,v|*v>now);if used.contains_key(&c.n){bail!("ticket used")};used.insert(c.n.clone(),c.e);Ok(c)
}
async fn download(State(st):State<App>,h:HeaderMap,Json(req):Json<Download>)->Response{
    let (u,d)=match identity(&h){Ok(v)=>v,Err(s)=>return api_error(s,"update_auth_required")};if req.version!=1||req.ticket.len()>4096{return api_error(StatusCode::BAD_REQUEST,"invalid_download_request")}
    let c=match consume_ticket(&st,&req.ticket,&u,&d){Ok(v)=>v,Err(_)=>return api_error(StatusCode::GONE,"download_ticket_invalid")};
    let m=match manifest(&st.manifest).await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"update_manifest_unavailable")};let r=match m.releases.get(&c.p){Some(v) if v.version_code==c.c&&v.sha256==c.s=>v.clone(),_=>return api_error(StatusCode::GONE,"release_changed")};if !safe_name(&r.file_name){return api_error(StatusCode::SERVICE_UNAVAILABLE,"artifact_unavailable")}
    let path=st.files.join(&r.file_name);let file=match tokio::fs::File::open(&path).await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"artifact_unavailable")};let meta=match file.metadata().await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"artifact_unavailable")};if !meta.is_file()||meta.len() as i64!=r.size_bytes{return api_error(StatusCode::SERVICE_UNAVAILABLE,"artifact_metadata_mismatch")}
    let stream=ReaderStream::new(file);let body=Body::from_stream(stream);let mut resp=Response::new(body);*resp.status_mut()=StatusCode::OK;let hd=resp.headers_mut();hd.insert(header::CONTENT_TYPE,HeaderValue::from_static(if c.p.starts_with("android-"){"application/vnd.android.package-archive"}else{"application/octet-stream"}));if let Ok(v)=HeaderValue::from_str(&r.size_bytes.to_string()){hd.insert(header::CONTENT_LENGTH,v);}if let Ok(v)=HeaderValue::from_str(&r.sha256){hd.insert("x-fedmes-sha256",v);}if let Ok(v)=HeaderValue::from_str(&r.version_name){hd.insert("x-fedmes-version",v);}hd.insert(header::CACHE_CONTROL,HeaderValue::from_static("private, no-store, max-age=0"));resp
}
