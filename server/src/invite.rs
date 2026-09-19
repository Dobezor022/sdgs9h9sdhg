use crate::{db::Db, util};
use anyhow::{bail, Context, Result};
use chrono::{Duration, Utc};
use serde::Serialize;
use std::path::Path;
use url::Url;

#[derive(Serialize)]
struct QrPayload<'a> {
    version: i64,
    #[serde(rename = "type")]
    kind: &'a str,
    server_url: &'a str,
    username: &'a str,
    token: &'a str,
    expires_at: &'a str,
}

pub fn normalize_server_url(input: &str, allow_http: bool) -> Result<String> {
    let mut u = Url::parse(input.trim()).context("server URL must be absolute")?;
    if u.host_str().is_none() || !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() || (u.path() != "" && u.path() != "/") {
        bail!("server URL must be an origin without credentials/path/query/fragment");
    }
    match u.scheme() {
        "https" => {},
        "http" if allow_http => {},
        _ => bail!("server URL must use HTTPS"),
    }
    u.set_path("");
    Ok(u.as_str().trim_end_matches('/').to_owned())
}

pub async fn issue(db: &Db, username: &str, server_url: &str, output: &Path, ttl: std::time::Duration, replace: bool) -> Result<String> {
    if !util::valid_user(username) { bail!("unknown fixed FedMes user"); }
    if ttl.is_zero() || ttl > std::time::Duration::from_secs(15 * 60) { bail!("invitation TTL must be >0 and <=15m"); }
    if output.extension().and_then(|v|v.to_str()).map(|v|v.eq_ignore_ascii_case("png")) != Some(true) { bail!("output must be .png"); }
    if output.exists() && !replace { bail!("output already exists; use --replace or choose a new file"); }
    if let Some(parent) = output.parent() { tokio::fs::create_dir_all(parent).await?; }

    let token_raw = util::random_bytes(32);
    let token = util::b64url(&token_raw);
    let digest = util::sha256(&token_raw).to_vec();
    let id = uuid::Uuid::new_v4().to_string();
    let created = Utc::now();
    let expires = created + Duration::from_std(ttl)?;
    let created_s = util::ts(created);
    let expires_s = util::ts(expires);
    let user = username.to_owned();
    db.run(move |c| {
        c.execute("INSERT INTO provisioning_invitations(id,username,token_digest,created_at,expires_at) VALUES(?1,?2,?3,?4,?5)", rusqlite::params![id,user,digest,created_s,expires_s])?;
        Ok(())
    }).await?;

    let expires_text = util::ts(expires);
    let payload = serde_json::to_vec(&QrPayload { version: 1, kind: "fedmes.provisioning", server_url, username, token: &token, expires_at: &expires_text })?;
    let png = util::render_qr_png(&payload, 512)?;
    let tmp = output.with_extension(format!("png.tmp.{}", uuid::Uuid::new_v4()));
    tokio::fs::write(&tmp, png).await?;
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await?;
    }
    if replace && output.exists() { let _ = tokio::fs::remove_file(output).await; }
    tokio::fs::rename(&tmp, output).await?;
    Ok(expires_text)
}
