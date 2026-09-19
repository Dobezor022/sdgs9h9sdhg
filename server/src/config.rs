use anyhow::{bail, Context, Result};
use std::{env, net::SocketAddr, path::PathBuf, time::Duration};
use url::Url;

#[derive(Clone, Debug)]
pub struct Config {
    pub public_url: String,
    pub address: SocketAddr,
    pub data_dir: PathBuf,
    pub database_path: PathBuf,
    pub media_dir: PathBuf,
    pub shutdown_timeout: Duration,
}

impl Config {
    pub fn load() -> Result<Self> {
        let data_dir = env::var("FEDMES_DATA_DIR").unwrap_or_else(|_| "data".into());
        let data_dir = std::fs::canonicalize(&data_dir).unwrap_or_else(|_| PathBuf::from(&data_dir));
        let address: SocketAddr = env::var("FEDMES_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8008".into())
            .parse()
            .context("FEDMES_ADDR must be host:port")?;
        let public_url = env::var("FEDMES_PUBLIC_URL").context("FEDMES_PUBLIC_URL is required")?;
        let parsed = Url::parse(public_url.trim()).context("invalid FEDMES_PUBLIC_URL")?;
        if parsed.scheme() != "https" || parsed.host_str().is_none() || !parsed.username().is_empty()
            || parsed.password().is_some() || (parsed.path() != "" && parsed.path() != "/")
            || parsed.query().is_some() || parsed.fragment().is_some()
        {
            bail!("FEDMES_PUBLIC_URL must be an HTTPS origin without credentials/path/query/fragment");
        }
        let public_url = parsed.as_str().trim_end_matches('/').to_owned();
        let shutdown_timeout = env::var("FEDMES_SHUTDOWN_TIMEOUT")
            .ok()
            .as_deref()
            .map(parse_duration)
            .transpose()?
            .unwrap_or(Duration::from_secs(10));
        if shutdown_timeout.is_zero() || shutdown_timeout > Duration::from_secs(60) {
            bail!("FEDMES_SHUTDOWN_TIMEOUT must be >0 and <=60s");
        }
        Ok(Self {
            database_path: data_dir.join("fedmes.sqlite3"),
            media_dir: data_dir.join("media"),
            public_url,
            address,
            data_dir,
            shutdown_timeout,
        })
    }
}

pub fn parse_duration(value: &str) -> Result<Duration> {
    let value = value.trim();
    if let Some(v) = value.strip_suffix("ms") { return Ok(Duration::from_millis(v.parse()?)); }
    if let Some(v) = value.strip_suffix('s') { return Ok(Duration::from_secs(v.parse()?)); }
    if let Some(v) = value.strip_suffix('m') { return Ok(Duration::from_secs(v.parse::<u64>()? * 60)); }
    if let Some(v) = value.strip_suffix('h') { return Ok(Duration::from_secs(v.parse::<u64>()? * 3600)); }
    bail!("unsupported duration: {value}")
}
