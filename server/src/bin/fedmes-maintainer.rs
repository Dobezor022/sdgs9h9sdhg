use anyhow::{bail, Result};
use clap::{ArgAction, Parser};
use fedmes_server::{config, VERSION, VERSION_CODE};
use serde_json::{json, Value};
use std::{path::{Path,PathBuf}, time::Duration};

#[derive(Parser)]
#[command(name="fedmes-maintainer", version=VERSION)]
struct Args{
    #[arg(long,default_value="1m")] interval:String,
    #[arg(long="update-interval",default_value="30m")] update_interval:String,
    #[arg(long="auto-server-update",default_value_t=false,action=ArgAction::Set)] auto_server_update:bool,
    #[arg(long="server-update-url")] server_update_url:Option<String>,
    #[arg(long,default_value_t=false)] once:bool,
    #[arg(long="data-dir",default_value="/var/lib/fedmes")] data_dir:PathBuf,
}

#[tokio::main]
async fn main(){if let Err(e)=run().await{eprintln!("FedMes Maintainer error: {e:#}");std::process::exit(1)}}
async fn run()->Result<()> {
    let a=Args::parse();let interval=config::parse_duration(&a.interval)?;let _update_interval=config::parse_duration(&a.update_interval)?;
    if a.auto_server_update { eprintln!("FedMes Maintainer {VERSION} ({VERSION_CODE}): automatic server replacement is disabled in the Rust-transition release; use signed/manual deploy bundle."); }
    if let Some(url)=a.server_update_url.as_deref(){if !url.starts_with("https://"){bail!("server update URL must use HTTPS")}}
    loop{
        cycle(&a.data_dir).await?;
        if a.once{break}
        tokio::time::sleep(interval).await;
    }
    Ok(())
}
async fn cycle(root:&Path)->Result<()> {
    let updates=root.join("updates");let files=updates.join("files");let media=root.join("media");
    tokio::fs::create_dir_all(&files).await?;tokio::fs::create_dir_all(&media).await?;
    repair_manifest(&updates.join("releases.json")).await?;
    clean_tmp(&files).await?;clean_tmp(&media).await?;
    #[cfg(unix)] repair_permissions(root,&updates,&files,&media).await?;
    Ok(())
}
async fn repair_manifest(path:&Path)->Result<()> {
    let mut value:Value=match tokio::fs::read(path).await{Ok(b)=>serde_json::from_slice(&b).unwrap_or_else(|_|json!({"schema":2,"releases":{}})),Err(_)=>json!({"schema":2,"releases":{}})};
    if value.get("schema").and_then(Value::as_i64)!=Some(2){value["schema"]=json!(2)}
    if !value.get("releases").map(Value::is_object).unwrap_or(false){value["releases"]=json!({})}
    let data=serde_json::to_vec_pretty(&value)?;let tmp=path.with_extension("json.tmp");tokio::fs::write(&tmp,data).await?;tokio::fs::rename(tmp,path).await?;Ok(())
}
async fn clean_tmp(dir:&Path)->Result<()> {let mut rd=tokio::fs::read_dir(dir).await?;while let Some(e)=rd.next_entry().await?{let name=e.file_name();let s=name.to_string_lossy();if s.starts_with('.')&&(s.contains(".tmp")||s.ends_with(".part")){let _=tokio::fs::remove_file(e.path()).await;}}Ok(())}
#[cfg(unix)] async fn repair_permissions(root:&Path,updates:&Path,files:&Path,media:&Path)->Result<()> {use std::os::unix::fs::PermissionsExt;for d in [root,updates,files,media]{tokio::fs::set_permissions(d,std::fs::Permissions::from_mode(0o700)).await?;}let manifest=updates.join("releases.json");if manifest.exists(){tokio::fs::set_permissions(manifest,std::fs::Permissions::from_mode(0o600)).await?;}Ok(())}
