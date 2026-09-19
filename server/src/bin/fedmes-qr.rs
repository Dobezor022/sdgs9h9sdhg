use anyhow::{bail, Result};
use clap::Parser;
use fedmes_server::{config, db::Db, invite, util, VERSION};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name="fedmes-qr", version=VERSION)]
struct Args {
    #[arg(long="server-url")] server_url: String,
    #[arg(long="data-dir", default_value="/var/lib/fedmes")] data_dir: PathBuf,
    #[arg(long="out-dir")] out_dir: PathBuf,
    #[arg(long="ttl", default_value="15m")] ttl: String,
    #[arg(long="users", default_value="all")] users: String,
    #[arg(long="allow-http", default_value_t=false)] allow_http: bool,
    #[arg(long="replace", default_value_t=false)] replace: bool,
    // Kept for CLI compatibility with 2.0.0. Rust QR generation no longer shells out.
    #[arg(long="server-exe")] _server_exe: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    if let Err(e)=run().await { eprintln!("Ошибка: {e:#}"); std::process::exit(1); }
}

async fn run() -> Result<()> {
    let args=Args::parse();
    let url=invite::normalize_server_url(&args.server_url,args.allow_http)?;
    let ttl=config::parse_duration(&args.ttl)?;
    if ttl>std::time::Duration::from_secs(15*60){bail!("максимальный TTL QR — 15m");}
    tokio::fs::create_dir_all(&args.data_dir).await?;
    tokio::fs::create_dir_all(&args.out_dir).await?;
    let db=Db::open(args.data_dir.join("fedmes.sqlite3")).await?;
    let users:Vec<String>=if args.users.trim().eq_ignore_ascii_case("all"){
        util::USERS.iter().map(|x|x.to_string()).collect()
    }else{
        let mut out=Vec::new();
        for x in args.users.split(',').map(|x|x.trim().to_ascii_lowercase()).filter(|x|!x.is_empty()){
            if !util::valid_user(&x){bail!("неизвестный пользователь {x}");}
            if !out.contains(&x){out.push(x);}
        }
        if out.is_empty(){bail!("не выбраны пользователи");}
        out
    };
    println!("FedMes QR {VERSION}");
    println!("Сервер:   {url}");
    println!("Данные:   {}",args.data_dir.display());
    println!("QR:       {}",args.out_dir.display());
    println!("Пользователи: {}\n",users.join(", "));
    for user in users{
        let out=args.out_dir.join(format!("fedmes-invite-{user}.png"));
        let expires=invite::issue(&db,&user,&url,&out,ttl,args.replace).await?;
        println!("invitation created username={user} qr={} expires_at={expires}",out.display());
    }
    println!("\nQR-коды готовы: {}",args.out_dir.display());
    println!("Не публикуйте QR-коды на сайте и удалите их после подключения устройств.");
    Ok(())
}
