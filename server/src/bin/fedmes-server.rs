use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fedmes_server::{blind::StreamBroker, config, db::Db, invite, server, AppState, EventClock, VERSION, VERSION_CODE};
use std::{path::PathBuf, sync::Arc};

#[derive(Parser)]
#[command(name="fedmes-server", version=VERSION, about="FedMes Rust backend")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Serve,
    Invite {
        #[arg(long="user")] user: String,
        #[arg(long="server-url")] server_url: String,
        #[arg(long="out")] out: PathBuf,
        #[arg(long="ttl", default_value="10m")] ttl: String,
        #[arg(long="data-dir", default_value="data")] data_dir: PathBuf,
        #[arg(long="allow-http", default_value_t=false)] allow_http: bool,
        #[arg(long="replace", default_value_t=false)] replace: bool,
    },
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("FedMes Server error: {e:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve().await,
        Command::Invite { user, server_url, out, ttl, data_dir, allow_http, replace } => {
            let url = invite::normalize_server_url(&server_url, allow_http)?;
            tokio::fs::create_dir_all(&data_dir).await?;
            let db = Db::open(data_dir.join("fedmes.sqlite3")).await?;
            let ttl = config::parse_duration(&ttl)?;
            let expires = invite::issue(&db, &user, &url, &out, ttl, replace).await?;
            println!("invitation created username={} qr={} expires_at={}", user, out.display(), expires);
            Ok(())
        }
    }
}

async fn serve() -> Result<()> {
    let cfg = config::Config::load()?;
    tokio::fs::create_dir_all(&cfg.data_dir).await?;
    tokio::fs::create_dir_all(&cfg.media_dir).await?;
    let db = Db::open(&cfg.database_path).await?;
    let address = cfg.address;
    let shutdown_timeout = cfg.shutdown_timeout;
    let state = AppState { config: Arc::new(cfg), db, events: Arc::new(EventClock::default()), streams: Arc::new(StreamBroker::default()) };
    let app = server::router(state);
    let listener = tokio::net::TcpListener::bind(address).await.with_context(|| format!("bind {address}"))?;
    eprintln!("FedMes Rust Server {} ({}) listening on {}", VERSION, VERSION_CODE, address);
    axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = tokio::signal::ctrl_c().await;
        tokio::time::sleep(std::time::Duration::from_millis(50).min(shutdown_timeout)).await;
    }).await?;
    Ok(())
}
