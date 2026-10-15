use clap::{Parser, Subcommand};
use std::{path::PathBuf, time::Duration};
use tervano_server::{AppState, Config, app, connect, create_enrollment_token, create_technician};

#[derive(Parser)]
#[command(name = "tervano-server", version, about = "Tervano Server")]
struct Cli {
    /// Path to server.toml (defaults are used if missing).
    #[arg(long, short, default_value = "server.toml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the HTTP API.
    Serve,
    /// Manage agent enrollment tokens.
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// Manage technician API tokens.
    Tech {
        #[command(subcommand)]
        cmd: TechCmd,
    },
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Create an enrollment token. Printed once; only its hash is stored.
    Create {
        #[arg(long, default_value_t = 1)]
        uses: u32,
        #[arg(long, default_value_t = 24)]
        hours: u64,
    },
}

#[derive(Subcommand)]
enum TechCmd {
    /// Create a technician and print their API token (once).
    Create {
        #[arg(long)]
        name: String,
    },
}

fn load_config(path: &PathBuf) -> anyhow::Result<Config> {
    let cfg: Config = match std::fs::read_to_string(path) {
        Ok(s) => toml::from_str(&s).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
        Err(e) => return Err(e.into()),
    };
    cfg.validate()?;
    Ok(cfg)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let cfg = load_config(&cli.config)?;
    let db = connect(&cfg.database_url).await?;

    match cli.cmd {
        Cmd::Serve => {
            let addr: std::net::SocketAddr = cfg.listen.parse()?;
            if !addr.ip().is_loopback() {
                // shortcut: plaintext HTTP until T-109 (TLS) lands; loopback-only is the safe default.
                tracing::warn!(
                    "listening on non-loopback {addr} WITHOUT TLS — development use only"
                );
            }
            let state = AppState {
                db,
                offline_after_ms: cfg.offline_after_secs as i64 * 1000,
            };
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tracing::info!("tervano-server listening on http://{addr}");
            axum::serve(listener, app(state))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
        Cmd::Token {
            cmd: TokenCmd::Create { uses, hours },
        } => {
            let token =
                create_enrollment_token(&db, uses, Duration::from_secs(hours * 3600)).await?;
            println!("{token}");
        }
        Cmd::Tech {
            cmd: TechCmd::Create { name },
        } => {
            let token = create_technician(&db, &name).await?;
            println!("{token}");
        }
    }
    Ok(())
}
