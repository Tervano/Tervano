mod cert;

use clap::{Parser, Subcommand};
use std::{path::PathBuf, time::Duration};
use tervano_server::{
    AppState, Config, app, audit, connect, create_enrollment_token, create_technician,
    spawn_offline_sweeper,
};

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
    /// Run the API.
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
    /// TLS certificates.
    Cert {
        #[command(subcommand)]
        cmd: CertCmd,
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

#[derive(Subcommand)]
enum CertCmd {
    /// Create (or reuse) a private CA in --out and issue a server certificate from it.
    Init {
        /// DNS name or IP address clients use to reach this server. Repeatable.
        #[arg(long = "name", required = true)]
        names: Vec<String>,
        #[arg(long, default_value = "tls")]
        out: PathBuf,
    },
    /// Issue a technician client certificate for direct (serverless) agent management.
    Tech {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "tls")]
        out: PathBuf,
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

/// The OS user running a CLI command, for audit attribution.
fn cli_actor() -> String {
    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".into());
    format!("cli:{user}")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    // Certificate commands need no config or database (usable in serverless deployments).
    match &cli.cmd {
        Cmd::Cert {
            cmd: CertCmd::Init { names, out },
        } => return cert::init(out, names),
        Cmd::Cert {
            cmd: CertCmd::Tech { name, out },
        } => return cert::tech(out, name),
        _ => {}
    }
    let cfg = load_config(&cli.config)?;
    let db = connect(&cfg.database_url).await?;

    match cli.cmd {
        Cmd::Serve => {
            let addr: std::net::SocketAddr = cfg.listen.parse()?;
            let state = AppState::new(db, cfg.offline_after_secs as i64 * 1000);
            spawn_offline_sweeper(state.clone());
            let router = app(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
            let handle = axum_server::Handle::new();
            let h = handle.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                h.graceful_shutdown(Some(Duration::from_secs(10)));
            });
            match (&cfg.tls_cert, &cfg.tls_key) {
                (Some(cert), Some(key)) => {
                    rustls::crypto::ring::default_provider()
                        .install_default()
                        .map_err(|_| anyhow::anyhow!("rustls provider already installed"))?;
                    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                        .await
                        .map_err(|e| anyhow::anyhow!("loading TLS cert/key: {e}"))?;
                    tracing::info!("tervano-server listening on https://{addr}");
                    axum_server::bind_rustls(addr, tls)
                        .handle(handle)
                        .serve(router)
                        .await?;
                }
                // Config::validate guarantees this is loopback.
                _ => {
                    tracing::info!("tervano-server listening on http://{addr} (loopback only)");
                    axum_server::bind(addr).handle(handle).serve(router).await?;
                }
            }
        }
        Cmd::Token {
            cmd: TokenCmd::Create { uses, hours },
        } => {
            let token =
                create_enrollment_token(&db, uses, Duration::from_secs(hours * 3600)).await?;
            audit(
                &db,
                &cli_actor(),
                "enrollment_token.create",
                "",
                true,
                &format!("uses={uses} hours={hours}"),
                None,
            )
            .await;
            println!("{token}");
        }
        Cmd::Tech {
            cmd: TechCmd::Create { name },
        } => {
            let token = create_technician(&db, &name).await?;
            audit(
                &db,
                &cli_actor(),
                "technician.create",
                &name,
                true,
                "",
                None,
            )
            .await;
            println!("{token}");
        }
        Cmd::Cert { .. } => unreachable!("handled above"),
    }
    Ok(())
}
