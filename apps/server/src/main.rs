mod cert;

use clap::{Parser, Subcommand};
use std::{path::PathBuf, time::Duration};
use tervano_server::{
    AppState, Config, DEFAULT_TECH_TOKEN_HOURS, MAX_TECH_TOKEN_HOURS, app, audit, connect,
    create_enrollment_token, create_technician_with_ttl, revoke_technician, rotate_technician,
    spawn_event_purger, spawn_offline_sweeper,
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
        /// Lifetime in hours (default 30 days, maximum 90 days).
        #[arg(long, default_value_t = DEFAULT_TECH_TOKEN_HOURS)]
        hours: u64,
    },
    /// Replace an active or expired token and print the replacement once.
    Rotate {
        #[arg(long)]
        name: String,
        #[arg(long, default_value_t = DEFAULT_TECH_TOKEN_HOURS)]
        hours: u64,
    },
    /// Disable a technician API token. A revoked name cannot be rotated.
    Revoke {
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

fn tech_token_duration(hours: u64) -> anyhow::Result<Duration> {
    anyhow::ensure!(
        (1..=MAX_TECH_TOKEN_HOURS).contains(&hours),
        "technician token hours must be 1-{MAX_TECH_TOKEN_HOURS}"
    );
    Ok(Duration::from_secs(hours * 3600))
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
            spawn_event_purger(state.db.clone(), cfg.event_retention_days);
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
            cmd: TechCmd::Create { name, hours },
        } => {
            let token = create_technician_with_ttl(&db, &name, tech_token_duration(hours)?).await?;
            audit(
                &db,
                &cli_actor(),
                "technician.create",
                &name,
                true,
                &format!("hours={hours}"),
                None,
            )
            .await;
            println!("{token}");
        }
        Cmd::Tech {
            cmd: TechCmd::Rotate { name, hours },
        } => {
            let token =
                rotate_technician(&db, &name, tech_token_duration(hours)?, &cli_actor()).await?;
            println!("{token}");
        }
        Cmd::Tech {
            cmd: TechCmd::Revoke { name },
        } => {
            revoke_technician(&db, &name, &cli_actor()).await?;
            println!("revoked {name}");
        }
        Cmd::Cert { .. } => unreachable!("handled above"),
    }
    Ok(())
}
