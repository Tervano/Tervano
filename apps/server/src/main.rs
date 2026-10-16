mod cert;

use clap::{Parser, Subcommand};
use std::{path::PathBuf, time::Duration};
use tervano_protocol::TechRole;
use tervano_server::audit_archive::{
    archive_audit, export_audit, spawn_audit_archiver, verify_archives,
};
use tervano_server::{
    AppState, Config, DEFAULT_TECH_TOKEN_HOURS, MAX_TECH_TOKEN_HOURS, app, audit, connect,
    create_enrollment_token, create_technician_with_ttl, revoke_technician, rotate_technician,
    set_technician_access, spawn_event_purger, spawn_offline_sweeper, spawn_query_group_refresher,
};

#[derive(Clone, Copy, clap::ValueEnum)]
enum RoleArg {
    /// Read devices, inventory, events and jobs.
    Viewer,
    /// Also queue and cancel jobs and edit device groups.
    Operator,
    /// Also the audit log, metrics and scope groups.
    Admin,
}

impl From<RoleArg> for TechRole {
    fn from(r: RoleArg) -> Self {
        match r {
            RoleArg::Viewer => TechRole::Viewer,
            RoleArg::Operator => TechRole::Operator,
            RoleArg::Admin => TechRole::Admin,
        }
    }
}

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
    /// Enrolled devices.
    Device {
        #[command(subcommand)]
        cmd: DeviceCmd,
    },
    /// Export or archive the append-only audit trail.
    Audit {
        #[command(subcommand)]
        cmd: AuditCmd,
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
        #[arg(long, value_enum, default_value = "admin")]
        role: RoleArg,
        /// Limit to the devices of this group (repeatable; search groups refresh every minute). Omit for every device.
        #[arg(long)]
        scope: Vec<String>,
    },
    /// Change a technician's role and/or device scope.
    Set {
        #[arg(long)]
        name: String,
        #[arg(long, value_enum)]
        role: Option<RoleArg>,
        /// Replace the scope with these groups (repeatable).
        #[arg(long, conflicts_with = "all_devices")]
        scope: Vec<String>,
        /// Remove the scope: the technician sees every device.
        #[arg(long)]
        all_devices: bool,
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
enum DeviceCmd {
    /// List enrolled devices (including revoked ones).
    List,
    /// Decommission a device: its credentials stop working and it leaves search results.
    Revoke {
        #[arg(long)]
        id: uuid::Uuid,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Export a complete read snapshot to a new NDJSON file.
    Export {
        #[arg(long)]
        out: PathBuf,
    },
    /// Archive rows older than the retention window, then remove those rows.
    Archive {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        retain_days: u32,
    },
    /// Verify archive hashes and row ranges after backup or transfer.
    Verify {
        #[arg(long)]
        dir: PathBuf,
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

/// Ctrl+C, or SIGTERM on Unix (what systemd and container runtimes send to stop a service).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
                return;
            }
            Err(e) => {
                tracing::warn!("cannot listen for SIGTERM: {e}; only Ctrl+C stops gracefully")
            }
        }
    }
    let _ = tokio::signal::ctrl_c().await;
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
        // Colour codes only for a terminal, not the journal or a log file.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
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
            if let (Some(days), Some(dir)) = (cfg.audit_retention_days, &cfg.audit_archive_dir) {
                let archived = archive_audit(&db, dir, days, "server").await?;
                tracing::info!(archived, days, "audit retention checked at startup");
                spawn_audit_archiver(db.clone(), dir.clone(), days);
            }
            let state = AppState::with_rate_limits(
                db,
                cfg.offline_after_secs as i64 * 1000,
                cfg.requests_per_second,
                cfg.enrollments_per_minute,
            );
            spawn_offline_sweeper(state.clone());
            spawn_query_group_refresher(state.db.clone());
            spawn_event_purger(state.db.clone(), cfg.event_retention_days);
            let router = app(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
            let handle = axum_server::Handle::new();
            let h = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                tracing::info!("shutting down: finishing in-flight requests (up to 10 s)");
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
            cmd:
                TechCmd::Create {
                    name,
                    hours,
                    role,
                    scope,
                },
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
            let scope = (!scope.is_empty()).then_some(scope.as_slice());
            if let Err(e) =
                set_technician_access(&db, &name, Some(role.into()), scope, &cli_actor()).await
            {
                // Never leave a technician with more access than asked for.
                revoke_technician(&db, &name, &cli_actor()).await?;
                return Err(e.context(format!("{name} was created and then revoked")));
            }
            println!("{token}");
        }
        Cmd::Tech {
            cmd:
                TechCmd::Set {
                    name,
                    role,
                    scope,
                    all_devices,
                },
        } => {
            anyhow::ensure!(
                role.is_some() || !scope.is_empty() || all_devices,
                "nothing to change: pass --role, --scope or --all-devices"
            );
            let scope = (all_devices || !scope.is_empty()).then_some(scope.as_slice());
            set_technician_access(&db, &name, role.map(Into::into), scope, &cli_actor()).await?;
            println!("updated {name}");
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
        Cmd::Device {
            cmd: DeviceCmd::List,
        } => {
            for (id, hostname, last_seen, revoked) in tervano_server::list_devices(&db).await? {
                println!(
                    "{id}  {hostname:<24} last_seen={last_seen}{}",
                    if revoked { "  REVOKED" } else { "" }
                );
            }
        }
        Cmd::Device {
            cmd: DeviceCmd::Revoke { id },
        } => {
            let hostname = tervano_server::revoke_device(&db, id, &cli_actor()).await?;
            println!("revoked {hostname} ({id}); it must re-enroll with a new token to return");
        }
        Cmd::Audit {
            cmd: AuditCmd::Export { out },
        } => {
            let (rows, sha256) = export_audit(&db, &out).await?;
            println!("exported {rows} audit rows; sha256={sha256}");
        }
        Cmd::Audit {
            cmd: AuditCmd::Archive { dir, retain_days },
        } => {
            let rows = archive_audit(&db, &dir, retain_days, &cli_actor()).await?;
            println!("archived {rows} audit rows");
        }
        Cmd::Audit {
            cmd: AuditCmd::Verify { dir },
        } => {
            let (files, rows) = verify_archives(&dir)?;
            println!("verified {files} audit files and {rows} rows");
        }
        Cmd::Cert { .. } => unreachable!("handled above"),
    }
    Ok(())
}
