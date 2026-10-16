mod collect;
mod direct;
mod eventlog;
mod exec;
mod files;
mod inventory;
mod logfile;
mod netwatch;
mod peripherals;
mod processes;
#[cfg(windows)]
mod reg;
mod registry;
mod secure;
mod serverjobs;
#[cfg(windows)]
mod service;
mod services;
mod software;
mod terminal;
mod wmiq;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};
use tervano_protocol::*;
use tokio::sync::watch;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Tervano Server to report to. Omit for serverless operation (direct management only).
    #[serde(default)]
    pub server_url: Option<String>,
    #[serde(default)]
    pub enrollment_token: String,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default = "default_poll")]
    pub poll_secs: u64,
    #[serde(default = "default_heartbeat")]
    pub heartbeat_secs: u64,
    /// Extra PEM CA certificate to trust for the server (e.g. `ca.pem` from `tervano-server cert init`).
    /// The Windows certificate store is always trusted too.
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
    /// File this config was loaded from (so the enrollment token can be cleared after use).
    #[serde(skip)]
    pub source: Option<PathBuf>,
    /// Direct management listener. Omit to disable.
    #[serde(default)]
    pub direct: Option<direct::DirectConfig>,
    /// Scripts queued on the server (T-800). Off unless enabled here.
    #[serde(default)]
    pub server_jobs: serverjobs::ServerJobsConfig,
}

fn default_poll() -> u64 {
    15
}
fn default_heartbeat() -> u64 {
    60
}

pub fn default_state_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("Tervano").join("Agent")
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let s =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut cfg: Config =
            toml::from_str(&s).with_context(|| format!("parsing {}", path.display()))?;
        cfg.source = Some(path.to_owned());
        if let Some(url) = &cfg.server_url {
            anyhow::ensure!(
                url_transport_ok(url),
                "server_url must be https:// (plain http:// is only allowed to a loopback address)"
            );
        }
        if let Some(d) = &cfg.direct {
            d.validate()?;
        }
        cfg.server_jobs.validate()?;
        anyhow::ensure!(
            !cfg.server_jobs.enabled || cfg.server_url.is_some(),
            "[server_jobs] needs server_url"
        );
        anyhow::ensure!(
            cfg.server_url.is_some() || cfg.direct.is_some(),
            "nothing to do: set server_url and/or a [direct] section"
        );
        anyhow::ensure!(
            cfg.poll_secs >= 1 && cfg.heartbeat_secs >= cfg.poll_secs,
            "need 1 <= poll_secs <= heartbeat_secs"
        );
        Ok(cfg)
    }
}

struct Identity {
    device_id: uuid::Uuid,
    device_secret: String,
}

/// On-disk form of [`Identity`]: the secret is DPAPI-protected (hex).
#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    device_id: uuid::Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    protected_secret: Option<String>,
    /// Plaintext secret written by agent 0.1.0; migrated to `protected_secret` on load.
    #[serde(default, skip_serializing)]
    device_secret: Option<String>,
}

impl Identity {
    fn load(path: &std::path::Path) -> anyhow::Result<Option<Self>> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let corrupt = || format!("{} is unreadable; delete it to re-enroll", path.display());
        let stored: StoredIdentity = serde_json::from_slice(&bytes).with_context(corrupt)?;
        let id = match (stored.protected_secret, stored.device_secret) {
            (Some(p), _) => {
                let raw = secure::unprotect(&hex::decode(p).with_context(corrupt)?)
                    .with_context(corrupt)?;
                Identity {
                    device_id: stored.device_id,
                    device_secret: String::from_utf8(raw).with_context(corrupt)?,
                }
            }
            (None, Some(plain)) => {
                let id = Identity {
                    device_id: stored.device_id,
                    device_secret: plain,
                };
                id.save(path)?;
                tracing::info!("migrated identity secret to DPAPI protection");
                id
            }
            (None, None) => anyhow::bail!(corrupt()),
        };
        Ok(Some(id))
    }

    fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let stored = StoredIdentity {
            device_id: self.device_id,
            protected_secret: Some(hex::encode(secure::protect(self.device_secret.as_bytes())?)),
            device_secret: None,
        };
        // Write-then-rename so a crash never leaves a half-written identity.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(&stored)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

#[derive(Clone)]
struct Client {
    http: reqwest::Client,
    base: String,
}

impl Client {
    fn new(base: &str, ca_cert: Option<&std::path::Path>) -> anyhow::Result<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(PROTOCOL_HEADER, PROTOCOL_VERSION.parse()?);
        let mut builder = reqwest::Client::builder();
        if let Some(path) = ca_cert {
            let pem = std::fs::read(path)
                .with_context(|| format!("reading ca_cert {}", path.display()))?;
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
        }
        let http = builder
            .https_only(!base.starts_with("http://"))
            .default_headers(headers)
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("TervanoAgent/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            base: base.trim_end_matches('/').to_owned(),
        })
    }

    async fn enroll(&self, token: &str, state: &DeviceState) -> anyhow::Result<EnrollResponse> {
        let res = self
            .http
            .post(format!("{}/api/v1/enroll", self.base))
            .json(&EnrollRequest {
                token: token.into(),
                state: state.clone(),
            })
            .send()
            .await?;
        Ok(check(res).await?.json().await?)
    }

    async fn send(&self, secret: &str, events: &[AgentEvent]) -> anyhow::Result<EventAck> {
        let res = self
            .http
            .post(format!("{}/api/v1/events", self.base))
            .bearer_auth(secret)
            .json(events)
            .send()
            .await?;
        Ok(check(res).await?.json().await?)
    }

    async fn send_inventory(&self, secret: &str, report: &InventoryReport) -> anyhow::Result<()> {
        let res = self
            .http
            .post(format!("{}/api/v1/inventory", self.base))
            .bearer_auth(secret)
            .json(report)
            .send()
            .await?;
        check(res).await.map(|_| ())
    }

    /// The next server job for this device, if any.
    async fn claim_job(&self, secret: &str) -> anyhow::Result<Option<AgentJob>> {
        let res = self
            .http
            .post(format!("{}/api/v1/agent/jobs/claim", self.base))
            .bearer_auth(secret)
            .send()
            .await?;
        let res = check(res).await?;
        if res.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }
        Ok(Some(res.json().await?))
    }

    /// Running-job check-in; the reply says whether the job was cancelled.
    async fn job_progress(&self, secret: &str, id: uuid::Uuid) -> anyhow::Result<JobControl> {
        let res = self
            .http
            .post(format!("{}/api/v1/agent/jobs/{id}/progress", self.base))
            .bearer_auth(secret)
            .send()
            .await?;
        Ok(check(res).await?.json().await?)
    }

    async fn job_result(&self, secret: &str, id: uuid::Uuid, r: &JobResult) -> anyhow::Result<()> {
        let res = self
            .http
            .post(format!("{}/api/v1/agent/jobs/{id}/result", self.base))
            .bearer_auth(secret)
            .json(r)
            .send()
            .await?;
        check(res).await.map(|_| ())
    }
}

/// After a successful enrollment the bootstrap token has no further use on this machine, so it is
/// blanked in the config file rather than left in plaintext (T-219). The file is rewritten in place
/// so any ACL an administrator set on it is kept. Failure is only a warning: enrollment succeeded.
fn clear_enrollment_token(cfg: &Config) {
    let Some(path) = &cfg.source else { return };
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let mut changed = false;
    let lines: Vec<String> = text
        .lines()
        .map(|l| {
            let key = l.trim_start();
            if key.starts_with("enrollment_token")
                && key["enrollment_token".len()..]
                    .trim_start()
                    .starts_with('=')
            {
                changed = true;
                "enrollment_token = \"\"  # cleared by the agent after enrolling".to_owned()
            } else {
                l.to_owned()
            }
        })
        .collect();
    if !changed {
        return;
    }
    let ending = if text.contains("\r\n") { "\r\n" } else { "\n" };
    match std::fs::write(path, lines.join(ending) + ending) {
        Ok(()) => tracing::info!("cleared the enrollment token from {}", path.display()),
        Err(e) => tracing::warn!(
            "could not clear the enrollment token from {}: {e}; remove it by hand",
            path.display()
        ),
    }
}

/// Inventory is sent at startup and then daily; a failed upload is retried sooner.
const INVENTORY_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
const INVENTORY_RETRY: Duration = Duration::from_secs(15 * 60);

async fn check(res: reqwest::Response) -> anyhow::Result<reqwest::Response> {
    if res.status().is_success() {
        return Ok(res);
    }
    let status = res.status();
    let msg = res
        .json::<ApiError>()
        .await
        .map(|e| e.error)
        .unwrap_or_default();
    anyhow::bail!("server returned {status}: {msg}")
}

/// Sleeps for `d`, returning false early if shutdown was requested.
async fn sleep_or_stop(d: Duration, stop: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => true,
        _ = stop.changed() => false,
    }
}

/// Scales `d` by a random factor in [1 - spread, 1 + spread] so thousands of agents that
/// restarted together (or lost the server together) don't hit it in lockstep.
fn jitter(d: Duration, spread: f64) -> Duration {
    // uuid v4 is already a dependency and draws from the OS RNG; no extra crate needed.
    let r = (uuid::Uuid::new_v4().as_u128() % 10_000) as f64 / 10_000.0; // [0, 1)
    d.mul_f64(1.0 - spread + 2.0 * spread * r)
}

/// Runs the configured roles (server reporting and/or direct management) until `stop` fires.
/// A failure in either is fatal so misconfiguration is loud rather than half-working.
pub async fn run(cfg: Config, stop: watch::Receiver<bool>) -> anyhow::Result<()> {
    std::fs::create_dir_all(&cfg.state_dir)?;
    let direct = async {
        match &cfg.direct {
            Some(d) => direct::serve(d.clone(), cfg.state_dir.clone(), stop.clone()).await,
            None => Ok(()),
        }
    };
    let reporting = async {
        match &cfg.server_url {
            Some(url) => report(&cfg, url, stop.clone()).await,
            None => Ok(()),
        }
    };
    tokio::try_join!(direct, reporting)?;
    Ok(())
}

/// Reporting loop: enroll if needed, then report state changes and heartbeats until `stop` fires.
async fn report(
    cfg: &Config,
    server_url: &str,
    mut stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let client = Client::new(server_url, cfg.ca_cert.as_deref())?;
    let id_path = cfg.state_dir.join("identity.json");
    let poll = Duration::from_secs(cfg.poll_secs);
    let max_backoff = Duration::from_secs(300);

    let identity = match Identity::load(&id_path)? {
        Some(id) => id,
        None => {
            anyhow::ensure!(
                !cfg.enrollment_token.is_empty(),
                "not enrolled and no enrollment_token configured"
            );
            let mut backoff = poll;
            loop {
                match client
                    .enroll(&cfg.enrollment_token, &collect::device_state())
                    .await
                {
                    Ok(r) => {
                        let id = Identity {
                            device_id: r.device_id,
                            device_secret: r.device_secret,
                        };
                        id.save(&id_path)?;
                        clear_enrollment_token(cfg);
                        tracing::info!(device = %id.device_id, "enrolled");
                        break id;
                    }
                    Err(e) => tracing::warn!("enrollment failed: {e:#}; retrying in {backoff:?}"),
                }
                if !sleep_or_stop(backoff, &mut stop).await {
                    return Ok(());
                }
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    };
    tracing::info!(device = %identity.device_id, server = %server_url, "reporting to server");
    // Enabled: picked up within a poll; disabled: claimed (and refused) once per heartbeat.
    let job_poll = if cfg.server_jobs.enabled {
        poll
    } else {
        Duration::from_secs(cfg.heartbeat_secs)
    };
    tokio::spawn(serverjobs::run(
        client.clone(),
        identity.device_secret.clone(),
        cfg.server_jobs.clone(),
        exec::Jobs::new(cfg.state_dir.clone()),
        job_poll,
        stop.clone(),
    ));

    // Seeded from the clock so a restarted agent never reuses a seq; corrected from the server's ack.
    let mut seq = now_millis() as u64;
    let mut reported: Option<DeviceState> = None;
    let mut pending: Option<EventKind> = None;
    let mut last_sent = std::time::Instant::now();
    let mut first = true;
    let mut backoff = poll;
    let mut next_inventory = std::time::Instant::now();
    // Next heartbeat is due after a jittered interval, re-drawn after every send.
    let mut heartbeat_every = jitter(Duration::from_secs(cfg.heartbeat_secs), 0.1);
    let net_changed = std::sync::Arc::new(tokio::sync::Notify::new());
    let _net_watch = netwatch::watch(net_changed.clone());

    loop {
        let state = collect::device_state();
        if reported.as_ref() != Some(&state) {
            // Coalesce: only the newest state matters, so it replaces anything unsent.
            pending = Some(if first {
                EventKind::Startup {
                    state: state.clone(),
                }
            } else {
                EventKind::StateChanged {
                    state: state.clone(),
                }
            });
        } else if pending.is_none() && last_sent.elapsed() >= heartbeat_every {
            pending = Some(EventKind::Heartbeat);
        }

        let mut wait = poll;
        if let Some(kind) = pending.clone() {
            seq += 1;
            match client
                .send(
                    &identity.device_secret,
                    &[AgentEvent {
                        seq,
                        at: now_millis(),
                        kind,
                    }],
                )
                .await
            {
                Ok(ack) if ack.last_seq < seq => {
                    // Should not happen; resend next tick.
                    tracing::warn!(seq, ack = ack.last_seq, "server did not apply event");
                }
                Ok(ack) if ack.last_seq > seq => {
                    // Our clock went backwards; jump past the server and resend immediately.
                    seq = ack.last_seq;
                    wait = Duration::ZERO;
                }
                Ok(_) => {
                    if let Some(EventKind::Startup { state } | EventKind::StateChanged { state }) =
                        pending.take()
                    {
                        tracing::info!(
                            sessions = state.sessions.len(),
                            addrs = state.addresses.len(),
                            "state reported"
                        );
                        reported = Some(state);
                    }
                    first = false;
                    last_sent = std::time::Instant::now();
                    heartbeat_every = jitter(Duration::from_secs(cfg.heartbeat_secs), 0.1);
                    backoff = poll;
                }
                Err(e) => {
                    if e.to_string().contains("401") {
                        tracing::error!(
                            "server rejected this device's identity (revoked or unknown); delete identity.json and re-enroll with a new token"
                        );
                    }
                    // Equal jitter: half fixed, half random, so a reconnect storm spreads out.
                    wait = jitter(backoff, 0.5);
                    tracing::warn!("report failed: {e:#}; retrying in {wait:?}");
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
        // Only once the server knows this device (first state report accepted).
        if !first && std::time::Instant::now() >= next_inventory {
            let report = tokio::task::spawn_blocking(|| InventoryReport {
                collected_at: now_millis(),
                hardware: inventory::hardware(),
                software: software::inventory(),
            })
            .await?;
            next_inventory = std::time::Instant::now()
                + match client
                    .send_inventory(&identity.device_secret, &report)
                    .await
                {
                    Ok(()) => {
                        tracing::info!(apps = report.software.apps.len(), "inventory reported");
                        INVENTORY_EVERY
                    }
                    Err(e) => {
                        tracing::warn!("inventory upload failed: {e:#}; retrying in 15 min");
                        INVENTORY_RETRY
                    }
                };
        }
        let woke_by_network = tokio::select! {
            _ = tokio::time::sleep(wait) => false,
            _ = stop.changed() => break,
            _ = net_changed.notified() => true,
        };
        if woke_by_network {
            // Address changes arrive in bursts (DHCP, IPv6 privacy addresses); let them settle.
            tracing::info!("network change detected");
            if !sleep_or_stop(Duration::from_secs(2), &mut stop).await {
                break;
            }
        }
    }

    seq += 1;
    let bye = AgentEvent {
        seq,
        at: now_millis(),
        kind: EventKind::Shutdown,
    };
    if let Err(e) = tokio::time::timeout(
        Duration::from_secs(3),
        client.send(&identity.device_secret, &[bye]),
    )
    .await
    {
        tracing::debug!("shutdown notice not sent: {e}");
    }
    Ok(())
}

fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
}

const USAGE: &str = "\
usage: TervanoAgent <command>
  run [config]                 run in the foreground (default config: agent.toml)
  collect                      print the state this agent would report, as JSON
  inventory                    print this computer's hardware inventory, as JSON
  software                     print installed software and pending-reboot reasons, as JSON
  direct-fingerprint [config]  print the SHA-256 fingerprint consoles pin for direct management
  service install [config]     install the Windows service (admin; default config: %ProgramData%\\Tervano\\Agent\\agent.toml)
  service uninstall            remove the Windows service (admin)";

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["run", rest @ ..] => {
            init_logging();
            let cfg = Config::load(std::path::Path::new(
                rest.first().copied().unwrap_or("agent.toml"),
            ))?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let (tx, rx) = watch::channel(false);
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    let _ = tx.send(true);
                });
                run(cfg, rx).await
            })
        }
        ["direct-fingerprint", rest @ ..] => {
            let cfg = Config::load(std::path::Path::new(
                rest.first().copied().unwrap_or("agent.toml"),
            ))?;
            let path = cfg.state_dir.join("direct-cert.pem");
            let der = {
                use rustls::pki_types::{CertificateDer, pem::PemObject};
                CertificateDer::from_pem_file(&path).with_context(|| {
                    format!(
                        "{} missing: start the agent with [direct] once",
                        path.display()
                    )
                })?
            };
            println!("{}", direct::fingerprint(&der));
            Ok(())
        }
        ["inventory"] => {
            println!("{}", serde_json::to_string_pretty(&inventory::hardware())?);
            Ok(())
        }
        ["software"] => {
            println!("{}", serde_json::to_string_pretty(&software::inventory())?);
            Ok(())
        }
        ["collect"] => {
            println!(
                "{}",
                serde_json::to_string_pretty(&collect::device_state())?
            );
            Ok(())
        }
        #[cfg(windows)]
        ["service", "install", rest @ ..] => {
            let cfg = rest
                .first()
                .map(PathBuf::from)
                .unwrap_or_else(|| default_state_dir().join("agent.toml"));
            service::install(&std::path::absolute(cfg)?)
        }
        #[cfg(windows)]
        ["service", "uninstall"] => service::uninstall(),
        #[cfg(windows)]
        ["service", "run", cfg] => service::run_as_service(PathBuf::from(cfg)),
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}
