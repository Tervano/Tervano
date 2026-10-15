mod collect;
#[cfg(windows)]
mod service;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};
use tervano_protocol::*;
use tokio::sync::watch;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server_url: String,
    #[serde(default)]
    pub enrollment_token: String,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default = "default_poll")]
    pub poll_secs: u64,
    #[serde(default = "default_heartbeat")]
    pub heartbeat_secs: u64,
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
        let cfg: Config =
            toml::from_str(&s).with_context(|| format!("parsing {}", path.display()))?;
        anyhow::ensure!(
            cfg.server_url.starts_with("https://") || cfg.server_url.starts_with("http://"),
            "server_url must be an http(s) URL"
        );
        anyhow::ensure!(
            cfg.poll_secs >= 1 && cfg.heartbeat_secs >= cfg.poll_secs,
            "need 1 <= poll_secs <= heartbeat_secs"
        );
        Ok(cfg)
    }
}

/// Persisted enrollment identity.
// shortcut: secret stored as plaintext JSON in state_dir; DPAPI + ACLs are T-208.
#[derive(Serialize, Deserialize)]
struct Identity {
    device_id: uuid::Uuid,
    device_secret: String,
}

struct Client {
    http: reqwest::Client,
    base: String,
}

impl Client {
    fn new(base: &str) -> anyhow::Result<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(PROTOCOL_HEADER, PROTOCOL_VERSION.parse()?);
        let http = reqwest::Client::builder()
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
}

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

/// Agent main loop: enroll if needed, then report state changes and heartbeats until `stop` fires.
pub async fn run(cfg: Config, mut stop: watch::Receiver<bool>) -> anyhow::Result<()> {
    let client = Client::new(&cfg.server_url)?;
    std::fs::create_dir_all(&cfg.state_dir)?;
    let id_path = cfg.state_dir.join("identity.json");
    let poll = Duration::from_secs(cfg.poll_secs);
    let max_backoff = Duration::from_secs(300);

    let identity: Identity = match std::fs::read(&id_path) {
        Ok(b) => serde_json::from_slice(&b)
            .context("identity.json is corrupt; delete it to re-enroll")?,
        Err(_) => {
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
                        std::fs::write(&id_path, serde_json::to_vec(&id)?)?;
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
    tracing::info!(device = %identity.device_id, server = %cfg.server_url, "agent running");

    // Seeded from the clock so a restarted agent never reuses a seq; corrected from the server's ack.
    let mut seq = now_millis() as u64;
    let mut reported: Option<DeviceState> = None;
    let mut pending: Option<EventKind> = None;
    let mut last_sent = std::time::Instant::now();
    let mut first = true;
    let mut backoff = poll;

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
        } else if pending.is_none()
            && last_sent.elapsed() >= Duration::from_secs(cfg.heartbeat_secs)
        {
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
                    backoff = poll;
                }
                Err(e) => {
                    tracing::warn!("report failed: {e:#}; retrying in {backoff:?}");
                    wait = backoff;
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
        if !sleep_or_stop(wait, &mut stop).await {
            break;
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
