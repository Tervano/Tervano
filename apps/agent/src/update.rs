//! Signed self-update (T-810, PLAN §12 item 13). Off unless `[update] enabled = true` with the
//! release public key. The Server only relays releases: an update is installed only when its
//! manifest carries a valid signature by that key, names this platform and a newer version than the
//! running one (no downgrades), and the downloaded binary matches the manifest's size and SHA-256.
//! The running executable is renamed to `<exe>.old` (Windows allows renaming, not deleting, a
//! running image), the new one takes its path, and the agent restarts; `.old` is removed at the
//! next start.

use crate::{Client, jitter, sleep_or_stop};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tervano_protocol::*;
use tokio::sync::watch;

/// Same cap the Server applies when publishing.
const MAX_BINARY: u64 = 200 * 1024 * 1024;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Release public key (64 hex digits, printed by `tervano-server release keygen`).
    #[serde(default)]
    pub public_key: String,
    #[serde(default = "default_check")]
    pub check_minutes: u64,
}

fn default_check() -> u64 {
    60
}

impl UpdateConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.enabled {
            anyhow::ensure!(
                hex::decode(&self.public_key).is_ok_and(|k| k.len() == 32),
                "[update] public_key must be the 64-hex-digit release public key"
            );
            anyhow::ensure!(
                self.check_minutes >= 1,
                "[update] check_minutes must be >= 1"
            );
        }
        Ok(())
    }
}

fn newer(a: &str, b: &str) -> bool {
    let parts = |v: &str| -> Vec<u64> { v.split('.').map(|p| p.parse().unwrap_or(0)).collect() };
    parts(a) > parts(b)
}

fn old_path(exe: &Path) -> PathBuf {
    let mut name = exe.as_os_str().to_owned();
    name.push(".old");
    PathBuf::from(name)
}

/// Removes the executable an earlier update replaced.
pub fn cleanup() {
    if let Ok(exe) = std::env::current_exe() {
        let old = old_path(&exe);
        if old.exists() {
            match std::fs::remove_file(&old) {
                Ok(()) => tracing::info!("removed {} left by the last update", old.display()),
                Err(e) => tracing::warn!("could not remove {}: {e}", old.display()),
            }
        }
    }
}

/// Checks the signed manifest; `Ok(None)` when it is fine but not newer than this agent.
fn verify(cfg: &UpdateConfig, release: &SignedRelease) -> anyhow::Result<Option<ReleaseManifest>> {
    let key = hex::decode(&cfg.public_key)?;
    let sig = hex::decode(release.signature.trim())
        .map_err(|_| anyhow::anyhow!("signature is not hex"))?;
    UnparsedPublicKey::new(&ED25519, key)
        .verify(release.manifest.as_bytes(), &sig)
        .map_err(|_| anyhow::anyhow!("manifest signature does not verify with the release key"))?;
    let m: ReleaseManifest = serde_json::from_str(&release.manifest)?;
    anyhow::ensure!(
        m.platform == agent_platform(),
        "release is for {}, this agent is {}",
        m.platform,
        agent_platform()
    );
    anyhow::ensure!(
        m.size <= MAX_BINARY,
        "release larger than {MAX_BINARY} bytes"
    );
    Ok(newer(&m.version, env!("CARGO_PKG_VERSION")).then_some(m))
}

/// Puts `new` at the running executable's path, keeping the old one as `<exe>.old`.
fn install(new: &Path) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let old = old_path(&exe);
    let _ = std::fs::remove_file(&old);
    std::fs::rename(&exe, &old)?;
    // The staging file may sit on another volume, where a rename fails.
    let placed = std::fs::rename(new, &exe).or_else(|_| std::fs::copy(new, &exe).map(|_| ()));
    if let Err(e) = placed {
        let _ = std::fs::rename(&old, &exe);
        return Err(anyhow::anyhow!("placing the new executable failed: {e}"));
    }
    let _ = std::fs::remove_file(new);
    Ok(())
}

/// One check: `Ok(true)` when a new version was installed and the agent should restart.
async fn check_once(
    client: &Client,
    secret: &str,
    cfg: &UpdateConfig,
    state_dir: &Path,
) -> anyhow::Result<bool> {
    let Some(release) = client.latest_release(secret, &agent_platform()).await? else {
        return Ok(false);
    };
    let Some(m) = verify(cfg, &release)? else {
        return Ok(false);
    };
    tracing::info!(version = %m.version, size = m.size, "downloading signed agent update");
    let bytes = client
        .release_binary(secret, &m.platform, &m.version, m.size)
        .await?;
    anyhow::ensure!(
        bytes.len() as u64 == m.size && hex::encode(Sha256::digest(&bytes)) == m.sha256,
        "downloaded binary does not match the signed manifest; not installed"
    );
    let dir = state_dir.join("update");
    std::fs::create_dir_all(&dir)?;
    let staged = dir.join(format!("TervanoAgent-{}.exe", m.version));
    std::fs::write(&staged, &bytes)?;
    install(&staged)?;
    tracing::info!(
        from = env!("CARGO_PKG_VERSION"),
        to = %m.version,
        "agent updated; restarting"
    );
    Ok(true)
}

/// Checks for updates until `stop` fires; on an installed update sets `updated` and asks the agent
/// to stop so it can restart into the new version.
pub async fn run(
    client: Client,
    secret: String,
    cfg: UpdateConfig,
    state_dir: PathBuf,
    restart: watch::Sender<bool>,
    updated: std::sync::Arc<std::sync::atomic::AtomicBool>,
    mut stop: watch::Receiver<bool>,
) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(every_min = cfg.check_minutes, "signed self-update enabled");
    // Soon after start, so a restart picks up a pending release quickly, but not in lockstep.
    let mut wait = jitter(Duration::from_secs(20), 0.5);
    loop {
        if !sleep_or_stop(wait, &mut stop).await {
            return;
        }
        match check_once(&client, &secret, &cfg, &state_dir).await {
            Ok(true) => {
                updated.store(true, std::sync::atomic::Ordering::SeqCst);
                let _ = restart.send(true);
                return;
            }
            Ok(false) => tracing::debug!("no agent update"),
            Err(e) => tracing::warn!("agent update check failed: {e:#}"),
        }
        wait = jitter(Duration::from_secs(cfg.check_minutes * 60), 0.1);
    }
}
