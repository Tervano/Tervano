//! Signed agent releases (T-810, PLAN §12 item 13). A release is an agent binary plus a manifest
//! (version, platform, SHA-256, size) signed with the *release key*, an Ed25519 key kept away from
//! the Server (`release sign` runs wherever it lives). The Server stores and serves releases; agents
//! verify the signature against the public key in their own configuration, so a compromised Server
//! cannot make them run anything the release key did not sign.

use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::path::Path;

/// Largest agent binary accepted (the agent enforces the same).
pub const MAX_BINARY: u64 = 200 * 1024 * 1024;

/// `release keygen`: creates the release key (PKCS#8) and returns its public key (hex).
pub fn keygen(out: &Path) -> anyhow::Result<String> {
    anyhow::ensure!(
        !out.exists(),
        "{} exists; refusing to overwrite a release key",
        out.display()
    );
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("generating the release key failed"))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    std::io::Write::write_all(&mut options.open(out)?, pkcs8.as_ref())?;
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| anyhow::anyhow!("generated key unreadable"))?;
    Ok(hex::encode(key.public_key().as_ref()))
}

fn valid_version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 32
        && v.split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// `release sign`: writes `<file>.manifest.json` and `<file>.sig` next to the binary.
pub fn sign(key: &Path, file: &Path, version: &str, platform: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        valid_version(version),
        "version must be dotted numbers, e.g. 0.2.0"
    );
    let key = Ed25519KeyPair::from_pkcs8(&std::fs::read(key)?)
        .map_err(|_| anyhow::anyhow!("{} is not an Ed25519 PKCS#8 key", key.display()))?;
    let bytes = std::fs::read(file)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_BINARY,
        "binary larger than {MAX_BINARY} bytes"
    );
    let manifest = serde_json::to_string(&ReleaseManifest {
        version: version.to_owned(),
        platform: platform.to_owned(),
        sha256: hex::encode(Sha256::digest(&bytes)),
        size: bytes.len() as u64,
    })?;
    let signature = hex::encode(key.sign(manifest.as_bytes()).as_ref());
    let (m_path, s_path) = (
        file.with_extension("manifest.json"),
        file.with_extension("sig"),
    );
    std::fs::write(&m_path, &manifest)?;
    std::fs::write(&s_path, &signature)?;
    println!("wrote {} and {}", m_path.display(), s_path.display());
    println!(
        "public key of this release key: {}",
        hex::encode(key.public_key().as_ref())
    );
    Ok(())
}

/// `release publish`: stores a signed release after checking the binary matches its manifest.
pub async fn publish(
    db: &SqlitePool,
    file: &Path,
    manifest_path: &Path,
    signature_path: &Path,
    actor: &str,
) -> anyhow::Result<ReleaseManifest> {
    let manifest_json = std::fs::read_to_string(manifest_path)?;
    let manifest: ReleaseManifest = serde_json::from_str(&manifest_json)?;
    let signature = std::fs::read_to_string(signature_path)?.trim().to_owned();
    anyhow::ensure!(
        hex::decode(&signature)
            .map(|s| s.len() == 64)
            .unwrap_or(false),
        "signature must be 128 hex digits"
    );
    anyhow::ensure!(valid_version(&manifest.version), "bad version in manifest");
    let bytes = std::fs::read(file)?;
    anyhow::ensure!(
        bytes.len() as u64 == manifest.size
            && hex::encode(Sha256::digest(&bytes)) == manifest.sha256,
        "{} does not match the manifest (size or SHA-256)",
        file.display()
    );
    sqlx::query(
        "INSERT INTO agent_releases (platform, version, manifest, signature, binary, published_at, published_by)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&manifest.platform)
    .bind(&manifest.version)
    .bind(&manifest_json)
    .bind(&signature)
    .bind(&bytes)
    .bind(now_millis())
    .bind(actor)
    .execute(db)
    .await
    .map_err(|e| anyhow::anyhow!("storing the release failed (already published?): {e}"))?;
    audit(
        db,
        actor,
        "release.publish",
        &format!("{}/{}", manifest.platform, manifest.version),
        true,
        &format!("sha256={} size={}", manifest.sha256, manifest.size),
        None,
    )
    .await;
    Ok(manifest)
}

pub async fn list(db: &SqlitePool) -> anyhow::Result<Vec<(String, String, i64)>> {
    Ok(sqlx::query_as(
        "SELECT platform, version, published_at FROM agent_releases ORDER BY platform, published_at",
    )
    .fetch_all(db)
    .await?)
}

/// Numeric dotted-version order.
pub fn newer(a: &str, b: &str) -> bool {
    let parts = |v: &str| -> Vec<u64> { v.split('.').map(|p| p.parse().unwrap_or(0)).collect() };
    parts(a) > parts(b)
}

#[derive(Deserialize)]
pub(crate) struct UpdateParams {
    platform: String,
}

/// `GET /api/v1/agent/update?platform=…`: the newest release for the agent's platform, or 204.
pub(crate) async fn latest(
    State(s): State<AppState>,
    _dev: DeviceAuth,
    Query(p): Query<UpdateParams>,
) -> Result<Response, AppError> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT version, manifest, signature FROM agent_releases WHERE platform = ?",
    )
    .bind(&p.platform)
    .fetch_all(&s.db)
    .await?;
    let best = rows
        .into_iter()
        .reduce(|best, r| if newer(&r.0, &best.0) { r } else { best });
    Ok(match best {
        Some((_, manifest, signature)) => Json(SignedRelease {
            manifest,
            signature,
        })
        .into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    })
}

/// `GET /api/v1/agent/update/{platform}/{version}`: the release binary.
pub(crate) async fn binary(
    State(s): State<AppState>,
    _dev: DeviceAuth,
    axum::extract::Path((platform, version)): axum::extract::Path<(String, String)>,
) -> Result<Response, AppError> {
    let bytes: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT binary FROM agent_releases WHERE platform = ? AND version = ?")
            .bind(&platform)
            .bind(&version)
            .fetch_optional(&s.db)
            .await?;
    let bytes =
        bytes.ok_or_else(|| AppError::new(err(StatusCode::NOT_FOUND, "no such release")))?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}
