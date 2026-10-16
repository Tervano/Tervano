//! Connection tickets (T-403): short-lived, Ed25519-signed grants for one technician on one device,
//! issued within the technician's role and scope. Agents verify them offline against the public key
//! in their configuration, so direct access a technician was given keeps working while the Server
//! is down, until the ticket expires (PLAN §2), and no further.

use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};

pub const MIN_TICKET_MINUTES: u32 = 5;
pub const MAX_TICKET_MINUTES: u32 = 24 * 60;

pub struct TicketSigner {
    key: Ed25519KeyPair,
    minutes: u32,
}

impl TicketSigner {
    pub fn new(key: Ed25519KeyPair, minutes: u32) -> Self {
        Self { key, minutes }
    }
}

/// Loads the signing key (PKCS#8), creating it on first use with owner-only permissions on Unix.
/// On Windows the file inherits the server directory's ACL, which the deployment guide restricts.
pub fn load_or_create_key(path: &std::path::Path) -> anyhow::Result<Ed25519KeyPair> {
    let bad = || anyhow::anyhow!("{} is not an Ed25519 PKCS#8 key", path.display());
    match std::fs::read(path) {
        Ok(bytes) => return Ed25519KeyPair::from_pkcs8(&bytes).map_err(|_| bad()),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(anyhow::anyhow!("reading {}: {e}", path.display()));
        }
        Err(_) => {}
    }
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("generating the ticket key failed"))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    std::io::Write::write_all(&mut options.open(path)?, pkcs8.as_ref())?;
    tracing::info!("created ticket signing key {}", path.display());
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| bad())
}

/// What agents put in `[direct] ticket_key`.
pub fn public_key_hex(key: &Ed25519KeyPair) -> String {
    hex::encode(key.public_key().as_ref())
}

pub(crate) async fn issue(
    State(s): State<AppState>,
    tech: TechAuth,
    client: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(id): Path<Uuid>,
) -> Result<Json<TicketResponse>, AppError> {
    let Some(signer) = s.tickets.clone() else {
        return Err(AppError::new(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "connection tickets are not enabled on this server",
        )));
    };
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices WHERE id = ? AND revoked = 0)")
            .bind(id.to_string())
            .fetch_one(&s.db)
            .await?;
    if !exists {
        return Err(AppError::new(err(
            StatusCode::NOT_FOUND,
            "device not found",
        )));
    }
    tech.check_device(&s.db, id).await?;
    let level = if tech.role >= TechRole::Operator {
        TicketLevel::Operate
    } else {
        TicketLevel::Read
    };
    let now = now_millis();
    let claims = TicketClaims {
        v: 1,
        device_id: id,
        technician: tech.name.clone(),
        level,
        issued_at: now,
        expires_at: now + i64::from(signer.minutes) * 60_000,
    };
    let payload = serde_json::to_vec(&claims).expect("claims serialize");
    let signature = signer.key.sign(&payload);
    audit(
        &s.db,
        &format!("tech:{}", tech.name),
        "ticket.issue",
        &id.to_string(),
        true,
        &format!("level={level:?} minutes={}", signer.minutes),
        client.map(|c| c.0.0.ip()),
    )
    .await;
    Ok(Json(TicketResponse {
        ticket: format!(
            "{}.{}",
            hex::encode(&payload),
            hex::encode(signature.as_ref())
        ),
        level,
        expires_at: claims.expires_at,
    }))
}
