//! Connection tickets on the direct channel (T-403). A ticket is a Server-signed grant for one
//! technician on this device; it is checked here offline against the Server's public key from
//! `[direct] ticket_key`, so it keeps working while the Server is down, until it expires.

use ring::signature::{ED25519, UnparsedPublicKey};
use std::path::PathBuf;
use tervano_protocol::{Millis, TicketClaims, TicketLevel, now_millis};
use uuid::Uuid;

/// Tolerated clock difference between Server and agent for `issued_at`.
const CLOCK_SKEW_MS: Millis = 2 * 60 * 1000;
/// Longest lifetime accepted, whatever the Server says (its own maximum is 24 h).
const MAX_LIFETIME_MS: Millis = 24 * 60 * 60 * 1000;

pub struct TicketVerifier {
    /// Ed25519 public key; `None` when tickets are not configured.
    key: Option<Vec<u8>>,
    state_dir: PathBuf,
}

impl TicketVerifier {
    pub fn new(key_hex: Option<&str>, state_dir: PathBuf) -> anyhow::Result<Self> {
        let key = key_hex
            .map(|k| {
                let bytes = hex::decode(k.trim())
                    .map_err(|_| anyhow::anyhow!("direct.ticket_key must be hex"))?;
                anyhow::ensure!(
                    bytes.len() == 32,
                    "direct.ticket_key must be the 64-hex-digit key from `tervano-server ticket public-key`"
                );
                Ok(bytes)
            })
            .transpose()?;
        Ok(Self { key, state_dir })
    }

    /// This agent's Server device id, from its enrollment (no secret involved).
    pub fn device_id(&self) -> Option<Uuid> {
        #[derive(serde::Deserialize)]
        struct Stored {
            device_id: Uuid,
        }
        let bytes = std::fs::read(self.state_dir.join("identity.json")).ok()?;
        serde_json::from_slice::<Stored>(&bytes)
            .ok()
            .map(|s| s.device_id)
    }

    /// Checks `ticket` (`hex(claims).hex(signature)`) for `technician`; returns what it grants.
    pub fn verify(&self, ticket: &str, technician: &str) -> Result<TicketLevel, String> {
        let key = self
            .key
            .as_ref()
            .ok_or("this computer does not accept server tickets (no [direct] ticket_key)")?;
        let (payload, signature) = ticket.split_once('.').ok_or("malformed ticket")?;
        let payload = hex::decode(payload).map_err(|_| "malformed ticket")?;
        let signature = hex::decode(signature).map_err(|_| "malformed ticket")?;
        UnparsedPublicKey::new(&ED25519, key)
            .verify(&payload, &signature)
            .map_err(|_| "ticket signature is not from this computer's Tervano Server")?;
        let claims: TicketClaims =
            serde_json::from_slice(&payload).map_err(|_| "unreadable ticket")?;
        if claims.v != 1 {
            return Err(format!("unsupported ticket version {}", claims.v));
        }
        if claims.technician != technician {
            return Err(format!(
                "ticket is for {}, not for certificate {technician}",
                claims.technician
            ));
        }
        let own = self.device_id().ok_or(
            "this computer is not enrolled with a Tervano Server, so tickets cannot apply",
        )?;
        if claims.device_id != own {
            return Err("ticket is for another computer".into());
        }
        let now = now_millis();
        if claims.expires_at <= now {
            return Err("ticket expired; get a new one from the Server".into());
        }
        if claims.issued_at > now + CLOCK_SKEW_MS
            || claims.expires_at - claims.issued_at > MAX_LIFETIME_MS
        {
            return Err("ticket times are not plausible (check both clocks)".into());
        }
        Ok(claims.level)
    }
}
