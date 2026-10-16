//! The agent's device certificate for mutual TLS with the Server (T-808). The key is generated on
//! this machine and stored DPAPI-protected; only a CSR (public key) leaves it. The Server signs it
//! with its device CA; the certificate is renewed when a third of its lifetime is left.

use std::path::Path;
use tervano_protocol::{Millis, now_millis};

const KEY_FILE: &str = "device-key.dpapi";
const CERT_FILE: &str = "device-cert.pem";

/// A fresh key and its CSR, waiting for the Server to sign it.
pub struct Pending {
    key_pem: String,
    pub csr: String,
}

pub fn new_request() -> anyhow::Result<Pending> {
    let key = rcgen::KeyPair::generate()?;
    // The Server sets subject and usage itself; the CSR only carries the public key.
    let csr = rcgen::CertificateParams::new(Vec::<String>::new())?
        .serialize_request(&key)?
        .pem()?;
    Ok(Pending {
        key_pem: key.serialize_pem(),
        csr,
    })
}

impl Pending {
    /// Stores the key (DPAPI) and the signed certificate; returns the PEM identity for TLS.
    pub fn complete(self, state_dir: &Path, cert_pem: &str) -> anyhow::Result<String> {
        anyhow::ensure!(
            validity(cert_pem).is_some(),
            "the Server returned an unreadable certificate"
        );
        let protected = crate::secure::protect(self.key_pem.as_bytes())?;
        write_atomic(&state_dir.join(KEY_FILE), hex::encode(protected).as_bytes())?;
        write_atomic(&state_dir.join(CERT_FILE), cert_pem.as_bytes())?;
        Ok(identity_pem(cert_pem, &self.key_pem))
    }
}

pub struct Loaded {
    /// Certificate chain + key, PEM, for `reqwest::Identity::from_pem`.
    pub identity_pem: String,
    pub expires_at: Millis,
    /// A third of the lifetime or less is left.
    pub renew_due: bool,
}

/// The stored certificate and key, `None` if this device has none yet.
pub fn load(state_dir: &Path) -> anyhow::Result<Option<Loaded>> {
    let (key_path, cert_path) = (state_dir.join(KEY_FILE), state_dir.join(CERT_FILE));
    if !key_path.exists() || !cert_path.exists() {
        return Ok(None);
    }
    let cert_pem = std::fs::read_to_string(&cert_path)?;
    let key_pem = String::from_utf8(crate::secure::unprotect(&hex::decode(
        std::fs::read_to_string(&key_path)?.trim(),
    )?)?)?;
    let (not_before, not_after) = validity(&cert_pem)
        .ok_or_else(|| anyhow::anyhow!("{} is unreadable", cert_path.display()))?;
    Ok(Some(Loaded {
        identity_pem: identity_pem(&cert_pem, &key_pem),
        expires_at: not_after,
        renew_due: now_millis() >= not_after - (not_after - not_before) / 3,
    }))
}

fn identity_pem(cert_pem: &str, key_pem: &str) -> String {
    format!("{}\n{}", cert_pem.trim_end(), key_pem)
}

/// (not before, not after) of the first certificate in `pem`, in ms.
fn validity(pem: &str) -> Option<(Millis, Millis)> {
    let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).ok()?;
    let cert = block.parse_x509().ok()?;
    let v = cert.validity();
    Some((
        v.not_before.timestamp() * 1000,
        v.not_after.timestamp() * 1000,
    ))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
