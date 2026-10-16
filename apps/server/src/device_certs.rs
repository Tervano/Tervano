//! Device certificates (T-808, PLAN §12 items 1 and 3): mutual TLS between agents and the Server.
//!
//! The Server runs its own *device CA* (separate from the CA that issues the Server and technician
//! certificates, so a compromised Server cannot mint technician certificates). An agent generates
//! its key on the device and sends a CSR; the Server signs it with CN = device id and records the
//! certificate's fingerprint on the device. From then on that device must present the certificate
//! (plus its secret) on every request; renewal rotates the fingerprint, revocation of the device
//! ends both. TLS client auth is optional at the handshake so Consoles keep using bearer tokens.

use super::*;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::path::Path;

pub const MIN_CERT_DAYS: u32 = 1;
pub const MAX_CERT_DAYS: u32 = 397;

/// SHA-256 (hex) of the client certificate presented on this connection, if any. Attached to every
/// request by [`ClientCertAcceptor`].
#[derive(Clone, Debug, Default)]
pub struct ClientCert(pub Option<String>);

pub struct DeviceCa {
    key: KeyPair,
    pem: String,
    days: u32,
}

/// Fixed parameters, so re-creating them with the stored key yields the same issuer.
fn ca_params() -> anyhow::Result<CertificateParams> {
    let mut p = CertificateParams::new(Vec::<String>::new())?;
    p.distinguished_name
        .push(DnType::CommonName, "Tervano Device CA");
    p.distinguished_name
        .push(DnType::OrganizationName, "Tervano");
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.not_before = rcgen::date_time_ymd(2024, 1, 1);
    p.not_after = rcgen::date_time_ymd(2054, 1, 1);
    Ok(p)
}

impl DeviceCa {
    /// Loads `device-ca.pem` / `device-ca-key.pem` from `dir`, creating them on first use. The key
    /// file relies on the directory's permissions (owner-only on Unix).
    pub fn load_or_create(dir: &Path, days: u32) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let (cert_path, key_path) = (dir.join("device-ca.pem"), dir.join("device-ca-key.pem"));
        let key = if key_path.exists() {
            KeyPair::from_pem(&std::fs::read_to_string(&key_path)?)
                .map_err(|e| anyhow::anyhow!("{}: {e}", key_path.display()))?
        } else {
            let key = KeyPair::generate()?;
            std::fs::write(&cert_path, ca_params()?.self_signed(&key)?.pem())?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            std::io::Write::write_all(
                &mut options.open(&key_path)?,
                key.serialize_pem().as_bytes(),
            )?;
            tracing::info!("created the device CA in {}", dir.display());
            key
        };
        let pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| anyhow::anyhow!("{}: {e}", cert_path.display()))?;
        Ok(Self { key, pem, days })
    }

    pub fn pem(&self) -> &str {
        &self.pem
    }

    /// Signs the device's CSR (its signature is verified) as a client certificate for `device_id`.
    /// Only the public key is taken from the CSR. Returns (leaf + CA PEM, leaf SHA-256, expiry).
    pub fn sign(&self, csr_pem: &str, device_id: Uuid) -> Result<(String, String, Millis), String> {
        if csr_pem.len() > 16 * 1024 {
            return Err("certificate request too large".into());
        }
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|e| format!("invalid certificate request: {e}"))?;
        let mut p = CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
        p.distinguished_name
            .push(DnType::CommonName, device_id.to_string());
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let now = std::time::SystemTime::now();
        // Backdated an hour for clock skew.
        p.not_before = (now - Duration::from_secs(3600)).into();
        let expires = now + Duration::from_secs(u64::from(self.days) * 86_400);
        p.not_after = expires.into();
        csr.params = p;
        let ca = ca_params().map_err(|e| e.to_string())?;
        let cert = csr
            .signed_by(&Issuer::new(ca, &self.key))
            .map_err(|e| format!("signing failed: {e}"))?;
        let fingerprint = hex::encode(Sha256::digest(cert.der()));
        let expires_at = expires
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as Millis)
            .unwrap_or(0);
        Ok((
            format!("{}{}", cert.pem(), self.pem),
            fingerprint,
            expires_at,
        ))
    }
}

/// The Server's TLS configuration. With a device CA, client certificates from it are requested and
/// verified, but not required at the handshake (Consoles authenticate with bearer tokens).
pub fn tls_config(
    cert: &Path,
    key: &Path,
    device_ca: Option<&DeviceCa>,
) -> anyhow::Result<rustls::ServerConfig> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| anyhow::anyhow!("{}: {e}", cert.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("{}: {e}", cert.display()))?;
    let key =
        PrivateKeyDer::from_pem_file(key).map_err(|e| anyhow::anyhow!("{}: {e}", key.display()))?;
    let builder = rustls::ServerConfig::builder();
    let builder = match device_ca {
        Some(ca) => {
            let mut roots = rustls::RootCertStore::empty();
            for c in CertificateDer::pem_slice_iter(ca.pem().as_bytes()) {
                roots.add(c.map_err(|e| anyhow::anyhow!("device CA: {e}"))?)?;
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .allow_unauthenticated()
                .build()?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };
    let mut config = builder.with_single_cert(chain, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// Completes the TLS handshake, then attaches the client certificate's fingerprint to every request
/// on the connection.
#[derive(Clone)]
pub struct ClientCertAcceptor(pub axum_server::tls_rustls::RustlsAcceptor);

impl<I, S> axum_server::accept::Accept<I, S> for ClientCertAcceptor
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = tokio_rustls::server::TlsStream<I>;
    type Service = axum::middleware::AddExtension<S, ClientCert>;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = std::io::Result<(Self::Stream, Self::Service)>> + Send,
        >,
    >;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.0.clone();
        Box::pin(async move {
            let (stream, service) = inner.accept(stream, service).await?;
            // The verifier already checked any certificate against the device CA.
            let fingerprint = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|der| hex::encode(Sha256::digest(der)));
            Ok((
                stream,
                tower::Layer::layer(&Extension(ClientCert(fingerprint)), service),
            ))
        })
    }
}

/// `POST /api/v1/device/certificate`: issues or renews this device's certificate. A device that
/// has none yet authenticates with its secret alone; one that has a certificate must present it.
pub(crate) async fn issue(
    State(s): State<AppState>,
    dev: DeviceBootstrapAuth,
    Json(req): Json<DeviceCertRequest>,
) -> Result<Json<DeviceCertResponse>, AppError> {
    let Some(ca) = s.device_ca.clone() else {
        return Err(AppError::new(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "device certificates need the Server to run with TLS",
        )));
    };
    let id: Uuid = dev
        .id
        .parse()
        .map_err(|_| AppError::new(err(StatusCode::INTERNAL_SERVER_ERROR, "corrupt device id")))?;
    let (certificate, fingerprint, expires_at) = ca
        .sign(&req.csr, id)
        .map_err(|e| AppError::new(err(StatusCode::BAD_REQUEST, e)))?;
    // The certificate used for this request stays valid until the new one is first used, so a
    // lost response cannot lock the device out.
    sqlx::query(
        "UPDATE devices SET prev_cert_sha256 = cert_sha256, cert_sha256 = ?, cert_expires_at = ?
         WHERE id = ?",
    )
    .bind(&fingerprint)
    .bind(expires_at)
    .bind(&dev.id)
    .execute(&s.db)
    .await?;
    audit(
        &s.db,
        &format!("device:{}", dev.id),
        if dev.had_cert {
            "device.cert_renew"
        } else {
            "device.cert_issue"
        },
        &dev.id,
        true,
        &format!("sha256={fingerprint} expires_at={expires_at}"),
        None,
    )
    .await;
    Ok(Json(DeviceCertResponse {
        certificate,
        expires_at,
    }))
}

/// A device authenticated for the certificate endpoint (see [`issue`]).
pub struct DeviceBootstrapAuth {
    pub id: String,
    pub had_cert: bool,
}

impl FromRequestParts<AppState> for DeviceBootstrapAuth {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, s: &AppState) -> Result<Self, Self::Rejection> {
        let (id, had_cert) = device_auth(parts, s, true).await?;
        Ok(Self { id, had_cert })
    }
}

/// Checks the bearer secret and, when the device has a certificate (or the Server requires one),
/// that the TLS client certificate is it. `bootstrap` lets a device without a certificate in, even
/// when certificates are required, so it can obtain one. Returns (device id, has certificate).
pub(crate) async fn device_auth(
    parts: &Parts,
    s: &AppState,
    bootstrap: bool,
) -> Result<(String, bool), AppError> {
    let unauthorized = |msg: &str| AppError::new(err(StatusCode::UNAUTHORIZED, msg.to_owned()));
    let secret = bearer(parts).ok_or_else(|| unauthorized("invalid device credentials"))?;
    let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, cert_sha256, prev_cert_sha256 FROM devices WHERE secret_hash = ? AND revoked = 0",
    )
    .bind(hash_secret(secret))
    .fetch_optional(&s.db)
    .await?;
    let (id, current, previous) = row.ok_or_else(|| unauthorized("invalid device credentials"))?;
    let presented = parts
        .extensions
        .get::<ClientCert>()
        .and_then(|c| c.0.clone());
    match (&current, &presented) {
        (Some(cur), Some(p)) if cur == p => {
            if previous.is_some() {
                // The renewed certificate is in use: the old one stops working now.
                sqlx::query("UPDATE devices SET prev_cert_sha256 = NULL WHERE id = ?")
                    .bind(&id)
                    .execute(&s.db)
                    .await?;
            }
            Ok((id, true))
        }
        (Some(_), Some(p)) if previous.as_deref() == Some(p.as_str()) => Ok((id, true)),
        (Some(_), _) => Err(unauthorized(
            "this device must present its device certificate (mutual TLS)",
        )),
        (None, _) if s.require_device_certs && !bootstrap => Err(unauthorized(
            "this Server requires a device certificate; the agent requests one automatically",
        )),
        (None, _) => Ok((id, false)),
    }
}
