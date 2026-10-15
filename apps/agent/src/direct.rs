//! Direct (serverless) management listener: HTTPS with mandatory technician client certificates.
//!
//! Authentication: the technician presents a client certificate issued by the organization's Tervano CA
//! (`tervano-server cert tech`); its CN is the technician name. The agent presents its own self-generated
//! certificate, which consoles pin by SHA-256 fingerprint (`TervanoAgent direct-fingerprint`).
//! Authorization is checked here, per operation, never just in the Console (PLAN §12.9).

use crate::{collect, secure};
use anyhow::Context;
use axum::{Extension, Json, Router, http::StatusCode, middleware::AddExtension, routing::get};
use axum_server::{accept::Accept, tls_rustls::RustlsAcceptor};
use futures_util::future::BoxFuture;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{io, path::Path, path::PathBuf, sync::Arc, time::Duration};
use tervano_protocol::*;
use tokio::sync::watch;
use tower::Layer;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConfig {
    /// e.g. "0.0.0.0:8472".
    pub listen: String,
    /// PEM CA whose client certificates are accepted (the organization's Tervano CA).
    pub technician_ca: PathBuf,
    /// If non-empty, only these technician names (certificate CNs) are authorized.
    #[serde(default)]
    pub allowed_technicians: Vec<String>,
}

impl DirectConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        self.listen
            .parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow::anyhow!("direct.listen: {e}"))?;
        anyhow::ensure!(
            self.technician_ca.exists(),
            "direct.technician_ca {} not found",
            self.technician_ca.display()
        );
        Ok(())
    }
}

/// Operations a technician can request directly. Each is authorized individually.
#[derive(Debug, Clone, Copy)]
enum Op {
    ReadDeviceInfo,
}

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::ReadDeviceInfo => "device.read",
        }
    }
}

/// The authenticated technician, from the verified client certificate.
#[derive(Debug, Clone)]
struct Technician(Arc<str>);

/// Per-operation authorization. Every request is logged with its decision (local audit trail).
// shortcut: one allowlist covers all ops; per-op roles arrive with RBAC (T-806/T-402).
fn authorize(
    cfg: &DirectConfig,
    tech: &Technician,
    op: Op,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let ok = cfg.allowed_technicians.is_empty()
        || cfg.allowed_technicians.iter().any(|t| **t == *tech.0);
    tracing::info!(technician = %tech.0, op = op.name(), allowed = ok, "direct request");
    if ok {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(ApiError {
                error: format!("technician {} is not authorized for {}", tech.0, op.name()),
            }),
        ))
    }
}

const CERT_FILE: &str = "direct-cert.pem";
const KEY_FILE: &str = "direct-key.dpapi";

/// SHA-256 of the agent's direct certificate, lowercase hex; what consoles pin.
pub fn fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// Loads the agent's direct TLS identity, generating it on first use. The key is DPAPI-protected.
pub fn load_or_create_identity(
    state_dir: &Path,
) -> anyhow::Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let (cert_path, key_path) = (state_dir.join(CERT_FILE), state_dir.join(KEY_FILE));
    if !cert_path.exists() || !key_path.exists() {
        let state = collect::device_state();
        let (host, domain) = (state.hostname, state.domain);
        let mut names = vec![host.clone()];
        if let Some(d) = domain {
            names.push(format!("{host}.{d}"));
        }
        let key = rcgen::KeyPair::generate()?;
        let mut p = rcgen::CertificateParams::new(names)?;
        p.distinguished_name
            .push(rcgen::DnType::CommonName, format!("Tervano Agent {host}"));
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        p.not_after = rcgen::date_time_ymd(2100, 1, 1);
        let cert = p.self_signed(&key)?;
        std::fs::write(
            &key_path,
            hex::encode(secure::protect(key.serialize_pem().as_bytes())?),
        )?;
        std::fs::write(&cert_path, cert.pem())?;
    }
    let cert = CertificateDer::from_pem_file(&cert_path).context("reading direct-cert.pem")?;
    let key_pem = secure::unprotect(&hex::decode(std::fs::read_to_string(&key_path)?.trim())?)
        .context("direct-key.dpapi unreadable; delete direct-* files to regenerate")?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem).context("parsing direct key")?;
    Ok((cert, key))
}

fn tls_config(cfg: &DirectConfig, state_dir: &Path) -> anyhow::Result<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(&cfg.technician_ca).context("reading technician_ca")? {
        roots.add(c?)?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()?;
    let (cert, key) = load_or_create_identity(state_dir)?;
    tracing::info!(fingerprint = %fingerprint(&cert), "direct listener identity");
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tls)
}

/// Completes the mTLS handshake, then attaches the technician (client cert CN) to every request.
#[derive(Clone)]
struct TechAcceptor(RustlsAcceptor);

impl<I, S> Accept<I, S> for TechAcceptor
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = tokio_rustls::server::TlsStream<I>;
    type Service = AddExtension<S, Technician>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.0.clone();
        Box::pin(async move {
            let (stream, service) = inner.accept(stream, service).await?;
            // The verifier already required a CA-signed client cert; we only need its CN.
            let name = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .and_then(|der| common_name(der))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "client certificate has no CN",
                    )
                })?;
            Ok((stream, Extension(Technician(name.into())).layer(service)))
        })
    }
}

fn common_name(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let cn = cert.subject().iter_common_name().next()?.as_str().ok()?;
    (!cn.is_empty()).then(|| cn.to_owned())
}

async fn device_info(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: axum::http::HeaderMap,
) -> Result<Json<DeviceState>, (StatusCode, Json<ApiError>)> {
    let bad = |m: String| (StatusCode::BAD_REQUEST, Json(ApiError { error: m }));
    match headers.get(PROTOCOL_HEADER).and_then(|v| v.to_str().ok()) {
        Some(v) if is_compatible(v) => {}
        other => {
            return Err(bad(format!(
                "protocol {other:?} not compatible with {PROTOCOL_VERSION}"
            )));
        }
    }
    authorize(&cfg, &tech, Op::ReadDeviceInfo)?;
    let state = tokio::task::spawn_blocking(collect::device_state)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: e.to_string(),
                }),
            )
        })?;
    Ok(Json(state))
}

/// Serves direct management until `stop` fires.
pub async fn serve(
    cfg: DirectConfig,
    state_dir: PathBuf,
    mut stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let addr: std::net::SocketAddr = cfg.listen.parse()?;
    let tls =
        axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config(&cfg, &state_dir)?));
    let app = Router::new()
        .route("/v1/device", get(device_info))
        .layer(Extension(Arc::new(cfg)))
        .layer(axum::extract::DefaultBodyLimit::max(16 * 1024));
    let handle = axum_server::Handle::new();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = stop.changed().await;
        h.graceful_shutdown(Some(Duration::from_secs(5)));
    });
    tracing::info!("direct management listening on https://{addr} (client certificate required)");
    axum_server::bind(addr)
        .acceptor(TechAcceptor(RustlsAcceptor::new(tls)))
        .handle(handle)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}
