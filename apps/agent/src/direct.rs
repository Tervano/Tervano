//! Direct (serverless) management listener: HTTPS with mandatory technician client certificates.
//!
//! Authentication: the technician presents a client certificate issued by the organization's Tervano CA
//! (`tervano-server cert tech`); its CN is the technician name. The agent presents its own self-generated
//! certificate, which consoles pin by SHA-256 fingerprint (`TervanoAgent direct-fingerprint`).
//! Authorization is checked here, per operation, never just in the Console (PLAN §12.9).

use crate::{collect, processes::Processes, secure, services};
use anyhow::Context;
use axum::{
    Extension, Json, Router,
    extract::Path as UrlPath,
    http::{HeaderMap, StatusCode},
    middleware::AddExtension,
    routing::{get, post},
};
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
    /// If non-empty, only these technician names (certificate CNs) may use read-only operations.
    #[serde(default)]
    pub allowed_technicians: Vec<String>,
    /// Technicians allowed to change this machine (e.g. terminate processes). Empty = nobody:
    /// changing operations are never granted implicitly.
    #[serde(default)]
    pub operators: Vec<String>,
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
    ListProcesses,
    KillProcess,
    ListServices,
    ControlService,
    SetServiceStartType,
}

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::ReadDeviceInfo => "device.read",
            Op::ListProcesses => "process.list",
            Op::KillProcess => "process.kill",
            Op::ListServices => "service.list",
            Op::ControlService => "service.control",
            Op::SetServiceStartType => "service.start_type",
        }
    }

    /// Operations that change the machine need an explicit `operators` entry.
    fn changes_machine(self) -> bool {
        matches!(
            self,
            Op::KillProcess | Op::ControlService | Op::SetServiceStartType
        )
    }
}

/// The authenticated technician, from the verified client certificate.
#[derive(Debug, Clone)]
struct Technician(Arc<str>);

type ApiResult<T> = Result<T, (StatusCode, Json<ApiError>)>;

fn api_err(status: StatusCode, error: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (
        status,
        Json(ApiError {
            error: error.into(),
        }),
    )
}

fn check_protocol(headers: &HeaderMap) -> ApiResult<()> {
    match headers.get(PROTOCOL_HEADER).and_then(|v| v.to_str().ok()) {
        Some(v) if is_compatible(v) => Ok(()),
        other => Err(api_err(
            StatusCode::BAD_REQUEST,
            format!("protocol {other:?} not compatible with {PROTOCOL_VERSION}"),
        )),
    }
}

/// Per-operation authorization: read-only ops follow `allowed_technicians`, changing ops require
/// `operators`. Every request is logged with its decision (local audit trail).
// shortcut: two fixed roles; configurable per-op roles arrive with RBAC (T-806).
fn authorize(cfg: &DirectConfig, tech: &Technician, op: Op) -> ApiResult<()> {
    let listed = |list: &[String]| list.iter().any(|t| **t == *tech.0);
    let ok = if op.changes_machine() {
        listed(&cfg.operators)
    } else {
        cfg.allowed_technicians.is_empty() || listed(&cfg.allowed_technicians)
    };
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

/// Runs blocking OS calls off the async workers.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> ApiResult<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn device_info(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
) -> ApiResult<Json<DeviceState>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::ReadDeviceInfo)?;
    Ok(Json(blocking(collect::device_state).await?))
}

async fn list_processes(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    Extension(procs): Extension<Arc<Processes>>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<ProcessInfo>>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::ListProcesses)?;
    Ok(Json(blocking(move || procs.list()).await?))
}

async fn kill_process(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    Extension(procs): Extension<Arc<Processes>>,
    headers: HeaderMap,
    UrlPath(pid): UrlPath<u32>,
    Json(req): Json<KillRequest>,
) -> ApiResult<StatusCode> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::KillProcess)?;
    let name = req.name.clone();
    let result = blocking(move || procs.kill(pid, &req)).await?;
    tracing::info!(technician = %tech.0, pid, process = %name, ok = result.is_ok(), detail = ?result.as_ref().err(), "process.kill");
    result
        .map(|()| StatusCode::NO_CONTENT)
        .map_err(|e| api_err(StatusCode::CONFLICT, e))
}

async fn list_services(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<ServiceEntry>>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::ListServices)?;
    blocking(services::list)
        .await?
        .map(Json)
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, e))
}

/// Logs a machine-changing service operation with its outcome, then maps it to a response.
fn service_outcome(
    tech: &Technician,
    op: Op,
    name: &str,
    what: String,
    result: Result<ServiceEntry, String>,
) -> ApiResult<Json<ServiceEntry>> {
    tracing::info!(technician = %tech.0, op = op.name(), service = name, what, ok = result.is_ok(), detail = ?result.as_ref().err(), "service change");
    result
        .map(Json)
        .map_err(|e| api_err(StatusCode::CONFLICT, e))
}

async fn control_service(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
    UrlPath(name): UrlPath<String>,
    Json(req): Json<ServiceControlRequest>,
) -> ApiResult<Json<ServiceEntry>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::ControlService)?;
    let n = name.clone();
    let result = blocking(move || services::control(&n, req.action)).await?;
    service_outcome(
        &tech,
        Op::ControlService,
        &name,
        format!("{:?}", req.action),
        result,
    )
}

async fn set_service_start_type(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
    UrlPath(name): UrlPath<String>,
    Json(req): Json<StartTypeRequest>,
) -> ApiResult<Json<ServiceEntry>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::SetServiceStartType)?;
    let n = name.clone();
    let result = blocking(move || services::set_start_type(&n, req.start_type)).await?;
    service_outcome(
        &tech,
        Op::SetServiceStartType,
        &name,
        format!("{:?}", req.start_type),
        result,
    )
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
        .route("/v1/processes", get(list_processes))
        .route("/v1/processes/{pid}/kill", post(kill_process))
        .route("/v1/services", get(list_services))
        .route("/v1/services/{name}/control", post(control_service))
        .route(
            "/v1/services/{name}/start-type",
            post(set_service_start_type),
        )
        .layer(Extension(Arc::new(cfg)))
        .layer(Extension(Arc::new(Processes::new())))
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
