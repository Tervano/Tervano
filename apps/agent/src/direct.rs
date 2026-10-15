//! Direct (serverless) management listener: HTTPS with mandatory technician client certificates.
//!
//! Authentication: the technician presents a client certificate issued by the organization's Tervano CA
//! (`tervano-server cert tech`); its CN is the technician name. The agent presents its own self-generated
//! certificate, which consoles pin by SHA-256 fingerprint (`TervanoAgent direct-fingerprint`).
//! Authorization is checked here, per operation, never just in the Console (PLAN §12.9).

use crate::{
    collect, eventlog, exec::Jobs, files, inventory, peripherals, processes::Processes, registry,
    secure, services, software, wmiq,
};
use anyhow::Context;
use axum::{
    Extension, Json, Router,
    extract::{Path as UrlPath, Query},
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
    ReadEventLog,
    ReadInventory,
    ReadRegistry,
    WriteRegistry,
    RunCommand,
    CommandStatus,
    ListFiles,
    ReadFile,
    WriteFile,
    ManageSoftware,
    QueryWmi,
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
            Op::ReadEventLog => "eventlog.read",
            Op::ReadInventory => "inventory.read",
            Op::ReadRegistry => "registry.read",
            Op::WriteRegistry => "registry.write",
            Op::RunCommand => "exec.run",
            Op::CommandStatus => "exec.status",
            Op::ListFiles => "files.list",
            Op::ReadFile => "files.read",
            Op::WriteFile => "files.write",
            Op::ManageSoftware => "software.manage",
            Op::QueryWmi => "wmi.query",
        }
    }

    /// Operations that change the machine, or read what only an administrator should (file
    /// contents, command output), need an explicit `operators` entry.
    fn needs_operator(self) -> bool {
        matches!(
            self,
            Op::KillProcess
                | Op::ControlService
                | Op::SetServiceStartType
                | Op::WriteRegistry
                | Op::RunCommand
                // Command output can be as sensitive as running it.
                | Op::CommandStatus
                // The agent can read any file (credential stores included) when it runs as SYSTEM.
                | Op::ReadFile
                | Op::WriteFile
                | Op::ManageSoftware
                // WMI exposes data such as process command lines, which can carry secrets.
                | Op::QueryWmi
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
    let ok = if op.needs_operator() {
        listed(&cfg.operators)
    } else {
        cfg.allowed_technicians.is_empty() || listed(&cfg.allowed_technicians)
    };
    // Status polls arrive every second while a command runs; keep them out of the info log.
    if matches!(op, Op::CommandStatus) && ok {
        tracing::debug!(technician = %tech.0, op = op.name(), allowed = ok, "direct request");
    } else {
        tracing::info!(technician = %tech.0, op = op.name(), allowed = ok, "direct request");
    }
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

async fn event_channels(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<String>>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::ReadEventLog)?;
    blocking(eventlog::channels)
        .await?
        .map(Json)
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, e))
}

async fn event_records(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
    Query(q): Query<EventQuery>,
) -> ApiResult<Json<Vec<EventRecord>>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::ReadEventLog)?;
    tracing::info!(technician = %tech.0, channel = %q.channel, "eventlog query");
    // Bad filters and unreadable channels (e.g. Security without admin) are the caller's to fix.
    blocking(move || eventlog::query(&q))
        .await?
        .map(Json)
        .map_err(|e| api_err(StatusCode::CONFLICT, e))
}

async fn hardware_inventory(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
) -> ApiResult<Json<HardwareInventory>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::ReadInventory)?;
    Ok(Json(blocking(inventory::hardware).await?))
}

async fn software_inventory(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
) -> ApiResult<Json<SoftwareInventory>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::ReadInventory)?;
    Ok(Json(blocking(software::inventory).await?))
}

async fn registry_key(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
    Query(k): Query<RegKeyPath>,
) -> ApiResult<Json<RegKeyContents>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::ReadRegistry)?;
    blocking(move || registry::read(&k))
        .await?
        .map(Json)
        .map_err(|e| api_err(StatusCode::CONFLICT, e))
}

async fn registry_export(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
    Query(k): Query<RegKeyPath>,
) -> ApiResult<Json<String>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::ReadRegistry)?;
    tracing::info!(technician = %tech.0, hive = ?k.hive, path = %k.path, "registry export");
    blocking(move || registry::export(&k))
        .await?
        .map(Json)
        .map_err(|e| api_err(StatusCode::CONFLICT, e))
}

/// Runs a registry change and logs who changed what (value data is not logged: it may be secret).
async fn registry_change(
    cfg: &DirectConfig,
    tech: &Technician,
    what: String,
    f: impl FnOnce() -> Result<(), String> + Send + 'static,
) -> ApiResult<StatusCode> {
    authorize(cfg, tech, Op::WriteRegistry)?;
    let result = blocking(f).await?;
    tracing::info!(technician = %tech.0, what, ok = result.is_ok(), detail = ?result.as_ref().err(), "registry change");
    result
        .map(|()| StatusCode::NO_CONTENT)
        .map_err(|e| api_err(StatusCode::CONFLICT, e))
}

async fn registry_set_value(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
    Json(req): Json<RegSetValueRequest>,
) -> ApiResult<StatusCode> {
    check_protocol(&headers)?;
    let what = format!("set {:?}\\{} [{:?}]", req.key.hive, req.key.path, req.name);
    registry_change(&cfg, &tech, what, move || registry::set_value(&req)).await
}

async fn registry_delete_value(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
    Json(req): Json<RegDeleteValueRequest>,
) -> ApiResult<StatusCode> {
    check_protocol(&headers)?;
    let what = format!(
        "delete value {:?}\\{} [{:?}]",
        req.key.hive, req.key.path, req.name
    );
    registry_change(&cfg, &tech, what, move || registry::delete_value(&req)).await
}

async fn registry_delete_key(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
    Json(req): Json<RegDeleteKeyRequest>,
) -> ApiResult<StatusCode> {
    check_protocol(&headers)?;
    let what = format!(
        "delete key {:?}\\{} recursive={}",
        req.key.hive, req.key.path, req.recursive
    );
    registry_change(&cfg, &tech, what, move || registry::delete_key(&req)).await
}

async fn exec_start(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    Extension(jobs): Extension<Arc<Jobs>>,
    headers: HeaderMap,
    Json(req): Json<ExecRequest>,
) -> ApiResult<Json<ExecStatus>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::RunCommand)?;
    let id = jobs
        .start(&tech.0, req)
        .map_err(|e| api_err(StatusCode::CONFLICT, e))?;
    jobs.status(id)
        .map(Json)
        .ok_or_else(|| api_err(StatusCode::INTERNAL_SERVER_ERROR, "command vanished"))
}

async fn exec_status(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    Extension(jobs): Extension<Arc<Jobs>>,
    headers: HeaderMap,
    UrlPath(id): UrlPath<uuid::Uuid>,
) -> ApiResult<Json<ExecStatus>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::CommandStatus)?;
    jobs.status(id).map(Json).ok_or_else(|| {
        api_err(
            StatusCode::NOT_FOUND,
            "no such command (finished ones are kept 10 minutes)",
        )
    })
}

async fn exec_cancel(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    Extension(jobs): Extension<Arc<Jobs>>,
    headers: HeaderMap,
    UrlPath(id): UrlPath<uuid::Uuid>,
) -> ApiResult<StatusCode> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::RunCommand)?;
    tracing::info!(technician = %tech.0, %id, "exec cancel");
    jobs.cancel(id)
        .map(|()| StatusCode::NO_CONTENT)
        .map_err(|e| api_err(StatusCode::CONFLICT, e))
}

async fn files_list(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
    Query(q): Query<FilePathQuery>,
) -> ApiResult<Json<DirListing>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::ListFiles)?;
    blocking(move || files::list(&q.path))
        .await?
        .map(Json)
        .map_err(|e| api_err(StatusCode::CONFLICT, e))
}

async fn files_read(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
    Query(q): Query<FileChunkQuery>,
) -> ApiResult<([(String, String); 1], Vec<u8>)> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::ReadFile)?;
    if q.offset == 0 {
        // One line per transfer, not per chunk.
        tracing::info!(technician = %tech.0, path = %q.path, "file download");
    }
    let (bytes, size) = blocking(move || files::read_chunk(&q.path, q.offset, q.len))
        .await?
        .map_err(|e| api_err(StatusCode::CONFLICT, e))?;
    Ok(([(FILE_SIZE_HEADER.to_string(), size.to_string())], bytes))
}

async fn files_hash(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
    Query(q): Query<FilePathQuery>,
) -> ApiResult<Json<FileHash>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::ReadFile)?;
    blocking(move || files::hash(&q.path))
        .await?
        .map(Json)
        .map_err(|e| api_err(StatusCode::CONFLICT, e))
}

async fn files_upload(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
    Query(q): Query<FileChunkQuery>,
    body: axum::body::Bytes,
) -> ApiResult<Json<UploadProgress>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::WriteFile)?;
    if q.offset == 0 {
        tracing::info!(technician = %tech.0, path = %q.path, "file upload");
    }
    blocking(move || files::upload_chunk(&q.path, q.offset, &body))
        .await?
        .map(|part_size| Json(UploadProgress { part_size }))
        .map_err(|(e, _)| api_err(StatusCode::CONFLICT, e))
}

async fn files_upload_finish(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
    Json(req): Json<UploadFinish>,
) -> ApiResult<Json<FileHash>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::WriteFile)?;
    let path = req.path.clone();
    let result = blocking(move || files::upload_finish(&req)).await?;
    tracing::info!(technician = %tech.0, path, ok = result.is_ok(), detail = ?result.as_ref().err(), "file upload finished");
    result
        .map(Json)
        .map_err(|e| api_err(StatusCode::CONFLICT, e))
}

async fn files_op(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
    Json(op): Json<FileOp>,
) -> ApiResult<StatusCode> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::WriteFile)?;
    let what = format!("{op:?}");
    let result = blocking(move || files::op(&op)).await?;
    tracing::info!(technician = %tech.0, what, ok = result.is_ok(), detail = ?result.as_ref().err(), "file operation");
    result
        .map(|()| StatusCode::NO_CONTENT)
        .map_err(|e| api_err(StatusCode::CONFLICT, e))
}

/// Installers can run long; they get the maximum job timeout below 1 h.
const INSTALL_TIMEOUT_SECS: u32 = 1800;

/// Runs an install/uninstall command as a tracked job so the Console can poll it like Commands.
fn software_job(
    jobs: &Jobs,
    tech: &Technician,
    what: &str,
    script: String,
) -> ApiResult<Json<ExecStatus>> {
    tracing::info!(technician = %tech.0, what, "software change");
    let id = jobs
        .start(
            &tech.0,
            ExecRequest {
                shell: Shell::Cmd,
                script,
                context: ExecContext::Agent,
                timeout_secs: Some(INSTALL_TIMEOUT_SECS),
            },
        )
        .map_err(|e| api_err(StatusCode::CONFLICT, e))?;
    jobs.status(id)
        .map(Json)
        .ok_or_else(|| api_err(StatusCode::INTERNAL_SERVER_ERROR, "job vanished"))
}

async fn software_uninstall(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    Extension(jobs): Extension<Arc<Jobs>>,
    headers: HeaderMap,
    Json(req): Json<UninstallRequest>,
) -> ApiResult<Json<ExecStatus>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::ManageSoftware)?;
    let (name, script) =
        blocking(move || software::uninstall_command(&req.uninstall_key, &req.scope))
            .await?
            .map_err(|e| api_err(StatusCode::CONFLICT, e))?;
    software_job(&jobs, &tech, &format!("uninstall {name}"), script)
}

async fn software_install(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    Extension(jobs): Extension<Arc<Jobs>>,
    headers: HeaderMap,
    Json(req): Json<InstallRequest>,
) -> ApiResult<Json<ExecStatus>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::ManageSoftware)?;
    let path = req.msi_path.clone();
    let script = blocking(move || software::install_command(&req.msi_path))
        .await?
        .map_err(|e| api_err(StatusCode::CONFLICT, e))?;
    software_job(&jobs, &tech, &format!("install {path}"), script)
}

async fn peripherals_inventory(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
) -> ApiResult<Json<Peripherals>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::ReadInventory)?;
    blocking(peripherals::inventory)
        .await?
        .map(Json)
        .map_err(|e| api_err(StatusCode::CONFLICT, e))
}

async fn wmi_query(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
    Query(q): Query<WmiQuery>,
) -> ApiResult<Json<WmiTable>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::QueryWmi)?;
    tracing::info!(technician = %tech.0, namespace = ?q.namespace, wql = %q.wql, "wmi query");
    blocking(move || wmiq::query(&q))
        .await?
        .map(Json)
        .map_err(|e| api_err(StatusCode::CONFLICT, e))
}

async fn wmi_classes(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
    Query(q): Query<WmiQuery>,
) -> ApiResult<Json<Vec<String>>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::QueryWmi)?;
    blocking(move || wmiq::classes(q.namespace.as_deref()))
        .await?
        .map(Json)
        .map_err(|e| api_err(StatusCode::CONFLICT, e))
}

async fn update_status(
    Extension(cfg): Extension<Arc<DirectConfig>>,
    Extension(tech): Extension<Technician>,
    headers: HeaderMap,
) -> ApiResult<Json<UpdateStatus>> {
    check_protocol(&headers)?;
    authorize(&cfg, &tech, Op::ReadInventory)?;
    blocking(wmiq::updates)
        .await?
        .map(Json)
        .map_err(|e| api_err(StatusCode::CONFLICT, e))
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
        .route("/v1/eventlog/channels", get(event_channels))
        .route("/v1/eventlog/events", get(event_records))
        .route("/v1/inventory/hardware", get(hardware_inventory))
        .route("/v1/inventory/software", get(software_inventory))
        .route("/v1/inventory/peripherals", get(peripherals_inventory))
        .route("/v1/wmi/query", get(wmi_query))
        .route("/v1/wmi/classes", get(wmi_classes))
        .route("/v1/updates", get(update_status))
        .route("/v1/software/uninstall", post(software_uninstall))
        .route("/v1/software/install", post(software_install))
        .route("/v1/registry/key", get(registry_key))
        .route("/v1/registry/export", get(registry_export))
        .route("/v1/registry/value", post(registry_set_value))
        .route("/v1/registry/value/delete", post(registry_delete_value))
        .route("/v1/registry/key/delete", post(registry_delete_key))
        .route("/v1/exec", post(exec_start))
        .route("/v1/exec/{id}", get(exec_status))
        .route("/v1/exec/{id}/cancel", post(exec_cancel))
        .route("/v1/files/list", get(files_list))
        .route("/v1/files/read", get(files_read))
        .route("/v1/files/hash", get(files_hash))
        .route(
            "/v1/files/upload",
            // The only route taking a large body: one chunk plus headroom.
            post(files_upload).layer(axum::extract::DefaultBodyLimit::max(
                FILE_CHUNK_MAX as usize + 64 * 1024,
            )),
        )
        .route("/v1/files/upload/finish", post(files_upload_finish))
        .route("/v1/files/op", post(files_op))
        .route("/v1/services/{name}/control", post(control_service))
        .route(
            "/v1/services/{name}/start-type",
            post(set_service_start_type),
        )
        .layer(Extension(Arc::new(cfg)))
        .layer(Extension(Arc::new(Processes::new())))
        .layer(Extension(Arc::new(Jobs::new(state_dir.clone()))))
        // Scripts are capped at 64 KiB; leave room for the JSON envelope.
        .layer(axum::extract::DefaultBodyLimit::max(96 * 1024));
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
