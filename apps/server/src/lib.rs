//! Tervano Server library: HTTP API + persistence. `main.rs` is the CLI around it.

pub mod audit_archive;
mod compliance;
mod groups;
mod rbac;
mod reports;

pub use rbac::set_technician_access;
mod jobs;

use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, FromRequestParts, Path, Query, Request, State},
    http::{HeaderValue, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool, sqlite::SqliteConnectOptions};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tervano_protocol::*;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    pub database_url: String,
    pub offline_after_secs: u64,
    pub event_retention_days: u32,
    pub requests_per_second: u32,
    pub enrollments_per_minute: u32,
    pub audit_retention_days: Option<u32>,
    pub audit_archive_dir: Option<std::path::PathBuf>,
    /// PEM certificate chain and private key. Required unless `listen` is loopback.
    pub tls_cert: Option<std::path::PathBuf>,
    pub tls_key: Option<std::path::PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8470".into(),
            database_url: "sqlite://tervano.db?mode=rwc".into(),
            offline_after_secs: 180,
            event_retention_days: 30,
            requests_per_second: 100,
            enrollments_per_minute: 60,
            audit_retention_days: None,
            audit_archive_dir: None,
            tls_cert: None,
            tls_key: None,
        }
    }
}

impl Config {
    pub fn validate(&self) -> anyhow::Result<()> {
        let addr: std::net::SocketAddr = self
            .listen
            .parse()
            .map_err(|e| anyhow::anyhow!("listen: {e}"))?;
        anyhow::ensure!(
            self.tls_cert.is_some() == self.tls_key.is_some(),
            "set both tls_cert and tls_key, or neither"
        );
        anyhow::ensure!(
            self.tls_cert.is_some() || addr.ip().is_loopback(),
            "listen = {addr} is not loopback: configure tls_cert/tls_key (see `tervano-server cert init`)"
        );
        anyhow::ensure!(
            self.offline_after_secs >= 10,
            "offline_after_secs must be >= 10"
        );
        anyhow::ensure!(
            self.event_retention_days >= 1,
            "event_retention_days must be >= 1"
        );
        anyhow::ensure!(
            (1..=100_000).contains(&self.requests_per_second),
            "requests_per_second must be 1-100000"
        );
        anyhow::ensure!(
            (1..=100_000).contains(&self.enrollments_per_minute),
            "enrollments_per_minute must be 1-100000"
        );
        anyhow::ensure!(
            self.audit_retention_days.is_some() == self.audit_archive_dir.is_some(),
            "set both audit_retention_days and audit_archive_dir, or neither"
        );
        if let (Some(days), Some(dir)) = (self.audit_retention_days, &self.audit_archive_dir) {
            anyhow::ensure!(days >= 1, "audit_retention_days must be >= 1");
            anyhow::ensure!(dir.is_absolute(), "audit_archive_dir must be absolute");
            anyhow::ensure!(dir.is_dir(), "audit_archive_dir must already exist");
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub offline_after_ms: i64,
    /// Ids of devices whose summary may have changed; fanned out to `/api/v1/stream` clients.
    pub changes: tokio::sync::broadcast::Sender<Uuid>,
    accepted_events: Arc<AtomicU64>,
    started_at_seconds: i64,
    limits: Arc<RequestLimits>,
}

const MAX_API_BODY: usize = 256 * 1024;
/// Software inventories run ~240 bytes per app; this covers several thousand apps.
const MAX_INVENTORY_BODY: usize = 2 * 1024 * 1024;
const INVENTORY_PATH: &str = "/api/v1/inventory";
/// Two 64 KiB output streams can triple in size as escaped JSON.
const MAX_JOB_RESULT_BODY: usize = 1024 * 1024;

/// Largest body admitted for `path`; matches the per-route `DefaultBodyLimit`s in [`app`].
fn body_limit(path: &str) -> usize {
    if path == INVENTORY_PATH {
        MAX_INVENTORY_BODY
    } else if path.starts_with("/api/v1/agent/jobs/") && path.ends_with("/result") {
        MAX_JOB_RESULT_BODY
    } else {
        MAX_API_BODY
    }
}
const MAX_IN_FLIGHT: usize = 128;
const MAX_STREAMS: usize = 256;
const MAX_RATE_PEERS: usize = 65_536;

#[derive(Clone, Copy, Hash, Eq, PartialEq)]
enum RateClass {
    Enrollment,
    General,
}

struct RateWindow {
    started: Instant,
    count: u32,
}

struct RequestLimits {
    peers: Mutex<HashMap<(IpAddr, RateClass), RateWindow>>,
    requests_per_second: u32,
    enrollments_per_minute: u32,
    in_flight: Arc<tokio::sync::Semaphore>,
    streams: Arc<tokio::sync::Semaphore>,
}

impl RequestLimits {
    fn new(requests_per_second: u32, enrollments_per_minute: u32) -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
            requests_per_second,
            enrollments_per_minute,
            in_flight: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT)),
            streams: Arc::new(tokio::sync::Semaphore::new(MAX_STREAMS)),
        }
    }

    fn admit(&self, peer: IpAddr, class: RateClass) -> bool {
        let (window, max) = match class {
            RateClass::Enrollment => (Duration::from_secs(60), self.enrollments_per_minute),
            RateClass::General => (Duration::from_secs(1), self.requests_per_second),
        };
        let now = Instant::now();
        let Ok(mut peers) = self.peers.lock() else {
            return false;
        };
        let key = (peer, class);
        if !peers.contains_key(&key) && peers.len() >= MAX_RATE_PEERS {
            peers.retain(|(_, class), entry| {
                let life = match class {
                    RateClass::Enrollment => Duration::from_secs(60),
                    RateClass::General => Duration::from_secs(1),
                };
                now.duration_since(entry.started) < life
            });
            if peers.len() >= MAX_RATE_PEERS {
                return false;
            }
        }
        let entry = peers.entry(key).or_insert(RateWindow {
            started: now,
            count: 0,
        });
        if now.duration_since(entry.started) >= window {
            entry.started = now;
            entry.count = 0;
        }
        if entry.count >= max {
            return false;
        }
        entry.count += 1;
        true
    }
}

impl AppState {
    pub fn new(db: SqlitePool, offline_after_ms: i64) -> Self {
        Self::with_rate_limits(db, offline_after_ms, 100, 60)
    }

    pub fn with_rate_limits(
        db: SqlitePool,
        offline_after_ms: i64,
        requests_per_second: u32,
        enrollments_per_minute: u32,
    ) -> Self {
        // Bounded: a client that falls this far behind gets a `resync` instead of unbounded memory.
        let (changes, _) = tokio::sync::broadcast::channel(1024);
        Self {
            db,
            offline_after_ms,
            changes,
            accepted_events: Arc::new(AtomicU64::new(0)),
            started_at_seconds: now_millis() / 1000,
            limits: Arc::new(RequestLimits::new(
                requests_per_second,
                enrollments_per_minute,
            )),
        }
    }

    fn publish(&self, id: &str) {
        if let Ok(id) = id.parse() {
            // Err just means nobody is listening.
            let _ = self.changes.send(id);
        }
    }
}

/// Announces devices that just crossed the offline timeout, since no request marks that moment.
pub fn spawn_offline_sweeper(state: AppState) {
    const EVERY_MS: i64 = 5_000;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(EVERY_MS as u64));
        loop {
            tick.tick().await;
            let cutoff = now_millis() - state.offline_after_ms;
            let ids: Result<Vec<String>, _> = sqlx::query_scalar(
                "SELECT id FROM devices WHERE revoked = 0 AND last_seen <= ? AND last_seen > ?",
            )
            .bind(cutoff)
            .bind(cutoff - EVERY_MS)
            .fetch_all(&state.db)
            .await;
            match ids {
                Ok(ids) => ids.iter().for_each(|id| state.publish(id)),
                Err(e) => tracing::warn!("offline sweep failed: {e}"),
            }
        }
    });
}

/// Removes old device event snapshots at startup and hourly, without monopolizing SQLite writes.
/// Keeps query-group membership current (T-812): a device that starts or stops matching a saved
/// search joins or leaves the group, and with it any technician scope built on it, within a minute.
pub fn spawn_query_group_refresher(db: SqlitePool) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            if let Err(e) = groups::refresh_query_groups(&db, None).await {
                tracing::warn!("query group refresh failed: {e}");
            }
        }
    });
}

pub fn spawn_event_purger(db: SqlitePool, retention_days: u32) {
    let retention_ms = i64::from(retention_days) * 86_400_000;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            tick.tick().await;
            let cutoff = now_millis() - retention_ms;
            let mut deleted = 0;
            loop {
                let result = sqlx::query(
                    "DELETE FROM device_events WHERE rowid IN (
                        SELECT rowid FROM device_events WHERE received_at < ?
                        ORDER BY received_at LIMIT 1000)",
                )
                .bind(cutoff)
                .execute(&db)
                .await;
                match result {
                    Ok(result) => {
                        let count = result.rows_affected();
                        deleted += count;
                        if count < 1000 {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("event purge failed: {e}");
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            if deleted > 0 {
                tracing::info!(deleted, retention_days, "old device events purged");
            }
        }
    });
}

pub async fn connect(database_url: &str) -> anyhow::Result<SqlitePool> {
    let opts = SqliteConnectOptions::from_str(database_url)?
        .foreign_keys(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
    // In-memory DBs are per-connection, so they need a single connection.
    let max = if database_url.contains(":memory:") {
        1
    } else {
        8
    };
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(max)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(opts)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

pub fn hash_secret(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

/// 256-bit random secret, hex encoded.
pub fn new_secret() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("OS RNG unavailable");
    hex::encode(buf)
}

/// Creates an enrollment token valid for `uses` enrollments within `valid_for`. Returns the plaintext token.
pub async fn create_enrollment_token(
    db: &SqlitePool,
    uses: u32,
    valid_for: Duration,
) -> anyhow::Result<String> {
    let token = new_secret();
    let now = now_millis();
    sqlx::query("INSERT INTO enrollment_tokens (token_hash, uses_left, expires_at, created_at) VALUES (?, ?, ?, ?)")
        .bind(hash_secret(&token))
        .bind(uses as i64)
        .bind(now + valid_for.as_millis() as i64)
        .bind(now)
        .execute(db)
        .await?;
    Ok(token)
}

pub const DEFAULT_TECH_TOKEN_HOURS: u64 = 30 * 24;
pub const MAX_TECH_TOKEN_HOURS: u64 = 90 * 24;

fn technician_expiry(valid_for: Duration) -> anyhow::Result<i64> {
    let millis = i64::try_from(valid_for.as_millis())?;
    let max_millis = i64::try_from(MAX_TECH_TOKEN_HOURS)? * 3_600_000;
    anyhow::ensure!(
        (3_600_000..=max_millis).contains(&millis),
        "technician token lifetime must be between 1 hour and 90 days"
    );
    now_millis()
        .checked_add(millis)
        .ok_or_else(|| anyhow::anyhow!("technician token expiry exceeds timestamp range"))
}

fn validate_technician_name(name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !name.trim().is_empty() && name.len() <= 128 && !name.chars().any(char::is_control),
        "technician name must be 1-128 bytes without control characters"
    );
    Ok(())
}

/// Creates a technician API token valid for 30 days. Returns the plaintext token once.
pub async fn create_technician(db: &SqlitePool, name: &str) -> anyhow::Result<String> {
    create_technician_with_ttl(
        db,
        name,
        Duration::from_secs(DEFAULT_TECH_TOKEN_HOURS * 3600),
    )
    .await
}

pub async fn create_technician_with_ttl(
    db: &SqlitePool,
    name: &str,
    valid_for: Duration,
) -> anyhow::Result<String> {
    validate_technician_name(name)?;
    let expires_at = technician_expiry(valid_for)?;
    let token = new_secret();
    sqlx::query("INSERT INTO technicians (id, name, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)")
        .bind(Uuid::new_v4().to_string())
        .bind(name)
        .bind(hash_secret(&token))
        .bind(now_millis())
        .bind(expires_at)
        .execute(db)
        .await?;
    Ok(token)
}

/// Replaces one active or expired token. A revoked technician cannot be rotated back into service.
pub async fn rotate_technician(
    db: &SqlitePool,
    name: &str,
    valid_for: Duration,
    actor: &str,
) -> anyhow::Result<String> {
    validate_technician_name(name)?;
    let expires_at = technician_expiry(valid_for)?;
    let token = new_secret();
    let mut tx = db.begin().await?;
    let changed = sqlx::query(
        "UPDATE technicians SET token_hash = ?, expires_at = ? WHERE name = ? AND revoked_at IS NULL",
    )
    .bind(hash_secret(&token))
    .bind(expires_at)
    .bind(name)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    anyhow::ensure!(changed == 1, "technician not found or revoked");
    sqlx::query("INSERT INTO audit_log (at, actor, action, target, ok, detail) VALUES (?, ?, 'technician.rotate', ?, 1, ?)")
        .bind(now_millis())
        .bind(actor)
        .bind(name)
        .bind(format!("expires_at={expires_at}"))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(token)
}

/// Invalidates a technician token. The audit row and revocation commit together.
/// One enrolled device as the CLI lists it: (id, hostname, last_seen ms, revoked).
pub async fn list_devices(db: &SqlitePool) -> anyhow::Result<Vec<(String, String, i64, bool)>> {
    let rows = sqlx::query(
        "SELECT id, hostname, last_seen, revoked FROM devices ORDER BY hostname COLLATE NOCASE",
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get("id"),
                r.get("hostname"),
                r.get("last_seen"),
                r.get::<i64, _>("revoked") != 0,
            )
        })
        .collect())
}

/// Decommissions a device: its secret stops working, it disappears from search, and its
/// events/inventory are no longer accepted. The agent must re-enroll with a new token to return.
pub async fn revoke_device(db: &SqlitePool, id: Uuid, actor: &str) -> anyhow::Result<String> {
    let mut tx = db.begin().await?;
    let hostname: Option<String> =
        sqlx::query_scalar("SELECT hostname FROM devices WHERE id = ? AND revoked = 0")
            .bind(id.to_string())
            .fetch_optional(&mut *tx)
            .await?;
    let hostname =
        hostname.ok_or_else(|| anyhow::anyhow!("device not found or already revoked"))?;
    sqlx::query("UPDATE devices SET revoked = 1 WHERE id = ?")
        .bind(id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO audit_log (at, actor, action, target, ok, detail) VALUES (?, ?, 'device.revoke', ?, 1, ?)")
        .bind(now_millis())
        .bind(actor)
        .bind(id.to_string())
        .bind(&hostname)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(hostname)
}

pub async fn revoke_technician(db: &SqlitePool, name: &str, actor: &str) -> anyhow::Result<()> {
    validate_technician_name(name)?;
    let now = now_millis();
    let mut tx = db.begin().await?;
    let changed =
        sqlx::query("UPDATE technicians SET revoked_at = ? WHERE name = ? AND revoked_at IS NULL")
            .bind(now)
            .bind(name)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    anyhow::ensure!(changed == 1, "technician not found or already revoked");
    sqlx::query("INSERT INTO audit_log (at, actor, action, target, ok, detail) VALUES (?, ?, 'technician.revoke', ?, 1, '')")
        .bind(now)
        .bind(actor)
        .bind(name)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub fn app(state: AppState) -> Router {
    let api = Router::new()
        .route("/enroll", post(enroll))
        .route("/events", post(ingest_events))
        .route(
            "/inventory",
            post(ingest_inventory).layer(axum::extract::DefaultBodyLimit::max(MAX_INVENTORY_BODY)),
        )
        .route("/devices/{id}/inventory", get(device_inventory))
        .route("/devices", get(search_devices))
        .route("/devices/{id}", get(device_details))
        .route("/devices/{id}/events", get(device_events))
        .route("/audit", get(list_audit))
        .route("/me", get(rbac::me))
        .route(
            "/compliance",
            get(compliance::list).post(compliance::create),
        )
        .route("/compliance/{id}", delete(compliance::delete_check))
        .route("/compliance/{id}/results", get(compliance::results))
        .route("/reports/software", get(reports::software))
        .route("/reports/software/devices", get(reports::software_devices))
        .route("/reports/os", get(reports::os))
        .route("/reports/hardware", get(reports::hardware))
        .route(
            "/groups",
            get(groups::list_groups).post(groups::create_group),
        )
        .route("/groups/{id}", delete(groups::delete_group))
        .route("/groups/{id}/members", post(groups::change_members))
        .route("/jobs", post(jobs::create_job).get(jobs::list_jobs))
        .route("/jobs/{id}", get(jobs::get_job))
        .route("/jobs/{id}/cancel", post(jobs::cancel_job))
        .route("/agent/jobs/claim", post(jobs::claim_job))
        .route("/agent/jobs/{id}/progress", post(jobs::job_progress))
        .route(
            "/agent/jobs/{id}/result",
            post(jobs::job_result).layer(axum::extract::DefaultBodyLimit::max(MAX_JOB_RESULT_BODY)),
        )
        .route("/stream", get(stream_changes))
        .layer(middleware::from_fn(require_protocol))
        // State JSON is small; this bounds memory per request.
        .layer(axum::extract::DefaultBodyLimit::max(MAX_API_BODY));
    Router::new()
        .route("/metrics", get(metrics))
        .nest("/api/v1", api)
        .layer(middleware::from_fn_with_state(state.clone(), admit_request))
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
        .with_state(state)
}

async fn admit_request(State(s): State<AppState>, req: Request, next: Next) -> Response {
    if req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > body_limit(req.uri().path()))
    {
        return err(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    }
    // ConnectInfo uses the socket peer. A reverse proxy needs its own client-aware limit.
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::from([0, 0, 0, 0]), |info| info.0.ip());
    let class = if req.uri().path().ends_with("/enroll") {
        RateClass::Enrollment
    } else {
        RateClass::General
    };
    if !s.limits.admit(peer, class) {
        let retry = if matches!(class, RateClass::Enrollment) {
            "60"
        } else {
            "1"
        };
        return limited(StatusCode::TOO_MANY_REQUESTS, retry);
    }
    let Ok(permit) = s.limits.in_flight.clone().try_acquire_owned() else {
        return limited(StatusCode::SERVICE_UNAVAILABLE, "1");
    };
    let response = next.run(req).await;
    drop(permit);
    response
}

async fn readyz(State(s): State<AppState>) -> StatusCode {
    match sqlx::query("SELECT 1").execute(&s.db).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Prometheus text exposition; only aggregate counts are exposed to authenticated technicians.
async fn metrics(State(s): State<AppState>, tech: TechAuth) -> Result<impl IntoResponse, AppError> {
    tech.require(&s, TechRole::Admin, "metrics.read", "")
        .await?;
    let cutoff = now_millis() - s.offline_after_ms;
    let (devices, online, stored_events): (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM devices WHERE revoked = 0),
                (SELECT COUNT(*) FROM devices WHERE revoked = 0 AND last_seen > ?),
                (SELECT COUNT(*) FROM device_events)",
    )
    .bind(cutoff)
    .fetch_one(&s.db)
    .await?;
    let body = format!(
        "# HELP tervano_server_start_time_seconds Unix time when this Server process started.\n\
         # TYPE tervano_server_start_time_seconds gauge\n\
         tervano_server_start_time_seconds {}\n\
         # HELP tervano_agent_events_accepted_total Agent events accepted since this Server process started.\n\
         # TYPE tervano_agent_events_accepted_total counter\n\
         tervano_agent_events_accepted_total {}\n\
         # HELP tervano_devices_enrolled Enrolled devices that are not revoked.\n\
         # TYPE tervano_devices_enrolled gauge\n\
         tervano_devices_enrolled {devices}\n\
         # HELP tervano_devices_online Non-revoked devices inside the offline timeout.\n\
         # TYPE tervano_devices_online gauge\n\
         tervano_devices_online {online}\n\
         # HELP tervano_device_events_stored Device history rows currently stored after retention.\n\
         # TYPE tervano_device_events_stored gauge\n\
         tervano_device_events_stored {stored_events}\n",
        s.started_at_seconds,
        s.accepted_events.load(Ordering::Relaxed),
    );
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    ))
}

async fn require_protocol(req: Request, next: Next) -> Response {
    match req
        .headers()
        .get(PROTOCOL_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        Some(v) if is_compatible(v) => next.run(req).await,
        Some(v) => err(
            StatusCode::BAD_REQUEST,
            format!("incompatible protocol {v}, server speaks {PROTOCOL_VERSION}"),
        ),
        None => err(
            StatusCode::BAD_REQUEST,
            format!("missing {PROTOCOL_HEADER} header"),
        ),
    }
}

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ApiError { error: msg.into() })).into_response()
}

fn limited(status: StatusCode, retry_after: &'static str) -> Response {
    let mut response = err(status, "request limit reached");
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static(retry_after));
    response
}

/// Boxed so `Result<_, AppError>` stays small (clippy::result_large_err).
pub struct AppError(Box<Response>);

impl AppError {
    fn new(r: Response) -> Self {
        Self(Box::new(r))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        *self.0
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!("database error: {e}");
        AppError::new(err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))
    }
}

fn bearer(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// An authenticated, non-revoked enrolled device.
pub struct DeviceAuth {
    pub id: String,
}

impl FromRequestParts<AppState> for DeviceAuth {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, s: &AppState) -> Result<Self, Self::Rejection> {
        let unauthorized =
            || AppError::new(err(StatusCode::UNAUTHORIZED, "invalid device credentials"));
        let secret = bearer(parts).ok_or_else(unauthorized)?;
        let id: Option<String> =
            sqlx::query_scalar("SELECT id FROM devices WHERE secret_hash = ? AND revoked = 0")
                .bind(hash_secret(secret))
                .fetch_optional(&s.db)
                .await?;
        id.map(|id| DeviceAuth { id }).ok_or_else(unauthorized)
    }
}

/// An authenticated technician, with their role and whether a device scope limits them.
pub struct TechAuth {
    pub name: String,
    token_hash: String,
    pub role: TechRole,
    pub scoped: bool,
}

async fn technician_token_active(db: &SqlitePool, token_hash: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM technicians WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?)",
    )
    .bind(token_hash)
    .bind(now_millis())
    .fetch_one(db)
    .await
}

impl FromRequestParts<AppState> for TechAuth {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, s: &AppState) -> Result<Self, Self::Rejection> {
        let unauthorized =
            || AppError::new(err(StatusCode::UNAUTHORIZED, "invalid technician token"));
        let token = bearer(parts).ok_or_else(unauthorized)?;
        let token_hash = hash_secret(token);
        let row: Option<(String, String, bool)> = sqlx::query_as(
            "SELECT name, role,
                    EXISTS(SELECT 1 FROM technician_scopes ts WHERE ts.technician = technicians.name)
             FROM technicians WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?",
        )
        .bind(&token_hash)
        .bind(now_millis())
        .fetch_optional(&s.db)
        .await?;
        match row {
            Some((name, role, scoped)) => Ok(TechAuth {
                name,
                token_hash,
                role: rbac::parse_role(&role),
                scoped,
            }),
            None => {
                let client_ip = parts
                    .extensions
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|c| c.0.ip());
                audit(
                    &s.db,
                    "anonymous",
                    "technician.auth",
                    "",
                    false,
                    "invalid, expired, or revoked token",
                    client_ip,
                )
                .await;
                Err(unauthorized())
            }
        }
    }
}

/// Appends to the audit log. Best-effort: a failure is logged, not surfaced to the caller.
// shortcut: privileged ops still succeed if the audit write fails; fail-closed once ops exist (T-402).
pub async fn audit(
    db: &SqlitePool,
    actor: &str,
    action: &str,
    target: &str,
    ok: bool,
    detail: &str,
    client_ip: Option<IpAddr>,
) {
    // Detail can contain client-supplied text; cap it so it can't bloat the log.
    let detail: String = detail.chars().take(512).collect();
    let r = sqlx::query(
        "INSERT INTO audit_log (at, actor, action, target, ok, detail, client_ip) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(now_millis())
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(ok)
    .bind(detail)
    .bind(client_ip.map(|ip| ip.to_string()))
    .execute(db)
    .await;
    if let Err(e) = r {
        tracing::error!(action, actor, "audit write failed: {e}");
    }
}

async fn enroll(
    State(s): State<AppState>,
    client: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, AppError> {
    let client_ip = client.map(|c| c.0.0.ip());
    let now = now_millis();
    let mut tx = s.db.begin().await?;
    // Atomically consume one use of a valid token.
    let consumed = sqlx::query(
        "UPDATE enrollment_tokens SET uses_left = uses_left - 1 WHERE token_hash = ? AND uses_left > 0 AND expires_at > ?",
    )
    .bind(hash_secret(&req.token))
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if consumed != 1 {
        drop(tx);
        let host: String = req.state.hostname.chars().take(64).collect();
        audit(
            &s.db,
            "anonymous",
            "device.enroll",
            &host,
            false,
            "invalid or expired token",
            client_ip,
        )
        .await;
        return Err(AppError::new(err(
            StatusCode::FORBIDDEN,
            "invalid or expired enrollment token",
        )));
    }
    let id = Uuid::new_v4();
    let secret = new_secret();
    sqlx::query(
        "INSERT INTO devices (id, secret_hash, hostname, os, enrolled_at, last_seen, state_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(hash_secret(&secret))
    .bind(&req.state.hostname)
    .bind(&req.state.os.name)
    .bind(now)
    .bind(now)
    .bind(serde_json::to_string(&req.state).expect("state serializes"))
    .execute(&mut *tx)
    .await?;
    write_projections(&mut tx, &id.to_string(), &req.state).await?;
    tx.commit().await?;
    tracing::info!(device = %id, hostname = %req.state.hostname, "device enrolled");
    s.publish(&id.to_string());
    let actor = format!("device:{id}");
    audit(
        &s.db,
        &actor,
        "device.enroll",
        &req.state.hostname,
        true,
        "",
        client_ip,
    )
    .await;
    Ok(Json(EnrollResponse {
        device_id: id,
        device_secret: secret,
    }))
}

async fn write_projections(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: &str,
    state: &DeviceState,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM device_addresses WHERE device_id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM device_sessions WHERE device_id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    // Keep the substring index (migration 0008) in step with the projections it is built from.
    sqlx::query("DELETE FROM device_search WHERE device_id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    let mut body = state.hostname.clone();
    for u in &state.sessions {
        body.push(' ');
        body.push_str(&u.username);
    }
    for a in &state.addresses {
        body.push(' ');
        body.push_str(&a.address);
    }
    sqlx::query("INSERT INTO device_search (device_id, body) VALUES (?, ?)")
        .bind(id)
        .bind(body)
        .execute(&mut **tx)
        .await?;
    for a in &state.addresses {
        sqlx::query(
            "INSERT INTO device_addresses (device_id, interface, address) VALUES (?, ?, ?)",
        )
        .bind(id)
        .bind(&a.interface)
        .bind(&a.address)
        .execute(&mut **tx)
        .await?;
    }
    for u in &state.sessions {
        sqlx::query("INSERT INTO device_sessions (device_id, username, domain, state, station) VALUES (?, ?, ?, ?, ?)")
            .bind(id)
            .bind(&u.username)
            .bind(&u.domain)
            .bind(serde_json::to_value(u.state).expect("enum serializes").as_str().unwrap_or("other"))
            .bind(&u.station)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

/// Applies a batch of events in seq order. Events with seq <= last applied are skipped (retry/replay safe).
async fn ingest_events(
    State(s): State<AppState>,
    dev: DeviceAuth,
    Json(events): Json<Vec<AgentEvent>>,
) -> Result<Json<EventAck>, AppError> {
    if events.len() > 500 {
        return Err(AppError::new(err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "max 500 events per batch",
        )));
    }
    let mut events = events;
    events.sort_by_key(|e| e.seq);
    let mut tx = s.db.begin().await?;
    let (mut last_seq, prev_seen): (i64, i64) =
        sqlx::query_as("SELECT last_seq, last_seen FROM devices WHERE id = ?")
            .bind(&dev.id)
            .fetch_one(&mut *tx)
            .await?;
    let now = now_millis();
    // A device coming back from offline is a visible change even if only a heartbeat arrived.
    let was_offline = prev_seen <= now - s.offline_after_ms;
    let mut changed = false;
    let mut accepted = 0;
    for ev in events {
        let seq = i64::try_from(ev.seq).map_err(|_| {
            AppError::new(err(StatusCode::BAD_REQUEST, "event seq exceeds maximum"))
        })?;
        if seq <= last_seq {
            continue;
        }
        last_seq = seq;
        accepted += 1;
        changed |= was_offline || !matches!(ev.kind, EventKind::Heartbeat);
        if !matches!(ev.kind, EventKind::Heartbeat) {
            sqlx::query("INSERT INTO device_events (device_id, seq, received_at, event_json) VALUES (?, ?, ?, ?)")
                .bind(&dev.id)
                .bind(seq)
                .bind(now)
                .bind(serde_json::to_string(&ev).expect("event serializes"))
                .execute(&mut *tx)
                .await?;
        }
        match &ev.kind {
            EventKind::Startup { state } | EventKind::StateChanged { state } => {
                sqlx::query("UPDATE devices SET hostname = ?, os = ?, state_json = ? WHERE id = ?")
                    .bind(&state.hostname)
                    .bind(&state.os.name)
                    .bind(serde_json::to_string(state).expect("state serializes"))
                    .bind(&dev.id)
                    .execute(&mut *tx)
                    .await?;
                write_projections(&mut tx, &dev.id, state).await?;
            }
            EventKind::Heartbeat => {}
            EventKind::Shutdown => {
                // Mark offline immediately rather than waiting for the timeout.
                sqlx::query("UPDATE devices SET last_seen = 0, last_seq = ? WHERE id = ?")
                    .bind(last_seq)
                    .bind(&dev.id)
                    .execute(&mut *tx)
                    .await?;
                continue;
            }
        }
        sqlx::query("UPDATE devices SET last_seen = ?, last_seq = ? WHERE id = ?")
            .bind(now)
            .bind(last_seq)
            .bind(&dev.id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    s.accepted_events.fetch_add(accepted, Ordering::Relaxed);
    if changed {
        s.publish(&dev.id);
    }
    Ok(Json(EventAck {
        last_seq: last_seq as u64,
    }))
}

#[derive(Deserialize)]
struct SearchParams {
    #[serde(default)]
    q: String,
    /// Only devices in this group (T-801).
    group: Option<Uuid>,
    #[serde(default = "default_limit")]
    limit: u32,
}

fn default_limit() -> u32 {
    100
}

/// Escapes LIKE wildcards so user input is matched literally.
fn like_prefix(q: &str) -> String {
    let mut s = q
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    s.push('%');
    s
}

/// Prefix search over hostname, logged-in username (also `DOMAIN\user`) and IP. Empty query lists all.
/// The device-matching condition of a search (on `devices d`, parameter `?1`) and the value to
/// bind. Shared by device search and query-group membership so the two always agree.
fn search_condition(q: &str) -> (&'static str, String) {
    // `DOMAIN\user` → search on the user part.
    let q = q.rsplit_once('\\').map_or(q, |(_, user)| user);
    if q.chars().count() >= 3 {
        // Substring match via the trigram index. The input becomes one quoted FTS phrase, so FTS
        // query syntax typed by a technician is never interpreted.
        (
            "d.id IN (SELECT device_id FROM device_search WHERE device_search MATCH ?1)",
            format!("\"{}\"", q.replace('"', "\"\"")),
        )
    } else {
        (
            r"(d.hostname LIKE ?1 ESCAPE '\'
              OR EXISTS (SELECT 1 FROM device_sessions s WHERE s.device_id = d.id AND s.username LIKE ?1 ESCAPE '\')
              OR EXISTS (SELECT 1 FROM device_addresses a WHERE a.device_id = d.id AND a.address LIKE ?1 ESCAPE '\'))",
            like_prefix(q),
        )
    }
}

/// Ids of the non-revoked devices a search matches, for query-group membership.
pub(crate) async fn matching_device_ids(
    db: &SqlitePool,
    q: &str,
) -> Result<Vec<String>, sqlx::Error> {
    let (condition, value) = search_condition(q);
    sqlx::query_scalar(&format!(
        "SELECT d.id FROM devices d WHERE d.revoked = 0 AND {condition}"
    ))
    .bind(value)
    .fetch_all(db)
    .await
}

async fn search_devices(
    State(s): State<AppState>,
    tech: TechAuth,
    Query(p): Query<SearchParams>,
) -> Result<Json<Vec<DeviceSummary>>, AppError> {
    let mut q = p.q.trim().to_owned();
    // Static group: filter by membership. Query group: its saved search runs instead, and what the
    // technician typed narrows that result below.
    let mut member_of = None;
    let mut narrow = None;
    if let Some(g) = p.group {
        match groups::lookup(&s.db, g).await? {
            (GroupKind::Static, _) => member_of = Some(g.to_string()),
            (GroupKind::Query, stored) => {
                narrow = Some(q.to_lowercase()).filter(|n| !n.is_empty());
                q = stored.unwrap_or_default();
            }
        }
    }
    let q = q.as_str();
    let limit = p.limit.clamp(1, 1000) as i64;
    let (condition, value) = search_condition(q);
    let rows = sqlx::query(&format!(
        "SELECT id, hostname, os, last_seen, state_json FROM devices d
         WHERE revoked = 0 AND {condition}
           AND (?3 IS NULL OR id IN (SELECT device_id FROM group_members WHERE group_id = ?3))
           AND (?4 IS NULL OR id IN (SELECT m.device_id FROM group_members m
               JOIN technician_scopes ts ON ts.group_id = m.group_id WHERE ts.technician = ?4))
         ORDER BY hostname COLLATE NOCASE LIMIT ?2"
    ))
    .bind(value)
    .bind(limit)
    .bind(&member_of)
    .bind(tech.scope_name())
    .fetch_all(&s.db)
    .await?;
    let cutoff = now_millis() - s.offline_after_ms;
    let out = rows
        .into_iter()
        .filter_map(|r| {
            let state: DeviceState = serde_json::from_str(r.get::<&str, _>("state_json")).ok()?;
            let last_seen: i64 = r.get("last_seen");
            Some(DeviceSummary {
                id: r.get::<&str, _>("id").parse().ok()?,
                hostname: r.get("hostname"),
                os: r.get("os"),
                online: last_seen > cutoff,
                last_seen,
                primary_ip: primary_ip(&state.addresses),
                users: state.sessions.iter().map(|u| u.username.clone()).collect(),
            })
        })
        .filter(|d: &DeviceSummary| {
            narrow.as_deref().is_none_or(|n| {
                d.hostname.to_lowercase().contains(n)
                    || d.users.iter().any(|u| u.to_lowercase().contains(n))
                    || d.primary_ip.as_deref().is_some_and(|ip| ip.contains(n))
            })
        })
        .collect();
    Ok(Json(out))
}

/// Prefers a non-link-local IPv4 address.
fn primary_ip(addrs: &[NetAddress]) -> Option<String> {
    let usable =
        |a: &&NetAddress| !a.address.starts_with("169.254.") && !a.address.starts_with("fe80");
    addrs
        .iter()
        .filter(usable)
        .find(|a| !a.address.contains(':'))
        .or_else(|| addrs.iter().find(usable))
        .map(|a| a.address.clone())
}

/// Server-sent events: `device` (data `{"id": ...}`) when a device's summary may have changed,
/// `resync` when this client missed events and should reload everything.
async fn stream_changes(
    State(s): State<AppState>,
    tech: TechAuth,
) -> Result<
    axum::response::sse::Sse<
        impl tokio_stream::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
    >,
    AppError,
> {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use tokio_stream::wrappers::ReceiverStream;
    let permit = s
        .limits
        .streams
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::new(limited(StatusCode::TOO_MANY_REQUESTS, "1")))?;
    let (sender, receiver) =
        tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(16);
    tokio::spawn(async move {
        let _permit = permit;
        let mut changes = s.changes.subscribe();
        let mut recheck = tokio::time::interval(Duration::from_secs(15));
        loop {
            let outgoing = tokio::select! {
                _ = sender.closed() => break,
                _ = recheck.tick() => None,
                result = changes.recv() => match result {
                    // Scoped technicians only hear about devices they can see.
                    Ok(id) if !tech.sees_device(&s.db, &id.to_string()).await.unwrap_or(false) => None,
                    Ok(id) => Some(Event::default()
                        .event(STREAM_DEVICE)
                        .data(serde_json::to_string(&DeviceChanged { id }).expect("serializes"))),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        Some(Event::default().event(STREAM_RESYNC).data("{}"))
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
            };
            if sender.is_closed() {
                break;
            }
            match technician_token_active(&s.db, &tech.token_hash).await {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    tracing::warn!("SSE token recheck failed: {e}");
                    break;
                }
            }
            if let Some(event) = outgoing
                && sender.send(Ok(event)).await.is_err()
            {
                break;
            }
        }
    });
    Ok(Sse::new(ReceiverStream::new(receiver)).keep_alive(KeepAlive::default()))
}

#[derive(Deserialize)]
struct AuditParams {
    /// Return records with id < before (pagination, newest first).
    before: Option<i64>,
    #[serde(default = "default_limit")]
    limit: u32,
}

// shortcut: any technician can read the audit log until RBAC (T-806).
async fn list_audit(
    State(s): State<AppState>,
    tech: TechAuth,
    Query(p): Query<AuditParams>,
) -> Result<Json<Vec<AuditRecord>>, AppError> {
    tech.require(&s, TechRole::Admin, "audit.read", "").await?;
    let rows = sqlx::query(
        "SELECT id, at, actor, action, target, ok, detail, client_ip FROM audit_log
         WHERE id < ? ORDER BY id DESC LIMIT ?",
    )
    .bind(p.before.unwrap_or(i64::MAX))
    .bind(p.limit.clamp(1, 1000) as i64)
    .fetch_all(&s.db)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| AuditRecord {
                id: r.get("id"),
                at: r.get("at"),
                actor: r.get("actor"),
                action: r.get("action"),
                target: r.get("target"),
                ok: r.get("ok"),
                detail: r.get("detail"),
                client_ip: r.get("client_ip"),
            })
            .collect(),
    ))
}

async fn device_details(
    State(s): State<AppState>,
    tech: TechAuth,
    Path(id): Path<Uuid>,
) -> Result<Json<DeviceDetails>, AppError> {
    tech.check_device(&s.db, id).await?;
    let row = sqlx::query(
        "SELECT enrolled_at, last_seen, state_json FROM devices WHERE id = ? AND revoked = 0",
    )
    .bind(id.to_string())
    .fetch_optional(&s.db)
    .await?
    .ok_or_else(|| AppError::new(err(StatusCode::NOT_FOUND, "device not found")))?;
    let last_seen: i64 = row.get("last_seen");
    let state = serde_json::from_str(row.get::<&str, _>("state_json")).map_err(|_| {
        AppError::new(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "corrupt device state",
        ))
    })?;
    Ok(Json(DeviceDetails {
        id,
        online: last_seen > now_millis() - s.offline_after_ms,
        enrolled_at: row.get("enrolled_at"),
        last_seen,
        state,
    }))
}

#[derive(Deserialize)]
struct EventHistoryParams {
    /// Return events with seq < before (newest first).
    before: Option<i64>,
    #[serde(default = "default_limit")]
    limit: u32,
}

/// Stores the latest inventory snapshot from an enrolled device (replacing the previous one).
async fn ingest_inventory(
    State(s): State<AppState>,
    dev: DeviceAuth,
    Json(report): Json<InventoryReport>,
) -> Result<StatusCode, AppError> {
    if report.software.apps.len() > 20_000 || report.hardware.disks.len() > 256 {
        return Err(AppError::new(err(
            StatusCode::BAD_REQUEST,
            "inventory exceeds sanity limits",
        )));
    }
    sqlx::query(
        "INSERT INTO device_inventory (device_id, collected_at, received_at, report_json)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(device_id) DO UPDATE SET collected_at = excluded.collected_at,
             received_at = excluded.received_at, report_json = excluded.report_json",
    )
    .bind(&dev.id)
    .bind(report.collected_at)
    .bind(now_millis())
    .bind(serde_json::to_string(&report).expect("report serializes"))
    .execute(&s.db)
    .await?;
    tracing::info!(device = %dev.id, apps = report.software.apps.len(), "inventory stored");
    Ok(StatusCode::NO_CONTENT)
}

/// Latest inventory snapshot of a device; 404 until the agent has sent one.
async fn device_inventory(
    State(s): State<AppState>,
    tech: TechAuth,
    Path(id): Path<Uuid>,
) -> Result<Json<InventoryReport>, AppError> {
    tech.check_device(&s.db, id).await?;
    let json: Option<String> = sqlx::query_scalar(
        "SELECT i.report_json FROM device_inventory i JOIN devices d ON d.id = i.device_id
         WHERE i.device_id = ? AND d.revoked = 0",
    )
    .bind(id.to_string())
    .fetch_optional(&s.db)
    .await?;
    let json = json.ok_or_else(|| {
        AppError::new(err(
            StatusCode::NOT_FOUND,
            "no inventory received from this device yet",
        ))
    })?;
    serde_json::from_str(&json).map(Json).map_err(|e| {
        tracing::error!(device = %id, "corrupt inventory: {e}");
        AppError::new(err(StatusCode::INTERNAL_SERVER_ERROR, "corrupt inventory"))
    })
}

async fn device_events(
    State(s): State<AppState>,
    tech: TechAuth,
    Path(id): Path<Uuid>,
    Query(p): Query<EventHistoryParams>,
) -> Result<Json<Vec<DeviceEventRecord>>, AppError> {
    tech.check_device(&s.db, id).await?;
    let device_id = id.to_string();
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices WHERE id = ? AND revoked = 0)")
            .bind(&device_id)
            .fetch_one(&s.db)
            .await?;
    if !exists {
        return Err(AppError::new(err(
            StatusCode::NOT_FOUND,
            "device not found",
        )));
    }
    let before = p.before.map_or(i64::MAX, |seq| seq.saturating_sub(1));
    let rows = sqlx::query(
        "SELECT received_at, event_json FROM device_events
         WHERE device_id = ? AND seq <= ? ORDER BY seq DESC LIMIT ?",
    )
    .bind(device_id)
    .bind(before)
    .bind(p.limit.clamp(1, 100) as i64)
    .fetch_all(&s.db)
    .await?;
    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        let event = serde_json::from_str(row.get("event_json")).map_err(|e| {
            tracing::error!(device = %id, "corrupt device event: {e}");
            AppError::new(err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "corrupt device event",
            ))
        })?;
        events.push(DeviceEventRecord {
            received_at: row.get("received_at"),
            event,
        });
    }
    Ok(Json(events))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_escapes_wildcards() {
        assert_eq!(like_prefix("a%b_c\\"), "a\\%b\\_c\\\\%");
    }

    #[test]
    fn primary_ip_prefers_routable_v4() {
        let a = |s: &str| NetAddress {
            interface: "x".into(),
            address: s.into(),
        };
        assert_eq!(
            primary_ip(&[a("fe80::1"), a("169.254.1.1"), a("10.1.1.1")]).as_deref(),
            Some("10.1.1.1")
        );
        assert_eq!(
            primary_ip(&[a("fe80::1"), a("2001:db8::1")]).as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(primary_ip(&[]), None);
    }
}
