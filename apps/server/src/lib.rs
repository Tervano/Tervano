//! Tervano Server library: HTTP API + persistence. `main.rs` is the CLI around it.

use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, FromRequestParts, Path, Query, Request, State},
    http::{StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool, sqlite::SqliteConnectOptions};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};
use tervano_protocol::*;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    pub database_url: String,
    pub offline_after_secs: u64,
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
        Ok(())
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub offline_after_ms: i64,
    /// Ids of devices whose summary may have changed; fanned out to `/api/v1/stream` clients.
    pub changes: tokio::sync::broadcast::Sender<Uuid>,
}

impl AppState {
    pub fn new(db: SqlitePool, offline_after_ms: i64) -> Self {
        // Bounded: a client that falls this far behind gets a `resync` instead of unbounded memory.
        let (changes, _) = tokio::sync::broadcast::channel(1024);
        Self {
            db,
            offline_after_ms,
            changes,
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

/// Creates a technician API token. Returns the plaintext token.
pub async fn create_technician(db: &SqlitePool, name: &str) -> anyhow::Result<String> {
    let token = new_secret();
    sqlx::query("INSERT INTO technicians (id, name, token_hash, created_at) VALUES (?, ?, ?, ?)")
        .bind(Uuid::new_v4().to_string())
        .bind(name)
        .bind(hash_secret(&token))
        .bind(now_millis())
        .execute(db)
        .await?;
    Ok(token)
}

pub fn app(state: AppState) -> Router {
    let api = Router::new()
        .route("/enroll", post(enroll))
        .route("/events", post(ingest_events))
        .route("/devices", get(search_devices))
        .route("/devices/{id}", get(device_details))
        .route("/devices/{id}/events", get(device_events))
        .route("/audit", get(list_audit))
        .route("/stream", get(stream_changes))
        .layer(middleware::from_fn(require_protocol))
        // State JSON is small; this bounds memory per request.
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024));
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
        .nest("/api/v1", api)
        .with_state(state)
}

async fn readyz(State(s): State<AppState>) -> StatusCode {
    match sqlx::query("SELECT 1").execute(&s.db).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
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

pub struct AppError(Response);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        self.0
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!("database error: {e}");
        AppError(err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))
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
        let unauthorized = || AppError(err(StatusCode::UNAUTHORIZED, "invalid device credentials"));
        let secret = bearer(parts).ok_or_else(unauthorized)?;
        let id: Option<String> =
            sqlx::query_scalar("SELECT id FROM devices WHERE secret_hash = ? AND revoked = 0")
                .bind(hash_secret(secret))
                .fetch_optional(&s.db)
                .await?;
        id.map(|id| DeviceAuth { id }).ok_or_else(unauthorized)
    }
}

/// An authenticated technician.
pub struct TechAuth {
    pub name: String,
}

impl FromRequestParts<AppState> for TechAuth {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, s: &AppState) -> Result<Self, Self::Rejection> {
        let unauthorized = || AppError(err(StatusCode::UNAUTHORIZED, "invalid technician token"));
        let token = bearer(parts).ok_or_else(unauthorized)?;
        let name: Option<String> =
            sqlx::query_scalar("SELECT name FROM technicians WHERE token_hash = ?")
                .bind(hash_secret(token))
                .fetch_optional(&s.db)
                .await?;
        match name {
            Some(name) => Ok(TechAuth { name }),
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
                    "unknown token",
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
        return Err(AppError(err(
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
        return Err(AppError(err(
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
    for ev in events {
        let seq = i64::try_from(ev.seq)
            .map_err(|_| AppError(err(StatusCode::BAD_REQUEST, "event seq exceeds maximum")))?;
        if seq <= last_seq {
            continue;
        }
        last_seq = seq;
        changed |= was_offline || !matches!(ev.kind, EventKind::Heartbeat);
        if !matches!(ev.kind, EventKind::Heartbeat) {
            // shortcut: state snapshots accumulate until configurable retention is added (T-120).
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
async fn search_devices(
    State(s): State<AppState>,
    _tech: TechAuth,
    Query(p): Query<SearchParams>,
) -> Result<Json<Vec<DeviceSummary>>, AppError> {
    let q = p.q.trim();
    // `DOMAIN\user` → search on the user part.
    let q = q.rsplit_once('\\').map_or(q, |(_, user)| user);
    let pattern = like_prefix(q);
    let rows = sqlx::query(
        "SELECT id, hostname, os, last_seen, state_json FROM devices d
         WHERE revoked = 0 AND (
            hostname LIKE ?1 ESCAPE '\\'
            OR EXISTS (SELECT 1 FROM device_sessions s WHERE s.device_id = d.id AND s.username LIKE ?1 ESCAPE '\\')
            OR EXISTS (SELECT 1 FROM device_addresses a WHERE a.device_id = d.id AND a.address LIKE ?1 ESCAPE '\\'))
         ORDER BY hostname COLLATE NOCASE LIMIT ?2",
    )
    .bind(&pattern)
    .bind(p.limit.clamp(1, 1000) as i64)
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
// shortcut: every technician sees every device id; scope by RBAC once it exists (T-806).
async fn stream_changes(
    State(s): State<AppState>,
    _tech: TechAuth,
) -> axum::response::sse::Sse<
    impl tokio_stream::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
> {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use tokio_stream::{StreamExt, wrappers::BroadcastStream};
    let events = BroadcastStream::new(s.changes.subscribe()).map(|r| {
        Ok(match r {
            Ok(id) => Event::default()
                .event(STREAM_DEVICE)
                .data(serde_json::to_string(&DeviceChanged { id }).expect("serializes")),
            Err(_lagged) => Event::default().event(STREAM_RESYNC).data("{}"),
        })
    });
    Sse::new(events).keep_alive(KeepAlive::default())
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
    _tech: TechAuth,
    Query(p): Query<AuditParams>,
) -> Result<Json<Vec<AuditRecord>>, AppError> {
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
    _tech: TechAuth,
    Path(id): Path<Uuid>,
) -> Result<Json<DeviceDetails>, AppError> {
    let row = sqlx::query(
        "SELECT enrolled_at, last_seen, state_json FROM devices WHERE id = ? AND revoked = 0",
    )
    .bind(id.to_string())
    .fetch_optional(&s.db)
    .await?
    .ok_or_else(|| AppError(err(StatusCode::NOT_FOUND, "device not found")))?;
    let last_seen: i64 = row.get("last_seen");
    let state = serde_json::from_str(row.get::<&str, _>("state_json")).map_err(|_| {
        AppError(err(
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

async fn device_events(
    State(s): State<AppState>,
    _tech: TechAuth,
    Path(id): Path<Uuid>,
    Query(p): Query<EventHistoryParams>,
) -> Result<Json<Vec<DeviceEventRecord>>, AppError> {
    let device_id = id.to_string();
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices WHERE id = ? AND revoked = 0)")
            .bind(&device_id)
            .fetch_one(&s.db)
            .await?;
    if !exists {
        return Err(AppError(err(StatusCode::NOT_FOUND, "device not found")));
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
            AppError(err(
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
