//! Server jobs (T-800): a technician queues a script for many devices; each agent claims its part
//! on its own poll, runs it with its exec engine and posts the result. The server only stores and
//! hands out work: whether a job runs is decided on the device, which must have opted in to server
//! jobs and allow the creating technician, so a compromised server cannot run code on every agent.

use super::*;
use serde::{Serialize, de::DeserializeOwned};
use std::collections::BTreeSet;

/// Same limit the agent's exec engine enforces.
const MAX_SCRIPT_BYTES: usize = 64 * 1024;
const MAX_NAME_CHARS: usize = 120;
const DEFAULT_TIMEOUT: u32 = 300;
/// A claimed target with no result this long after its timeout is marked failed.
const RESULT_GRACE_MS: i64 = 10 * 60 * 1000;
/// Agents check in this often while running a job; this long without one means it is gone.
const PROGRESS_LOST_MS: i64 = 2 * 60 * 1000;
/// Latest allowed `run_at`.
const MAX_DELAY_MS: i64 = 90 * 24 * 60 * 60 * 1000;
const STALE: &str = "no result from the device (agent stopped or lost the server while running it)";

fn bad(msg: impl Into<String>) -> AppError {
    AppError::new(err(StatusCode::BAD_REQUEST, msg))
}

/// Stored form of a snake_case protocol enum.
fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn enum_parse<T: DeserializeOwned>(s: &str) -> Result<T, AppError> {
    serde_json::from_value(serde_json::Value::String(s.to_owned())).map_err(|_| {
        tracing::error!("corrupt job row: unknown value {s:?}");
        AppError::new(err(StatusCode::INTERNAL_SERVER_ERROR, "corrupt job"))
    })
}

fn parse_uuid(s: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(s).map_err(|_| {
        tracing::error!("corrupt job row: bad id {s:?}");
        AppError::new(err(StatusCode::INTERNAL_SERVER_ERROR, "corrupt job"))
    })
}

/// Cuts `s` to at most `cap` bytes on a char boundary; returns whether it was cut.
fn cap_text(s: &mut String, cap: usize) -> bool {
    if s.len() <= cap {
        return false;
    }
    let end = (0..=cap)
        .rev()
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(0);
    s.truncate(end);
    true
}

/// Marks targets whose agent never answered as failed, so a job always reaches an end state:
/// either it stopped checking in, or (agents that never check in) the timeout passed long ago.
async fn expire_stale(db: &SqlitePool) -> Result<(), sqlx::Error> {
    let now = now_millis();
    sqlx::query(
        "UPDATE job_targets SET state = 'failed', error = ?, finished_at = ?
         WHERE state = 'running' AND (
             claimed_at + (SELECT timeout_secs FROM jobs WHERE jobs.id = job_targets.job_id) * 1000
                 + ? < ?
             OR progress_at + ? < ?)",
    )
    .bind(STALE)
    .bind(now)
    .bind(RESULT_GRACE_MS)
    .bind(now)
    .bind(PROGRESS_LOST_MS)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

/// Jobs, newest first; `creator` limits them to one technician's (scoped technicians).
async fn summaries(
    db: &SqlitePool,
    only: Option<Uuid>,
    creator: Option<&str>,
    limit: u32,
) -> Result<Vec<JobSummary>, AppError> {
    let only = only.map(|id| id.to_string());
    let rows = sqlx::query(
        "SELECT j.id, j.name, j.created_by, j.created_at, j.shell, j.script_sha256, j.timeout_secs,
                j.run_at, j.max_parallel, j.cancelled_at IS NOT NULL AS cancelled,
                COUNT(t.device_id) AS targets,
                IFNULL(SUM(t.state = 'pending'), 0) AS pending,
                IFNULL(SUM(t.state = 'running'), 0) AS running,
                IFNULL(SUM(t.state = 'exited' AND t.exit_code IS 0), 0) AS succeeded
         FROM jobs j LEFT JOIN job_targets t ON t.job_id = j.id
         WHERE (?1 IS NULL OR j.id = ?1) AND (?3 IS NULL OR j.created_by = ?3)
         GROUP BY j.id ORDER BY j.created_at DESC LIMIT ?2",
    )
    .bind(only)
    .bind(i64::from(limit))
    .bind(creator)
    .fetch_all(db)
    .await?;
    rows.iter()
        .map(|r| {
            let count = |c: &str| r.get::<i64, _>(c) as u32;
            let (targets, pending, running, succeeded) = (
                count("targets"),
                count("pending"),
                count("running"),
                count("succeeded"),
            );
            Ok(JobSummary {
                id: parse_uuid(r.get("id"))?,
                name: r.get("name"),
                created_by: r.get("created_by"),
                created_at: r.get("created_at"),
                shell: enum_parse(r.get("shell"))?,
                script_sha256: r.get("script_sha256"),
                timeout_secs: r.get::<i64, _>("timeout_secs") as u32,
                run_at: r.get("run_at"),
                max_parallel: r.get::<Option<i64>, _>("max_parallel").map(|n| n as u32),
                cancelled: r.get("cancelled"),
                targets,
                pending,
                running,
                succeeded,
                failed: targets - pending - running - succeeded,
            })
        })
        .collect()
}

async fn summary(db: &SqlitePool, id: Uuid) -> Result<JobSummary, AppError> {
    summaries(db, Some(id), None, 1)
        .await?
        .pop()
        .ok_or_else(|| AppError::new(err(StatusCode::NOT_FOUND, "job not found")))
}

/// The job's summary if this technician may see it: scoped technicians see only their own jobs.
async fn visible(db: &SqlitePool, tech: &TechAuth, id: Uuid) -> Result<JobSummary, AppError> {
    let s = summary(db, id).await?;
    if tech.scoped && s.created_by != tech.name {
        return Err(AppError::new(err(StatusCode::NOT_FOUND, "job not found")));
    }
    Ok(s)
}

pub(crate) async fn create_job(
    State(s): State<AppState>,
    tech: TechAuth,
    client: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(req): Json<JobCreate>,
) -> Result<Json<JobSummary>, AppError> {
    tech.require(&s, TechRole::Operator, "job.create", "")
        .await?;
    let name = req.name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return Err(bad(format!(
            "job name must be 1 to {MAX_NAME_CHARS} printable characters"
        )));
    }
    if req.script.trim().is_empty() || req.script.len() > MAX_SCRIPT_BYTES {
        return Err(bad(format!("script must be 1 to {MAX_SCRIPT_BYTES} bytes")));
    }
    let timeout = req.timeout_secs.unwrap_or(DEFAULT_TIMEOUT);
    if !(1..=3600).contains(&timeout) {
        return Err(bad("timeout_secs must be 1-3600"));
    }
    let now = now_millis();
    // A start time in the past just means "now".
    let run_at = req.run_at.filter(|&t| t > now);
    if run_at.is_some_and(|t| t > now + MAX_DELAY_MS) {
        return Err(bad("run_at can be at most 90 days ahead"));
    }
    if req
        .max_parallel
        .is_some_and(|n| n == 0 || n as usize > JOB_MAX_TARGETS)
    {
        return Err(bad(format!("max_parallel must be 1-{JOB_MAX_TARGETS}")));
    }
    let devices: BTreeSet<Uuid> = req.devices.iter().copied().collect();
    if devices.is_empty() || devices.len() > JOB_MAX_TARGETS {
        return Err(bad(format!(
            "a job needs 1 to {JOB_MAX_TARGETS} target devices"
        )));
    }

    let id = Uuid::new_v4();
    let sha = hex::encode(Sha256::digest(req.script.as_bytes()));
    let mut tx = s.db.begin().await?;
    let mut unknown = 0;
    for d in &devices {
        let ok: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices WHERE id = ? AND revoked = 0)")
                .bind(d.to_string())
                .fetch_one(&mut *tx)
                .await?;
        unknown += usize::from(!ok);
    }
    if unknown > 0 {
        return Err(bad(format!(
            "{unknown} of the {} selected devices are unknown or revoked",
            devices.len()
        )));
    }
    if tech.scoped {
        let mut outside = 0;
        for d in &devices {
            outside += usize::from(!tech.sees_device(&s.db, &d.to_string()).await?);
        }
        if outside > 0 {
            drop(tx);
            let why = format!("{outside} of the selected devices are outside your device scope");
            return Err(tech.deny(&s, "job.create", "", why).await);
        }
    }
    sqlx::query(
        "INSERT INTO jobs (id, name, created_by, created_at, shell, script, script_sha256,
             timeout_secs, run_at, max_parallel)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(name)
    .bind(&tech.name)
    .bind(now)
    .bind(enum_str(&req.shell))
    .bind(&req.script)
    .bind(&sha)
    .bind(i64::from(timeout))
    .bind(run_at)
    .bind(req.max_parallel.map(i64::from))
    .execute(&mut *tx)
    .await?;
    for d in &devices {
        sqlx::query("INSERT INTO job_targets (job_id, device_id) VALUES (?, ?)")
            .bind(id.to_string())
            .bind(d.to_string())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    // The script may hold secrets; the audit log identifies it by hash only.
    audit(
        &s.db,
        &format!("tech:{}", tech.name),
        "job.create",
        &id.to_string(),
        true,
        &format!(
            "name={name:?} targets={} shell={} timeout={timeout}s run_at={run_at:?} max_parallel={:?} sha256={sha}",
            devices.len(),
            enum_str(&req.shell),
            req.max_parallel
        ),
        client.map(|c| c.0.0.ip()),
    )
    .await;
    tracing::info!(job = %id, technician = %tech.name, targets = devices.len(), "job created");
    Ok(Json(summary(&s.db, id).await?))
}

#[derive(Deserialize)]
pub(crate) struct ListParams {
    #[serde(default = "default_list")]
    limit: u32,
}

fn default_list() -> u32 {
    50
}

pub(crate) async fn list_jobs(
    State(s): State<AppState>,
    tech: TechAuth,
    Query(p): Query<ListParams>,
) -> Result<Json<Vec<JobSummary>>, AppError> {
    expire_stale(&s.db).await?;
    Ok(Json(
        summaries(&s.db, None, tech.scope_name(), p.limit.clamp(1, 200)).await?,
    ))
}

pub(crate) async fn get_job(
    State(s): State<AppState>,
    tech: TechAuth,
    Path(id): Path<Uuid>,
) -> Result<Json<JobDetail>, AppError> {
    expire_stale(&s.db).await?;
    let summary = visible(&s.db, &tech, id).await?;
    let script: String = sqlx::query_scalar("SELECT script FROM jobs WHERE id = ?")
        .bind(id.to_string())
        .fetch_one(&s.db)
        .await?;
    let rows = sqlx::query(
        "SELECT t.device_id, d.hostname, t.state, t.exit_code, t.stdout, t.stderr, t.truncated,
                t.error, t.started_at, t.finished_at
         FROM job_targets t JOIN devices d ON d.id = t.device_id
         WHERE t.job_id = ? ORDER BY d.hostname COLLATE NOCASE",
    )
    .bind(id.to_string())
    .fetch_all(&s.db)
    .await?;
    let targets = rows
        .iter()
        .map(|r| {
            Ok(JobTarget {
                device_id: parse_uuid(r.get("device_id"))?,
                hostname: r.get("hostname"),
                state: enum_parse(r.get("state"))?,
                exit_code: r.get::<Option<i64>, _>("exit_code").map(|c| c as i32),
                stdout: r.get("stdout"),
                stderr: r.get("stderr"),
                truncated: r.get("truncated"),
                error: r.get("error"),
                started_at: r.get("started_at"),
                finished_at: r.get("finished_at"),
            })
        })
        .collect::<Result<_, AppError>>()?;
    Ok(Json(JobDetail {
        summary,
        script,
        targets,
    }))
}

/// Stops handing the job out; devices running it learn of the cancel at their next check-in
/// (within seconds) and stop the script. Agents older than protocol 1.17 let it finish.
pub(crate) async fn cancel_job(
    State(s): State<AppState>,
    tech: TechAuth,
    client: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(id): Path<Uuid>,
) -> Result<Json<JobSummary>, AppError> {
    tech.require(&s, TechRole::Operator, "job.cancel", &id.to_string())
        .await?;
    visible(&s.db, &tech, id).await?;
    let now = now_millis();
    let mut tx = s.db.begin().await?;
    let found = sqlx::query("UPDATE jobs SET cancelled_at = IFNULL(cancelled_at, ?) WHERE id = ?")
        .bind(now)
        .bind(id.to_string())
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if found == 0 {
        return Err(AppError::new(err(StatusCode::NOT_FOUND, "job not found")));
    }
    let dropped = sqlx::query(
        "UPDATE job_targets SET state = 'cancelled', finished_at = ?,
             error = 'cancelled before the device picked it up'
         WHERE job_id = ? AND state = 'pending'",
    )
    .bind(now)
    .bind(id.to_string())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    audit(
        &s.db,
        &format!("tech:{}", tech.name),
        "job.cancel",
        &id.to_string(),
        true,
        &format!("{dropped} pending targets cancelled"),
        client.map(|c| c.0.0.ip()),
    )
    .await;
    Ok(Json(summary(&s.db, id).await?))
}

/// Hands this device its oldest pending job and marks it running; 204 when there is none.
pub(crate) async fn claim_job(
    State(s): State<AppState>,
    dev: DeviceAuth,
) -> Result<Response, AppError> {
    // One statement, so concurrent claims from many devices cannot overshoot max_parallel.
    let job_id: Option<String> = sqlx::query_scalar(
        "UPDATE job_targets SET state = 'running', claimed_at = ?1
         WHERE device_id = ?2 AND state = 'pending' AND job_id = (
             SELECT j.id FROM job_targets t JOIN jobs j ON j.id = t.job_id
             WHERE t.device_id = ?2 AND t.state = 'pending' AND j.cancelled_at IS NULL
                 AND (j.run_at IS NULL OR j.run_at <= ?1)
                 AND (j.max_parallel IS NULL OR (SELECT COUNT(*) FROM job_targets r
                     WHERE r.job_id = j.id AND r.state = 'running') < j.max_parallel)
             ORDER BY j.created_at LIMIT 1)
         RETURNING job_id",
    )
    .bind(now_millis())
    .bind(&dev.id)
    .fetch_optional(&s.db)
    .await?;
    let Some(job_id) = job_id else {
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    let row = sqlx::query("SELECT created_by, shell, script, timeout_secs FROM jobs WHERE id = ?")
        .bind(&job_id)
        .fetch_one(&s.db)
        .await?;
    tracing::info!(job = %job_id, device = %dev.id, "job claimed");
    Ok(Json(AgentJob {
        id: parse_uuid(&job_id)?,
        created_by: row.get("created_by"),
        shell: enum_parse(row.get("shell"))?,
        script: row.get("script"),
        timeout_secs: row.get::<i64, _>("timeout_secs") as u32,
    })
    .into_response())
}

/// Running-job check-in: records that the device is alive and tells it whether to stop.
pub(crate) async fn job_progress(
    State(s): State<AppState>,
    dev: DeviceAuth,
    Path(id): Path<Uuid>,
) -> Result<Json<JobControl>, AppError> {
    let cancel: Option<bool> = sqlx::query_scalar(
        "UPDATE job_targets SET progress_at = ? WHERE job_id = ? AND device_id = ? AND state = 'running'
         RETURNING (SELECT cancelled_at IS NOT NULL FROM jobs WHERE jobs.id = job_targets.job_id)",
    )
    .bind(now_millis())
    .bind(id.to_string())
    .bind(&dev.id)
    .fetch_optional(&s.db)
    .await?;
    let cancel = cancel.ok_or_else(|| {
        AppError::new(err(
            StatusCode::CONFLICT,
            "this device has no running target in that job",
        ))
    })?;
    Ok(Json(JobControl { cancel }))
}

pub(crate) async fn job_result(
    State(s): State<AppState>,
    dev: DeviceAuth,
    Path(id): Path<Uuid>,
    Json(mut r): Json<JobResult>,
) -> Result<StatusCode, AppError> {
    let state = match r.state {
        ExecState::Running => return Err(bad("a result cannot be in the running state")),
        ExecState::Exited => JobTargetState::Exited,
        ExecState::TimedOut => JobTargetState::TimedOut,
        ExecState::Cancelled => JobTargetState::Cancelled,
        ExecState::Failed => JobTargetState::Failed,
    };
    let cut_out = cap_text(&mut r.stdout, JOB_OUTPUT_CAP);
    let cut_err = cap_text(&mut r.stderr, JOB_OUTPUT_CAP);
    let error = r.error.map(|mut e| {
        cap_text(&mut e, 2048);
        e
    });
    // A late result may replace the "no result" mark the expiry put there.
    let updated = sqlx::query(
        "UPDATE job_targets SET state = ?, started_at = ?, finished_at = ?, exit_code = ?,
             stdout = ?, stderr = ?, truncated = ?, error = ?
         WHERE job_id = ? AND device_id = ?
             AND (state = 'running' OR (state = 'failed' AND error = ?))",
    )
    .bind(enum_str(&state))
    .bind(r.started_at)
    .bind(r.finished_at)
    .bind(r.exit_code)
    .bind(&r.stdout)
    .bind(&r.stderr)
    .bind(r.truncated || cut_out || cut_err)
    .bind(error)
    .bind(id.to_string())
    .bind(&dev.id)
    .bind(STALE)
    .execute(&s.db)
    .await?
    .rows_affected();
    if updated == 0 {
        return Err(AppError::new(err(
            StatusCode::CONFLICT,
            "this device has no running target in that job",
        )));
    }
    tracing::info!(job = %id, device = %dev.id, ?state, exit_code = ?r.exit_code, "job result");
    Ok(StatusCode::NO_CONTENT)
}
