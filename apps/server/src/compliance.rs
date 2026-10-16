//! Compliance checks (T-805): rules evaluated on demand against each device's latest inventory and
//! state, limited to the caller's device scope. Remediation is not run here: the Console turns the
//! failing devices and the check's script into an ordinary job, which goes through the job
//! confirmation, RBAC and each agent's own `[server_jobs]` opt-in.

use super::*;
use std::cmp::Ordering;

const MAX_CHECKS: i64 = 100;
const MAX_NAME_CHARS: usize = 80;
const MAX_SCRIPT_BYTES: usize = 64 * 1024;

fn bad(msg: impl Into<String>) -> AppError {
    AppError::new(err(StatusCode::BAD_REQUEST, msg))
}

fn not_found() -> AppError {
    AppError::new(err(StatusCode::NOT_FOUND, "compliance check not found"))
}

/// Dotted version numbers, compared numerically ("10.2" > "9.11"); non-digits separate parts.
fn version_cmp(a: &str, b: &str) -> Ordering {
    let parts = |s: &str| -> Vec<u64> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .map(|p| p.parse().unwrap_or(u64::MAX))
            .collect()
    };
    let (a, b) = (parts(a), parts(b));
    for i in 0..a.len().max(b.len()) {
        let o = a.get(i).unwrap_or(&0).cmp(b.get(i).unwrap_or(&0));
        if o != Ordering::Equal {
            return o;
        }
    }
    Ordering::Equal
}

fn has_digit(s: &str) -> bool {
    s.chars().any(|c| c.is_ascii_digit())
}

fn validate(rule: &ComplianceRule) -> Result<(), AppError> {
    let ok = match rule {
        ComplianceRule::SoftwarePresent { name, min_version } => {
            !name.trim().is_empty()
                && name.chars().count() <= 200
                && min_version.as_deref().is_none_or(has_digit)
        }
        ComplianceRule::SoftwareAbsent { name } => {
            !name.trim().is_empty() && name.chars().count() <= 200
        }
        ComplianceRule::DiskFreeAtLeast { gib } => (1..=100_000).contains(gib),
        ComplianceRule::OsBuildAtLeast { build } => has_digit(build) && build.len() <= 40,
        ComplianceRule::InventoryNewerThan { days } => (1..=365).contains(days),
        ComplianceRule::NoRebootPending
        | ComplianceRule::SecureBootOn
        | ComplianceRule::TpmPresent => true,
    };
    if ok {
        Ok(())
    } else {
        Err(bad(
            "invalid rule: software names 1-200 characters, versions and builds need digits, 1-100000 GiB, 1-365 days",
        ))
    }
}

const GIB: u64 = 1024 * 1024 * 1024;

/// Judges one device. `os_build` comes from the device's live state, the rest from its inventory.
fn evaluate(
    rule: &ComplianceRule,
    os_build: Option<&str>,
    inv: Option<&InventoryReport>,
) -> (ComplianceStatus, String) {
    use ComplianceStatus::*;
    let verdict = |pass: bool, detail: String| (if pass { Pass } else { Fail }, detail);
    if let ComplianceRule::OsBuildAtLeast { build } = rule {
        return match os_build {
            Some(b) => verdict(
                version_cmp(b, build) != Ordering::Less,
                format!("build {b}"),
            ),
            None => (Unknown, "no OS build reported".into()),
        };
    }
    let Some(inv) = inv else {
        return (Unknown, "no inventory received yet".into());
    };
    let matching = |needle: &str| {
        let needle = needle.trim().to_lowercase();
        inv.software
            .apps
            .iter()
            .filter(move |a| a.name.to_lowercase().contains(&needle))
    };
    match rule {
        ComplianceRule::SoftwarePresent { name, min_version } => {
            let best = matching(name).max_by(|a, b| {
                version_cmp(
                    a.version.as_deref().unwrap_or(""),
                    b.version.as_deref().unwrap_or(""),
                )
            });
            match (best, min_version) {
                (None, _) => (Fail, "not installed".into()),
                (Some(a), None) => (Pass, describe(a)),
                (Some(a), Some(min)) => verdict(
                    a.version
                        .as_deref()
                        .is_some_and(|v| version_cmp(v, min) != Ordering::Less),
                    describe(a),
                ),
            }
        }
        ComplianceRule::SoftwareAbsent { name } => match matching(name).next() {
            Some(a) => (Fail, format!("found {}", describe(a))),
            None => (Pass, "not installed".into()),
        },
        ComplianceRule::NoRebootPending => {
            let r = &inv.software.reboot_pending;
            verdict(
                r.is_empty(),
                if r.is_empty() {
                    "no reboot pending".into()
                } else {
                    r.join("; ")
                },
            )
        }
        ComplianceRule::SecureBootOn => match inv.hardware.secure_boot {
            Some(on) => verdict(on, if on { "on" } else { "off" }.into()),
            None => (Unknown, "Secure Boot state not reported".into()),
        },
        ComplianceRule::TpmPresent => match &inv.hardware.tpm_version {
            Some(v) => (Pass, format!("TPM {v}")),
            None => (Fail, "no TPM visible".into()),
        },
        ComplianceRule::DiskFreeAtLeast { gib } => {
            let disks = &inv.hardware.disks;
            let system = disks
                .iter()
                .find(|d| d.mount_point.eq_ignore_ascii_case("C:\\"))
                .or_else(|| disks.iter().find(|d| !d.removable));
            match system {
                Some(d) => verdict(
                    d.free_bytes >= u64::from(*gib) * GIB,
                    format!("{} GiB free on {}", d.free_bytes / GIB, d.mount_point),
                ),
                None => (Unknown, "no fixed disk reported".into()),
            }
        }
        ComplianceRule::InventoryNewerThan { days } => {
            let age_days = (now_millis() - inv.collected_at).max(0) / 86_400_000;
            verdict(
                age_days < i64::from(*days),
                format!("collected {age_days} day(s) ago"),
            )
        }
        ComplianceRule::OsBuildAtLeast { .. } => unreachable!("handled above"),
    }
}

fn describe(a: &InstalledApp) -> String {
    match &a.version {
        Some(v) => format!("{} {v}", a.name),
        None => a.name.clone(),
    }
}

struct Device {
    id: Uuid,
    hostname: String,
    os_build: Option<String>,
    inventory: Option<InventoryReport>,
}

/// Every non-revoked device the technician can see, with its build and parsed inventory.
// shortcut: parses every inventory per request; cache evaluations if fleets get large, T-813.
async fn devices(db: &SqlitePool, tech: &TechAuth) -> Result<Vec<Device>, AppError> {
    let rows = sqlx::query(
        "SELECT d.id, d.hostname, json_extract(d.state_json, '$.os.build') AS build, i.report_json
         FROM devices d LEFT JOIN device_inventory i ON i.device_id = d.id
         WHERE d.revoked = 0 AND (?1 IS NULL OR d.id IN (SELECT m.device_id FROM group_members m
             JOIN technician_scopes ts ON ts.group_id = m.group_id WHERE ts.technician = ?1))
         ORDER BY d.hostname COLLATE NOCASE",
    )
    .bind(tech.scope_name())
    .fetch_all(db)
    .await?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            Some(Device {
                id: r.get::<&str, _>("id").parse().ok()?,
                hostname: r.get("hostname"),
                os_build: r.get("build"),
                inventory: r
                    .get::<Option<&str>, _>("report_json")
                    .and_then(|j| serde_json::from_str(j).ok()),
            })
        })
        .collect())
}

struct Stored {
    id: Uuid,
    name: String,
    rule: ComplianceRule,
    remediation: Option<Remediation>,
    created_by: String,
    created_at: Millis,
}

async fn stored(db: &SqlitePool, only: Option<Uuid>) -> Result<Vec<Stored>, AppError> {
    let rows = sqlx::query(
        "SELECT id, name, rule_json, remediation_shell, remediation_script, created_by, created_at
         FROM compliance_checks WHERE ?1 IS NULL OR id = ?1 ORDER BY name COLLATE NOCASE",
    )
    .bind(only.map(|i| i.to_string()))
    .fetch_all(db)
    .await?;
    let corrupt = || {
        AppError::new(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "corrupt compliance check",
        ))
    };
    rows.iter()
        .map(|r| {
            let shell: Option<String> = r.get("remediation_shell");
            let script: Option<String> = r.get("remediation_script");
            Ok(Stored {
                id: r.get::<&str, _>("id").parse().map_err(|_| corrupt())?,
                name: r.get("name"),
                rule: serde_json::from_str(r.get("rule_json")).map_err(|_| corrupt())?,
                remediation: match (shell.as_deref(), script) {
                    (Some("cmd"), Some(script)) => Some(Remediation {
                        shell: Shell::Cmd,
                        script,
                    }),
                    (Some(_), Some(script)) => Some(Remediation {
                        shell: Shell::Powershell,
                        script,
                    }),
                    _ => None,
                },
                created_by: r.get("created_by"),
                created_at: r.get("created_at"),
            })
        })
        .collect()
}

fn with_counts(c: Stored, devices: &[Device]) -> ComplianceCheck {
    let (mut passing, mut failing, mut unknown) = (0, 0, 0);
    for d in devices {
        match evaluate(&c.rule, d.os_build.as_deref(), d.inventory.as_ref()).0 {
            ComplianceStatus::Pass => passing += 1,
            ComplianceStatus::Fail => failing += 1,
            ComplianceStatus::Unknown => unknown += 1,
        }
    }
    ComplianceCheck {
        id: c.id,
        name: c.name,
        rule: c.rule,
        remediation: c.remediation,
        created_by: c.created_by,
        created_at: c.created_at,
        passing,
        failing,
        unknown,
    }
}

pub(crate) async fn list(
    State(s): State<AppState>,
    tech: TechAuth,
) -> Result<Json<Vec<ComplianceCheck>>, AppError> {
    let devices = devices(&s.db, &tech).await?;
    let checks = stored(&s.db, None).await?;
    Ok(Json(
        checks
            .into_iter()
            .map(|c| with_counts(c, &devices))
            .collect(),
    ))
}

pub(crate) async fn results(
    State(s): State<AppState>,
    tech: TechAuth,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<ComplianceResult>>, AppError> {
    let check = stored(&s.db, Some(id)).await?.pop().ok_or_else(not_found)?;
    let mut out: Vec<ComplianceResult> = devices(&s.db, &tech)
        .await?
        .into_iter()
        .map(|d| {
            let (status, detail) =
                evaluate(&check.rule, d.os_build.as_deref(), d.inventory.as_ref());
            ComplianceResult {
                device_id: d.id,
                hostname: d.hostname,
                status,
                detail,
            }
        })
        .collect();
    let rank = |s: ComplianceStatus| match s {
        ComplianceStatus::Fail => 0,
        ComplianceStatus::Unknown => 1,
        ComplianceStatus::Pass => 2,
    };
    // Stable: hostname order is kept within each status.
    out.sort_by_key(|r| rank(r.status));
    Ok(Json(out))
}

pub(crate) async fn create(
    State(s): State<AppState>,
    tech: TechAuth,
    client: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(req): Json<ComplianceCheckCreate>,
) -> Result<Json<ComplianceCheck>, AppError> {
    tech.require(&s, TechRole::Operator, "compliance.create", "")
        .await?;
    tech.require_unscoped(&s, "compliance.create", "").await?;
    let name = req.name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return Err(bad(format!(
            "name must be 1 to {MAX_NAME_CHARS} printable characters"
        )));
    }
    validate(&req.rule)?;
    if let Some(r) = &req.remediation
        && (r.script.trim().is_empty() || r.script.len() > MAX_SCRIPT_BYTES)
    {
        return Err(bad(format!(
            "remediation script must be 1 to {MAX_SCRIPT_BYTES} bytes"
        )));
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM compliance_checks")
        .fetch_one(&s.db)
        .await?;
    if count >= MAX_CHECKS {
        return Err(bad(format!("at most {MAX_CHECKS} compliance checks")));
    }
    let id = Uuid::new_v4();
    let inserted = sqlx::query(
        "INSERT INTO compliance_checks
             (id, name, rule_json, remediation_shell, remediation_script, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(name) DO NOTHING",
    )
    .bind(id.to_string())
    .bind(name)
    .bind(serde_json::to_string(&req.rule).expect("rule serializes"))
    .bind(req.remediation.as_ref().map(|r| match r.shell {
        Shell::Cmd => "cmd",
        Shell::Powershell => "powershell",
    }))
    .bind(req.remediation.as_ref().map(|r| r.script.as_str()))
    .bind(&tech.name)
    .bind(now_millis())
    .execute(&s.db)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(AppError::new(err(
            StatusCode::CONFLICT,
            format!("a check named {name:?} already exists"),
        )));
    }
    audit(
        &s.db,
        &format!("tech:{}", tech.name),
        "compliance.create",
        &id.to_string(),
        true,
        &format!(
            "name={name:?} rule={} remediation_sha256={:?}",
            serde_json::to_string(&req.rule).unwrap_or_default(),
            req.remediation
                .as_ref()
                .map(|r| hex::encode(Sha256::digest(r.script.as_bytes())))
        ),
        client.map(|c| c.0.0.ip()),
    )
    .await;
    let devices = devices(&s.db, &tech).await?;
    let check = stored(&s.db, Some(id)).await?.pop().ok_or_else(not_found)?;
    Ok(Json(with_counts(check, &devices)))
}

pub(crate) async fn delete_check(
    State(s): State<AppState>,
    tech: TechAuth,
    client: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let target = id.to_string();
    tech.require(&s, TechRole::Operator, "compliance.delete", &target)
        .await?;
    tech.require_unscoped(&s, "compliance.delete", &target)
        .await?;
    let name: Option<String> =
        sqlx::query_scalar("DELETE FROM compliance_checks WHERE id = ? RETURNING name")
            .bind(&target)
            .fetch_optional(&s.db)
            .await?;
    let name = name.ok_or_else(not_found)?;
    audit(
        &s.db,
        &format!("tech:{}", tech.name),
        "compliance.delete",
        &target,
        true,
        &format!("name={name:?}"),
        client.map(|c| c.0.0.ip()),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}
