//! Fleet reports (T-804): software, OS and hardware views built from the stored device state and
//! the latest inventory snapshots. Every report follows the caller's device scope (T-806) and reads
//! the inventory projections (`device_software`, `device_facts`, T-813), not the inventory JSON.

use super::*;

/// Scope filter on a `devices d` row using parameter `?n`, bound to the technician name (or NULL
/// for everyone). The index must match the bind order, or SQLite reads NULL and filters nothing.
fn scope(n: u8) -> String {
    format!(
        "(?{n} IS NULL OR d.id IN (SELECT m.device_id FROM group_members m
         JOIN technician_scopes ts ON ts.group_id = m.group_id WHERE ts.technician = ?{n}))"
    )
}

#[derive(Deserialize)]
pub(crate) struct SoftwareParams {
    #[serde(default)]
    q: String,
    #[serde(default = "default_rows")]
    limit: u32,
}

fn default_rows() -> u32 {
    1000
}

/// Escapes LIKE wildcards and wraps the text for a substring match.
fn like_contains(q: &str) -> String {
    let escaped = q
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

/// Distinct (name, version, publisher) with the number of devices that have it.
pub(crate) async fn software(
    State(s): State<AppState>,
    tech: TechAuth,
    Query(p): Query<SoftwareParams>,
) -> Result<Json<Vec<SoftwareReportRow>>, AppError> {
    let q = p.q.trim();
    if q.chars().count() > 200 {
        return Err(AppError::new(err(
            StatusCode::BAD_REQUEST,
            "filter too long",
        )));
    }
    // device_software holds live devices only (rows go on revoke), so no devices join: the
    // covering index answers the grouping on its own.
    let rows = sqlx::query(
        "SELECT a.name, a.version, a.publisher, COUNT(DISTINCT a.device_id) AS devices
         FROM device_software a
         WHERE (?4 IS NULL OR a.device_id IN (SELECT m.device_id FROM group_members m
                 JOIN technician_scopes ts ON ts.group_id = m.group_id WHERE ts.technician = ?4))
           AND (?1 = '' OR a.name LIKE ?2 ESCAPE '\\' OR a.publisher LIKE ?2 ESCAPE '\\')
         GROUP BY 1, 2, 3
         ORDER BY devices DESC, name COLLATE NOCASE, version
         LIMIT ?3",
    )
    .bind(q)
    .bind(like_contains(q))
    .bind(i64::from(p.limit.clamp(1, 5000)))
    .bind(tech.scope_name())
    .fetch_all(&s.db)
    .await?;
    Ok(Json(
        rows.iter()
            .map(|r| SoftwareReportRow {
                name: r.get("name"),
                version: r.get("version"),
                publisher: r.get("publisher"),
                devices: r.get::<i64, _>("devices") as u32,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub(crate) struct SoftwareDevicesParams {
    name: String,
    /// Omitted = any version; empty = entries without a version.
    version: Option<String>,
}

/// Devices that have one software entry.
pub(crate) async fn software_devices(
    State(s): State<AppState>,
    tech: TechAuth,
    Query(p): Query<SoftwareDevicesParams>,
) -> Result<Json<Vec<ReportDevice>>, AppError> {
    let rows = sqlx::query(&format!(
        "SELECT DISTINCT d.id, d.hostname, d.last_seen
         FROM devices d
         JOIN device_software a ON a.device_id = d.id
         WHERE d.revoked = 0 AND {}
           AND a.name = ?1
           AND (?2 IS NULL OR IFNULL(a.version, '') = ?2)
         ORDER BY d.hostname COLLATE NOCASE
         LIMIT 5000",
        scope(3)
    ))
    .bind(&p.name)
    .bind(&p.version)
    .bind(tech.scope_name())
    .fetch_all(&s.db)
    .await?;
    devices_out(&s, rows)
}

fn devices_out(
    s: &AppState,
    rows: Vec<sqlx::sqlite::SqliteRow>,
) -> Result<Json<Vec<ReportDevice>>, AppError> {
    let cutoff = now_millis() - s.offline_after_ms;
    Ok(Json(
        rows.iter()
            .filter_map(|r| {
                let last_seen: i64 = r.get("last_seen");
                Some(ReportDevice {
                    id: r.get::<&str, _>("id").parse().ok()?,
                    hostname: r.get("hostname"),
                    online: last_seen > cutoff,
                    last_seen,
                })
            })
            .collect(),
    ))
}

/// Devices per OS name and build.
pub(crate) async fn os(
    State(s): State<AppState>,
    tech: TechAuth,
) -> Result<Json<Vec<OsReportRow>>, AppError> {
    let rows = sqlx::query(&format!(
        "SELECT json_extract(d.state_json, '$.os.name') AS name,
                json_extract(d.state_json, '$.os.version') AS version,
                json_extract(d.state_json, '$.os.build') AS build,
                COUNT(*) AS devices,
                SUM(d.last_seen > ?1) AS online
         FROM devices d
         WHERE d.revoked = 0 AND {}
         GROUP BY 1, 2, 3
         ORDER BY devices DESC, name, build",
        scope(2)
    ))
    .bind(now_millis() - s.offline_after_ms)
    .bind(tech.scope_name())
    .fetch_all(&s.db)
    .await?;
    Ok(Json(
        rows.iter()
            .map(|r| OsReportRow {
                name: r.get::<Option<String>, _>("name").unwrap_or_default(),
                version: r.get::<Option<String>, _>("version").unwrap_or_default(),
                build: r.get::<Option<String>, _>("build").unwrap_or_default(),
                devices: r.get::<i64, _>("devices") as u32,
                online: r.get::<i64, _>("online") as u32,
            })
            .collect(),
    ))
}

/// One row per device with an inventory: model, CPU, memory, system disk, security features.
pub(crate) async fn hardware(
    State(s): State<AppState>,
    tech: TechAuth,
) -> Result<Json<Vec<HardwareReportRow>>, AppError> {
    let rows = sqlx::query(&format!(
        "SELECT d.id, d.hostname, f.collected_at, f.manufacturer, f.model,
                f.serial_number AS serial, f.cpu_model AS cpu, f.cpu_logical_cores AS cores,
                f.memory_total_bytes AS memory, f.tpm_version AS tpm, f.secure_boot,
                f.system_disk_total_bytes, f.system_disk_free_bytes, f.reboot_pending
         FROM devices d JOIN device_facts f ON f.device_id = d.id
         WHERE d.revoked = 0 AND {}
         ORDER BY d.hostname COLLATE NOCASE",
        scope(1)
    ))
    .bind(tech.scope_name())
    .fetch_all(&s.db)
    .await?;
    Ok(Json(
        rows.iter()
            .filter_map(|r| {
                Some(HardwareReportRow {
                    device_id: r.get::<&str, _>("id").parse().ok()?,
                    hostname: r.get("hostname"),
                    collected_at: r.get("collected_at"),
                    manufacturer: r.get("manufacturer"),
                    model: r.get("model"),
                    serial_number: r.get("serial"),
                    cpu_model: r.get::<Option<String>, _>("cpu").unwrap_or_default(),
                    cpu_logical_cores: r.get::<Option<i64>, _>("cores").unwrap_or(0) as u32,
                    memory_total_bytes: r.get::<Option<i64>, _>("memory").unwrap_or(0) as u64,
                    system_disk_total_bytes: r
                        .get::<Option<i64>, _>("system_disk_total_bytes")
                        .map(|b| b as u64),
                    system_disk_free_bytes: r
                        .get::<Option<i64>, _>("system_disk_free_bytes")
                        .map(|b| b as u64),
                    tpm_version: r.get("tpm"),
                    secure_boot: r.get::<Option<i64>, _>("secure_boot").map(|b| b != 0),
                    reboot_pending: !r.get::<&str, _>("reboot_pending").is_empty(),
                })
            })
            .collect(),
    ))
}
