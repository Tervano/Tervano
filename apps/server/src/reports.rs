//! Fleet reports (T-804): software, OS and hardware views built from the stored device state and
//! the latest inventory snapshots. Every report follows the caller's device scope (T-806). The
//! software report aggregates in SQLite (JSON1) so it never loads whole inventories into memory.

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
    let rows = sqlx::query(&format!(
        "SELECT json_extract(a.value, '$.name') AS name,
                json_extract(a.value, '$.version') AS version,
                json_extract(a.value, '$.publisher') AS publisher,
                COUNT(DISTINCT d.id) AS devices
         FROM devices d
         JOIN device_inventory i ON i.device_id = d.id
         JOIN json_each(i.report_json, '$.software.apps') a
         WHERE d.revoked = 0 AND {}
           AND (?1 = '' OR json_extract(a.value, '$.name') LIKE ?2 ESCAPE '\\'
                OR json_extract(a.value, '$.publisher') LIKE ?2 ESCAPE '\\')
         GROUP BY 1, 2, 3
         ORDER BY devices DESC, name COLLATE NOCASE, version
         LIMIT ?3",
        scope(4)
    ))
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
         JOIN device_inventory i ON i.device_id = d.id
         JOIN json_each(i.report_json, '$.software.apps') a
         WHERE d.revoked = 0 AND {}
           AND json_extract(a.value, '$.name') = ?1
           AND (?2 IS NULL OR IFNULL(json_extract(a.value, '$.version'), '') = ?2)
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
        "SELECT d.id, d.hostname, i.collected_at,
                json_extract(i.report_json, '$.hardware.manufacturer') AS manufacturer,
                json_extract(i.report_json, '$.hardware.model') AS model,
                json_extract(i.report_json, '$.hardware.serial_number') AS serial,
                json_extract(i.report_json, '$.hardware.cpu_model') AS cpu,
                json_extract(i.report_json, '$.hardware.cpu_logical_cores') AS cores,
                json_extract(i.report_json, '$.hardware.memory_total_bytes') AS memory,
                json_extract(i.report_json, '$.hardware.tpm_version') AS tpm,
                json_extract(i.report_json, '$.hardware.secure_boot') AS secure_boot,
                json_extract(i.report_json, '$.hardware.disks') AS disks,
                json_array_length(i.report_json, '$.software.reboot_pending') AS reboot
         FROM devices d JOIN device_inventory i ON i.device_id = d.id
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
                let disks: Vec<DiskInfo> =
                    serde_json::from_str(r.get::<Option<&str>, _>("disks")?).ok()?;
                // The Windows system drive, else the first fixed disk.
                let system = disks
                    .iter()
                    .find(|d| d.mount_point.eq_ignore_ascii_case("C:\\"))
                    .or_else(|| disks.iter().find(|d| !d.removable));
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
                    system_disk_total_bytes: system.map(|d| d.total_bytes),
                    system_disk_free_bytes: system.map(|d| d.free_bytes),
                    tpm_version: r.get("tpm"),
                    secure_boot: r.get::<Option<i64>, _>("secure_boot").map(|b| b != 0),
                    reboot_pending: r.get::<Option<i64>, _>("reboot").unwrap_or(0) > 0,
                })
            })
            .collect(),
    ))
}
