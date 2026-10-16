//! Inventory projections (T-813): each inventory upload is also written as one `device_facts` row
//! (hardware and security scalars) and one `device_software` row per installed app, so reports and
//! compliance query indexed tables instead of re-parsing every device's inventory JSON.

use super::*;

/// The Windows system drive (C:), else the first fixed disk.
pub(crate) fn system_disk(disks: &[DiskInfo]) -> Option<&DiskInfo> {
    disks
        .iter()
        .find(|d| d.mount_point.eq_ignore_ascii_case("C:\\"))
        .or_else(|| disks.iter().find(|d| !d.removable))
}

/// Software rows per INSERT; 5 parameters each stays far below SQLite's variable limit.
const SOFTWARE_BATCH: usize = 200;

/// Replaces the device's projections with those of `r`. Runs in the caller's transaction so the
/// projections never disagree with the stored inventory.
pub(crate) async fn write(
    tx: &mut sqlx::SqliteConnection,
    device_id: &str,
    r: &InventoryReport,
) -> Result<(), sqlx::Error> {
    let hw = &r.hardware;
    let disk = system_disk(&hw.disks);
    sqlx::query(
        "INSERT OR REPLACE INTO device_facts (device_id, collected_at, manufacturer, model,
             serial_number, cpu_model, cpu_logical_cores, memory_total_bytes, tpm_version,
             secure_boot, reboot_pending, system_disk_mount, system_disk_total_bytes,
             system_disk_free_bytes)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(device_id)
    .bind(r.collected_at)
    .bind(&hw.manufacturer)
    .bind(&hw.model)
    .bind(&hw.serial_number)
    .bind(&hw.cpu_model)
    .bind(i64::from(hw.cpu_logical_cores))
    .bind(hw.memory_total_bytes as i64)
    .bind(&hw.tpm_version)
    .bind(hw.secure_boot)
    .bind(r.software.reboot_pending.join("; "))
    .bind(disk.map(|d| d.mount_point.as_str()))
    .bind(disk.map(|d| d.total_bytes as i64))
    .bind(disk.map(|d| d.free_bytes as i64))
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM device_software WHERE device_id = ?")
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    for chunk in r.software.apps.chunks(SOFTWARE_BATCH) {
        let mut q = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "INSERT INTO device_software (device_id, name, name_lower, version, publisher) ",
        );
        q.push_values(chunk, |mut row, a| {
            row.push_bind(device_id)
                .push_bind(&a.name)
                .push_bind(a.name.to_lowercase())
                .push_bind(&a.version)
                .push_bind(&a.publisher);
        });
        q.build().execute(&mut *tx).await?;
    }
    Ok(())
}
