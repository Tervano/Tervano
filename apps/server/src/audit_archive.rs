//! Export and archive of append-only audit rows. Archive files are durable before pruning.

use anyhow::{Context, ensure};
use serde_json::to_vec;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use tervano_protocol::AuditRecord;
use uuid::Uuid;

use crate::now_millis;

const BATCH: i64 = 1000;
const DELETE_TRIGGER: &str = "CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log \
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END";

fn archive_dir(path: &Path) -> anyhow::Result<PathBuf> {
    let dir = path
        .canonicalize()
        .with_context(|| format!("archive directory {}", path.display()))?;
    ensure!(
        dir.is_dir(),
        "archive path is not a directory: {}",
        dir.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&dir)?.permissions().mode();
        ensure!(
            mode & 0o077 == 0,
            "archive directory must be owner-only (mode 0700)"
        );
    }
    Ok(dir)
}

fn new_private_file(path: &Path) -> anyhow::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn temp_path(dir: &Path) -> PathBuf {
    dir.join(format!(".tervano-audit-{}.tmp", Uuid::new_v4()))
}

fn publish(temp: &Path, final_path: &Path, allow_identical: bool) -> anyhow::Result<()> {
    let result: anyhow::Result<()> = (|| match fs::hard_link(temp, final_path) {
        Ok(()) => Ok(()),
        Err(e) if allow_identical && e.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure!(
                fs::read(temp)? == fs::read(final_path)?,
                "existing archive differs: {}",
                final_path.display()
            );
            Ok(())
        }
        Err(e) => Err(e.into()),
    })();
    let _ = fs::remove_file(temp);
    result?;
    #[cfg(unix)]
    File::open(final_path.parent().context("archive has no parent")?)?.sync_all()?;
    Ok(())
}

fn audit_record(row: sqlx::sqlite::SqliteRow) -> AuditRecord {
    AuditRecord {
        id: row.get("id"),
        at: row.get("at"),
        actor: row.get("actor"),
        action: row.get("action"),
        target: row.get("target"),
        ok: row.get("ok"),
        detail: row.get("detail"),
        client_ip: row.get("client_ip"),
    }
}

fn line(record: &AuditRecord) -> anyhow::Result<Vec<u8>> {
    let mut bytes = to_vec(record)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Write a complete read snapshot to a new NDJSON file without changing the database.
pub async fn export_audit(db: &SqlitePool, out: &Path) -> anyhow::Result<(u64, String)> {
    let dir = archive_dir(out.parent().context("export path has no parent")?)?;
    let final_path = dir.join(out.file_name().context("export path has no file name")?);
    ensure!(
        !final_path.exists(),
        "export already exists: {}",
        final_path.display()
    );
    let temp = temp_path(&dir);
    let mut file = new_private_file(&temp)?;
    let mut digest = Sha256::new();
    let mut count = 0_u64;
    let mut after = 0_i64;
    let mut tx = db.begin().await?;
    loop {
        let rows = sqlx::query(
            "SELECT id, at, actor, action, target, ok, detail, client_ip FROM audit_log \
             WHERE id > ? ORDER BY id LIMIT ?",
        )
        .bind(after)
        .bind(BATCH)
        .fetch_all(&mut *tx)
        .await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            let record = audit_record(row);
            let bytes = line(&record)?;
            file.write_all(&bytes)?;
            digest.update(&bytes);
            after = record.id;
            count += 1;
        }
    }
    tx.commit().await?;
    file.sync_all()?;
    drop(file);
    publish(&temp, &final_path, false)?;
    Ok((count, hex::encode(digest.finalize())))
}

async fn archive_batch(
    db: &SqlitePool,
    dir: &Path,
    cutoff: i64,
    actor: &str,
) -> anyhow::Result<u64> {
    // Claim the writer slot before reading so another audit insert cannot turn
    // this snapshot into SQLITE_BUSY_SNAPSHOT during the later delete.
    let mut tx = db.begin_with("BEGIN IMMEDIATE").await?;
    let rows = sqlx::query(
        "SELECT id, at, actor, action, target, ok, detail, client_ip FROM audit_log \
         WHERE at < ? ORDER BY id LIMIT ?",
    )
    .bind(cutoff)
    .bind(BATCH)
    .fetch_all(&mut *tx)
    .await?;
    if rows.is_empty() {
        return Ok(0);
    }
    let records: Vec<_> = rows.into_iter().map(audit_record).collect();
    let first = records.first().context("empty audit batch")?.id;
    let last = records.last().context("empty audit batch")?.id;
    let mut bytes = Vec::new();
    for record in &records {
        bytes.extend(line(record)?);
    }
    let hash = hex::encode(Sha256::digest(&bytes));
    let name = format!("audit-{first:016}-{last:016}-{hash}.jsonl");
    let final_path = dir.join(&name);
    let temp = temp_path(dir);
    let mut file = new_private_file(&temp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    publish(&temp, &final_path, true)?;

    // DDL and deletion are one SQLite transaction. Failure restores the trigger
    // and leaves the already-durable archive for an idempotent retry.
    sqlx::query("DROP TRIGGER audit_log_no_delete")
        .execute(&mut *tx)
        .await?;
    let deleted = sqlx::query("DELETE FROM audit_log WHERE id BETWEEN ? AND ? AND at < ?")
        .bind(first)
        .bind(last)
        .bind(cutoff)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    ensure!(
        deleted == records.len() as u64,
        "audit archive/delete row count mismatch"
    );
    sqlx::query(DELETE_TRIGGER).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO audit_log (at, actor, action, target, ok, detail) \
         VALUES (?, ?, 'audit.archive', ?, 1, ?)",
    )
    .bind(now_millis())
    .bind(actor)
    .bind(&name)
    .bind(format!("rows={} sha256={hash}", deleted))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(deleted)
}

/// Retain recent rows and archive older ones before pruning. An archive error keeps the rows.
pub async fn archive_audit(
    db: &SqlitePool,
    dir: &Path,
    retention_days: u32,
    actor: &str,
) -> anyhow::Result<u64> {
    ensure!(
        retention_days >= 1,
        "audit retention must be at least one day"
    );
    let dir = archive_dir(dir)?;
    let cutoff = now_millis() - i64::from(retention_days) * 86_400_000;
    let mut total = 0;
    loop {
        let count = archive_batch(db, &dir, cutoff, actor).await?;
        total += count;
        if count == 0 {
            break;
        }
    }
    Ok(total)
}

/// Check file hashes and the row ID range encoded in each archive name.
pub fn verify_archives(dir: &Path) -> anyhow::Result<(u64, u64)> {
    let dir = archive_dir(dir)?;
    let mut files = 0;
    let mut rows = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("audit-") || !name.ends_with(".jsonl") {
            continue;
        }
        let parts: Vec<_> = name
            .trim_start_matches("audit-")
            .trim_end_matches(".jsonl")
            .split('-')
            .collect();
        ensure!(parts.len() == 3, "invalid audit archive name: {name}");
        let first: i64 = parts[0].parse()?;
        let last: i64 = parts[1].parse()?;
        let bytes = fs::read(entry.path())?;
        ensure!(
            hex::encode(Sha256::digest(&bytes)) == parts[2],
            "audit archive hash mismatch: {name}"
        );
        let mut previous = None;
        let mut count = 0;
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let record: AuditRecord = serde_json::from_slice(line)?;
            if let Some(previous) = previous {
                ensure!(
                    record.id > previous,
                    "audit archive IDs are not increasing: {name}"
                );
            } else {
                ensure!(
                    record.id == first,
                    "audit archive first ID mismatch: {name}"
                );
            }
            previous = Some(record.id);
            count += 1;
        }
        ensure!(
            previous == Some(last),
            "audit archive last ID mismatch: {name}"
        );
        files += 1;
        rows += count;
    }
    Ok((files, rows))
}

pub fn spawn_audit_archiver(db: SqlitePool, dir: PathBuf, retention_days: u32) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60 * 60)).await;
            if let Err(e) = archive_audit(&db, &dir, retention_days, "server").await {
                tracing::error!("audit archival failed; rows retained: {e:#}");
            }
        }
    });
}
