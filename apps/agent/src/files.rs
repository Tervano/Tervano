//! Remote file management and resumable, integrity-checked transfer (PLAN §7 "File management", T-705).

use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use tervano_protocol::{DirListing, FILE_CHUNK_MAX, FileEntry, FileHash, FileOp, UploadFinish};

const PART_SUFFIX: &str = ".tervano-part";

/// Accepts only absolute local drive paths (`C:\…`). UNC, device (`\\?\`, `\\.\`) and relative
/// paths are refused so a technician can't reach network shares with the machine's credentials.
pub fn local_path(p: &str) -> Result<PathBuf, String> {
    let p = p.trim();
    let b = p.as_bytes();
    let drive = b.len() >= 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b[2] == b'\\' || b[2] == b'/');
    if !drive || p.contains('\0') || p.len() > 32_000 {
        return Err(format!(
            "{p:?} is not an absolute local path like C:\\folder\\file"
        ));
    }
    let path = PathBuf::from(p);
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("paths may not contain '..'".into());
    }
    Ok(path)
}

/// Number of components below the drive root (`C:\a\b` → 2).
fn depth(p: &Path) -> usize {
    p.components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count()
}

fn io_err(what: &str, p: &Path, e: std::io::Error) -> String {
    format!("{what} {}: {e}", p.display())
}

fn millis(t: std::io::Result<std::time::SystemTime>) -> Option<i64> {
    t.ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as i64)
}

pub fn list(path: &str) -> Result<DirListing, String> {
    if path.trim().is_empty() {
        let entries = (b'A'..=b'Z')
            .map(|d| format!("{}:\\", d as char))
            .filter(|root| Path::new(root).exists())
            .map(|name| FileEntry {
                name,
                is_dir: true,
                size: 0,
                modified: None,
                readonly: false,
                hidden: false,
            })
            .collect();
        return Ok(DirListing {
            path: String::new(),
            entries,
        });
    }
    let dir = local_path(path)?;
    let mut entries: Vec<FileEntry> = std::fs::read_dir(&dir)
        .map_err(|e| io_err("cannot list", &dir, e))?
        .filter_map(Result::ok)
        .filter_map(|e| {
            let md = e.metadata().ok()?;
            #[cfg(windows)]
            let hidden = {
                use std::os::windows::fs::MetadataExt;
                md.file_attributes() & 0x2 != 0 // FILE_ATTRIBUTE_HIDDEN
            };
            #[cfg(not(windows))]
            let hidden = e.file_name().to_string_lossy().starts_with('.');
            Some(FileEntry {
                name: e.file_name().to_string_lossy().into_owned(),
                is_dir: md.is_dir(),
                size: if md.is_dir() { 0 } else { md.len() },
                modified: millis(md.modified()),
                readonly: md.permissions().readonly(),
                hidden,
            })
        })
        .collect();
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(DirListing {
        path: dir.display().to_string(),
        entries,
    })
}

/// Reads up to `len` bytes at `offset`; returns (bytes, total file size).
pub fn read_chunk(path: &str, offset: u64, len: Option<u32>) -> Result<(Vec<u8>, u64), String> {
    let p = local_path(path)?;
    let mut f = std::fs::File::open(&p).map_err(|e| io_err("cannot open", &p, e))?;
    let size = f
        .metadata()
        .map_err(|e| io_err("cannot stat", &p, e))?
        .len();
    let want = u64::from(len.unwrap_or(FILE_CHUNK_MAX).min(FILE_CHUNK_MAX))
        .min(size.saturating_sub(offset));
    f.seek(SeekFrom::Start(offset))
        .map_err(|e| io_err("cannot seek", &p, e))?;
    let mut buf = Vec::with_capacity(want as usize);
    f.take(want)
        .read_to_end(&mut buf)
        .map_err(|e| io_err("cannot read", &p, e))?;
    Ok((buf, size))
}

fn sha256_file(p: &Path) -> Result<FileHash, String> {
    let mut f = std::fs::File::open(p).map_err(|e| io_err("cannot open", p, e))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut size = 0u64;
    loop {
        let n = f.read(&mut buf).map_err(|e| io_err("cannot read", p, e))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        size += n as u64;
    }
    Ok(FileHash {
        size,
        sha256: hex::encode(h.finalize()),
    })
}

pub fn hash(path: &str) -> Result<FileHash, String> {
    sha256_file(&local_path(path)?)
}

fn part_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(PART_SUFFIX);
    PathBuf::from(s)
}

/// Appends a chunk to `<path>.tervano-part`. `offset` must equal the bytes already received
/// (0 starts over), which makes uploads resumable without ever corrupting the part file.
/// Returns Err((message, current part size)) on a mismatch.
pub fn upload_chunk(path: &str, offset: u64, data: &[u8]) -> Result<u64, (String, u64)> {
    let p = local_path(path).map_err(|e| (e, 0))?;
    let part = part_path(&p);
    let have = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
    if offset != 0 && offset != have {
        return Err((
            format!("upload offset {offset} does not match {have} bytes received"),
            have,
        ));
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(offset == 0)
        .append(offset != 0)
        .open(&part)
        .map_err(|e| (io_err("cannot write", &part, e), have))?;
    f.write_all(data)
        .and_then(|()| f.flush())
        .map_err(|e| (io_err("cannot write", &part, e), have))?;
    Ok(offset + data.len() as u64)
}

/// Verifies the part file's hash, then moves it into place.
pub fn upload_finish(req: &UploadFinish) -> Result<FileHash, String> {
    let p = local_path(&req.path)?;
    let part = part_path(&p);
    let got = sha256_file(&part)?;
    if !got.sha256.eq_ignore_ascii_case(req.sha256.trim()) {
        let _ = std::fs::remove_file(&part);
        return Err(format!(
            "upload corrupted in transit (SHA-256 {} != expected {}); the partial file was discarded",
            got.sha256, req.sha256
        ));
    }
    if p.exists() && !req.overwrite {
        let _ = std::fs::remove_file(&part);
        return Err(format!(
            "{} already exists (choose overwrite to replace it)",
            p.display()
        ));
    }
    // std::fs::rename replaces an existing file on Windows (MoveFileEx REPLACE_EXISTING).
    std::fs::rename(&part, &p).map_err(|e| io_err("cannot move upload into", &p, e))?;
    Ok(got)
}

pub fn op(op: &FileOp) -> Result<(), String> {
    match op {
        FileOp::Rename { from, to } => {
            let (from, to) = (local_path(from)?, local_path(to)?);
            if to.exists() {
                return Err(format!("{} already exists", to.display()));
            }
            std::fs::rename(&from, &to).map_err(|e| io_err("cannot rename", &from, e))
        }
        FileOp::Copy { from, to } => {
            let (from, to) = (local_path(from)?, local_path(to)?);
            if from.is_dir() {
                return Err("copying folders is not supported yet; copy files individually".into());
            }
            if to.exists() {
                return Err(format!("{} already exists", to.display()));
            }
            std::fs::copy(&from, &to)
                .map(|_| ())
                .map_err(|e| io_err("cannot copy", &from, e))
        }
        FileOp::Delete { path, recursive } => {
            let p = local_path(path)?;
            if p.is_dir() {
                // A drive root or a top-level folder (C:\Windows, C:\Users) is never removed wholesale.
                if *recursive && depth(&p) < 2 {
                    return Err(format!(
                        "refusing to recursively delete top-level folder {}",
                        p.display()
                    ));
                }
                if *recursive {
                    std::fs::remove_dir_all(&p)
                } else {
                    std::fs::remove_dir(&p)
                }
            } else {
                std::fs::remove_file(&p)
            }
            .map_err(|e| io_err("cannot delete", &p, e))
        }
        FileOp::Mkdir { path } => {
            let p = local_path(path)?;
            std::fs::create_dir_all(&p).map_err(|e| io_err("cannot create", &p, e))
        }
    }
}
