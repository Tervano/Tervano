//! Service-mode logging: a size-rotated log file (T-216) and a Windows Event Log fallback for
//! errors that happen before the file logger exists (T-218).

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;

/// Appends to `path`; when it would exceed `max_bytes`, shifts `path.1`…`path.{keep-1}` up by one,
/// renames `path` to `path.1` and starts a fresh file. Disk use is bounded by `max_bytes * keep`.
pub struct RotatingLog {
    path: PathBuf,
    max_bytes: u64,
    keep: u32,
    file: File,
    size: u64,
}

impl RotatingLog {
    pub fn open(path: PathBuf, max_bytes: u64, keep: u32) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path,
            max_bytes,
            keep: keep.max(1),
            file,
            size,
        })
    }

    fn numbered(&self, n: u32) -> PathBuf {
        let mut s = self.path.as_os_str().to_owned();
        s.push(format!(".{n}"));
        PathBuf::from(s)
    }

    fn rotate(&mut self) -> io::Result<()> {
        let _ = std::fs::remove_file(self.numbered(self.keep - 1));
        for n in (1..self.keep - 1).rev() {
            let _ = std::fs::rename(self.numbered(n), self.numbered(n + 1));
        }
        if self.keep > 1 {
            std::fs::rename(&self.path, self.numbered(1))?;
        } else {
            std::fs::remove_file(&self.path)?;
        }
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.size = 0;
        Ok(())
    }
}

impl Write for RotatingLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.size > 0 && self.size + buf.len() as u64 > self.max_bytes {
            // A failed rotation keeps logging to the current file rather than losing lines.
            let _ = self.rotate();
        }
        let n = self.file.write(buf)?;
        self.size += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// Event source name used in the Application log.
pub const EVENT_SOURCE: &str = "TervanoAgent";

/// Writes an error to the Windows Application event log. Used when the file logger is not
/// available (bad config, unwritable state dir), so service failures are never silent.
#[cfg(windows)]
pub fn event_log_error(message: &str) {
    use windows::Win32::System::EventLog::{
        DeregisterEventSource, EVENTLOG_ERROR_TYPE, RegisterEventSourceW, ReportEventW,
    };
    use windows::core::{HSTRING, PCWSTR};
    let msg = HSTRING::from(message);
    // SAFETY: wide strings live for the calls; the handle is deregistered once.
    unsafe {
        let Ok(h) = RegisterEventSourceW(PCWSTR::null(), &HSTRING::from(EVENT_SOURCE)) else {
            return;
        };
        // Event ID 1000 with EventCreate.exe as message file renders the string as-is.
        let _ = ReportEventW(
            h,
            EVENTLOG_ERROR_TYPE,
            0,
            1000,
            None,
            0,
            Some(&[PCWSTR(msg.as_ptr())]),
            None,
        );
        let _ = DeregisterEventSource(h);
    }
}

#[cfg(not(windows))]
pub fn event_log_error(message: &str) {
    eprintln!("{message}");
}
