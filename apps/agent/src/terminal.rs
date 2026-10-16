//! Interactive remote terminal (T-708): a long-lived PowerShell or CMD process whose stdin the
//! technician writes to and whose output is read back by offset. Runs as the agent's account.

use crate::exec::{KillTree, system32};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tervano_protocol::{Shell, TerminalOutput};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use uuid::Uuid;

const MAX_SESSIONS: usize = 2;
const BUFFER_CAP: usize = 256 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_INPUT: usize = 16 * 1024;

/// One line per command, run with output formatted the way the console host would show it.
/// shortcut: multi-line constructs must be typed on one line; a real PS host is future work (T-708).
const PS_LOOP: &str = "[Console]::InputEncoding=[Console]::OutputEncoding=[Text.Encoding]::UTF8; while ($null -ne ($l = [Console]::In.ReadLine())) { try { Invoke-Expression $l 2>&1 | Out-String -Stream } catch { $_ | Out-String -Stream } }";

#[derive(Default)]
struct Out {
    buf: String,
    /// Absolute offset of `buf[0]` in the session's whole output.
    start: u64,
    exited: bool,
    exit_code: Option<i32>,
}

struct Session {
    stdin: tokio::sync::Mutex<Option<tokio::process::ChildStdin>>,
    out: Mutex<Out>,
    touched: Mutex<Instant>,
    close: Mutex<Option<oneshot::Sender<()>>>,
}

#[derive(Default)]
pub struct Terminals {
    sessions: Mutex<HashMap<Uuid, Arc<Session>>>,
}

fn append(session: &Session, text: &str) {
    let mut o = session.out.lock().expect("not poisoned");
    o.buf.push_str(text);
    if o.buf.len() > BUFFER_CAP {
        // Drop the oldest output on a char boundary; readers see `skipped`.
        let excess = o.buf.len() - BUFFER_CAP;
        let cut = (excess..o.buf.len())
            .find(|&i| o.buf.is_char_boundary(i))
            .unwrap_or(o.buf.len());
        o.buf.drain(..cut);
        o.start += cut as u64;
    }
}

async fn pump(mut pipe: impl AsyncRead + Unpin, session: Arc<Session>) {
    let mut buf = [0u8; 8192];
    let mut pending = Vec::new();
    while let Ok(n) = pipe.read(&mut buf).await {
        if n == 0 {
            break;
        }
        pending.extend_from_slice(&buf[..n]);
        // Keep a UTF-8 sequence split across reads for the next read.
        let valid = match std::str::from_utf8(&pending) {
            Ok(_) => pending.len(),
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            Err(_) => pending.len(),
        };
        let text = String::from_utf8_lossy(&pending[..valid]).into_owned();
        pending.drain(..valid);
        append(&session, &text);
    }
}

impl Terminals {
    pub fn open(&self, technician: &str, shell: Shell) -> Result<Uuid, String> {
        let mut sessions = self.sessions.lock().expect("not poisoned");
        sessions.retain(|_, s| !s.out.lock().expect("not poisoned").exited);
        if sessions.len() >= MAX_SESSIONS {
            return Err(format!(
                "at most {MAX_SESSIONS} terminals per computer; close one first"
            ));
        }
        let mut cmd = match shell {
            Shell::Powershell => {
                let mut c = tokio::process::Command::new(system32(
                    r"WindowsPowerShell\v1.0\powershell.exe",
                ));
                // Switch stdin/stdout to UTF-8 *before* reading (setting InputEncoding rebuilds
                // Console.In), then run each line in one scope so variables persist. A script
                // block from -Command, not a file, so execution policy is not bypassed.
                c.args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    PS_LOOP,
                ]);
                c
            }
            Shell::Cmd => {
                let mut c = tokio::process::Command::new(system32("cmd.exe"));
                c.args(["/D", "/Q", "/K", "chcp 65001 >nul"]);
                c
            }
        };
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .current_dir(std::env::temp_dir());
        #[cfg(windows)]
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("cannot start shell: {e}"))?;
        let tree = KillTree::new(&child);
        let (tx, rx) = oneshot::channel();
        let session = Arc::new(Session {
            stdin: tokio::sync::Mutex::new(child.stdin.take()),
            out: Mutex::new(Out::default()),
            touched: Mutex::new(Instant::now()),
            close: Mutex::new(Some(tx)),
        });
        for pipe in [
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn AsyncRead + Unpin + Send>),
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn AsyncRead + Unpin + Send>),
        ]
        .into_iter()
        .flatten()
        {
            tokio::spawn(pump(pipe, session.clone()));
        }
        let id = Uuid::new_v4();
        tracing::info!(technician, %id, ?shell, "terminal opened");
        let s = session.clone();
        tokio::spawn(async move {
            let mut rx = rx;
            let code = loop {
                tokio::select! {
                    r = child.wait() => break r.ok().and_then(|st| st.code()),
                    _ = &mut rx => break None,
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {
                        if s.touched.lock().expect("not poisoned").elapsed() < IDLE_TIMEOUT {
                            continue;
                        }
                        append(&s, "\r\n[Tervano: terminal closed after 15 minutes without input]\r\n");
                        break None;
                    }
                }
            };
            // Ends the shell and anything it started (closing or timing out never leaves orphans).
            if let Some(t) = &tree {
                t.terminate();
            }
            let _ = child.kill().await;
            let mut o = s.out.lock().expect("not poisoned");
            o.exited = true;
            o.exit_code = code;
            tracing::info!(%id, ?code, "terminal closed");
        });
        sessions.insert(id, session);
        Ok(id)
    }

    fn get(&self, id: Uuid) -> Result<Arc<Session>, String> {
        self.sessions
            .lock()
            .expect("not poisoned")
            .get(&id)
            .cloned()
            .ok_or_else(|| "no such terminal (it may have been closed)".into())
    }

    pub async fn input(&self, technician: &str, id: Uuid, text: &str) -> Result<(), String> {
        if text.len() > MAX_INPUT {
            return Err(format!("input is limited to {MAX_INPUT} bytes per request"));
        }
        let s = self.get(id)?;
        if s.out.lock().expect("not poisoned").exited {
            return Err("terminal has exited".into());
        }
        *s.touched.lock().expect("not poisoned") = Instant::now();
        // Typed commands can contain secrets; the audit trail records that input happened, not what.
        tracing::info!(technician, %id, bytes = text.len(), sha256 = %hex::encode(Sha256::digest(text.as_bytes())), "terminal input");
        let mut stdin = s.stdin.lock().await;
        let pipe = stdin.as_mut().ok_or("terminal input is closed")?;
        pipe.write_all(text.as_bytes())
            .await
            .map_err(|e| format!("cannot write to the terminal: {e}"))?;
        pipe.flush().await.map_err(|e| e.to_string())
    }

    pub fn output(&self, id: Uuid, since: u64) -> Result<TerminalOutput, String> {
        let s = self.get(id)?;
        let o = s.out.lock().expect("not poisoned");
        let skipped = since < o.start;
        let from = since.saturating_sub(o.start).min(o.buf.len() as u64) as usize;
        // Offsets come from earlier responses, so they are char boundaries unless forged.
        let from = (from..=o.buf.len())
            .find(|&i| o.buf.is_char_boundary(i))
            .unwrap_or(o.buf.len());
        Ok(TerminalOutput {
            id,
            output: o.buf[from..].to_owned(),
            next: o.start + o.buf.len() as u64,
            skipped,
            exited: o.exited,
            exit_code: o.exit_code,
        })
    }

    pub fn close(&self, technician: &str, id: Uuid) -> Result<(), String> {
        let s = self.get(id)?;
        tracing::info!(technician, %id, "terminal close requested");
        match s.close.lock().expect("not poisoned").take() {
            Some(tx) => {
                let _ = tx.send(());
                Ok(())
            }
            None => Err("terminal already closed".into()),
        }
    }
}
