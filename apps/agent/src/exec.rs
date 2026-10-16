//! Remote PowerShell/CMD execution (PLAN §7 "Remote command execution", T-707).
//!
//! Jobs are started, polled and cancelled; output is captured with a cap. Scripts reach the shell
//! through stdin or a private temp file, never the command line, and execution policy is not
//! bypassed (PowerShell runs a script block, not a script file).

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tervano_protocol::{ExecContext, ExecRequest, ExecState, ExecStatus, Shell, now_millis};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use uuid::Uuid;

const MAX_RUNNING: usize = 4;
const MAX_SCRIPT_BYTES: usize = 64 * 1024;
const OUTPUT_CAP: usize = 1024 * 1024;
const KEEP_FINISHED: i64 = 10 * 60 * 1000;
const MAX_JOBS: usize = 50;

/// Reads the whole script from stdin as UTF-8 and runs it as a script block.
const PS_WRAPPER: &str = "[Console]::InputEncoding=[Text.Encoding]::UTF8;\
[Console]::OutputEncoding=[Text.Encoding]::UTF8;\
& ([scriptblock]::Create([Console]::In.ReadToEnd()))";

struct Job {
    status: ExecStatus,
    cancel: Option<oneshot::Sender<()>>,
}

pub struct Jobs {
    /// Where CMD scripts are written (the agent's ACL'd state dir).
    dir: PathBuf,
    jobs: Mutex<HashMap<Uuid, Arc<Mutex<Job>>>>,
}

pub(crate) fn system32(exe: &str) -> PathBuf {
    // Full paths so a planted binary on PATH can never run with the agent's rights.
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    PathBuf::from(root).join("System32").join(exe)
}

impl Jobs {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            // Shells run from the temp dir, so a relative state dir would not resolve.
            dir: std::path::absolute(&dir).unwrap_or(dir),
            jobs: Mutex::new(HashMap::new()),
        }
    }

    pub fn start(&self, technician: &str, req: ExecRequest) -> Result<Uuid, String> {
        if req.context == ExecContext::User {
            return Err("running as the signed-in user needs the session helper, which is not available yet; use the agent context".into());
        }
        if req.script.trim().is_empty() || req.script.len() > MAX_SCRIPT_BYTES {
            return Err(format!("script must be 1 to {MAX_SCRIPT_BYTES} bytes"));
        }
        let timeout = req.timeout_secs.unwrap_or(60);
        if !(1..=3600).contains(&timeout) {
            return Err("timeout_secs must be 1-3600".into());
        }
        let mut jobs = self.jobs.lock().expect("not poisoned");
        let now = now_millis();
        jobs.retain(|_, j| {
            let j = j.lock().expect("not poisoned");
            j.status.finished_at.is_none_or(|f| now - f < KEEP_FINISHED)
        });
        let running = jobs
            .values()
            .filter(|j| j.lock().expect("not poisoned").status.state == ExecState::Running)
            .count();
        if running >= MAX_RUNNING || jobs.len() >= MAX_JOBS {
            return Err(format!(
                "too many commands on this computer ({running} running); wait for one to finish"
            ));
        }
        let id = Uuid::new_v4();
        let (tx, rx) = oneshot::channel();
        let job = Arc::new(Mutex::new(Job {
            status: ExecStatus {
                id,
                state: ExecState::Running,
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                truncated: false,
                started_at: now,
                finished_at: None,
                error: None,
            },
            cancel: Some(tx),
        }));
        jobs.insert(id, job.clone());
        // The script itself is not logged (it may hold secrets); its hash identifies it.
        tracing::info!(
            technician,
            %id,
            shell = ?req.shell,
            bytes = req.script.len(),
            sha256 = %hex::encode(Sha256::digest(req.script.as_bytes())),
            timeout,
            "exec start"
        );
        tokio::spawn(run(
            job,
            req,
            Duration::from_secs(timeout.into()),
            self.dir.clone(),
            rx,
        ));
        Ok(id)
    }

    pub fn status(&self, id: Uuid) -> Option<ExecStatus> {
        let jobs = self.jobs.lock().expect("not poisoned");
        jobs.get(&id)
            .map(|j| j.lock().expect("not poisoned").status.clone())
    }

    pub fn cancel(&self, id: Uuid) -> Result<(), String> {
        let jobs = self.jobs.lock().expect("not poisoned");
        let job = jobs.get(&id).ok_or("no such command")?;
        match job.lock().expect("not poisoned").cancel.take() {
            Some(tx) => {
                let _ = tx.send(());
                Ok(())
            }
            None => Err("command already finished".into()),
        }
    }
}

fn finish(job: &Mutex<Job>, state: ExecState, exit_code: Option<i32>, error: Option<String>) {
    let mut j = job.lock().expect("not poisoned");
    j.status.state = state;
    j.status.exit_code = exit_code;
    j.status.error = error;
    j.status.finished_at = Some(now_millis());
    j.cancel = None;
    tracing::info!(id = %j.status.id, ?state, ?exit_code, "exec finished");
}

/// Copies a pipe into the job's stdout or stderr, keeping at most OUTPUT_CAP bytes.
async fn pump(mut pipe: impl AsyncRead + Unpin, job: Arc<Mutex<Job>>, stderr: bool) {
    let mut buf = [0u8; 8192];
    let mut pending: Vec<u8> = Vec::new();
    while let Ok(n) = pipe.read(&mut buf).await {
        if n == 0 {
            break;
        }
        pending.extend_from_slice(&buf[..n]);
        // Only decode complete UTF-8 sequences; keep a split character for the next read.
        let valid = match std::str::from_utf8(&pending) {
            Ok(_) => pending.len(),
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            Err(_) => pending.len(), // genuinely invalid bytes: decode lossily below
        };
        let text = String::from_utf8_lossy(&pending[..valid]).into_owned();
        pending.drain(..valid);
        let mut j = job.lock().expect("not poisoned");
        let out = if stderr {
            &mut j.status.stderr
        } else {
            &mut j.status.stdout
        };
        let room = OUTPUT_CAP.saturating_sub(out.len());
        if text.len() > room {
            let cut = (0..=room)
                .rev()
                .find(|&i| text.is_char_boundary(i))
                .unwrap_or(0);
            out.push_str(&text[..cut]);
            j.status.truncated = true;
        } else {
            out.push_str(&text);
        }
    }
}

async fn run(
    job: Arc<Mutex<Job>>,
    req: ExecRequest,
    timeout: Duration,
    dir: PathBuf,
    mut cancel: oneshot::Receiver<()>,
) {
    let id = job.lock().expect("not poisoned").status.id;
    let mut temp_file = None;
    let mut cmd = match req.shell {
        Shell::Powershell => {
            let mut c =
                tokio::process::Command::new(system32(r"WindowsPowerShell\v1.0\powershell.exe"));
            c.args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                PS_WRAPPER,
            ]);
            c.stdin(std::process::Stdio::piped());
            c
        }
        Shell::Cmd => {
            let path = dir.join(format!("exec-{id}.cmd"));
            // Echo off (scripts can turn it on) and UTF-8 output; CRLF line endings for cmd.exe.
            let body = format!(
                "@echo off\r\nchcp 65001 >nul\r\n{}\r\n",
                req.script.replace("\r\n", "\n").replace('\n', "\r\n")
            );
            if let Err(e) = std::fs::write(&path, body) {
                return finish(
                    &job,
                    ExecState::Failed,
                    None,
                    Some(format!("cannot write script: {e}")),
                );
            }
            let mut c = tokio::process::Command::new(system32("cmd.exe"));
            c.arg("/d").arg("/c").arg(&path);
            c.stdin(std::process::Stdio::null());
            temp_file = Some(path);
            c
        }
    };
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .current_dir(std::env::temp_dir());
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            if let Some(p) = &temp_file {
                let _ = std::fs::remove_file(p);
            }
            return finish(
                &job,
                ExecState::Failed,
                None,
                Some(format!("cannot start shell: {e}")),
            );
        }
    };
    let tree = platform::KillTree::new(&child);

    if let Some(mut stdin) = child.stdin.take() {
        let script = req.script.clone();
        // Write on its own task so a script that never reads stdin can't block us.
        tokio::spawn(async move {
            let _ = stdin.write_all(script.as_bytes()).await;
        });
    }
    let readers = [
        child
            .stdout
            .take()
            .map(|p| tokio::spawn(pump(p, job.clone(), false))),
        child
            .stderr
            .take()
            .map(|p| tokio::spawn(pump(p, job.clone(), true))),
    ];

    let (state, code) = tokio::select! {
        r = child.wait() => (ExecState::Exited, r.ok().and_then(|s| s.code())),
        _ = tokio::time::sleep(timeout) => (ExecState::TimedOut, None),
        _ = &mut cancel => (ExecState::Cancelled, None),
    };
    if state != ExecState::Exited {
        // Kill the shell and everything it started, not just the shell.
        if let Some(t) = &tree {
            t.terminate();
        }
        let _ = child.kill().await;
    }
    for r in readers.into_iter().flatten() {
        // Pipes close once the process tree is gone; don't wait forever on stragglers.
        let _ = tokio::time::timeout(Duration::from_secs(2), r).await;
    }
    if let Some(p) = temp_file {
        let _ = std::fs::remove_file(p);
    }
    finish(&job, state, code, None);
}

pub(crate) use platform::KillTree;

#[cfg(windows)]
mod platform {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, TerminateJobObject,
    };
    use windows::core::PCWSTR;

    /// A job object holding the command's process tree, so timeout/cancel can end all of it.
    /// Processes the script intentionally leaves running after a normal exit are not killed.
    pub struct KillTree(HANDLE);

    // SAFETY: a job-object handle is a kernel handle usable from any thread; we only call
    // thread-agnostic APIs on it and close it once.
    unsafe impl Send for KillTree {}
    unsafe impl Sync for KillTree {}

    impl KillTree {
        pub fn new(child: &tokio::process::Child) -> Option<Self> {
            let process = child.raw_handle()?;
            // SAFETY: no security attributes or name; the handle is closed in Drop.
            let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }.ok()?;
            let tree = KillTree(job);
            // shortcut: grandchildren spawned before this call escape the job (a few-ms window);
            // closing it needs CREATE_SUSPENDED spawning (T-707 follow-up if it matters in practice).
            // SAFETY: both handles are valid for the duration of the call.
            unsafe { AssignProcessToJobObject(tree.0, HANDLE(process.cast())) }.ok()?;
            Some(tree)
        }

        pub fn terminate(&self) {
            // SAFETY: valid job handle.
            unsafe {
                let _ = TerminateJobObject(self.0, 1);
            }
        }
    }

    impl Drop for KillTree {
        fn drop(&mut self) {
            // SAFETY: we own the handle and close it exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[cfg(not(windows))]
mod platform {
    pub struct KillTree;
    impl KillTree {
        pub fn new(_: &tokio::process::Child) -> Option<Self> {
            None
        }
        pub fn terminate(&self) {}
    }
}
