//! Server jobs (T-800): scripts a technician queued on the server for this computer.
//!
//! Off unless `[server_jobs] enabled = true`, and then only for the technicians listed there: the
//! server is not trusted to decide on its own what runs here. A disabled agent still claims its
//! jobs (at the heartbeat interval) and refuses them, so technicians see why nothing ran instead of
//! a job that stays pending forever. Jobs run one at a time, in order, through the same exec
//! engine as direct commands (timeout, process-tree kill, output cap, script logged by hash).

use crate::{Client, exec::Jobs, jitter, sleep_or_stop};
use serde::Deserialize;
use std::time::Duration;
use tervano_protocol::*;
use tokio::sync::watch;
use uuid::Uuid;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerJobsConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Server technician names whose jobs run here; `"*"` allows every technician.
    #[serde(default)]
    pub technicians: Vec<String>,
}

impl ServerJobsConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.enabled || !self.technicians.is_empty(),
            "[server_jobs] enabled needs technicians = [\"name\", ...] (or [\"*\"] for all)"
        );
        Ok(())
    }

    fn allows(&self, technician: &str) -> bool {
        self.technicians
            .iter()
            .any(|t| t == "*" || t.eq_ignore_ascii_case(technician))
    }
}

pub async fn run(
    client: Client,
    secret: String,
    cfg: ServerJobsConfig,
    jobs: Jobs,
    poll: Duration,
    mut stop: watch::Receiver<bool>,
) {
    if cfg.enabled {
        tracing::info!(technicians = ?cfg.technicians, "server jobs enabled");
    }
    let mut unsent: Option<(Uuid, JobResult)> = None;
    loop {
        if let Some((id, result)) = &unsent {
            match client.job_result(&secret, *id, result).await {
                Ok(()) => unsent = None,
                // The server no longer expects it (job deleted, or the device was re-assigned).
                Err(e) if e.to_string().contains("409") || e.to_string().contains("404") => {
                    tracing::warn!(job = %id, "server refused the job result: {e:#}");
                    unsent = None;
                }
                Err(e) => tracing::warn!(job = %id, "job result not delivered, will retry: {e:#}"),
            }
        }
        if unsent.is_none() {
            match client.claim_job(&secret).await {
                Ok(Some(job)) => {
                    let id = job.id;
                    let result = execute(&jobs, &cfg, job, &mut stop).await;
                    unsent = Some((id, result));
                    if *stop.borrow() {
                        if let Some((id, r)) = &unsent {
                            let _ = tokio::time::timeout(
                                Duration::from_secs(3),
                                client.job_result(&secret, *id, r),
                            )
                            .await;
                        }
                        return;
                    }
                    continue;
                }
                Ok(None) => {}
                // Connectivity problems are already reported by the state loop.
                Err(e) => tracing::debug!("job claim failed: {e:#}"),
            }
        }
        if !sleep_or_stop(jitter(poll, 0.2), &mut stop).await {
            return;
        }
    }
}

async fn execute(
    jobs: &Jobs,
    cfg: &ServerJobsConfig,
    job: AgentJob,
    stop: &mut watch::Receiver<bool>,
) -> JobResult {
    let started = now_millis();
    let refuse = |error: String| {
        tracing::warn!(job = %job.id, technician = %job.created_by, "server job refused: {error}");
        JobResult {
            state: ExecState::Failed,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            truncated: false,
            error: Some(error),
            started_at: started,
            finished_at: now_millis(),
        }
    };
    if !cfg.enabled {
        return refuse(
            "refused: server jobs are turned off on this computer ([server_jobs] in agent.toml)"
                .into(),
        );
    }
    if !cfg.allows(&job.created_by) {
        return refuse(format!(
            "refused: technician {} is not allowed to run server jobs on this computer",
            job.created_by
        ));
    }
    tracing::info!(job = %job.id, technician = %job.created_by, "running server job");
    let req = ExecRequest {
        shell: job.shell,
        script: job.script,
        context: ExecContext::Agent,
        timeout_secs: Some(job.timeout_secs),
    };
    let id = match jobs.start(&format!("server:{}", job.created_by), req) {
        Ok(id) => id,
        Err(e) => return refuse(format!("could not start: {e}")),
    };
    let mut cancelled = false;
    loop {
        let stopping = !sleep_or_stop(Duration::from_millis(500), stop).await;
        if stopping && !cancelled {
            // Agent shutting down: kill the script rather than leave it orphaned.
            let _ = jobs.cancel(id);
            cancelled = true;
        }
        let Some(st) = jobs.status(id) else {
            return refuse("the command record was lost".into());
        };
        if st.state != ExecState::Running {
            let mut r = JobResult {
                state: st.state,
                exit_code: st.exit_code,
                stdout: st.stdout,
                stderr: st.stderr,
                truncated: st.truncated,
                error: if cancelled {
                    Some("the agent stopped while the job was running".into())
                } else {
                    st.error
                },
                started_at: st.started_at,
                finished_at: st.finished_at.unwrap_or_else(now_millis),
            };
            r.truncated |= cap(&mut r.stdout) | cap(&mut r.stderr);
            return r;
        }
    }
}

/// Keeps the tail of the output (where errors usually are) within the upload cap.
fn cap(s: &mut String) -> bool {
    if s.len() <= JOB_OUTPUT_CAP {
        return false;
    }
    let start = (s.len() - JOB_OUTPUT_CAP..s.len())
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(s.len());
    s.drain(..start);
    true
}
