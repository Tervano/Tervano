//! Jobs page (T-800): queue a script on the server for the devices ticked on the Devices page, and
//! follow each device's result. Agents pick jobs up on their own poll and only run them if they
//! allow server jobs from this technician, so "refused" is a normal per-device outcome.

use crate::{
    Console, Message, SHELLS, ShellChoice, ago, centered, csv_cell, downloads_dir, error_box,
};
use iced::widget::{
    Space, button, checkbox, column, container, pick_list, row, rule, scrollable, text,
    text_editor, text_input,
};
use iced::{Alignment, Element, Length, Task, Theme};
use std::collections::BTreeMap;
use tervano_protocol::*;
use uuid::Uuid;

pub struct JobsState {
    /// Devices ticked on the Devices page, with their hostnames for display.
    pub selected: BTreeMap<Uuid, String>,
    list: Option<Result<Vec<JobSummary>, String>>,
    /// The job shown on the right, with its last fetched detail.
    open: Option<(Uuid, Option<Result<JobDetail, String>>)>,
    /// The new-job form is shown instead of a job.
    form: bool,
    name: String,
    shell: Shell,
    script: text_editor::Content,
    timeout: String,
    confirm: bool,
    busy: bool,
    notice: Option<Result<String, String>>,
    expanded: Option<Uuid>,
}

impl JobsState {
    pub fn new() -> Self {
        Self {
            selected: BTreeMap::new(),
            list: None,
            open: None,
            form: false,
            name: String::new(),
            shell: Shell::Powershell,
            script: text_editor::Content::new(),
            timeout: "300".into(),
            confirm: false,
            busy: false,
            notice: None,
            expanded: None,
        }
    }

    /// The open job may still change (devices pending or running), so it is worth polling.
    pub fn live(&self) -> bool {
        matches!(&self.open, Some((_, Some(Ok(d)))) if !finished(&d.summary))
            || matches!(&self.open, Some((_, None)))
    }
}

fn finished(s: &JobSummary) -> bool {
    s.pending == 0 && s.running == 0
}

#[derive(Debug, Clone)]
pub enum JobMsg {
    Toggle(Uuid, String, bool),
    /// Tick or untick every device in the current search result.
    SelectShown(bool),
    ClearSelection,
    NewForm,
    Name(String),
    Shell(ShellChoice),
    Edit(text_editor::Action),
    Timeout(String),
    Ask,
    Confirm,
    CancelConfirm,
    Created(Result<JobSummary, String>),
    /// Reload the list and the open job.
    Refresh,
    Listed(Result<Vec<JobSummary>, String>),
    Open(Uuid),
    Loaded(Uuid, Result<JobDetail, String>),
    Expand(Uuid),
    Cancel(Uuid),
    Cancelled(Result<JobSummary, String>),
    Export,
}

impl Console {
    pub(crate) fn jobs_update(&mut self, msg: JobMsg) -> Task<Message> {
        let j = &mut self.jobs;
        match msg {
            JobMsg::Toggle(id, host, on) => {
                if on {
                    if j.selected.len() < JOB_MAX_TARGETS {
                        j.selected.insert(id, host);
                    }
                } else {
                    j.selected.remove(&id);
                }
            }
            JobMsg::SelectShown(on) => {
                if let Ok(devices) = &self.devices {
                    for d in devices {
                        if !on {
                            j.selected.remove(&d.id);
                        } else if j.selected.len() < JOB_MAX_TARGETS {
                            j.selected.insert(d.id, d.hostname.clone());
                        }
                    }
                }
            }
            JobMsg::ClearSelection => j.selected.clear(),
            JobMsg::NewForm => {
                j.form = true;
                j.confirm = false;
                j.notice = None;
                self.page = crate::Page::Jobs;
                return self.jobs_refresh();
            }
            JobMsg::Name(s) => j.name = s,
            JobMsg::Shell(s) => j.shell = s.0,
            JobMsg::Edit(a) => j.script.perform(a),
            JobMsg::Timeout(s) => j.timeout = s,
            JobMsg::Ask => {
                j.notice = None;
                match self.job_request() {
                    Ok(_) => self.jobs.confirm = true,
                    Err(e) => self.jobs.notice = Some(Err(e)),
                }
            }
            JobMsg::CancelConfirm => j.confirm = false,
            JobMsg::Confirm => {
                j.confirm = false;
                let (req, client) = match (self.job_request(), self.client()) {
                    (Ok(r), Ok(c)) => (r, c),
                    (Err(e), _) | (_, Err(e)) => {
                        self.jobs.notice = Some(Err(e));
                        return Task::none();
                    }
                };
                self.jobs.busy = true;
                return Task::perform(async move { client.create_job(&req).await }, |r| {
                    Message::Job(JobMsg::Created(r))
                });
            }
            JobMsg::Created(r) => {
                j.busy = false;
                match r {
                    Ok(s) => {
                        j.notice = Some(Ok(format!(
                            "Queued \"{}\" for {} device(s). Agents pick it up on their next poll.",
                            s.name, s.targets
                        )));
                        j.form = false;
                        j.selected.clear();
                        j.script = text_editor::Content::new();
                        j.name.clear();
                        j.open = Some((s.id, None));
                        return self.jobs_refresh();
                    }
                    Err(e) => j.notice = Some(Err(e)),
                }
            }
            JobMsg::Refresh => return self.jobs_refresh(),
            JobMsg::Listed(r) => j.list = Some(r),
            JobMsg::Open(id) => {
                j.form = false;
                j.expanded = None;
                j.open = Some((id, None));
                return self.jobs_refresh();
            }
            JobMsg::Loaded(id, r) => {
                if let Some((open, detail)) = &mut j.open
                    && *open == id
                {
                    *detail = Some(r);
                }
            }
            JobMsg::Expand(id) => {
                j.expanded = if j.expanded == Some(id) {
                    None
                } else {
                    Some(id)
                };
            }
            JobMsg::Cancel(id) => {
                let client = self.client();
                return Task::perform(async move { client?.cancel_job(id).await }, |r| {
                    Message::Job(JobMsg::Cancelled(r))
                });
            }
            JobMsg::Cancelled(r) => {
                j.notice = Some(r.map(|s| {
                    format!(
                        "Cancelled \"{}\": devices that had not picked it up will not run it; {} still running finish.",
                        s.name, s.running
                    )
                }));
                return self.jobs_refresh();
            }
            JobMsg::Export => {
                if let (Some((_, Some(Ok(d)))), Some(dir)) = (&j.open, downloads_dir()) {
                    j.notice = Some(export_job_csv(&dir, d));
                }
            }
        }
        Task::none()
    }

    fn job_request(&self) -> Result<JobCreate, String> {
        let j = &self.jobs;
        if j.selected.is_empty() {
            return Err("Tick the target devices on the Devices page first.".into());
        }
        if j.name.trim().is_empty() {
            return Err("Give the job a name.".into());
        }
        let script = j.script.text();
        if script.trim().is_empty() {
            return Err("The script is empty.".into());
        }
        let timeout: u32 = j
            .timeout
            .trim()
            .parse()
            .ok()
            .filter(|t| (1..=3600).contains(t))
            .ok_or("Timeout must be 1 to 3600 seconds.")?;
        Ok(JobCreate {
            name: j.name.trim().to_owned(),
            shell: j.shell,
            script,
            timeout_secs: Some(timeout),
            devices: j.selected.keys().copied().collect(),
        })
    }

    pub(crate) fn jobs_refresh(&self) -> Task<Message> {
        let list = self.client();
        let list = Task::perform(async move { list?.jobs().await }, |r| {
            Message::Job(JobMsg::Listed(r))
        });
        let detail = match &self.jobs.open {
            Some((id, _)) => {
                let (id, client) = (*id, self.client());
                Task::perform(async move { client?.job(id).await }, move |r| {
                    Message::Job(JobMsg::Loaded(id, r))
                })
            }
            None => Task::none(),
        };
        Task::batch([list, detail])
    }

    /// Selection bar shown above the Devices list.
    pub(crate) fn jobs_selection_bar(&self) -> Element<'_, Message> {
        let n = self.jobs.selected.len();
        let shown = self.devices.as_ref().map_or(0, Vec::len);
        let all_shown = shown > 0
            && self
                .devices
                .as_ref()
                .is_ok_and(|d| d.iter().all(|d| self.jobs.selected.contains_key(&d.id)));
        row![
            checkbox(all_shown)
                .label("Select all shown")
                .text_size(13)
                .on_toggle(|on| Message::Job(JobMsg::SelectShown(on))),
            Space::new().width(Length::Fill),
            text(format!("{n} selected")).size(13),
            button(text("Clear").size(13))
                .style(button::subtle)
                .on_press_maybe((n > 0).then_some(Message::Job(JobMsg::ClearSelection))),
            button(text(format!("New job for {n}…")).size(13))
                .style(button::primary)
                .on_press_maybe((n > 0).then_some(Message::Job(JobMsg::NewForm))),
        ]
        .spacing(8)
        .align_y(Alignment::Center)
        .into()
    }

    pub(crate) fn jobs_view(&self) -> Element<'_, Message> {
        if self.settings.token.is_empty() {
            return centered("Jobs run through Tervano Server. Connect to a server in Settings.");
        }
        let j = &self.jobs;
        let header = row![
            text("Jobs").size(20),
            Space::new().width(Length::Fill),
            button(text("Refresh"))
                .style(button::secondary)
                .on_press(Message::Job(JobMsg::Refresh)),
            button(text("New job"))
                .style(button::primary)
                .on_press(Message::Job(JobMsg::NewForm)),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        let list: Element<_> = match &j.list {
            None => centered("Loading…"),
            Some(Err(e)) => error_box(e),
            Some(Ok(l)) if l.is_empty() => centered("No jobs yet."),
            Some(Ok(l)) => {
                let open = j.open.as_ref().map(|(id, _)| *id);
                let rows = l.iter().map(|s| {
                    let progress = if s.cancelled && s.running == 0 {
                        "cancelled".to_owned()
                    } else if finished(s) {
                        "done".to_owned()
                    } else {
                        format!("{} waiting · {} running", s.pending, s.running)
                    };
                    button(
                        column![
                            text(&s.name).size(14),
                            text(format!(
                                "{} · {} · {} ok · {} failed · {progress}",
                                s.created_by,
                                ago(s.created_at),
                                s.succeeded,
                                s.failed
                            ))
                            .size(12)
                            .style(text::secondary),
                        ]
                        .spacing(2),
                    )
                    .width(Length::Fill)
                    .padding([6, 10])
                    .style(if open == Some(s.id) {
                        button::secondary
                    } else {
                        button::text
                    })
                    .on_press(Message::Job(JobMsg::Open(s.id)))
                    .into()
                });
                scrollable(column(rows.collect::<Vec<_>>()).spacing(2))
                    .height(Length::Fill)
                    .into()
            }
        };

        let mut right = column![].spacing(8);
        if let Some(n) = &j.notice {
            right = right.push(match n {
                Ok(m) => text(m.clone()).size(13).style(text::success),
                Err(e) => text(e.clone()).size(13).style(text::danger),
            });
        }
        let right = if j.form {
            right.push(self.job_form())
        } else {
            match &j.open {
                None => right.push(centered(
                    "Pick a job, or tick devices on the Devices page and choose \"New job\".",
                )),
                Some((_, None)) => right.push(centered("Loading…")),
                Some((_, Some(Err(e)))) => right.push(error_box(e)),
                Some((_, Some(Ok(d)))) => right.push(self.job_detail(d)),
            }
        };
        column![
            header,
            row![
                container(list).width(Length::FillPortion(2)),
                rule::vertical(1),
                container(right).width(Length::FillPortion(5)),
            ]
            .spacing(12)
            .height(Length::Fill),
        ]
        .spacing(12)
        .into()
    }

    fn job_form(&self) -> Element<'_, Message> {
        let j = &self.jobs;
        let n = j.selected.len();
        let names: Vec<&str> = j.selected.values().map(String::as_str).take(12).collect();
        let targets = if n == 0 {
            "No devices selected: tick them on the Devices page.".to_owned()
        } else if n > names.len() {
            format!("{} and {} more", names.join(", "), n - names.len())
        } else {
            names.join(", ")
        };
        let mut col = column![
            text(format!("New job for {n} device(s)")).size(16),
            text(targets).size(12).style(text::secondary),
            text("Runs as each agent's own account (LocalSystem for the service). A device runs it only if its agent.toml enables [server_jobs] for you; others report \"refused\".")
                .size(12)
                .style(text::secondary),
            row![
                text_input("Job name, e.g. Restart print spooler", &j.name)
                    .on_input(|s| Message::Job(JobMsg::Name(s)))
                    .padding(6),
                pick_list(SHELLS, Some(ShellChoice(j.shell)), |s| Message::Job(JobMsg::Shell(s)))
                    .text_size(13),
                text("Timeout (s)").size(13),
                text_input("300", &j.timeout)
                    .on_input(|s| Message::Job(JobMsg::Timeout(s)))
                    .padding(6)
                    .width(70),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
            text_editor(&j.script)
                .placeholder("Restart-Service Spooler")
                .on_action(|a| Message::Job(JobMsg::Edit(a)))
                .font(iced::Font::MONOSPACE)
                .height(160),
            row![
                Space::new().width(Length::Fill),
                button(text(if j.busy { "Queuing…" } else { "Queue job" }))
                    .style(button::primary)
                    .on_press_maybe((n > 0 && !j.busy && !j.confirm).then_some(Message::Job(JobMsg::Ask))),
            ],
        ]
        .spacing(8);
        if j.confirm {
            col = col.push(
                container(
                    column![
                        text(format!(
                            "Queue this {} script for {n} device(s)? Each device that allows it runs it with its agent's privileges as soon as it next checks in.",
                            ShellChoice(j.shell)
                        )),
                        row![
                            button(text(format!("Queue for {n} devices")))
                                .style(button::danger)
                                .on_press(Message::Job(JobMsg::Confirm)),
                            button(text("Cancel"))
                                .style(button::secondary)
                                .on_press(Message::Job(JobMsg::CancelConfirm)),
                        ]
                        .spacing(8),
                    ]
                    .spacing(8),
                )
                .padding(10)
                .width(Length::Fill)
                .style(container::bordered_box),
            );
        }
        col.into()
    }

    fn job_detail<'a>(&'a self, d: &'a JobDetail) -> Element<'a, Message> {
        let s = &d.summary;
        let script_preview: String = d.script.lines().take(6).collect::<Vec<_>>().join("\n");
        let more = d.script.lines().count().saturating_sub(6);
        let head = column![
            row![
                text(&s.name).size(18),
                Space::new().width(Length::Fill),
                button(text("Cancel waiting").size(13))
                    .style(button::danger)
                    .on_press_maybe(
                        (s.pending > 0 && !s.cancelled)
                            .then_some(Message::Job(JobMsg::Cancel(s.id)))
                    ),
                button(text("Export CSV").size(13))
                    .style(button::secondary)
                    .on_press(Message::Job(JobMsg::Export)),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
            text(format!(
                "by {} · {} · {} · timeout {} s · script sha256 {}…",
                s.created_by,
                ago(s.created_at),
                ShellChoice(s.shell),
                s.timeout_secs,
                &s.script_sha256[..12.min(s.script_sha256.len())]
            ))
            .size(12)
            .style(text::secondary),
            text(format!(
                "{} device(s): {} succeeded · {} failed · {} running · {} waiting{}",
                s.targets,
                s.succeeded,
                s.failed,
                s.running,
                s.pending,
                if s.cancelled { " · cancelled" } else { "" }
            ))
            .size(13),
            container(
                text(if more > 0 {
                    format!("{script_preview}\n… {more} more line(s)")
                } else {
                    script_preview
                })
                .size(12)
                .font(iced::Font::MONOSPACE)
            )
            .padding(8)
            .width(Length::Fill)
            .style(container::rounded_box),
        ]
        .spacing(6);

        let rows = d.targets.iter().map(|t| {
            let (label, style) = target_status(t);
            let first = t
                .error
                .as_deref()
                .into_iter()
                .chain(t.stdout.lines())
                .chain(t.stderr.lines())
                .find(|l| !l.trim().is_empty())
                .unwrap_or("")
                .chars()
                .take(160)
                .collect::<String>();
            let line = button(
                row![
                    text(&t.hostname).size(13).width(Length::FillPortion(2)),
                    text(label)
                        .size(13)
                        .style(style)
                        .width(Length::FillPortion(1)),
                    text(first)
                        .size(12)
                        .font(iced::Font::MONOSPACE)
                        .width(Length::FillPortion(4)),
                ]
                .spacing(6),
            )
            .padding([4, 6])
            .width(Length::Fill)
            .style(button::text)
            .on_press(Message::Job(JobMsg::Expand(t.device_id)));
            if self.jobs.expanded != Some(t.device_id) {
                return line.into();
            }
            let mut full = String::new();
            if let Some(e) = &t.error {
                full.push_str(&format!("error: {e}\n"));
            }
            if !t.stdout.is_empty() {
                full.push_str(&format!("--- stdout ---\n{}\n", t.stdout.trim_end()));
            }
            if !t.stderr.is_empty() {
                full.push_str(&format!("--- stderr ---\n{}\n", t.stderr.trim_end()));
            }
            if t.truncated {
                full.push_str("(output was cut; the newest part is kept)\n");
            }
            if full.is_empty() {
                full.push_str("No output.");
            }
            column![
                line,
                container(text(full).size(12).font(iced::Font::MONOSPACE))
                    .padding(8)
                    .width(Length::Fill)
                    .style(container::rounded_box),
            ]
            .spacing(2)
            .into()
        });
        column![
            head,
            scrollable(column(rows.collect::<Vec<Element<_>>>()).spacing(2)).height(Length::Fill)
        ]
        .spacing(8)
        .into()
    }
}

fn target_status(t: &JobTarget) -> (String, fn(&Theme) -> text::Style) {
    match (t.state, t.exit_code) {
        (JobTargetState::Pending, _) => ("waiting".into(), text::secondary),
        (JobTargetState::Running, _) => ("running…".into(), text::secondary),
        (JobTargetState::Exited, Some(0)) => ("exit 0".into(), text::success),
        (JobTargetState::Exited, Some(c)) => (format!("exit {c}"), text::danger),
        (JobTargetState::TimedOut, _) => ("timed out".into(), text::danger),
        (JobTargetState::Cancelled, _) => ("cancelled".into(), text::secondary),
        (JobTargetState::Failed, _)
            if t.error.as_deref().is_some_and(|e| e.starts_with("refused")) =>
        {
            ("refused".into(), text::danger)
        }
        _ => ("failed".into(), text::danger),
    }
}

/// One row per device with full output, into `dir`.
fn export_job_csv(dir: &std::path::Path, d: &JobDetail) -> Result<String, String> {
    let mut csv = String::from("device,device_id,state,exit_code,stdout,stderr,error\r\n");
    for t in &d.targets {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{}\r\n",
            csv_cell(&t.hostname),
            t.device_id,
            target_status(t).0,
            t.exit_code.map(|c| c.to_string()).unwrap_or_default(),
            csv_cell(&t.stdout),
            csv_cell(&t.stderr),
            csv_cell(t.error.as_deref().unwrap_or("")),
        ));
    }
    let path = dir.join(format!("tervano-job-{}.csv", d.summary.id));
    std::fs::write(&path, csv).map_err(|e| format!("Export failed: {e}"))?;
    Ok(format!(
        "Exported {} results to {}",
        d.targets.len(),
        path.display()
    ))
}
