//! Compliance tab of the Reports page (T-805): define checks, see which devices pass or fail, and
//! turn a check's remediation script into a job for the failing devices. The job goes through the
//! normal Jobs form and confirmation, so nothing runs from this tab directly.

use crate::reports::{Loaded, table};
use crate::{
    Console, Message, SHELLS, ShellChoice, centered, csv_cell, downloads_dir, error_box, scroll,
};
use iced::widget::{
    Space, button, checkbox, column, container, pick_list, row, rule, text, text_editor, text_input,
};
use iced::{Alignment, Element, Length, Task};
use std::collections::BTreeMap;
use tervano_protocol::*;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RuleKind {
    SoftwarePresent,
    SoftwareAbsent,
    NoRebootPending,
    SecureBootOn,
    TpmPresent,
    DiskFree,
    OsBuild,
    InventoryAge,
}

const RULE_KINDS: [RuleKind; 8] = [
    RuleKind::SoftwarePresent,
    RuleKind::SoftwareAbsent,
    RuleKind::NoRebootPending,
    RuleKind::SecureBootOn,
    RuleKind::TpmPresent,
    RuleKind::DiskFree,
    RuleKind::OsBuild,
    RuleKind::InventoryAge,
];

impl std::fmt::Display for RuleKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RuleKind::SoftwarePresent => "Software installed",
            RuleKind::SoftwareAbsent => "Software not installed",
            RuleKind::NoRebootPending => "No reboot pending",
            RuleKind::SecureBootOn => "Secure Boot on",
            RuleKind::TpmPresent => "TPM present",
            RuleKind::DiskFree => "C: free space at least (GiB)",
            RuleKind::OsBuild => "OS build at least",
            RuleKind::InventoryAge => "Inventory newer than (days)",
        })
    }
}

impl RuleKind {
    /// Placeholder for the value field; `None` when the rule takes no value.
    fn value_hint(self) -> Option<&'static str> {
        match self {
            RuleKind::SoftwarePresent | RuleKind::SoftwareAbsent => {
                Some("Name contains, e.g. 7-Zip")
            }
            RuleKind::DiskFree => Some("20"),
            RuleKind::OsBuild => Some("26100"),
            RuleKind::InventoryAge => Some("3"),
            _ => None,
        }
    }
}

pub fn describe_rule(r: &ComplianceRule) -> String {
    match r {
        ComplianceRule::SoftwarePresent {
            name,
            min_version: None,
        } => format!("{name:?} installed"),
        ComplianceRule::SoftwarePresent {
            name,
            min_version: Some(v),
        } => format!("{name:?} installed, version ≥ {v}"),
        ComplianceRule::SoftwareAbsent { name } => format!("{name:?} not installed"),
        ComplianceRule::NoRebootPending => "no reboot pending".into(),
        ComplianceRule::SecureBootOn => "Secure Boot on".into(),
        ComplianceRule::TpmPresent => "TPM present".into(),
        ComplianceRule::DiskFreeAtLeast { gib } => format!("C: has ≥ {gib} GiB free"),
        ComplianceRule::OsBuildAtLeast { build } => format!("OS build ≥ {build}"),
        ComplianceRule::InventoryNewerThan { days } => {
            format!("inventory newer than {days} day(s)")
        }
    }
}

pub struct ComplianceState {
    checks: Option<Result<Vec<ComplianceCheck>, String>>,
    open: Option<(Uuid, Loaded<ComplianceResult>)>,
    form: bool,
    name: String,
    kind: RuleKind,
    value: String,
    min_version: String,
    with_fix: bool,
    fix_shell: Shell,
    fix_script: text_editor::Content,
    confirm_delete: bool,
    notice: Option<Result<String, String>>,
}

impl ComplianceState {
    pub fn new() -> Self {
        Self {
            checks: None,
            open: None,
            form: false,
            name: String::new(),
            kind: RuleKind::SoftwarePresent,
            value: String::new(),
            min_version: String::new(),
            with_fix: false,
            fix_shell: Shell::Powershell,
            fix_script: text_editor::Content::new(),
            confirm_delete: false,
            notice: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ComplianceMsg {
    Listed(Result<Vec<ComplianceCheck>, String>),
    Open(Uuid),
    Results(Uuid, Result<Vec<ComplianceResult>, String>),
    NewForm,
    CloseForm,
    Name(String),
    Kind(RuleKind),
    Value(String),
    MinVersion(String),
    WithFix(bool),
    FixShell(ShellChoice),
    FixEdit(text_editor::Action),
    Save,
    Saved(Result<ComplianceCheck, String>),
    AskDelete,
    CancelDelete,
    ConfirmDelete,
    Deleted(Result<(), String>),
    Remediate,
}

impl Console {
    pub(crate) fn compliance_load(&mut self) -> Task<Message> {
        let c = &mut self.compliance;
        c.checks = None;
        let list = self.client();
        let list = Task::perform(async move { list?.compliance_checks().await }, |r| {
            Message::Compliance(ComplianceMsg::Listed(r))
        });
        match self.compliance.open.as_ref().map(|(id, _)| *id) {
            Some(id) => Task::batch([list, self.compliance_results(id)]),
            None => list,
        }
    }

    fn compliance_results(&self, id: Uuid) -> Task<Message> {
        let client = self.client();
        Task::perform(
            async move { client?.compliance_results(id).await },
            move |r| Message::Compliance(ComplianceMsg::Results(id, r)),
        )
    }

    fn compliance_rule(&self) -> Result<ComplianceRule, String> {
        let c = &self.compliance;
        let v = c.value.trim();
        let number = |what: &str| -> Result<u32, String> {
            v.parse()
                .map_err(|_| format!("{what} must be a whole number."))
        };
        let text_value = |what: &str| -> Result<String, String> {
            if v.is_empty() {
                Err(format!("Enter {what}."))
            } else {
                Ok(v.to_owned())
            }
        };
        Ok(match c.kind {
            RuleKind::SoftwarePresent => ComplianceRule::SoftwarePresent {
                name: text_value("part of the software name")?,
                min_version: Some(c.min_version.trim().to_owned()).filter(|m| !m.is_empty()),
            },
            RuleKind::SoftwareAbsent => ComplianceRule::SoftwareAbsent {
                name: text_value("part of the software name")?,
            },
            RuleKind::NoRebootPending => ComplianceRule::NoRebootPending,
            RuleKind::SecureBootOn => ComplianceRule::SecureBootOn,
            RuleKind::TpmPresent => ComplianceRule::TpmPresent,
            RuleKind::DiskFree => ComplianceRule::DiskFreeAtLeast {
                gib: number("Free space")?,
            },
            RuleKind::OsBuild => ComplianceRule::OsBuildAtLeast {
                build: text_value("a build number")?,
            },
            RuleKind::InventoryAge => ComplianceRule::InventoryNewerThan {
                days: number("Days")?,
            },
        })
    }

    pub(crate) fn compliance_update(&mut self, msg: ComplianceMsg) -> Task<Message> {
        let c = &mut self.compliance;
        match msg {
            ComplianceMsg::Listed(r) => c.checks = Some(r),
            ComplianceMsg::Open(id) => {
                c.form = false;
                c.confirm_delete = false;
                c.open = Some((id, None));
                return self.compliance_results(id);
            }
            ComplianceMsg::Results(id, r) => {
                if let Some((open, results)) = &mut c.open
                    && *open == id
                {
                    *results = Some(r);
                }
            }
            ComplianceMsg::NewForm => {
                c.form = true;
                c.notice = None;
            }
            ComplianceMsg::CloseForm => c.form = false,
            ComplianceMsg::Name(s) => c.name = s,
            ComplianceMsg::Kind(k) => c.kind = k,
            ComplianceMsg::Value(s) => c.value = s,
            ComplianceMsg::MinVersion(s) => c.min_version = s,
            ComplianceMsg::WithFix(b) => c.with_fix = b,
            ComplianceMsg::FixShell(s) => c.fix_shell = s.0,
            ComplianceMsg::FixEdit(a) => c.fix_script.perform(a),
            ComplianceMsg::Save => {
                let rule = match self.compliance_rule() {
                    Ok(r) => r,
                    Err(e) => {
                        self.compliance.notice = Some(Err(e));
                        return Task::none();
                    }
                };
                let c = &self.compliance;
                if c.name.trim().is_empty() {
                    self.compliance.notice = Some(Err("Give the check a name.".into()));
                    return Task::none();
                }
                let remediation = c.with_fix.then(|| Remediation {
                    shell: c.fix_shell,
                    script: c.fix_script.text(),
                });
                let req = ComplianceCheckCreate {
                    name: c.name.trim().to_owned(),
                    rule,
                    remediation,
                };
                let client = self.client();
                return Task::perform(async move { client?.create_compliance(&req).await }, |r| {
                    Message::Compliance(ComplianceMsg::Saved(r))
                });
            }
            ComplianceMsg::Saved(r) => match r {
                Ok(check) => {
                    c.notice = Some(Ok(format!(
                        "Saved \"{}\": {} passing, {} failing.",
                        check.name, check.passing, check.failing
                    )));
                    c.form = false;
                    c.name.clear();
                    c.value.clear();
                    c.min_version.clear();
                    c.with_fix = false;
                    c.fix_script = text_editor::Content::new();
                    c.open = Some((check.id, None));
                    return self.compliance_load();
                }
                Err(e) => c.notice = Some(Err(e)),
            },
            ComplianceMsg::AskDelete => c.confirm_delete = true,
            ComplianceMsg::CancelDelete => c.confirm_delete = false,
            ComplianceMsg::ConfirmDelete => {
                c.confirm_delete = false;
                let Some((id, _)) = c.open else {
                    return Task::none();
                };
                let client = self.client();
                return Task::perform(async move { client?.delete_compliance(id).await }, |r| {
                    Message::Compliance(ComplianceMsg::Deleted(r))
                });
            }
            ComplianceMsg::Deleted(r) => {
                match r {
                    Ok(()) => {
                        c.notice = Some(Ok("Check deleted.".into()));
                        c.open = None;
                    }
                    Err(e) => c.notice = Some(Err(e)),
                }
                return self.compliance_load();
            }
            ComplianceMsg::Remediate => {
                let (Some(check), Some((_, Some(Ok(results))))) =
                    (self.open_check(), &self.compliance.open)
                else {
                    return Task::none();
                };
                let Some(fix) = check.remediation.clone() else {
                    return Task::none();
                };
                let failing: BTreeMap<Uuid, String> = results
                    .iter()
                    .filter(|r| r.status == ComplianceStatus::Fail)
                    .map(|r| (r.device_id, r.hostname.clone()))
                    .collect();
                let name = format!("Remediate: {}", check.name);
                if failing.is_empty() {
                    self.compliance.notice = Some(Err("No failing devices to remediate.".into()));
                    return Task::none();
                }
                return self.jobs_prefill(name, fix.shell, &fix.script, failing);
            }
        }
        Task::none()
    }

    fn open_check(&self) -> Option<&ComplianceCheck> {
        let (id, _) = self.compliance.open.as_ref()?;
        self.compliance
            .checks
            .as_ref()?
            .as_ref()
            .ok()?
            .iter()
            .find(|c| c.id == *id)
    }

    /// Exports the open check's results.
    pub(crate) fn compliance_export(&self, csv: bool) -> Result<String, String> {
        let (Some(check), Some((_, Some(Ok(results))))) =
            (self.open_check(), &self.compliance.open)
        else {
            return Err("Open a check to export its results.".into());
        };
        let dir = downloads_dir().ok_or("No Downloads folder to export to.")?;
        let stamp = now_millis();
        let (path, body) = if csv {
            let mut body = String::from("check,device,device_id,status,detail\r\n");
            for r in results {
                body.push_str(&format!(
                    "{},{},{},{:?},{}\r\n",
                    csv_cell(&check.name),
                    csv_cell(&r.hostname),
                    r.device_id,
                    r.status,
                    csv_cell(&r.detail)
                ));
            }
            (dir.join(format!("tervano-compliance-{stamp}.csv")), body)
        } else {
            let body = serde_json::json!({ "check": check, "results": results });
            (
                dir.join(format!("tervano-compliance-{stamp}.json")),
                serde_json::to_string_pretty(&body).map_err(|e| e.to_string())?,
            )
        };
        std::fs::write(&path, body).map_err(|e| format!("Export failed: {e}"))?;
        Ok(format!(
            "Exported {} results to {}",
            results.len(),
            path.display()
        ))
    }

    pub(crate) fn compliance_view(&self) -> Element<'_, Message> {
        let c = &self.compliance;
        let can_edit = self.can_edit_groups();
        let list: Element<_> = match &c.checks {
            None => centered("Loading…"),
            Some(Err(e)) => error_box(e),
            Some(Ok(l)) if l.is_empty() => centered("No compliance checks yet."),
            Some(Ok(l)) => {
                let open = c.open.as_ref().map(|(id, _)| *id);
                scroll(
                    column(l.iter().map(|k| {
                        button(
                            column![
                                text(&k.name).size(14),
                                text(describe_rule(&k.rule)).size(12).style(text::secondary),
                                row![
                                    text(format!("{} pass", k.passing))
                                        .size(12)
                                        .style(text::success),
                                    text(format!("{} fail", k.failing)).size(12).style(
                                        if k.failing > 0 {
                                            text::danger
                                        } else {
                                            text::secondary
                                        }
                                    ),
                                    text(format!("{} unknown", k.unknown))
                                        .size(12)
                                        .style(text::secondary),
                                ]
                                .spacing(8),
                            ]
                            .spacing(2),
                        )
                        .width(Length::Fill)
                        .padding([6, 10])
                        .style(if open == Some(k.id) {
                            crate::selected_row
                        } else {
                            button::text
                        })
                        .on_press(Message::Compliance(ComplianceMsg::Open(k.id)))
                        .into()
                    }))
                    .spacing(2),
                )
                .height(Length::Fill)
                .into()
            }
        };
        let mut left = column![
            row![
                text("Checks").size(15),
                Space::new().width(Length::Fill),
                button(text("New check").size(13))
                    .style(button::primary)
                    .on_press_maybe(
                        can_edit.then_some(Message::Compliance(ComplianceMsg::NewForm))
                    ),
            ]
            .align_y(Alignment::Center),
        ]
        .spacing(6);
        if let Some(n) = &c.notice {
            left = left.push(match n {
                Ok(m) => text(m.clone()).size(12).style(text::success),
                Err(e) => text(e.clone()).size(12).style(text::danger),
            });
        }
        left = left.push(list);
        let right: Element<_> = if c.form {
            self.compliance_form()
        } else {
            match (&c.open, self.open_check()) {
                (Some((_, results)), Some(check)) => {
                    self.compliance_detail(check, results.as_ref())
                }
                (Some(_), None) => centered("Loading…"),
                _ => centered("Pick a check to see which devices pass or fail."),
            }
        };
        row![
            container(left).width(Length::FillPortion(2)),
            rule::vertical(1),
            container(right).width(Length::FillPortion(3)),
        ]
        .spacing(10)
        .height(Length::Fill)
        .into()
    }

    fn compliance_detail<'a>(
        &'a self,
        check: &'a ComplianceCheck,
        results: Option<&'a Result<Vec<ComplianceResult>, String>>,
    ) -> Element<'a, Message> {
        let c = &self.compliance;
        let failing = check.failing;
        let mut actions = row![text(&check.name).size(17), Space::new().width(Length::Fill),]
            .spacing(8)
            .align_y(Alignment::Center);
        if check.remediation.is_some() {
            actions = actions.push(
                button(text(format!("Remediate {failing} failing…")).size(13))
                    .style(button::primary)
                    .on_press_maybe(
                        (failing > 0 && self.can(TechRole::Operator))
                            .then_some(Message::Compliance(ComplianceMsg::Remediate)),
                    ),
            );
        }
        if self.can_edit_groups() {
            actions = actions.push(
                button(text("Delete check").size(13))
                    .style(button::danger)
                    .on_press(Message::Compliance(ComplianceMsg::AskDelete)),
            );
        }
        let mut col = column![
            actions,
            text(format!(
                "{} · by {} · {} pass, {} fail, {} unknown",
                describe_rule(&check.rule),
                check.created_by,
                check.passing,
                check.failing,
                check.unknown
            ))
            .size(12)
            .style(text::secondary),
        ]
        .spacing(6);
        if let Some(fix) = &check.remediation {
            col = col.push(
                container(
                    text(format!(
                        "Remediation ({}): {}",
                        ShellChoice(fix.shell),
                        fix.script.lines().next().unwrap_or("")
                    ))
                    .size(12)
                    .font(iced::Font::MONOSPACE),
                )
                .padding(6)
                .width(Length::Fill)
                .style(container::rounded_box),
            );
        }
        if c.confirm_delete {
            col = col.push(
                container(
                    row![
                        text(format!("Delete check \"{}\"?", check.name)).size(13),
                        Space::new().width(Length::Fill),
                        button(text("Delete").size(13))
                            .style(button::danger)
                            .on_press(Message::Compliance(ComplianceMsg::ConfirmDelete)),
                        button(text("Cancel").size(13))
                            .style(button::secondary)
                            .on_press(Message::Compliance(ComplianceMsg::CancelDelete)),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                )
                .padding(8)
                .width(Length::Fill)
                .style(container::bordered_box),
            );
        }
        let body: Element<_> = match results {
            None => centered("Evaluating…"),
            Some(Err(e)) => error_box(e),
            Some(Ok(rows)) => table(
                &["Status", "Computer", "Found"],
                &[1, 2, 4],
                rows.iter().map(|r| {
                    vec![
                        match r.status {
                            ComplianceStatus::Pass => "pass",
                            ComplianceStatus::Fail => "FAIL",
                            ComplianceStatus::Unknown => "unknown",
                        }
                        .into(),
                        r.hostname.clone(),
                        r.detail.clone(),
                    ]
                }),
                Some(|i: usize| {
                    Message::Report(crate::reports::ReportMsg::OpenDevice(rows[i].device_id))
                }),
            ),
        };
        col.push(body).into()
    }

    fn compliance_form(&self) -> Element<'_, Message> {
        let c = &self.compliance;
        let mut col = column![
            row![
                text("New compliance check").size(16),
                Space::new().width(Length::Fill),
                button(text("Cancel").size(13))
                    .style(button::secondary)
                    .on_press(Message::Compliance(ComplianceMsg::CloseForm)),
            ]
            .align_y(Alignment::Center),
            text_input("Name, e.g. 7-Zip up to date", &c.name)
                .on_input(|s| Message::Compliance(ComplianceMsg::Name(s)))
                .padding(6),
            pick_list(RULE_KINDS, Some(c.kind), |k| {
                Message::Compliance(ComplianceMsg::Kind(k))
            })
            .text_size(13),
        ]
        .spacing(8);
        if let Some(hint) = c.kind.value_hint() {
            let mut line = row![
                text_input(hint, &c.value)
                    .on_input(|s| Message::Compliance(ComplianceMsg::Value(s)))
                    .padding(6)
            ]
            .spacing(8);
            if c.kind == RuleKind::SoftwarePresent {
                line = line.push(
                    text_input("Minimum version (optional)", &c.min_version)
                        .on_input(|s| Message::Compliance(ComplianceMsg::MinVersion(s)))
                        .padding(6)
                        .width(200),
                );
            }
            col = col.push(line);
        }
        col = col.push(
            checkbox(c.with_fix)
                .label(
                    "Remediation script (queued as a job for failing devices, after confirmation)",
                )
                .text_size(13)
                .on_toggle(|b| Message::Compliance(ComplianceMsg::WithFix(b))),
        );
        if c.with_fix {
            col = col
                .push(
                    pick_list(SHELLS, Some(ShellChoice(c.fix_shell)), |s| {
                        Message::Compliance(ComplianceMsg::FixShell(s))
                    })
                    .text_size(13),
                )
                .push(
                    text_editor(&c.fix_script)
                        .placeholder("winget upgrade --id 7zip.7zip --silent")
                        .on_action(|a| Message::Compliance(ComplianceMsg::FixEdit(a)))
                        .font(iced::Font::MONOSPACE)
                        .height(120),
                );
        }
        col.push(row![
            Space::new().width(Length::Fill),
            button(text("Save check"))
                .style(button::primary)
                .on_press(Message::Compliance(ComplianceMsg::Save)),
        ])
        .into()
    }
}
