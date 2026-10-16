//! Reports page (T-804): fleet software, OS and hardware from the server's stored state and
//! inventory, with drill-down from a software entry to its devices and CSV/JSON export.

use crate::{
    Console, Message, Page, ago, centered, csv_cell, downloads_dir, error_box, human_size,
};
use iced::widget::{Space, button, column, container, row, rule, scrollable, text, text_input};
use iced::{Alignment, Element, Length, Task};
use tervano_protocol::*;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReportTab {
    Software,
    Os,
    Hardware,
    Compliance,
}

/// (name, version) of a software entry.
type SoftwareKey = (String, Option<String>);
/// Not loaded yet, failed, or rows.
pub(crate) type Loaded<T> = Option<Result<Vec<T>, String>>;

pub struct ReportsState {
    tab: ReportTab,
    filter: String,
    software: Option<Result<Vec<SoftwareReportRow>, String>>,
    /// Software entry (name, version) whose devices are listed, with the result.
    picked: Option<(SoftwareKey, Loaded<ReportDevice>)>,
    os: Option<Result<Vec<OsReportRow>, String>>,
    hardware: Option<Result<Vec<HardwareReportRow>, String>>,
    notice: Option<Result<String, String>>,
}

impl ReportsState {
    pub fn new() -> Self {
        Self {
            tab: ReportTab::Software,
            filter: String::new(),
            software: None,
            picked: None,
            os: None,
            hardware: None,
            notice: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ReportMsg {
    Tab(ReportTab),
    Filter(String),
    Load,
    Software(Result<Vec<SoftwareReportRow>, String>),
    Pick(String, Option<String>),
    PickedDevices(String, Option<String>, Result<Vec<ReportDevice>, String>),
    Os(Result<Vec<OsReportRow>, String>),
    Hardware(Result<Vec<HardwareReportRow>, String>),
    OpenDevice(Uuid),
    ExportCsv,
    ExportJson,
}

impl Console {
    /// Loads the current tab's report.
    pub(crate) fn reports_load(&mut self) -> Task<Message> {
        let client = self.client();
        let r = &mut self.reports;
        r.notice = None;
        match r.tab {
            ReportTab::Software => {
                r.software = None;
                r.picked = None;
                let q = r.filter.trim().to_owned();
                Task::perform(async move { client?.software_report(&q).await }, |x| {
                    Message::Report(ReportMsg::Software(x))
                })
            }
            ReportTab::Os => {
                r.os = None;
                Task::perform(async move { client?.os_report().await }, |x| {
                    Message::Report(ReportMsg::Os(x))
                })
            }
            ReportTab::Hardware => {
                r.hardware = None;
                Task::perform(async move { client?.hardware_report().await }, |x| {
                    Message::Report(ReportMsg::Hardware(x))
                })
            }
            ReportTab::Compliance => self.compliance_load(),
        }
    }

    pub(crate) fn reports_update(&mut self, msg: ReportMsg) -> Task<Message> {
        let r = &mut self.reports;
        match msg {
            ReportMsg::Tab(t) => {
                r.tab = t;
                return self.reports_load();
            }
            ReportMsg::Filter(s) => r.filter = s,
            ReportMsg::Load => return self.reports_load(),
            ReportMsg::Software(x) => r.software = Some(x),
            ReportMsg::Pick(name, version) => {
                r.picked = Some(((name.clone(), version.clone()), None));
                let client = self.client();
                return Task::perform(
                    {
                        let (name, version) = (name.clone(), version.clone());
                        async move { client?.software_devices(&name, version.as_deref()).await }
                    },
                    move |x| {
                        Message::Report(ReportMsg::PickedDevices(name.clone(), version.clone(), x))
                    },
                );
            }
            ReportMsg::PickedDevices(name, version, x) => {
                if let Some((key, devices)) = &mut r.picked
                    && *key == (name, version)
                {
                    *devices = Some(x);
                }
            }
            ReportMsg::Os(x) => r.os = Some(x),
            ReportMsg::Hardware(x) => r.hardware = Some(x),
            ReportMsg::OpenDevice(id) => {
                self.page = Page::Devices;
                return self.update(Message::Select(id));
            }
            ReportMsg::ExportCsv | ReportMsg::ExportJson => {
                let csv = matches!(msg, ReportMsg::ExportCsv);
                let notice = if r.tab == ReportTab::Compliance {
                    self.compliance_export(csv)
                } else {
                    match downloads_dir() {
                        None => Err("No Downloads folder to export to.".into()),
                        Some(dir) => export(&dir, r, csv),
                    }
                };
                self.reports.notice = Some(notice);
            }
        }
        Task::none()
    }

    pub(crate) fn reports_view(&self) -> Element<'_, Message> {
        if self.settings.token.is_empty() {
            return centered("Reports come from Tervano Server. Connect to a server in Settings.");
        }
        let r = &self.reports;
        let tab = |label: &'static str, t: ReportTab| {
            button(text(label).size(13))
                .style(if r.tab == t {
                    button::primary
                } else {
                    button::secondary
                })
                .on_press(Message::Report(ReportMsg::Tab(t)))
        };
        let mut top = row![
            tab("Software", ReportTab::Software),
            tab("Operating systems", ReportTab::Os),
            tab("Hardware", ReportTab::Hardware),
            tab("Compliance", ReportTab::Compliance),
            Space::new().width(Length::Fill),
        ]
        .spacing(6)
        .align_y(Alignment::Center);
        if r.tab == ReportTab::Software {
            top = top.push(
                text_input("Filter by name or publisher", &r.filter)
                    .on_input(|s| Message::Report(ReportMsg::Filter(s)))
                    .on_submit(Message::Report(ReportMsg::Load))
                    .size(13)
                    .padding(6)
                    .width(240),
            );
        }
        top = top
            .push(
                button(text("Refresh").size(13))
                    .style(button::secondary)
                    .on_press(Message::Report(ReportMsg::Load)),
            )
            .push(
                button(text("Export CSV").size(13))
                    .style(button::secondary)
                    .on_press(Message::Report(ReportMsg::ExportCsv)),
            )
            .push(
                button(text("Export JSON").size(13))
                    .style(button::secondary)
                    .on_press(Message::Report(ReportMsg::ExportJson)),
            );
        let mut col = column![
            top,
            text("Built from each device's latest inventory (sent at agent start and daily) and current state. Only devices in your scope are counted.")
                .size(12)
                .style(text::secondary),
        ]
        .spacing(8);
        match &r.notice {
            Some(Ok(m)) => col = col.push(text(m.clone()).size(12).style(text::success)),
            Some(Err(e)) => col = col.push(text(e.clone()).size(12).style(text::danger)),
            None => {}
        }
        let body: Element<_> = match r.tab {
            ReportTab::Software => self.software_view(),
            ReportTab::Compliance => self.compliance_view(),
            ReportTab::Os => match &r.os {
                None => centered("Loading…"),
                Some(Err(e)) => error_box(e),
                Some(Ok(rows)) => table(
                    &["Operating system", "Version", "Build", "Devices", "Online"],
                    &[3, 1, 2, 1, 1],
                    rows.iter().map(|o| {
                        vec![
                            o.name.clone(),
                            o.version.clone(),
                            o.build.clone(),
                            o.devices.to_string(),
                            o.online.to_string(),
                        ]
                    }),
                    None::<fn(usize) -> Message>,
                ),
            },
            ReportTab::Hardware => match &r.hardware {
                None => centered("Loading…"),
                Some(Err(e)) => error_box(e),
                Some(Ok(rows)) => table(
                    &[
                        "Computer",
                        "Model",
                        "CPU",
                        "Memory",
                        "C: free",
                        "TPM",
                        "Secure Boot",
                        "Reboot",
                        "Inventory",
                    ],
                    &[2, 2, 3, 1, 2, 1, 1, 1, 1],
                    rows.iter().map(hardware_cells),
                    Some(|i: usize| {
                        let id = rows[i].device_id;
                        Message::Report(ReportMsg::OpenDevice(id))
                    }),
                ),
            },
        };
        col.push(body).into()
    }

    fn software_view(&self) -> Element<'_, Message> {
        let r = &self.reports;
        let rows = match &r.software {
            None => return centered("Loading…"),
            Some(Err(e)) => return error_box(e),
            Some(Ok(rows)) if rows.is_empty() => {
                return centered("No software matches (or no inventory received yet).");
            }
            Some(Ok(rows)) => rows,
        };
        let list = table(
            &["Name", "Version", "Publisher", "Devices"],
            &[4, 2, 3, 1],
            rows.iter().map(|s| {
                vec![
                    s.name.clone(),
                    s.version.clone().unwrap_or_default(),
                    s.publisher.clone().unwrap_or_default(),
                    s.devices.to_string(),
                ]
            }),
            Some(|i: usize| {
                let s = &rows[i];
                Message::Report(ReportMsg::Pick(s.name.clone(), s.version.clone()))
            }),
        );
        let Some(((name, version), devices)) = &r.picked else {
            return list;
        };
        let detail: Element<_> = match devices {
            None => centered("Loading…"),
            Some(Err(e)) => error_box(e),
            Some(Ok(devs)) => scrollable(
                column(devs.iter().map(|d| {
                    button(
                        row![
                            crate::status_dot(d.online),
                            text(&d.hostname).size(13).width(Length::Fill),
                            text(ago(d.last_seen)).size(12).style(text::secondary),
                        ]
                        .spacing(6)
                        .align_y(Alignment::Center),
                    )
                    .width(Length::Fill)
                    .padding([4, 6])
                    .style(button::text)
                    .on_press(Message::Report(ReportMsg::OpenDevice(d.id)))
                    .into()
                }))
                .spacing(2),
            )
            .height(Length::Fill)
            .into(),
        };
        row![
            container(list).width(Length::FillPortion(3)),
            rule::vertical(1),
            container(
                column![
                    text(name).size(15),
                    text(version.clone().unwrap_or_else(|| "(no version)".into()))
                        .size(12)
                        .style(text::secondary),
                    detail,
                ]
                .spacing(6)
            )
            .width(Length::FillPortion(1)),
        ]
        .spacing(10)
        .into()
    }
}

fn hardware_cells(h: &HardwareReportRow) -> Vec<String> {
    let yes_no = |b: Option<bool>| match b {
        Some(true) => "on",
        Some(false) => "off",
        None => "—",
    };
    vec![
        h.hostname.clone(),
        [h.manufacturer.as_deref(), h.model.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" "),
        format!("{} ({} threads)", h.cpu_model.trim(), h.cpu_logical_cores),
        human_size(h.memory_total_bytes),
        match (h.system_disk_free_bytes, h.system_disk_total_bytes) {
            (Some(f), Some(t)) => format!("{} of {}", human_size(f), human_size(t)),
            _ => "—".into(),
        },
        h.tpm_version.clone().unwrap_or_else(|| "none".into()),
        yes_no(h.secure_boot).into(),
        if h.reboot_pending { "pending" } else { "" }.into(),
        ago(h.collected_at),
    ]
}

/// A simple text table; rows are clickable when `on_row` is given.
pub(crate) fn table<'a>(
    headers: &[&'static str],
    widths: &[u16],
    rows: impl Iterator<Item = Vec<String>>,
    on_row: Option<impl Fn(usize) -> Message>,
) -> Element<'a, Message> {
    let cells = |values: Vec<Element<'a, Message>>| {
        row(values
            .into_iter()
            .zip(widths)
            .map(|(v, w)| container(v).width(Length::FillPortion(*w)).into()))
        .spacing(8)
    };
    let header = cells(
        headers
            .iter()
            .map(|h| text(*h).size(12).style(text::secondary).into())
            .collect(),
    );
    // shortcut: renders every row (server caps rows at 5000); virtualized lists are T-307.
    let body: Vec<Element<_>> = rows
        .enumerate()
        .map(|(i, values)| {
            let line = cells(
                values
                    .into_iter()
                    .map(|v| text(v).size(13).into())
                    .collect(),
            );
            match &on_row {
                Some(f) => button(line)
                    .width(Length::Fill)
                    .padding([3, 6])
                    .style(button::text)
                    .on_press(f(i))
                    .into(),
                None => container(line).padding([3, 6]).into(),
            }
        })
        .collect();
    column![
        container(header.padding([4, 6])).style(container::rounded_box),
        scrollable(column(body).spacing(1)).height(Length::Fill),
    ]
    .spacing(4)
    .into()
}

/// Writes the current tab's report to `dir` as CSV or JSON.
fn export(dir: &std::path::Path, r: &ReportsState, csv: bool) -> Result<String, String> {
    let (name, json, table): (&str, String, Vec<Vec<String>>) = match r.tab {
        ReportTab::Compliance => unreachable!("exported by the compliance tab"),
        ReportTab::Software => {
            let rows = loaded(&r.software)?;
            (
                "software",
                serde_json::to_string_pretty(rows).map_err(|e| e.to_string())?,
                std::iter::once(vec![
                    "name".into(),
                    "version".into(),
                    "publisher".into(),
                    "devices".into(),
                ])
                .chain(rows.iter().map(|s| {
                    vec![
                        s.name.clone(),
                        s.version.clone().unwrap_or_default(),
                        s.publisher.clone().unwrap_or_default(),
                        s.devices.to_string(),
                    ]
                }))
                .collect(),
            )
        }
        ReportTab::Os => {
            let rows = loaded(&r.os)?;
            (
                "os",
                serde_json::to_string_pretty(rows).map_err(|e| e.to_string())?,
                std::iter::once(
                    ["name", "version", "build", "devices", "online"]
                        .map(String::from)
                        .to_vec(),
                )
                .chain(rows.iter().map(|o| {
                    vec![
                        o.name.clone(),
                        o.version.clone(),
                        o.build.clone(),
                        o.devices.to_string(),
                        o.online.to_string(),
                    ]
                }))
                .collect(),
            )
        }
        ReportTab::Hardware => {
            let rows = loaded(&r.hardware)?;
            let opt = |v: Option<u64>| v.map(|b| b.to_string()).unwrap_or_default();
            (
                "hardware",
                serde_json::to_string_pretty(rows).map_err(|e| e.to_string())?,
                std::iter::once(
                    [
                        "hostname",
                        "device_id",
                        "manufacturer",
                        "model",
                        "serial_number",
                        "cpu_model",
                        "cpu_logical_cores",
                        "memory_total_bytes",
                        "system_disk_total_bytes",
                        "system_disk_free_bytes",
                        "tpm_version",
                        "secure_boot",
                        "reboot_pending",
                        "collected_at",
                    ]
                    .map(String::from)
                    .to_vec(),
                )
                .chain(rows.iter().map(|h| {
                    vec![
                        h.hostname.clone(),
                        h.device_id.to_string(),
                        h.manufacturer.clone().unwrap_or_default(),
                        h.model.clone().unwrap_or_default(),
                        h.serial_number.clone().unwrap_or_default(),
                        h.cpu_model.clone(),
                        h.cpu_logical_cores.to_string(),
                        h.memory_total_bytes.to_string(),
                        opt(h.system_disk_total_bytes),
                        opt(h.system_disk_free_bytes),
                        h.tpm_version.clone().unwrap_or_default(),
                        h.secure_boot.map(|b| b.to_string()).unwrap_or_default(),
                        h.reboot_pending.to_string(),
                        h.collected_at.to_string(),
                    ]
                }))
                .collect(),
            )
        }
    };
    let rows = table.len() - 1;
    let (path, body) = if csv {
        let body: String = table
            .iter()
            .map(|r| r.iter().map(|c| csv_cell(c)).collect::<Vec<_>>().join(",") + "\r\n")
            .collect();
        (
            dir.join(format!("tervano-{name}-{}.csv", now_millis())),
            body,
        )
    } else {
        (
            dir.join(format!("tervano-{name}-{}.json", now_millis())),
            json,
        )
    };
    std::fs::write(&path, body).map_err(|e| format!("Export failed: {e}"))?;
    Ok(format!("Exported {rows} rows to {}", path.display()))
}

fn loaded<T>(x: &Option<Result<Vec<T>, String>>) -> Result<&Vec<T>, String> {
    match x {
        Some(Ok(rows)) => Ok(rows),
        _ => Err("Nothing loaded to export yet.".into()),
    }
}
