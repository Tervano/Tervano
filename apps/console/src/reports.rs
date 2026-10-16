//! Reports page (T-804): fleet software, OS and hardware from the server's stored state and
//! inventory, with drill-down from a software entry to its devices and CSV/JSON export.

use crate::{
    Console, Message, Page, ago, centered, csv_cell, downloads_dir, error_box, human_size, scroll,
};
use iced::widget::{Space, button, column, container, row, rule, text, text_input};
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
    /// Scroll and sort of each [`TableId`], indexed by it.
    pub(crate) views: [TableView; 5],
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
            views: [TableView::default(); 5],
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
            ReportMsg::Software(x) => {
                r.software = Some(x);
                return self.reset_table(TableId::Software);
            }
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
            ReportMsg::Os(x) => {
                r.os = Some(x);
                return self.reset_table(TableId::Os);
            }
            ReportMsg::Hardware(x) => {
                r.hardware = Some(x);
                return self.reset_table(TableId::Hardware);
            }
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
                    TableId::Os,
                    &r.views[TableId::Os as usize],
                    &["Operating system", "Version", "Build", "Devices", "Online"],
                    &[3, 1, 2, 1, 1],
                    rows.len(),
                    |i| {
                        let o = &rows[i];
                        vec![
                            o.name.clone(),
                            o.version.clone(),
                            o.build.clone(),
                            o.devices.to_string(),
                            o.online.to_string(),
                        ]
                    },
                    None::<fn(usize) -> Message>,
                ),
            },
            ReportTab::Hardware => match &r.hardware {
                None => centered("Loading…"),
                Some(Err(e)) => error_box(e),
                Some(Ok(rows)) => table(
                    TableId::Hardware,
                    &r.views[TableId::Hardware as usize],
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
                    rows.len(),
                    |i| hardware_cells(&rows[i]),
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
            TableId::Software,
            &r.views[TableId::Software as usize],
            &["Name", "Version", "Publisher", "Devices"],
            &[4, 2, 3, 1],
            rows.len(),
            |i| {
                let s = &rows[i];
                vec![
                    s.name.clone(),
                    s.version.clone().unwrap_or_default(),
                    s.publisher.clone().unwrap_or_default(),
                    s.devices.to_string(),
                ]
            },
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
            Some(Ok(devs)) => scroll(
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

/// The large tables, each with its own scroll position and sort (T-307).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TableId {
    Software,
    Os,
    Hardware,
    Compliance,
    /// The Direct file browser (T-816).
    Files,
}

#[derive(Debug, Clone, Copy)]
pub struct TableView {
    /// Scroll offset and viewport height (px), from the scrollable.
    offset: f32,
    height: f32,
    /// Sorted column and whether ascending; `None` keeps the server's order.
    sort: Option<(usize, bool)>,
}

impl Default for TableView {
    fn default() -> Self {
        Self {
            offset: 0.0,
            // Until the first scroll event: enough rows for a tall window.
            height: 1200.0,
            sort: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum TableMsg {
    Scrolled(f32, f32),
    Sort(usize),
}

/// Fixed so only the visible rows need to exist (text that does not fit is clipped).
const ROW_H: f32 = 26.0;

fn scroll_id(id: TableId) -> iced::widget::Id {
    iced::widget::Id::new(match id {
        TableId::Software => "table-software",
        TableId::Os => "table-os",
        TableId::Hardware => "table-hardware",
        TableId::Compliance => "table-compliance",
        TableId::Files => "table-files",
    })
}

impl Console {
    pub(crate) fn table_update(&mut self, id: TableId, msg: TableMsg) -> Task<Message> {
        let v = &mut self.reports.views[id as usize];
        match msg {
            TableMsg::Scrolled(offset, height) => {
                v.offset = offset;
                v.height = height;
            }
            TableMsg::Sort(col) => {
                v.sort = match v.sort {
                    Some((c, true)) if c == col => Some((col, false)),
                    Some((c, false)) if c == col => None,
                    _ => Some((col, true)),
                };
                return self.reset_table(id);
            }
        }
        Task::none()
    }

    /// Back to the top (new data, new tab or new sort), for both the widget and our window.
    pub(crate) fn reset_table(&mut self, id: TableId) -> Task<Message> {
        self.reports.views[id as usize].offset = 0.0;
        iced::widget::operation::snap_to(
            scroll_id(id),
            iced::widget::scrollable::RelativeOffset::START,
        )
    }
}

/// A virtualized vertical list of fixed-height rows: only the rows in view are built (T-307,
/// T-816). `row(pos)` builds the row at position `pos`; scrolling reports back as
/// [`TableMsg::Scrolled`] for `id`.
pub(crate) fn virtual_list<'a>(
    id: TableId,
    view: &TableView,
    len: usize,
    row_h: f32,
    row: impl Fn(usize) -> Element<'a, Message>,
) -> iced::widget::Scrollable<'a, Message> {
    // Rows are row_h + 1 (spacing) apart; build a little more than the viewport.
    let pitch = row_h + 1.0;
    let first = ((view.offset / pitch).floor() as usize).min(len);
    let shown = ((view.height / pitch).ceil() as usize + 2).min(len - first);
    let mut body = column![Space::new().height(first as f32 * pitch)].spacing(1);
    for pos in first..first + shown {
        body = body.push(container(row(pos)).height(row_h).clip(true));
    }
    body = body.push(Space::new().height((len - first - shown) as f32 * pitch));
    scroll(body).id(scroll_id(id)).on_scroll(move |vp| {
        Message::Table(
            id,
            TableMsg::Scrolled(vp.absolute_offset().y, vp.bounds().height),
        )
    })
}

/// Orders numbers by value ("125.61 GB" < "1,024 GB" style values compare by their leading
/// number) and everything else case-insensitively.
fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let number = |s: &str| {
        let t: String = s
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ',')
            .filter(|c| *c != ',')
            .collect();
        t.parse::<f64>().ok()
    };
    match (number(a), number(b)) {
        (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
        _ => a.to_lowercase().cmp(&b.to_lowercase()),
    }
}

/// A virtualized text table: only the rows in view are built (T-307), with sortable headers.
/// `cells(i)` gives row `i`'s texts; `on_row(i)` makes rows clickable (with the original index).
pub(crate) fn table<'a>(
    id: TableId,
    view: &TableView,
    headers: &[&'static str],
    widths: &[u16],
    len: usize,
    cells: impl Fn(usize) -> Vec<String>,
    on_row: Option<impl Fn(usize) -> Message>,
) -> Element<'a, Message> {
    let line = |values: Vec<Element<'a, Message>>| {
        row(values.into_iter().zip(widths).map(|(v, w)| {
            container(v)
                .width(Length::FillPortion(*w))
                .height(ROW_H)
                .clip(true)
                .into()
        }))
        .spacing(8)
        .align_y(Alignment::Center)
    };
    let header = row(headers.iter().enumerate().zip(widths).map(|((i, h), w)| {
        let mark = match view.sort {
            Some((c, true)) if c == i => " ▲",
            Some((c, false)) if c == i => " ▼",
            _ => "",
        };
        button(text(format!("{h}{mark}")).size(12).style(text::secondary))
            .padding(0)
            .style(button::text)
            .width(Length::FillPortion(*w))
            .on_press(Message::Table(id, TableMsg::Sort(i)))
            .into()
    }))
    .spacing(8);

    let mut order: Vec<usize> = (0..len).collect();
    if let Some((col, asc)) = view.sort {
        let keys: Vec<String> = (0..len)
            .map(|i| cells(i).into_iter().nth(col).unwrap_or_default())
            .collect();
        order.sort_by(|&a, &b| {
            let o = natural_cmp(&keys[a], &keys[b]);
            if asc { o } else { o.reverse() }
        });
    }
    let list = virtual_list(id, view, len, ROW_H, |pos| {
        let i = order[pos];
        let values = line(
            cells(i)
                .into_iter()
                .map(|v| text(v).size(13).wrapping(text::Wrapping::None).into())
                .collect(),
        );
        match &on_row {
            Some(f) => button(values)
                .width(Length::Fill)
                .height(ROW_H)
                .padding([0, 6])
                .style(button::text)
                .on_press(f(i))
                .into(),
            None => container(values).height(ROW_H).padding([0, 6]).into(),
        }
    });
    column![
        container(header.padding([4, 6])).style(container::rounded_box),
        list.height(Length::Fill),
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
