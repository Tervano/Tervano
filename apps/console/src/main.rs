// Release builds are GUI-only; debug keeps a console for logs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod direct;

use iced::widget::{
    Space, button, column, container, pick_list, progress_bar, row, rule, scrollable, text,
    text_input,
};
use iced::{Alignment, Color, Element, Length, Subscription, Task, Theme};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tervano_protocol::*;

fn main() -> iced::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    iced::application(Console::boot, Console::update, Console::view)
        .title("Tervano Console")
        .theme(Console::theme)
        .subscription(Console::subscription)
        .window_size((1200.0, 760.0))
        .run()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
struct Settings {
    server_url: String,
    // shortcut: plaintext in the user's %APPDATA%; Credential Manager is T-306.
    token: String,
    /// Optional PEM CA to trust for the server (e.g. `ca.pem` from `tervano-server cert init`).
    ca_cert: String,
    dark: bool,
    /// Technician client certificate + key (PEM paths) for direct agent connections.
    // shortcut: key file is plaintext on disk; move to the Windows certificate store with T-306.
    tech_cert: String,
    tech_key: String,
    /// Agents managed directly (serverless), each pinned to its certificate fingerprint.
    endpoints: Vec<Endpoint>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct Endpoint {
    /// `host:port`.
    address: String,
    /// SHA-256 of the agent's certificate, lowercase hex.
    fingerprint: String,
}

impl Settings {
    fn path() -> Option<std::path::PathBuf> {
        Some(
            std::path::PathBuf::from(std::env::var_os("APPDATA")?)
                .join("Tervano")
                .join("console.toml"),
        )
    }

    fn load() -> Self {
        Self::path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_else(|| Settings {
                server_url: "http://127.0.0.1:8470".into(),
                ..Default::default()
            })
    }

    fn save(&self) -> Result<(), String> {
        let p = Self::path().ok_or("APPDATA not set")?;
        std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
        std::fs::write(p, toml::to_string(self).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Page {
    Devices,
    Direct,
    Settings,
}

#[derive(Debug, Clone)]
enum Message {
    Nav(Page),
    QueryChanged(String),
    Search,
    Refresh,
    SearchDone(u64, Result<Vec<DeviceSummary>, String>),
    Select(uuid::Uuid),
    DetailsDone(Result<DeviceDetails, String>),
    ServerUrlChanged(String),
    TokenChanged(String),
    CaCertChanged(String),
    SaveSettings,
    ToggleTheme,
    Live(api::LiveEvent),
    TechCertChanged(String),
    TechKeyChanged(String),
    DirectInput(String),
    DirectAdd,
    DirectProbed(String, Result<String, String>),
    DirectTrust,
    DirectCancel,
    DirectSelect(String),
    DirectLoaded(String, Result<DeviceState, String>),
    DirectRemove(String),
    DirectTab(DirectTab),
    ProcsLoaded(String, Result<Vec<ProcessInfo>, String>),
    ProcFilter(String),
    ProcSort(ProcSort),
    KillAsk(u32, String),
    KillConfirm,
    KillCancel,
    KillDone(Result<String, String>),
    SvcsLoaded(String, Result<Vec<ServiceEntry>, String>),
    SvcFilter(String),
    SvcAsk(SvcChange),
    SvcConfirm,
    SvcCancel,
    SvcDone(Result<String, String>),
    EvtChannel(String),
    EvtLevel(LevelChoice),
    EvtWithin(WithinChoice),
    EvtProvider(String),
    EvtId(String),
    EvtRun,
    EvtsLoaded(String, Result<Vec<EventRecord>, String>),
    EvtChannelsLoaded(Result<Vec<String>, String>),
    EvtToggle(u64),
    EvtExport,
    HwLoaded(String, Result<HardwareInventory, String>),
}

/// Level filter for the Events tab: `None` = any.
#[derive(Debug, Clone, Copy, PartialEq)]
struct LevelChoice(Option<u8>);

impl std::fmt::Display for LevelChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            None => "Any level",
            Some(1) => "Critical",
            Some(2) => "Error and worse",
            Some(3) => "Warning and worse",
            _ => "Information and worse",
        })
    }
}

const LEVEL_CHOICES: [LevelChoice; 5] = [
    LevelChoice(None),
    LevelChoice(Some(1)),
    LevelChoice(Some(2)),
    LevelChoice(Some(3)),
    LevelChoice(Some(4)),
];

/// Time window for the Events tab, in minutes: `None` = all time.
#[derive(Debug, Clone, Copy, PartialEq)]
struct WithinChoice(Option<u32>);

impl std::fmt::Display for WithinChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            None => "Any time",
            Some(60) => "Last hour",
            Some(1440) => "Last 24 hours",
            Some(10080) => "Last 7 days",
            _ => "Last 30 days",
        })
    }
}

const WITHIN_CHOICES: [WithinChoice; 5] = [
    WithinChoice(Some(60)),
    WithinChoice(Some(1440)),
    WithinChoice(Some(10080)),
    WithinChoice(Some(43200)),
    WithinChoice(None),
];

fn level_name(l: u8) -> &'static str {
    match l {
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        5 => "Verbose",
        _ => "Information",
    }
}

/// A service change awaiting the technician's confirmation.
#[derive(Debug, Clone)]
enum SvcChange {
    Control(String, ServiceAction),
    StartType(String, StartType),
}

impl SvcChange {
    fn describe(&self) -> String {
        match self {
            SvcChange::Control(n, a) => format!("{a:?} service {n}"),
            SvcChange::StartType(n, t) => format!("Set {n} to start {}", StartChoice(*t)),
        }
    }
}

/// Settable start types, for the picker.
#[derive(Debug, Clone, Copy, PartialEq)]
struct StartChoice(StartType);

impl std::fmt::Display for StartChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            StartType::Automatic => "Automatic",
            StartType::Manual => "Manual",
            StartType::Disabled => "Disabled",
            StartType::Boot => "Boot",
            StartType::System => "System",
        })
    }
}

const START_CHOICES: [StartChoice; 3] = [
    StartChoice(StartType::Automatic),
    StartChoice(StartType::Manual),
    StartChoice(StartType::Disabled),
];

#[derive(Debug, Clone, Copy, PartialEq)]
enum DirectTab {
    Summary,
    Processes,
    Services,
    Events,
    Hardware,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ProcSort {
    Cpu,
    Memory,
    Name,
    Pid,
}

/// An agent awaiting the technician's trust decision.
struct PendingTrust {
    address: String,
    /// `None` while probing.
    fingerprint: Option<Result<String, String>>,
}

struct Console {
    settings: Settings,
    draft: Settings,
    settings_status: Option<Result<String, String>>,
    page: Page,
    query: String,
    /// Ignores responses from superseded searches.
    search_gen: u64,
    loading: bool,
    devices: Result<Vec<DeviceSummary>, String>,
    selected: Option<uuid::Uuid>,
    details: Option<Result<DeviceDetails, String>>,
    /// Server push connected; polling is only the fallback while this is false.
    live: bool,
    /// A pushed change arrived; refresh once the debounce tick fires.
    dirty: bool,
    direct_input: String,
    direct_notice: Option<String>,
    pending_trust: Option<PendingTrust>,
    direct_selected: Option<String>,
    /// Last result per endpoint address, for status dots and the details panel.
    direct_results: std::collections::HashMap<String, Result<DeviceState, String>>,
    direct_tab: DirectTab,
    /// Process list of the selected endpoint, keyed by its address so stale replies are ignored.
    procs: Option<(String, Result<Vec<ProcessInfo>, String>)>,
    proc_filter: String,
    proc_sort: ProcSort,
    /// (pid, name) awaiting the technician's "Terminate" confirmation.
    confirm_kill: Option<(u32, String)>,
    kill_notice: Option<Result<String, String>>,
    svcs: Option<(String, Result<Vec<ServiceEntry>, String>)>,
    svc_filter: String,
    svc_confirm: Option<SvcChange>,
    svc_notice: Option<Result<String, String>>,
    /// A service change is running on the agent (restart can take tens of seconds).
    svc_busy: bool,
    evt_channel: String,
    evt_level: LevelChoice,
    evt_within: WithinChoice,
    evt_provider: String,
    evt_id: String,
    evts: Option<(String, Result<Vec<EventRecord>, String>)>,
    /// All channel names of the selected endpoint, for suggestions.
    evt_channels: Vec<String>,
    evt_expanded: Option<u64>,
    evt_notice: Option<Result<String, String>>,
    hw: Option<(String, Result<HardwareInventory, String>)>,
}

impl Console {
    fn boot() -> (Self, Task<Message>) {
        let settings = Settings::load();
        let configured = !settings.token.is_empty();
        let page = if configured {
            Page::Devices
        } else if !settings.endpoints.is_empty() {
            Page::Direct
        } else {
            Page::Settings
        };
        let mut c = Console {
            draft: settings.clone(),
            settings,
            settings_status: None,
            page,
            query: String::new(),
            search_gen: 0,
            loading: false,
            devices: Ok(Vec::new()),
            selected: None,
            details: None,
            live: false,
            dirty: false,
            direct_input: String::new(),
            direct_notice: None,
            pending_trust: None,
            direct_selected: None,
            direct_results: Default::default(),
            direct_tab: DirectTab::Summary,
            procs: None,
            proc_filter: String::new(),
            proc_sort: ProcSort::Cpu,
            confirm_kill: None,
            kill_notice: None,
            svcs: None,
            svc_filter: String::new(),
            svc_confirm: None,
            svc_notice: None,
            svc_busy: false,
            evt_channel: "System".into(),
            evt_level: LevelChoice(Some(3)),
            evt_within: WithinChoice(Some(1440)),
            evt_provider: String::new(),
            evt_id: String::new(),
            evts: None,
            evt_channels: Vec::new(),
            evt_expanded: None,
            evt_notice: None,
            hw: None,
        };
        let task = if configured { c.search() } else { Task::none() };
        (c, task)
    }

    fn client(&self) -> Result<api::Client, String> {
        api::Client::new(
            &self.settings.server_url,
            &self.settings.token,
            &self.settings.ca_cert,
        )
    }

    fn search(&mut self) -> Task<Message> {
        self.search_gen += 1;
        self.loading = true;
        let (generation, client, q) = (self.search_gen, self.client(), self.query.clone());
        Task::perform(async move { client?.search(&q).await }, move |r| {
            Message::SearchDone(generation, r)
        })
    }

    fn load_details(&self, id: uuid::Uuid) -> Task<Message> {
        let client = self.client();
        Task::perform(
            async move { client?.details(id).await },
            Message::DetailsDone,
        )
    }

    fn creds(&self) -> direct::Creds {
        direct::Creds {
            cert: self.settings.tech_cert.clone(),
            key: self.settings.tech_key.clone(),
        }
    }

    fn target(&self, address: &str) -> Option<direct::Target> {
        let ep = self
            .settings
            .endpoints
            .iter()
            .find(|e| e.address == address)?;
        Some(direct::Target {
            address: ep.address.clone(),
            pin: ep.fingerprint.clone(),
            creds: self.creds(),
        })
    }

    /// Reloads the selected endpoint's summary, plus its processes when that tab is open.
    fn load_direct(&self, address: &str) -> Task<Message> {
        let Some(t) = self.target(address) else {
            return Task::none();
        };
        let addr = t.address.clone();
        let device = Task::perform(direct::device(t.clone()), {
            let addr = addr.clone();
            move |r| Message::DirectLoaded(addr.clone(), r)
        });
        let tab = match self.direct_tab {
            DirectTab::Summary => return device,
            DirectTab::Processes => Task::perform(direct::processes(t), move |r| {
                Message::ProcsLoaded(addr.clone(), r)
            }),
            DirectTab::Services => Task::perform(direct::services(t), move |r| {
                Message::SvcsLoaded(addr.clone(), r)
            }),
            DirectTab::Events => {
                let q = self.event_query();
                let channels = if self.evt_channels.is_empty() {
                    Task::perform(
                        direct::event_channels(t.clone()),
                        Message::EvtChannelsLoaded,
                    )
                } else {
                    Task::none()
                };
                let events = Task::perform(direct::events(t, q), move |r| {
                    Message::EvtsLoaded(addr.clone(), r)
                });
                Task::batch([channels, events])
            }
            DirectTab::Hardware => Task::perform(direct::hardware(t), move |r| {
                Message::HwLoaded(addr.clone(), r)
            }),
        };
        Task::batch([device, tab])
    }

    fn save_settings(&mut self) {
        if let Err(e) = self.settings.save() {
            self.direct_notice = Some(format!("Could not save settings: {e}"));
        }
    }

    fn update(&mut self, msg: Message) -> Task<Message> {
        match msg {
            Message::Nav(p) => self.page = p,
            Message::QueryChanged(q) => self.query = q,
            Message::Search => return self.search(),
            Message::Refresh => {
                if self.page == Page::Devices && !self.settings.token.is_empty() && !self.loading {
                    self.dirty = false;
                    let details = self
                        .selected
                        .map(|id| self.load_details(id))
                        .unwrap_or_else(Task::none);
                    return Task::batch([self.search(), details]);
                }
            }
            Message::SearchDone(generation, r) => {
                if generation == self.search_gen {
                    self.loading = false;
                    self.devices = r;
                }
            }
            Message::Select(id) => {
                self.selected = Some(id);
                self.details = None;
                return self.load_details(id);
            }
            Message::DetailsDone(r) => {
                // Drop stale responses for a previously selected device.
                if r.as_ref().map_or(true, |d| Some(d.id) == self.selected) {
                    self.details = Some(r);
                }
            }
            Message::ServerUrlChanged(s) => self.draft.server_url = s,
            Message::TokenChanged(s) => self.draft.token = s,
            Message::CaCertChanged(s) => self.draft.ca_cert = s,
            Message::SaveSettings => {
                self.draft.server_url = self
                    .draft
                    .server_url
                    .trim()
                    .trim_end_matches('/')
                    .to_owned();
                self.draft.token = self.draft.token.trim().to_owned();
                self.draft.ca_cert = self.draft.ca_cert.trim().trim_matches('"').to_owned();
                self.draft.tech_cert = self.draft.tech_cert.trim().trim_matches('"').to_owned();
                self.draft.tech_key = self.draft.tech_key.trim().trim_matches('"').to_owned();
                // Endpoints are edited on the Direct page, not via the draft.
                self.draft.endpoints = self.settings.endpoints.clone();
                self.settings = self.draft.clone();
                self.settings_status = Some(self.settings.save().map(|_| "Saved.".into()));
                if self.settings.token.is_empty() {
                    self.page = Page::Direct;
                } else {
                    self.page = Page::Devices;
                    return self.search();
                }
            }
            Message::TechCertChanged(s) => self.draft.tech_cert = s,
            Message::TechKeyChanged(s) => self.draft.tech_key = s,
            Message::DirectInput(s) => self.direct_input = s,
            Message::DirectAdd => {
                let address = direct::normalize_address(&self.direct_input);
                if self.direct_input.trim().is_empty() {
                    return Task::none();
                }
                if self.settings.endpoints.iter().any(|e| e.address == address) {
                    self.direct_notice = Some(format!("{address} is already in the list."));
                    return Task::none();
                }
                self.direct_notice = None;
                self.pending_trust = Some(PendingTrust {
                    address: address.clone(),
                    fingerprint: None,
                });
                return Task::perform(direct::probe(address.clone(), self.creds()), move |r| {
                    Message::DirectProbed(address.clone(), r)
                });
            }
            Message::DirectProbed(address, r) => {
                if let Some(p) = &mut self.pending_trust
                    && p.address == address
                {
                    p.fingerprint = Some(r);
                }
            }
            Message::DirectTrust => {
                if let Some(PendingTrust {
                    address,
                    fingerprint: Some(Ok(fp)),
                }) = self.pending_trust.take()
                {
                    self.settings.endpoints.push(Endpoint {
                        address: address.clone(),
                        fingerprint: direct::normalize_fingerprint(&fp),
                    });
                    self.draft.endpoints = self.settings.endpoints.clone();
                    self.save_settings();
                    self.direct_input.clear();
                    self.direct_selected = Some(address.clone());
                    return self.load_direct(&address);
                }
            }
            Message::DirectCancel => self.pending_trust = None,
            Message::DirectSelect(address) => {
                if self.direct_selected.as_deref() != Some(address.as_str()) {
                    self.procs = None;
                    self.confirm_kill = None;
                    self.kill_notice = None;
                    self.svcs = None;
                    self.svc_confirm = None;
                    self.svc_notice = None;
                    self.evts = None;
                    self.evt_channels.clear();
                    self.evt_expanded = None;
                    self.evt_notice = None;
                    self.hw = None;
                }
                self.direct_selected = Some(address.clone());
                return self.load_direct(&address);
            }
            Message::DirectTab(tab) => {
                self.direct_tab = tab;
                if let Some(addr) = self.direct_selected.clone() {
                    return self.load_direct(&addr);
                }
            }
            Message::ProcsLoaded(address, r) => {
                if self.direct_selected.as_deref() == Some(address.as_str()) {
                    self.procs = Some((address, r));
                }
            }
            Message::ProcFilter(f) => self.proc_filter = f,
            Message::ProcSort(s) => self.proc_sort = s,
            Message::KillAsk(pid, name) => {
                self.kill_notice = None;
                self.confirm_kill = Some((pid, name));
            }
            Message::KillCancel => self.confirm_kill = None,
            Message::KillConfirm => {
                if let (Some((pid, name)), Some(t)) = (
                    self.confirm_kill.take(),
                    self.direct_selected.as_deref().and_then(|a| self.target(a)),
                ) {
                    let label = format!("{name} ({pid})");
                    return Task::perform(direct::kill(t, pid, name), move |r| {
                        Message::KillDone(r.map(|()| format!("Terminated {label}.")))
                    });
                }
            }
            Message::SvcsLoaded(address, r) => {
                if self.direct_selected.as_deref() == Some(address.as_str()) {
                    self.svcs = Some((address, r));
                }
            }
            Message::SvcFilter(f) => self.svc_filter = f,
            Message::SvcAsk(change) => {
                self.svc_notice = None;
                self.svc_confirm = Some(change);
            }
            Message::SvcCancel => self.svc_confirm = None,
            Message::SvcConfirm => {
                if let (Some(change), Some(t)) = (
                    self.svc_confirm.take(),
                    self.direct_selected.as_deref().and_then(|a| self.target(a)),
                ) {
                    self.svc_busy = true;
                    let done = change.describe();
                    let to_msg = move |r: Result<ServiceEntry, String>| {
                        Message::SvcDone(r.map(|s| format!("{done}: now {}.", s.state)))
                    };
                    return match change {
                        SvcChange::Control(n, a) => {
                            Task::perform(direct::control_service(t, n, a), to_msg)
                        }
                        SvcChange::StartType(n, st) => {
                            Task::perform(direct::set_start_type(t, n, st), to_msg)
                        }
                    };
                }
            }
            Message::SvcDone(r) => {
                self.svc_busy = false;
                self.svc_notice = Some(r);
                if let Some(addr) = self.direct_selected.clone() {
                    return self.load_direct(&addr);
                }
            }
            Message::EvtChannel(c) => self.evt_channel = c,
            Message::EvtLevel(l) => self.evt_level = l,
            Message::EvtWithin(w) => self.evt_within = w,
            Message::EvtProvider(p) => self.evt_provider = p,
            Message::EvtId(i) => self.evt_id = i.chars().filter(char::is_ascii_digit).collect(),
            Message::EvtRun => {
                self.evt_notice = None;
                if let Some(addr) = self.direct_selected.clone() {
                    return self.load_direct(&addr);
                }
            }
            Message::EvtsLoaded(address, r) => {
                if self.direct_selected.as_deref() == Some(address.as_str()) {
                    self.evts = Some((address, r));
                }
            }
            Message::EvtChannelsLoaded(r) => {
                // Suggestions are a convenience; a failure just means none are offered.
                self.evt_channels = r.unwrap_or_default();
            }
            Message::EvtToggle(id) => {
                self.evt_expanded = (self.evt_expanded != Some(id)).then_some(id);
            }
            Message::EvtExport => {
                if let (Some((addr, Ok(list))), Some(dir)) = (&self.evts, downloads_dir()) {
                    self.evt_notice = Some(export_events_csv(&dir, addr, &self.evt_channel, list));
                }
            }
            Message::HwLoaded(address, r) => {
                if self.direct_selected.as_deref() == Some(address.as_str()) {
                    self.hw = Some((address, r));
                }
            }
            Message::KillDone(r) => {
                self.kill_notice = Some(r);
                if let Some(addr) = self.direct_selected.clone() {
                    return self.load_direct(&addr);
                }
            }
            Message::DirectLoaded(address, r) => {
                self.direct_results.insert(address, r);
            }
            Message::DirectRemove(address) => {
                self.settings.endpoints.retain(|e| e.address != address);
                self.draft.endpoints = self.settings.endpoints.clone();
                self.direct_results.remove(&address);
                if self.direct_selected.as_deref() == Some(address.as_str()) {
                    self.direct_selected = None;
                }
                self.save_settings();
            }
            Message::Live(ev) => match ev {
                api::LiveEvent::Connected => {
                    tracing::info!("live updates connected");
                    self.live = true;
                    // Catch up on anything missed while disconnected.
                    self.dirty = true;
                }
                api::LiveEvent::Disconnected(e) => {
                    // Reconnect backoff caps this at one line per 30 s.
                    tracing::warn!("live updates unavailable: {e}");
                    self.live = false;
                }
                api::LiveEvent::Changed(id) => {
                    tracing::debug!(%id, "device changed");
                    self.dirty = true;
                }
                api::LiveEvent::Resync => self.dirty = true,
            },
            Message::ToggleTheme => {
                self.settings.dark = !self.settings.dark;
                self.draft.dark = self.settings.dark;
                let _ = self.settings.save();
            }
        }
        Task::none()
    }

    fn subscription(&self) -> Subscription<Message> {
        // Direct agents have no push channel; refresh the one being viewed.
        let direct_tick = match (&self.page, &self.direct_selected) {
            (Page::Direct, Some(addr)) => {
                let addr = addr.clone();
                iced::time::every(Duration::from_secs(15))
                    .with(addr)
                    .map(|(addr, _)| Message::DirectSelect(addr))
            }
            _ => Subscription::none(),
        };
        if self.settings.token.is_empty() {
            return direct_tick;
        }
        let key = (
            self.settings.server_url.clone(),
            self.settings.token.clone(),
            self.settings.ca_cert.clone(),
        );
        let mut subs = vec![
            Subscription::run_with(key, api::live).map(Message::Live),
            direct_tick,
        ];
        if self.dirty {
            // Debounce: a burst of pushed changes becomes one refresh.
            // shortcut: re-runs the whole current search per burst; patch rows in place if this gets heavy (T-307).
            subs.push(iced::time::every(Duration::from_secs(1)).map(|_| Message::Refresh));
        } else if !self.live {
            subs.push(iced::time::every(Duration::from_secs(15)).map(|_| Message::Refresh));
        }
        Subscription::batch(subs)
    }

    fn theme(&self) -> Theme {
        if self.settings.dark {
            Theme::Dark
        } else {
            Theme::Light
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let nav = |label: &'static str, page: Page| {
            let style = if self.page == page {
                button::primary
            } else {
                button::text
            };
            button(text(label).size(14))
                .width(Length::Fill)
                .padding([8, 12])
                .style(style)
                .on_press(Message::Nav(page))
        };
        let sidebar = container(
            column![
                text("Tervano").size(22),
                text("Console").size(12).style(text::secondary),
                Space::new().height(16),
                nav("Devices", Page::Devices),
                nav("Direct", Page::Direct),
                nav("Settings", Page::Settings),
                Space::new().height(Length::Fill),
                button(
                    text(if self.settings.dark {
                        "Light theme"
                    } else {
                        "Dark theme"
                    })
                    .size(13)
                )
                .width(Length::Fill)
                .style(button::subtle)
                .on_press(Message::ToggleTheme),
            ]
            .spacing(4)
            .padding(16),
        )
        .width(190)
        .height(Length::Fill)
        .style(container::bordered_box);

        let main: Element<_> = match self.page {
            Page::Devices => self.devices_view(),
            Page::Direct => self.direct_view(),
            Page::Settings => self.settings_view(),
        };
        row![
            sidebar,
            container(main)
                .padding(16)
                .width(Length::Fill)
                .height(Length::Fill)
        ]
        .into()
    }

    fn devices_view(&self) -> Element<'_, Message> {
        let search = row![
            text_input(
                "Search by computer name, user (DOMAIN\\user) or IP…",
                &self.query
            )
            .on_input(Message::QueryChanged)
            .on_submit(Message::Search)
            .padding(10)
            .size(15),
            button(text("Search"))
                .padding([10, 16])
                .style(button::primary)
                .on_press(Message::Search),
        ]
        .spacing(8);

        let list: Element<_> = match &self.devices {
            Err(e) => error_box(e),
            Ok(d) if d.is_empty() && self.loading => centered("Loading…"),
            Ok(d) if d.is_empty() => centered(if self.query.is_empty() {
                "No devices enrolled yet. Enroll an agent with a token from `tervano-server token create`."
            } else {
                "No devices match this search."
            }),
            Ok(devices) => {
                let header = row![
                    text("").width(14),
                    text("Name").width(Length::FillPortion(3)),
                    text("User").width(Length::FillPortion(2)),
                    text("IP address").width(Length::FillPortion(2)),
                    text("OS").width(Length::FillPortion(3)),
                    text("Last seen").width(Length::FillPortion(2)),
                ]
                .spacing(8)
                .padding([6, 10]);
                // shortcut: renders every row (server caps at 100); virtualization is T-307.
                let rows = devices.iter().map(|d| {
                    let selected = self.selected == Some(d.id);
                    button(
                        row![
                            status_dot(d.online),
                            text(&d.hostname).width(Length::FillPortion(3)),
                            text(d.users.join(", ")).width(Length::FillPortion(2)),
                            text(d.primary_ip.as_deref().unwrap_or("—"))
                                .width(Length::FillPortion(2)),
                            text(&d.os).width(Length::FillPortion(3)),
                            text(ago(d.last_seen)).width(Length::FillPortion(2)),
                        ]
                        .spacing(8)
                        .align_y(Alignment::Center),
                    )
                    .padding([8, 10])
                    .width(Length::Fill)
                    .style(if selected {
                        button::secondary
                    } else {
                        button::text
                    })
                    .on_press(Message::Select(d.id))
                    .into()
                });
                column![
                    container(header.width(Length::Fill)).style(container::rounded_box),
                    scrollable(column(rows).spacing(2)).height(Length::Fill),
                    text(format!(
                        "{} device(s) · {}{}",
                        devices.len(),
                        if self.live {
                            "live"
                        } else {
                            "live updates unavailable, polling every 15 s"
                        },
                        if self.loading {
                            " · refreshing…"
                        } else {
                            ""
                        }
                    ))
                    .size(12)
                    .style(text::secondary),
                ]
                .spacing(6)
                .into()
            }
        };

        let content: Element<_> = match &self.details {
            None if self.selected.is_none() => row![list].into(),
            details => row![
                container(list).width(Length::FillPortion(3)),
                rule::vertical(1),
                container(self.details_view(details.as_ref()))
                    .width(Length::FillPortion(2))
                    .padding([0, 8]),
            ]
            .spacing(12)
            .into(),
        };
        column![search, content].spacing(12).into()
    }

    fn details_view<'a>(
        &'a self,
        details: Option<&'a Result<DeviceDetails, String>>,
    ) -> Element<'a, Message> {
        let d = match details {
            None => return centered("Loading…"),
            Some(Err(e)) => return error_box(e),
            Some(Ok(d)) => d,
        };
        state_panel(
            &d.state,
            d.online,
            if d.online { "Online" } else { "Offline" },
            vec![
                ("Last seen", ago(d.last_seen)),
                ("Enrolled", ago(d.enrolled_at)),
                ("Device ID", d.id.to_string()),
            ],
        )
    }

    fn direct_view(&self) -> Element<'_, Message> {
        let add = row![
            text_input(
                "Agent address, e.g. pc-lab-01.corp.example or 10.0.0.5:8472",
                &self.direct_input
            )
            .on_input(Message::DirectInput)
            .on_submit(Message::DirectAdd)
            .padding(10)
            .size(15),
            button(text("Add agent"))
                .padding([10, 16])
                .style(button::primary)
                .on_press(Message::DirectAdd),
        ]
        .spacing(8);
        let mut top = column![
            add,
            text("Direct connections go straight to the agent with your technician certificate; no server is involved.")
                .size(12)
                .style(text::secondary),
        ]
        .spacing(6);
        if let Some(n) = &self.direct_notice {
            top = top.push(text(n).size(13).style(text::danger));
        }
        if let Some(p) = &self.pending_trust {
            top = top.push(trust_panel(p));
        }

        let list: Element<_> = if self.settings.endpoints.is_empty() {
            centered(
                "No agents yet. Add one by address; you'll confirm its certificate fingerprint before anything is exchanged.",
            )
        } else {
            let rows = self.settings.endpoints.iter().map(|e| {
                let result = self.direct_results.get(&e.address);
                let (online, label) = match result {
                    Some(Ok(s)) => (true, s.hostname.clone()),
                    Some(Err(_)) => (false, "unreachable or refused".into()),
                    None => (false, "not checked yet".into()),
                };
                let selected = self.direct_selected.as_deref() == Some(e.address.as_str());
                row![
                    button(
                        row![
                            status_dot(online),
                            text(&e.address).width(Length::FillPortion(3)),
                            text(label).width(Length::FillPortion(3)),
                            text(direct::display_fingerprint(
                                &e.fingerprint[..16.min(e.fingerprint.len())]
                            ))
                            .size(12)
                            .style(text::secondary)
                            .width(Length::FillPortion(2)),
                        ]
                        .spacing(8)
                        .align_y(Alignment::Center),
                    )
                    .padding([8, 10])
                    .width(Length::Fill)
                    .style(if selected {
                        button::secondary
                    } else {
                        button::text
                    })
                    .on_press(Message::DirectSelect(e.address.clone())),
                    button(text("Remove").size(12))
                        .style(button::subtle)
                        .on_press(Message::DirectRemove(e.address.clone())),
                ]
                .spacing(4)
                .align_y(Alignment::Center)
                .into()
            });
            scrollable(column(rows).spacing(2))
                .height(Length::Fill)
                .into()
        };

        let content: Element<_> = match self
            .direct_selected
            .as_ref()
            .map(|a| (a, self.direct_results.get(a)))
        {
            None => list,
            Some((_, result)) => {
                let panel = match result {
                    None => centered("Connecting…"),
                    Some(Err(e)) => error_box(e),
                    Some(Ok(s)) => {
                        let tab = |label, t: DirectTab| {
                            button(text(label).size(13))
                                .padding([6, 12])
                                .style(if self.direct_tab == t {
                                    button::primary
                                } else {
                                    button::secondary
                                })
                                .on_press(Message::DirectTab(t))
                        };
                        let body = match self.direct_tab {
                            DirectTab::Summary => state_panel(
                                s,
                                true,
                                "Reachable directly · live from the agent",
                                vec![],
                            ),
                            DirectTab::Processes => self.procs_view(),
                            DirectTab::Services => self.svcs_view(),
                            DirectTab::Events => self.evts_view(),
                            DirectTab::Hardware => self.hw_view(),
                        };
                        column![
                            row![
                                tab("Summary", DirectTab::Summary),
                                tab("Processes", DirectTab::Processes),
                                tab("Services", DirectTab::Services),
                                tab("Events", DirectTab::Events),
                                tab("Hardware", DirectTab::Hardware)
                            ]
                            .spacing(6),
                            body
                        ]
                        .spacing(10)
                        .into()
                    }
                };
                // Tables need room: shrink the endpoint list while one is open.
                let (list_w, panel_w) = if self.direct_tab == DirectTab::Summary {
                    (3, 2)
                } else {
                    (1, 3)
                };
                row![
                    container(list).width(Length::FillPortion(list_w)),
                    rule::vertical(1),
                    container(panel)
                        .width(Length::FillPortion(panel_w))
                        .padding([0, 8]),
                ]
                .spacing(12)
                .into()
            }
        };
        column![top, content].spacing(12).into()
    }

    fn hw_view(&self) -> Element<'_, Message> {
        let hw = match &self.hw {
            None => return centered("Reading hardware…"),
            Some((_, Err(e))) => return error_box(e),
            Some((_, Ok(hw))) => hw,
        };
        let opt = |v: &Option<String>| v.clone().unwrap_or_else(|| "unknown".into());
        let kv = |k: &'static str, v: String| {
            row![text(k).width(140).style(text::secondary), text(v)].spacing(8)
        };
        let section = |t: &'static str| text(t).size(13).style(text::primary);
        let gb = |b: u64| format!("{:.1} GB", b as f64 / 1_073_741_824.0);
        let mut disks = column![section("Storage")].spacing(6);
        for d in &hw.disks {
            let used = d.total_bytes.saturating_sub(d.free_bytes);
            disks = disks.push(
                column![
                    text(format!(
                        "{} {}  ·  {} free of {}  ·  {}{}",
                        d.mount_point,
                        d.label,
                        gb(d.free_bytes),
                        gb(d.total_bytes),
                        d.kind.to_uppercase(),
                        if d.removable { " · removable" } else { "" }
                    ))
                    .size(13),
                    progress_bar(0.0..=d.total_bytes.max(1) as f32, used as f32).girth(6),
                ]
                .spacing(3),
            );
        }
        let battery = match &hw.battery {
            None => "none".to_string(),
            Some(b) => format!(
                "{}{}",
                b.charge_percent
                    .map_or("charge unknown".into(), |c| format!("{c}%")),
                match b.on_ac_power {
                    Some(true) => " · on AC power",
                    Some(false) => " · on battery",
                    None => "",
                }
            ),
        };
        scrollable(
            column![
                section("System"),
                kv("Manufacturer", opt(&hw.manufacturer)),
                kv("Model", opt(&hw.model)),
                kv("Serial number", opt(&hw.serial_number)),
                kv(
                    "BIOS",
                    format!(
                        "{} {} ({})",
                        opt(&hw.bios_vendor),
                        opt(&hw.bios_version),
                        opt(&hw.bios_date)
                    )
                ),
                kv("Booted", ago(hw.boot_time)),
                rule::horizontal(1),
                section("Processor and memory"),
                kv("CPU", hw.cpu_model.clone()),
                kv(
                    "Cores",
                    format!(
                        "{} physical · {} logical",
                        hw.cpu_physical_cores.map_or("?".into(), |c| c.to_string()),
                        hw.cpu_logical_cores
                    )
                ),
                kv("CPU load", format!("{:.0}%", hw.cpu_usage_percent)),
                kv(
                    "Memory",
                    format!(
                        "{} used of {}",
                        gb(hw.memory_used_bytes),
                        gb(hw.memory_total_bytes)
                    )
                ),
                rule::horizontal(1),
                section("Security"),
                kv(
                    "Secure Boot",
                    match hw.secure_boot {
                        Some(true) => "enabled".into(),
                        Some(false) => "disabled".into(),
                        None => "unknown".into(),
                    }
                ),
                kv(
                    "TPM",
                    hw.tpm_version
                        .clone()
                        .unwrap_or_else(|| "not detected".into())
                ),
                kv("Battery", battery),
                rule::horizontal(1),
                disks,
            ]
            .spacing(8),
        )
        .into()
    }

    fn event_query(&self) -> EventQuery {
        EventQuery {
            channel: self.evt_channel.trim().to_owned(),
            max_level: self.evt_level.0,
            provider: Some(self.evt_provider.trim().to_owned()).filter(|p| !p.is_empty()),
            event_id: self.evt_id.parse().ok(),
            within_minutes: self.evt_within.0,
            limit: Some(200),
        }
    }

    fn evts_view(&self) -> Element<'_, Message> {
        let quick = ["System", "Application", "Security", "Setup"]
            .into_iter()
            .fold(row![].spacing(4), |r, c| {
                r.push(
                    button(text(c).size(12))
                        .style(if self.evt_channel == c {
                            button::primary
                        } else {
                            button::subtle
                        })
                        .padding([2, 8])
                        .on_press(Message::EvtChannel(c.into())),
                )
            });
        let controls = column![
            row![
                text_input(
                    "Channel, e.g. Microsoft-Windows-PowerShell/Operational",
                    &self.evt_channel
                )
                .on_input(Message::EvtChannel)
                .on_submit(Message::EvtRun)
                .padding(6)
                .width(Length::FillPortion(3)),
                pick_list(LEVEL_CHOICES, Some(self.evt_level), Message::EvtLevel)
                    .text_size(13)
                    .width(Length::FillPortion(2)),
                pick_list(WITHIN_CHOICES, Some(self.evt_within), Message::EvtWithin)
                    .text_size(13)
                    .width(Length::FillPortion(2)),
            ]
            .spacing(6),
            row![
                text_input("Provider (optional)", &self.evt_provider)
                    .on_input(Message::EvtProvider)
                    .on_submit(Message::EvtRun)
                    .padding(6)
                    .width(Length::FillPortion(3)),
                text_input("Event ID", &self.evt_id)
                    .on_input(Message::EvtId)
                    .on_submit(Message::EvtRun)
                    .padding(6)
                    .width(Length::FillPortion(1)),
                button(text("Query"))
                    .style(button::primary)
                    .on_press(Message::EvtRun),
                button(text("Export CSV"))
                    .style(button::secondary)
                    .on_press_maybe(
                        matches!(self.evts, Some((_, Ok(_)))).then_some(Message::EvtExport)
                    ),
            ]
            .spacing(6),
            quick,
        ]
        .spacing(6);

        // Channel suggestions while typing something that isn't an exact channel name.
        let typed = self.evt_channel.trim().to_lowercase();
        let suggestions: Vec<&String> =
            if typed.len() >= 3 && !self.evt_channels.iter().any(|c| c.to_lowercase() == typed) {
                self.evt_channels
                    .iter()
                    .filter(|c| c.to_lowercase().contains(&typed))
                    .take(6)
                    .collect()
            } else {
                Vec::new()
            };
        let mut col = column![controls].spacing(6);
        if !suggestions.is_empty() {
            col = col.push(suggestions.into_iter().fold(column![].spacing(2), |c, s| {
                c.push(
                    button(text(s).size(12))
                        .style(button::text)
                        .padding([1, 6])
                        .on_press(Message::EvtChannel(s.clone())),
                )
            }));
        }
        if let Some(n) = &self.evt_notice {
            col = col.push(match n {
                Ok(m) => text(m.clone()).size(13).style(text::success),
                Err(e) => text(e.clone()).size(13).style(text::danger),
            });
        }
        let list = match &self.evts {
            None => return col.push(centered("Loading events…")).into(),
            Some((_, Err(e))) => return col.push(error_box(e)).into(),
            Some((_, Ok(list))) => list,
        };
        if list.is_empty() {
            return col.push(centered("No events match these filters.")).into();
        }
        let rows = list.iter().map(|e| {
            let msg = e
                .message
                .as_deref()
                .unwrap_or("(no message text available)");
            let expanded = self.evt_expanded == Some(e.record_id);
            let summary: String = if expanded {
                msg.to_owned()
            } else {
                msg.lines().next().unwrap_or("").chars().take(140).collect()
            };
            let level_style = match e.level {
                1 | 2 => text::danger,
                3 => text::warning,
                _ => text::secondary,
            };
            button(
                column![
                    row![
                        text(ago(e.time)).size(12).width(80),
                        text(level_name(e.level))
                            .size(12)
                            .style(level_style)
                            .width(80),
                        text(&e.provider).size(12).width(Length::Fill),
                        text(format!("ID {}", e.event_id)).size(12),
                    ]
                    .spacing(6),
                    text(summary).size(13),
                ]
                .spacing(2),
            )
            .style(if expanded {
                button::secondary
            } else {
                button::text
            })
            .width(Length::Fill)
            .padding([4, 6])
            .on_press(Message::EvtToggle(e.record_id))
            .into()
        });
        col.push(scrollable(column(rows).spacing(2)).height(Length::Fill))
            .push(
                text(format!("{} events, newest first (max 200)", list.len()))
                    .size(12)
                    .style(text::secondary),
            )
            .into()
    }

    fn svcs_view(&self) -> Element<'_, Message> {
        let list = match &self.svcs {
            None => return centered("Loading services…"),
            Some((_, Err(e))) => return error_box(e),
            Some((_, Ok(list))) => list,
        };
        let f = self.svc_filter.to_lowercase();
        let shown: Vec<&ServiceEntry> = list
            .iter()
            .filter(|s| {
                f.is_empty()
                    || s.name.to_lowercase().contains(&f)
                    || s.display_name.to_lowercase().contains(&f)
                    || s.state.contains(&f)
            })
            .collect();

        let small = |label: &'static str, msg: Option<Message>| {
            button(text(label).size(12))
                .style(button::subtle)
                .padding([2, 6])
                .on_press_maybe(msg.filter(|_| !self.svc_busy))
        };
        let header = row![
            text("Service").size(12).width(Length::FillPortion(4)),
            text("State").size(12).width(Length::FillPortion(2)),
            text("Startup").size(12).width(Length::FillPortion(2)),
            text("Account").size(12).width(Length::FillPortion(3)),
            Space::new().width(170),
        ]
        .spacing(4);
        // shortcut: renders every matching row (~300); virtualize with T-307.
        let rows = shown.iter().map(|s| {
            let ctl =
                |a: ServiceAction| Some(Message::SvcAsk(SvcChange::Control(s.name.clone(), a)));
            let running = s.state == "running";
            let stopped = s.state == "stopped";
            let name = s.name.clone();
            let startup: Element<_> = match s.start_type {
                Some(st @ (StartType::Automatic | StartType::Manual | StartType::Disabled)) => {
                    pick_list(
                        START_CHOICES,
                        Some(StartChoice(st)),
                        move |c: StartChoice| {
                            Message::SvcAsk(SvcChange::StartType(name.clone(), c.0))
                        },
                    )
                    .text_size(12)
                    .padding([2, 6])
                    .into()
                }
                Some(other) => text(StartChoice(other).to_string()).size(13).into(),
                None => text("—").size(13).into(),
            };
            row![
                column![
                    text(&s.display_name).size(13),
                    text(&s.name).size(11).style(text::secondary)
                ]
                .width(Length::FillPortion(4)),
                text(s.state.replace('_', " "))
                    .size(13)
                    .width(Length::FillPortion(2)),
                container(startup).width(Length::FillPortion(2)),
                text(s.account.as_deref().unwrap_or("—"))
                    .size(12)
                    .width(Length::FillPortion(3)),
                row![
                    small(
                        "Start",
                        stopped.then(|| ctl(ServiceAction::Start)).flatten()
                    ),
                    small(
                        "Stop",
                        (running && s.can_stop)
                            .then(|| ctl(ServiceAction::Stop))
                            .flatten()
                    ),
                    small(
                        "Restart",
                        (running && s.can_stop)
                            .then(|| ctl(ServiceAction::Restart))
                            .flatten()
                    ),
                ]
                .spacing(2)
                .width(170),
            ]
            .spacing(4)
            .align_y(Alignment::Center)
            .into()
        });

        let mut col = column![
            text_input("Filter by name or state…", &self.svc_filter)
                .on_input(Message::SvcFilter)
                .padding(8),
        ]
        .spacing(6);
        if let Some(change) = &self.svc_confirm {
            col = col.push(
                container(
                    column![
                        text(format!(
                            "{}? Users and programs relying on it may be interrupted.",
                            change.describe()
                        )),
                        row![
                            button(text("Confirm"))
                                .style(button::danger)
                                .on_press(Message::SvcConfirm),
                            button(text("Cancel"))
                                .style(button::secondary)
                                .on_press(Message::SvcCancel),
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
        if self.svc_busy {
            col = col.push(
                text("Working on the agent…")
                    .size(13)
                    .style(text::secondary),
            );
        }
        if let Some(n) = &self.svc_notice {
            col = col.push(match n {
                Ok(m) => text(m.clone()).size(13).style(text::success),
                Err(e) => text(e.clone()).size(13).style(text::danger),
            });
        }
        col.push(container(header).style(container::rounded_box))
            .push(scrollable(column(rows).spacing(4)).height(Length::Fill))
            .push(
                text(format!("{} of {} services", shown.len(), list.len()))
                    .size(12)
                    .style(text::secondary),
            )
            .into()
    }

    fn procs_view(&self) -> Element<'_, Message> {
        let list = match &self.procs {
            None => return centered("Loading processes…"),
            Some((_, Err(e))) => return error_box(e),
            Some((_, Ok(list))) => list,
        };
        let f = self.proc_filter.to_lowercase();
        let mut shown: Vec<&ProcessInfo> = list
            .iter()
            .filter(|p| {
                f.is_empty()
                    || p.name.to_lowercase().contains(&f)
                    || p.pid.to_string() == f
                    || p.user
                        .as_deref()
                        .is_some_and(|u| u.to_lowercase().contains(&f))
            })
            .collect();
        match self.proc_sort {
            ProcSort::Cpu => shown.sort_by(|a, b| b.cpu_percent.total_cmp(&a.cpu_percent)),
            ProcSort::Memory => shown.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes)),
            ProcSort::Name => shown.sort_by_key(|p| p.name.to_lowercase()),
            ProcSort::Pid => shown.sort_by_key(|p| p.pid),
        }

        let head = |label: &'static str, s: ProcSort, w: u16| {
            button(
                text(if self.proc_sort == s {
                    format!("{label} ▾")
                } else {
                    label.to_string()
                })
                .size(12),
            )
            .style(button::text)
            .padding([2, 4])
            .width(Length::FillPortion(w))
            .on_press(Message::ProcSort(s))
        };
        let header = row![
            head("Name", ProcSort::Name, 4),
            head("PID", ProcSort::Pid, 1),
            text("User").size(12).width(Length::FillPortion(3)),
            head("CPU", ProcSort::Cpu, 1),
            head("Memory", ProcSort::Memory, 2),
            text("Arch").size(12).width(Length::FillPortion(1)),
            Space::new().width(70),
        ]
        .spacing(4);

        // shortcut: renders every matching row (a few hundred); virtualize with T-307.
        let rows = shown.iter().map(|p| {
            row![
                text(&p.name).size(13).width(Length::FillPortion(4)),
                text(p.pid.to_string())
                    .size(13)
                    .width(Length::FillPortion(1)),
                text(p.user.as_deref().unwrap_or("—"))
                    .size(13)
                    .width(Length::FillPortion(3)),
                text(format!("{:.1}%", p.cpu_percent))
                    .size(13)
                    .width(Length::FillPortion(1)),
                text(format!("{:.1} MB", p.memory_bytes as f64 / 1_048_576.0))
                    .size(13)
                    .width(Length::FillPortion(2)),
                text(p.arch.as_deref().unwrap_or("—"))
                    .size(13)
                    .width(Length::FillPortion(1)),
                button(text("Terminate").size(12))
                    .style(button::subtle)
                    .width(70)
                    .on_press(Message::KillAsk(p.pid, p.name.clone())),
            ]
            .spacing(4)
            .align_y(Alignment::Center)
            .into()
        });

        let mut col = column![
            text_input("Filter by name, PID or user…", &self.proc_filter)
                .on_input(Message::ProcFilter)
                .padding(8),
        ]
        .spacing(6);
        if let Some((pid, name)) = &self.confirm_kill {
            col = col.push(
                container(
                    column![
                        text(format!(
                            "Terminate {name} (PID {pid})? Unsaved work in it will be lost."
                        )),
                        row![
                            button(text("Terminate"))
                                .style(button::danger)
                                .on_press(Message::KillConfirm),
                            button(text("Cancel"))
                                .style(button::secondary)
                                .on_press(Message::KillCancel),
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
        if let Some(n) = &self.kill_notice {
            col = col.push(match n {
                Ok(m) => text(m.clone()).size(13).style(text::success),
                Err(e) => text(e.clone()).size(13).style(text::danger),
            });
        }
        col.push(container(header).style(container::rounded_box))
            .push(scrollable(column(rows).spacing(2)).height(Length::Fill))
            .push(
                text(format!("{} of {} processes", shown.len(), list.len()))
                    .size(12)
                    .style(text::secondary),
            )
            .into()
    }

    fn settings_view(&self) -> Element<'_, Message> {
        let mut col = column![
            text("Settings").size(22),
            text("Server URL").size(13),
            text_input("http://server:8470", &self.draft.server_url)
                .on_input(Message::ServerUrlChanged)
                .padding(10),
            text("Technician token").size(13),
            text_input(
                "from `tervano-server tech create --name <you>`",
                &self.draft.token
            )
            .on_input(Message::TokenChanged)
            .on_submit(Message::SaveSettings)
            .secure(true)
            .padding(10),
            text("CA certificate (optional)").size(13),
            text_input(
                "Path to ca.pem — only if the server uses a private CA",
                &self.draft.ca_cert
            )
            .on_input(Message::CaCertChanged)
            .on_submit(Message::SaveSettings)
            .padding(10),
            Space::new().height(8),
            text("Direct connections (serverless)").size(15),
            text("Technician certificate").size(13),
            text_input(
                "Path to tech-<you>.pem from `tervano-server cert tech --name <you>`",
                &self.draft.tech_cert
            )
            .on_input(Message::TechCertChanged)
            .on_submit(Message::SaveSettings)
            .padding(10),
            text("Technician key").size(13),
            text_input("Path to tech-<you>-key.pem", &self.draft.tech_key)
                .on_input(Message::TechKeyChanged)
                .on_submit(Message::SaveSettings)
                .padding(10),
            button(text("Save"))
                .padding([10, 16])
                .style(button::primary)
                .on_press(Message::SaveSettings),
        ]
        .spacing(8)
        .max_width(520);
        if let Some(status) = &self.settings_status {
            col = col.push(match status {
                Ok(m) => text(m.clone()).style(text::success),
                Err(e) => text(format!("Could not save settings: {e}")).style(text::danger),
            });
        }
        col.into()
    }
}

fn trust_panel(p: &PendingTrust) -> Element<'_, Message> {
    let body: Element<_> = match &p.fingerprint {
        None => text(format!("Contacting {}…", p.address)).into(),
        Some(Err(e)) => column![
            text(e.clone()).style(text::danger),
            button(text("Dismiss")).style(button::secondary).on_press(Message::DirectCancel),
        ]
        .spacing(8)
        .into(),
        Some(Ok(fp)) => column![
            text(format!("{} presents this certificate fingerprint:", p.address)),
            text(direct::display_fingerprint(fp)).size(15).font(iced::Font::MONOSPACE),
            text("Before trusting it, compare with the output of `TervanoAgent direct-fingerprint` on that computer. A mismatch means you may be talking to something else.")
                .size(12)
                .style(text::secondary),
            row![
                button(text("Trust and add")).style(button::primary).on_press(Message::DirectTrust),
                button(text("Cancel")).style(button::secondary).on_press(Message::DirectCancel),
            ]
            .spacing(8),
        ]
        .spacing(8)
        .into(),
    };
    container(body)
        .padding(12)
        .width(Length::Fill)
        .style(container::bordered_box)
        .into()
}

/// Device summary, sessions and network, shared by server-backed and direct views.
fn state_panel<'a>(
    s: &'a DeviceState,
    online: bool,
    status: &'a str,
    extra: Vec<(&'a str, String)>,
) -> Element<'a, Message> {
    let kv =
        |k: &'a str, v: String| row![text(k).width(120).style(text::secondary), text(v)].spacing(8);
    let section = |title: &'a str| text(title).size(13).style(text::primary);

    let mut sessions = column![section("Active users")].spacing(4);
    if s.sessions.is_empty() {
        sessions = sessions.push(text("No one is signed in.").style(text::secondary));
    }
    for u in &s.sessions {
        let state = match u.state {
            SessionState::Active => "active",
            SessionState::Disconnected => "disconnected",
            SessionState::Other => "other",
        };
        sessions = sessions.push(text(format!(
            "{}\\{}  ·  {}  ·  {state}",
            u.domain, u.username, u.station
        )));
    }

    let mut net = column![section("Network")].spacing(4);
    for a in &s.addresses {
        net = net.push(
            row![
                text(&a.interface).width(120).style(text::secondary),
                text(&a.address)
            ]
            .spacing(8),
        );
    }

    let mut summary = column![
        section("Summary"),
        kv(
            "Domain",
            s.domain.clone().unwrap_or_else(|| "Workgroup".into())
        ),
        kv("OS", s.os.name.clone()),
        kv(
            "Version",
            format!("{} (build {})", s.os.version, s.os.build)
        ),
        kv("Agent", s.agent_version.clone()),
    ]
    .spacing(8);
    for (k, v) in extra {
        summary = summary.push(kv(k, v));
    }

    scrollable(
        column![
            row![status_dot(online), text(&s.hostname).size(22)]
                .spacing(8)
                .align_y(Alignment::Center),
            text(status).size(12).style(text::secondary),
            rule::horizontal(1),
            summary,
            rule::horizontal(1),
            sessions,
            rule::horizontal(1),
            net,
        ]
        .spacing(8),
    )
    .into()
}

fn downloads_dir() -> Option<std::path::PathBuf> {
    Some(std::path::PathBuf::from(std::env::var_os("USERPROFILE")?).join("Downloads"))
}

/// Writes the current event results as CSV into `dir` and says where.
fn export_events_csv(
    dir: &std::path::Path,
    addr: &str,
    channel: &str,
    list: &[EventRecord],
) -> Result<String, String> {
    // Leading = + - @ would make spreadsheets evaluate the cell as a formula (CSV injection).
    let quote = |s: &str| {
        let s = if s.starts_with(['=', '+', '-', '@']) {
            format!("'{s}")
        } else {
            s.to_owned()
        };
        format!("\"{}\"", s.replace('"', "\"\""))
    };
    let mut csv = String::from("time_utc_ms,level,provider,event_id,record_id,message\r\n");
    for e in list {
        csv.push_str(&format!(
            "{},{},{},{},{},{}\r\n",
            e.time,
            level_name(e.level),
            quote(&e.provider),
            e.event_id,
            e.record_id,
            quote(e.message.as_deref().unwrap_or(""))
        ));
    }
    let safe = |s: &str| -> String {
        s.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect()
    };
    let path = dir.join(format!(
        "tervano-events-{}-{}-{}.csv",
        safe(addr),
        safe(channel),
        now_millis()
    ));
    std::fs::write(&path, csv).map_err(|e| format!("Export failed: {e}"))?;
    Ok(format!(
        "Exported {} events to {}",
        list.len(),
        path.display()
    ))
}

fn status_dot<'a>(online: bool) -> Element<'a, Message> {
    let color = if online {
        Color::from_rgb8(0x2e, 0xa0, 0x43)
    } else {
        Color::from_rgb8(0x8a, 0x8f, 0x98)
    };
    container(Space::new().width(10).height(10))
        .style(move |_| container::Style {
            background: Some(color.into()),
            border: iced::border::rounded(5),
            ..Default::default()
        })
        .width(14)
        .into()
}

fn centered<'a>(msg: &'a str) -> Element<'a, Message> {
    container(text(msg).style(text::secondary))
        .center(Length::Fill)
        .into()
}

fn error_box<'a>(e: &'a str) -> Element<'a, Message> {
    container(column![text("Something went wrong").size(15), text(e).size(13)].spacing(4))
        .padding(12)
        .width(Length::Fill)
        .style(container::danger)
        .into()
}

/// "12s ago", "5m ago", ... `0` means never.
fn ago(at: Millis) -> String {
    if at <= 0 {
        return "never".into();
    }
    let s = ((now_millis() - at) / 1000).max(0);
    match s {
        0..60 => format!("{s}s ago"),
        60..3600 => format!("{}m ago", s / 60),
        3600..86400 => format!("{}h ago", s / 3600),
        _ => format!("{}d ago", s / 86400),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ago_buckets() {
        let now = tervano_protocol::now_millis();
        assert_eq!(super::ago(0), "never");
        assert_eq!(super::ago(now - 5_000), "5s ago");
        assert_eq!(super::ago(now - 125_000), "2m ago");
        assert_eq!(super::ago(now - 2 * 86_400_000), "2d ago");
    }
}
