// Release builds are GUI-only; debug keeps a console for logs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod direct;

use iced::widget::{Space, button, column, container, row, rule, scrollable, text, text_input};
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

    fn load_direct(&self, address: &str) -> Task<Message> {
        let Some(ep) = self
            .settings
            .endpoints
            .iter()
            .find(|e| e.address == address)
        else {
            return Task::none();
        };
        let (addr, pin, creds) = (ep.address.clone(), ep.fingerprint.clone(), self.creds());
        Task::perform(direct::device(addr.clone(), pin, creds), move |r| {
            Message::DirectLoaded(addr.clone(), r)
        })
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
                self.direct_selected = Some(address.clone());
                return self.load_direct(&address);
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
                        state_panel(s, true, "Reachable directly · live from the agent", vec![])
                    }
                };
                row![
                    container(list).width(Length::FillPortion(3)),
                    rule::vertical(1),
                    container(panel)
                        .width(Length::FillPortion(2))
                        .padding([0, 8]),
                ]
                .spacing(12)
                .into()
            }
        };
        column![top, content].spacing(12).into()
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
