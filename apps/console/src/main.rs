// Release builds are GUI-only; debug keeps a console for logs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;

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
}

impl Console {
    fn boot() -> (Self, Task<Message>) {
        let settings = Settings::load();
        let configured = !settings.token.is_empty();
        let mut c = Console {
            draft: settings.clone(),
            settings,
            settings_status: None,
            page: if configured {
                Page::Devices
            } else {
                Page::Settings
            },
            query: String::new(),
            search_gen: 0,
            loading: false,
            devices: Ok(Vec::new()),
            selected: None,
            details: None,
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

    fn update(&mut self, msg: Message) -> Task<Message> {
        match msg {
            Message::Nav(p) => self.page = p,
            Message::QueryChanged(q) => self.query = q,
            Message::Search => return self.search(),
            Message::Refresh => {
                if self.page == Page::Devices && !self.settings.token.is_empty() && !self.loading {
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
                self.settings = self.draft.clone();
                self.settings_status = Some(self.settings.save().map(|_| "Saved.".into()));
                self.page = Page::Devices;
                return self.search();
            }
            Message::ToggleTheme => {
                self.settings.dark = !self.settings.dark;
                self.draft.dark = self.settings.dark;
                let _ = self.settings.save();
            }
        }
        Task::none()
    }

    fn subscription(&self) -> Subscription<Message> {
        // shortcut: 15 s polling until the server can push updates (T-113/T-310).
        iced::time::every(Duration::from_secs(15)).map(|_| Message::Refresh)
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
                        "{} device(s){}",
                        devices.len(),
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
        let s = &d.state;
        let kv = |k: &'a str, v: String| {
            row![text(k).width(120).style(text::secondary), text(v)].spacing(8)
        };
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

        scrollable(
            column![
                row![status_dot(d.online), text(&s.hostname).size(22)]
                    .spacing(8)
                    .align_y(Alignment::Center),
                text(if d.online { "Online" } else { "Offline" })
                    .size(12)
                    .style(text::secondary),
                rule::horizontal(1),
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
                kv("Last seen", ago(d.last_seen)),
                kv("Enrolled", ago(d.enrolled_at)),
                kv("Device ID", d.id.to_string()),
                rule::horizontal(1),
                sessions,
                rule::horizontal(1),
                net,
            ]
            .spacing(8),
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
            button(text("Save and connect"))
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
