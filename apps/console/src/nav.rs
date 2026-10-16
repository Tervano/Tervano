//! Fast navigation (T-308, T-309): favorites, recently opened devices and recent searches on the
//! Devices page, plus keyboard control — Ctrl+K search, ↑/↓ through results, Esc to close, and a
//! Ctrl+P command palette for pages, actions and devices.

use crate::{Console, Message, Page};
use iced::keyboard::{self, Key, key::Named};
use iced::widget::{Id, Space, button, column, container, row, scrollable, text, text_input};
use iced::{Alignment, Element, Length, Task};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_RECENT: usize = 10;
const MAX_FAVORITES: usize = 50;
const MAX_HISTORY: usize = 10;
const PALETTE_ROWS: usize = 10;

pub fn search_id() -> Id {
    Id::new("device-search")
}

fn palette_id() -> Id {
    Id::new("command-palette")
}

/// A device remembered in the Console settings (favorites, recents).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SavedDevice {
    pub id: Uuid,
    pub hostname: String,
}

#[derive(Debug, Clone)]
enum Command {
    Page(Page),
    NewJob,
    ToggleTheme,
    Refresh,
    Open(Uuid, String),
    Search(String),
}

impl Command {
    fn label(&self, favorite: bool) -> String {
        match self {
            Command::Page(p) => format!(
                "Go to {}",
                match p {
                    Page::Devices => "Devices",
                    Page::Jobs => "Jobs",
                    Page::Reports => "Reports",
                    Page::Direct => "Direct",
                    Page::Settings => "Settings",
                }
            ),
            Command::NewJob => "New job for the ticked devices".into(),
            Command::ToggleTheme => "Switch light/dark theme".into(),
            Command::Refresh => "Refresh the device list".into(),
            // The words "favorite"/"recent" make these findable by typing them.
            Command::Open(_, host) if favorite => format!("Open ★ {host} · favorite"),
            Command::Open(_, host) => format!("Open {host} · recent"),
            Command::Search(q) => format!("Search devices for \"{q}\""),
        }
    }
}

#[derive(Default)]
pub struct NavState {
    palette_open: bool,
    palette_query: String,
    palette_index: usize,
}

#[derive(Debug, Clone)]
pub enum NavMsg {
    Key(keyboard::Event),
    ToggleFavorite(Uuid, String),
    Open(Uuid),
    SearchFor(String),
    PaletteQuery(String),
    PaletteRun(Option<usize>),
    PaletteClose,
}

impl Console {
    /// Remembers an opened device at the top of the recent list.
    pub(crate) fn remember_device(&mut self, id: Uuid, hostname: &str) {
        // Details reload on every live update; only a change of the top entry is worth a save.
        if self
            .settings
            .recent
            .first()
            .is_some_and(|d| d.id == id && d.hostname == hostname)
        {
            return;
        }
        let recent = &mut self.settings.recent;
        recent.retain(|d| d.id != id);
        recent.insert(
            0,
            SavedDevice {
                id,
                hostname: hostname.to_owned(),
            },
        );
        recent.truncate(MAX_RECENT);
        self.persist_nav();
    }

    pub(crate) fn remember_search(&mut self, q: &str) {
        let q = q.trim();
        if q.is_empty() {
            return;
        }
        let history = &mut self.settings.search_history;
        history.retain(|h| h != q);
        history.insert(0, q.to_owned());
        history.truncate(MAX_HISTORY);
        self.persist_nav();
    }

    pub(crate) fn is_favorite(&self, id: Uuid) -> bool {
        self.settings.favorites.iter().any(|d| d.id == id)
    }

    fn persist_nav(&mut self) {
        // The draft must not overwrite these on the next settings save.
        self.draft.favorites = self.settings.favorites.clone();
        self.draft.recent = self.settings.recent.clone();
        self.draft.search_history = self.settings.search_history.clone();
        if let Err(e) = self.settings.save() {
            tracing::warn!("saving navigation history failed: {e}");
        }
    }

    pub(crate) fn nav_update(&mut self, msg: NavMsg) -> Task<Message> {
        match msg {
            NavMsg::Key(event) => return self.on_key(event),
            NavMsg::ToggleFavorite(id, hostname) => {
                if self.is_favorite(id) {
                    self.settings.favorites.retain(|d| d.id != id);
                } else if self.settings.favorites.len() < MAX_FAVORITES {
                    self.settings.favorites.push(SavedDevice { id, hostname });
                    self.settings
                        .favorites
                        .sort_by_key(|d| d.hostname.to_lowercase());
                }
                self.persist_nav();
            }
            NavMsg::Open(id) => {
                self.page = Page::Devices;
                return self.update(Message::Select(id));
            }
            NavMsg::SearchFor(q) => {
                self.page = Page::Devices;
                self.query = q;
                return self.update(Message::Search);
            }
            NavMsg::PaletteQuery(q) => {
                self.nav.palette_query = q;
                self.nav.palette_index = 0;
            }
            NavMsg::PaletteRun(index) => {
                let commands = self.palette_matches();
                let Some(cmd) = commands
                    .get(index.unwrap_or(self.nav.palette_index))
                    .map(|(c, _)| c.clone())
                else {
                    return Task::none();
                };
                self.close_palette();
                return self.run(cmd);
            }
            NavMsg::PaletteClose => self.close_palette(),
        }
        Task::none()
    }

    fn close_palette(&mut self) {
        self.nav = NavState::default();
    }

    fn run(&mut self, cmd: Command) -> Task<Message> {
        match cmd {
            Command::Page(p) => self.update(Message::Nav(p)),
            Command::NewJob => self.update(Message::Job(crate::jobs::JobMsg::NewForm)),
            Command::ToggleTheme => self.update(Message::ToggleTheme),
            Command::Refresh => {
                self.page = Page::Devices;
                self.update(Message::Search)
            }
            Command::Open(id, _) => self.nav_update(NavMsg::Open(id)),
            Command::Search(q) => self.nav_update(NavMsg::SearchFor(q)),
        }
    }

    fn on_key(&mut self, event: keyboard::Event) -> Task<Message> {
        let keyboard::Event::KeyPressed { key, modifiers, .. } = event else {
            return Task::none();
        };
        match key.as_ref() {
            Key::Character("k") if modifiers.command() => {
                self.close_palette();
                self.page = Page::Devices;
                iced::widget::operation::focus(search_id())
            }
            Key::Character("p") if modifiers.command() => {
                self.nav = NavState {
                    palette_open: true,
                    ..NavState::default()
                };
                iced::widget::operation::focus(palette_id())
            }
            Key::Named(Named::Escape) if self.nav.palette_open => {
                self.close_palette();
                Task::none()
            }
            Key::Named(Named::Escape) if self.page == Page::Devices && self.selected.is_some() => {
                self.selected = None;
                self.details = None;
                Task::none()
            }
            Key::Named(dir @ (Named::ArrowDown | Named::ArrowUp)) => {
                let down = dir == Named::ArrowDown;
                if self.nav.palette_open {
                    let n = self.palette_matches().len();
                    if n > 0 {
                        let i = self.nav.palette_index;
                        self.nav.palette_index = if down { (i + 1) % n } else { (i + n - 1) % n };
                    }
                    return Task::none();
                }
                if self.page != Page::Devices {
                    return Task::none();
                }
                let Ok(devices) = &self.devices else {
                    return Task::none();
                };
                if devices.is_empty() {
                    return Task::none();
                }
                let pos = self
                    .selected
                    .and_then(|s| devices.iter().position(|d| d.id == s));
                let next = match (pos, down) {
                    (None, true) => 0,
                    (None, false) => devices.len() - 1,
                    (Some(i), true) => (i + 1).min(devices.len() - 1),
                    (Some(i), false) => i.saturating_sub(1),
                };
                let id = devices[next].id;
                if Some(id) == self.selected {
                    return Task::none();
                }
                self.update(Message::Select(id))
            }
            _ => Task::none(),
        }
    }

    /// Commands matching the palette text (every word must appear), best first.
    fn palette_matches(&self) -> Vec<(Command, bool)> {
        let q = self.nav.palette_query.trim().to_lowercase();
        let words: Vec<&str> = q.split_whitespace().collect();
        let mut all: Vec<(Command, bool)> = Vec::new();
        for d in &self.settings.favorites {
            all.push((Command::Open(d.id, d.hostname.clone()), true));
        }
        for d in &self.settings.recent {
            if !self.is_favorite(d.id) {
                all.push((Command::Open(d.id, d.hostname.clone()), false));
            }
        }
        for p in [
            Page::Devices,
            Page::Jobs,
            Page::Reports,
            Page::Direct,
            Page::Settings,
        ] {
            all.push((Command::Page(p), false));
        }
        all.push((Command::NewJob, false));
        all.push((Command::Refresh, false));
        all.push((Command::ToggleTheme, false));
        let mut matches: Vec<(Command, bool)> = all
            .into_iter()
            .filter(|(c, fav)| {
                let label = c.label(*fav).to_lowercase();
                words.iter().all(|w| label.contains(w))
            })
            .collect();
        if !q.is_empty() {
            matches.push((
                Command::Search(self.nav.palette_query.trim().to_owned()),
                false,
            ));
        }
        matches
    }

    /// Favorites, recent devices and recent searches, shown above the list when not searching.
    pub(crate) fn quick_access(&self) -> Option<Element<'_, Message>> {
        if !self.query.trim().is_empty() || self.groups.active.is_some() {
            return None;
        }
        let s = &self.settings;
        if s.favorites.is_empty() && s.recent.is_empty() && s.search_history.is_empty() {
            return None;
        }
        let chip = |label: String, msg: Message| {
            button(text(label).size(12))
                .padding([3, 8])
                .style(button::secondary)
                .on_press(msg)
        };
        let line = |title: &'static str, chips: Vec<Element<'static, Message>>| {
            row![text(title).size(12).style(text::secondary).width(110)]
                .push(row(chips).spacing(6).wrap().vertical_spacing(6))
                .spacing(8)
                .align_y(Alignment::Center)
        };
        let mut col = column![].spacing(6);
        if !s.favorites.is_empty() {
            col = col.push(line(
                "Favorites",
                s.favorites
                    .iter()
                    .map(|d| {
                        chip(
                            format!("★ {}", d.hostname),
                            Message::Navigate(NavMsg::Open(d.id)),
                        )
                        .into()
                    })
                    .collect(),
            ));
        }
        if !s.recent.is_empty() {
            col = col.push(line(
                "Recent",
                s.recent
                    .iter()
                    .map(|d| chip(d.hostname.clone(), Message::Navigate(NavMsg::Open(d.id))).into())
                    .collect(),
            ));
        }
        if !s.search_history.is_empty() {
            col = col.push(line(
                "Recent searches",
                s.search_history
                    .iter()
                    .map(|q| {
                        chip(
                            format!("\"{q}\""),
                            Message::Navigate(NavMsg::SearchFor(q.clone())),
                        )
                        .into()
                    })
                    .collect(),
            ));
        }
        Some(col.into())
    }

    /// Favorite toggle for the details panel.
    pub(crate) fn favorite_button(&self, id: Uuid, hostname: &str) -> Element<'_, Message> {
        let fav = self.is_favorite(id);
        button(
            text(if fav {
                "★ Favorite"
            } else {
                "☆ Add to favorites"
            })
            .size(12),
        )
        .padding([3, 8])
        .style(if fav {
            button::primary
        } else {
            button::secondary
        })
        .on_press(Message::Navigate(NavMsg::ToggleFavorite(
            id,
            hostname.to_owned(),
        )))
        .into()
    }

    /// The command palette, drawn over the page while open.
    pub(crate) fn palette(&self) -> Option<Element<'_, Message>> {
        if !self.nav.palette_open {
            return None;
        }
        let matches = self.palette_matches();
        let rows: Vec<Element<_>> = matches
            .iter()
            .take(PALETTE_ROWS)
            .enumerate()
            .map(|(i, (c, fav))| {
                button(text(c.label(*fav)).size(14))
                    .width(Length::Fill)
                    .padding([6, 10])
                    .style(if i == self.nav.palette_index {
                        crate::selected_row
                    } else {
                        button::text
                    })
                    .on_press(Message::Navigate(NavMsg::PaletteRun(Some(i))))
                    .into()
            })
            .collect();
        let body: Element<_> = if rows.is_empty() {
            text("Nothing matches.")
                .size(13)
                .style(text::secondary)
                .into()
        } else {
            scrollable(column(rows).spacing(2))
                .height(Length::Shrink)
                .into()
        };
        let panel = container(
            column![
                text_input(
                    "Type a command, page or device… (Esc to close)",
                    &self.nav.palette_query
                )
                .id(palette_id())
                .on_input(|q| Message::Navigate(NavMsg::PaletteQuery(q)))
                .on_submit(Message::Navigate(NavMsg::PaletteRun(None)))
                .padding(10)
                .size(15),
                body,
                row![
                    text("↑/↓ choose · Enter run · Esc close")
                        .size(11)
                        .style(text::secondary),
                    Space::new().width(Length::Fill),
                    button(text("Close").size(12))
                        .padding([2, 8])
                        .style(button::subtle)
                        .on_press(Message::Navigate(NavMsg::PaletteClose)),
                ]
                .align_y(Alignment::Center),
            ]
            .spacing(8),
        )
        .padding(12)
        .width(560)
        .style(container::bordered_box);
        Some(
            container(column![Space::new().height(80), panel])
                .width(Length::Fill)
                .height(Length::Fill)
                .align_x(Alignment::Center)
                .into(),
        )
    }
}
