//! Device groups on the Devices page (T-801): filter the list by a group, save the ticked devices
//! or the current search as a group, and edit static groups. Ticking a whole group then feeds the
//! Jobs page like any other selection.

use crate::{Console, Message};
use iced::widget::{Space, button, column, container, pick_list, row, text, text_input};
use iced::{Alignment, Element, Length, Task};
use tervano_protocol::*;
use uuid::Uuid;

pub struct GroupsState {
    list: Option<Result<Vec<DeviceGroup>, String>>,
    /// The group the device list is filtered by.
    pub active: Option<Uuid>,
    name: String,
    confirm_delete: bool,
    notice: Option<Result<String, String>>,
}

impl GroupsState {
    pub fn new() -> Self {
        Self {
            list: None,
            active: None,
            name: String::new(),
            confirm_delete: false,
            notice: None,
        }
    }

    fn active_group(&self) -> Option<&DeviceGroup> {
        let id = self.active?;
        self.list
            .as_ref()?
            .as_ref()
            .ok()?
            .iter()
            .find(|g| g.id == id)
    }
}

/// Entry of the group picker; `None` = all devices.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupChoice(Option<DeviceGroup>);

impl std::fmt::Display for GroupChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            None => f.write_str("All devices"),
            Some(g) => match (&g.kind, &g.query, g.members) {
                (GroupKind::Query, Some(q), _) => write!(f, "{} (search: {q})", g.name),
                (_, _, Some(n)) => write!(f, "{} ({n})", g.name),
                _ => f.write_str(&g.name),
            },
        }
    }
}

#[derive(Debug, Clone)]
pub enum GroupMsg {
    Loaded(Result<Vec<DeviceGroup>, String>),
    Pick(GroupChoice),
    Name(String),
    SaveSelection,
    SaveSearch,
    Saved(Result<DeviceGroup, String>),
    AddSelected,
    RemoveSelected,
    Changed(Result<DeviceGroup, String>),
    AskDelete,
    CancelDelete,
    ConfirmDelete,
    Deleted(Result<(), String>),
}

impl Console {
    pub(crate) fn load_groups(&self) -> Task<Message> {
        let client = self.client();
        Task::perform(async move { client?.groups().await }, |r| {
            Message::Group(GroupMsg::Loaded(r))
        })
    }

    pub(crate) fn groups_update(&mut self, msg: GroupMsg) -> Task<Message> {
        let g = &mut self.groups;
        match msg {
            GroupMsg::Loaded(r) => {
                // A group deleted elsewhere stops filtering the list.
                if let (Ok(list), Some(active)) = (&r, g.active)
                    && !list.iter().any(|x| x.id == active)
                {
                    g.active = None;
                    g.list = Some(r);
                    return self.search();
                }
                g.list = Some(r);
            }
            GroupMsg::Pick(GroupChoice(choice)) => {
                g.active = choice.map(|x| x.id);
                g.confirm_delete = false;
                g.notice = None;
                return self.search();
            }
            GroupMsg::Name(s) => g.name = s,
            GroupMsg::SaveSelection | GroupMsg::SaveSearch => {
                let name = g.name.trim().to_owned();
                if name.is_empty() {
                    g.notice = Some(Err("Type a name for the new group first.".into()));
                    return Task::none();
                }
                let req = if matches!(msg, GroupMsg::SaveSelection) {
                    if self.jobs.selected.is_empty() {
                        g.notice = Some(Err("Tick some devices first.".into()));
                        return Task::none();
                    }
                    GroupCreate {
                        name,
                        kind: GroupKind::Static,
                        query: None,
                        devices: self.jobs.selected.keys().copied().collect(),
                    }
                } else {
                    if self.query.trim().is_empty() {
                        g.notice = Some(Err("Search for something first.".into()));
                        return Task::none();
                    }
                    GroupCreate {
                        name,
                        kind: GroupKind::Query,
                        query: Some(self.query.trim().to_owned()),
                        devices: Vec::new(),
                    }
                };
                let client = self.client();
                return Task::perform(async move { client?.create_group(&req).await }, |r| {
                    Message::Group(GroupMsg::Saved(r))
                });
            }
            GroupMsg::Saved(r) => match r {
                Ok(group) => {
                    g.notice = Some(Ok(format!("Saved group \"{}\".", group.name)));
                    g.name.clear();
                    return self.load_groups();
                }
                Err(e) => g.notice = Some(Err(e)),
            },
            GroupMsg::AddSelected | GroupMsg::RemoveSelected => {
                let Some(id) = g.active else {
                    return Task::none();
                };
                let ids: Vec<Uuid> = self.jobs.selected.keys().copied().collect();
                let change = if matches!(msg, GroupMsg::AddSelected) {
                    GroupMembers {
                        add: ids,
                        remove: Vec::new(),
                    }
                } else {
                    GroupMembers {
                        add: Vec::new(),
                        remove: ids,
                    }
                };
                let client = self.client();
                return Task::perform(
                    async move { client?.change_members(id, &change).await },
                    |r| Message::Group(GroupMsg::Changed(r)),
                );
            }
            GroupMsg::Changed(r) => {
                g.notice = Some(r.map(|group| {
                    format!(
                        "\"{}\" now has {} device(s).",
                        group.name,
                        group.members.unwrap_or(0)
                    )
                }));
                return Task::batch([self.load_groups(), self.search()]);
            }
            GroupMsg::AskDelete => g.confirm_delete = true,
            GroupMsg::CancelDelete => g.confirm_delete = false,
            GroupMsg::ConfirmDelete => {
                g.confirm_delete = false;
                let Some(id) = g.active else {
                    return Task::none();
                };
                let client = self.client();
                return Task::perform(async move { client?.delete_group(id).await }, |r| {
                    Message::Group(GroupMsg::Deleted(r))
                });
            }
            GroupMsg::Deleted(r) => match r {
                Ok(()) => {
                    g.notice = Some(Ok("Group deleted. Its devices are not affected.".into()));
                    g.active = None;
                    return Task::batch([self.load_groups(), self.search()]);
                }
                Err(e) => g.notice = Some(Err(e)),
            },
        }
        Task::none()
    }

    /// Group picker and group actions, above the device search.
    pub(crate) fn groups_bar(&self) -> Element<'_, Message> {
        let g = &self.groups;
        let mut choices = vec![GroupChoice(None)];
        if let Some(Ok(list)) = &g.list {
            choices.extend(list.iter().cloned().map(Some).map(GroupChoice));
        }
        let current = GroupChoice(g.active_group().cloned());
        let n = self.jobs.selected.len();
        let mut bar = row![
            text("Group").size(13),
            pick_list(choices, Some(current), |c| Message::Group(GroupMsg::Pick(
                c
            )))
            .text_size(13)
            .width(260),
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        // Hidden rather than refused: the server enforces the same rule (T-806).
        if self.can_edit_groups() {
            match g.active_group() {
                Some(active) => {
                    if active.kind == GroupKind::Static {
                        bar = bar
                            .push(
                                button(text(format!("Add {n} ticked")).size(13))
                                    .style(button::secondary)
                                    .on_press_maybe(
                                        (n > 0).then_some(Message::Group(GroupMsg::AddSelected)),
                                    ),
                            )
                            .push(
                                button(text(format!("Remove {n} ticked")).size(13))
                                    .style(button::secondary)
                                    .on_press_maybe(
                                        (n > 0).then_some(Message::Group(GroupMsg::RemoveSelected)),
                                    ),
                            );
                    }
                    bar = bar.push(Space::new().width(Length::Fill)).push(
                        button(text("Delete group").size(13))
                            .style(button::danger)
                            .on_press(Message::Group(GroupMsg::AskDelete)),
                    );
                }
                None => {
                    bar = bar
                        .push(Space::new().width(Length::Fill))
                        .push(
                            text_input("New group name", &g.name)
                                .on_input(|s| Message::Group(GroupMsg::Name(s)))
                                .size(13)
                                .padding(6)
                                .width(180),
                        )
                        .push(
                            button(text(format!("Save {n} ticked")).size(13))
                                .style(button::secondary)
                                .on_press_maybe(
                                    (n > 0).then_some(Message::Group(GroupMsg::SaveSelection)),
                                ),
                        )
                        .push(
                            button(text("Save search").size(13))
                                .style(button::secondary)
                                .on_press_maybe(
                                    (!self.query.trim().is_empty())
                                        .then_some(Message::Group(GroupMsg::SaveSearch)),
                                ),
                        );
                }
            }
        }
        let mut col = column![bar].spacing(6);
        if g.confirm_delete
            && let Some(active) = g.active_group()
        {
            col = col.push(
                container(
                    row![
                        text(format!(
                            "Delete group \"{}\"? Devices and jobs are not affected.",
                            active.name
                        ))
                        .size(13),
                        Space::new().width(Length::Fill),
                        button(text("Delete").size(13))
                            .style(button::danger)
                            .on_press(Message::Group(GroupMsg::ConfirmDelete)),
                        button(text("Cancel").size(13))
                            .style(button::secondary)
                            .on_press(Message::Group(GroupMsg::CancelDelete)),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                )
                .padding(8)
                .width(Length::Fill)
                .style(container::bordered_box),
            );
        }
        match &g.notice {
            Some(Ok(m)) => col = col.push(text(m.clone()).size(12).style(text::success)),
            Some(Err(e)) => col = col.push(text(e.clone()).size(12).style(text::danger)),
            None => {}
        }
        if let Some(Err(e)) = &g.list {
            col = col.push(
                text(format!("Groups unavailable: {e}"))
                    .size(12)
                    .style(text::danger),
            );
        }
        col.into()
    }
}
