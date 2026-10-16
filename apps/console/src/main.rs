// Release builds are GUI-only; debug keeps a console for logs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod compliance;
mod creds;
mod direct;
mod groups;
mod jobs;
mod reports;

use iced::widget::{
    Space, button, checkbox, column, container, pick_list, progress_bar, row, rule, scrollable,
    text, text_editor, text_input,
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
    /// Lives in Windows Credential Manager, never in console.toml (only read from it once to
    /// migrate older settings files).
    #[cfg_attr(windows, serde(skip_serializing))]
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
        let mut s: Settings = Self::path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_else(|| Settings {
                server_url: "http://127.0.0.1:8470".into(),
                ..Default::default()
            });
        if cfg!(windows) {
            if s.token.is_empty() {
                s.token = creds::load_token().unwrap_or_default();
            } else if s.save().is_ok() {
                // Older file with a plaintext token: save() moved it into Credential Manager and
                // rewrote the file without it.
                tracing::info!("moved the technician token into Windows Credential Manager");
            }
        }
        s
    }

    fn save(&self) -> Result<(), String> {
        // The credential is written first so a failure can't leave us with neither copy.
        creds::save_token(&self.token)?;
        let p = Self::path().ok_or("APPDATA not set")?;
        std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
        std::fs::write(p, toml::to_string(self).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Page {
    Devices,
    Jobs,
    Reports,
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
    InventoryDone(uuid::Uuid, Result<Option<InventoryReport>, String>),
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
    SwLoaded(String, Result<SoftwareInventory, String>),
    SwFilter(String),
    RegHive(HiveChoice),
    RegBits32(bool),
    RegPathInput(String),
    RegGo,
    RegUp,
    RegOpen(String),
    RegLoaded(String, Result<RegKeyContents, String>),
    RegFormName(String),
    RegFormType(RegType),
    RegFormData(String),
    RegEdit(RegValue),
    RegAskSet,
    RegAskDeleteValue(String),
    RegAskDeleteKey,
    RegRecursive(bool),
    RegConfirm,
    RegCancel,
    RegDone(Result<String, String>),
    RegExport,
    RegExported(Result<String, String>),
    CmdShell(ShellChoice),
    CmdEdit(text_editor::Action),
    CmdTimeout(String),
    CmdAskRun,
    CmdConfirm,
    CmdCancelConfirm,
    CmdUpdate(Result<ExecStatus, String>),
    CmdPoll,
    CmdStop,
    CmdStopped(Result<(), String>),
    FilesInput(String),
    FilesGo,
    FilesUp,
    FilesDrives,
    FilesOpen(String),
    FilesLoaded(String, Result<DirListing, String>),
    FilesDownload(String),
    FilesUploadPath(String),
    FilesOverwrite(bool),
    FilesUpload,
    FilesTransferDone(Result<String, String>),
    FilesNewFolder(String),
    FilesMkdir,
    FilesRenameStart(String),
    FilesRenameInput(String),
    FilesRenameApply,
    FilesAskDelete(String, bool),
    FilesRecursive(bool),
    FilesConfirm,
    FilesCancel,
    FilesOpDone(Result<String, String>),
    SwAskUninstall(String, UninstallRequest),
    SwMsiPath(String),
    SwAskInstall,
    SwConfirm,
    SwCancel,
    PeriphLoaded(String, Result<Peripherals, String>),
    WmiNamespace(String),
    WmiWql(String),
    WmiClassFilter(String),
    WmiPickClass(String),
    WmiRun,
    WmiLoaded(Result<WmiTable, String>),
    WmiClasses(Result<Vec<String>, String>),
    UpdatesLoaded(String, Result<UpdateStatus, String>),
    TermShell(ShellChoice),
    TermOpen,
    TermInput(String),
    TermSend,
    TermSent(Result<(), String>),
    TermPoll,
    TermUpdate(Result<TerminalOutput, String>),
    TermClose,
    BulkToggle(String, bool),
    BulkSelectAll(bool),
    BulkShell(ShellChoice),
    BulkEdit(text_editor::Action),
    BulkTimeout(String),
    BulkAsk,
    BulkConfirm,
    BulkCancel,
    BulkDone(String, Result<ExecStatus, String>),
    BulkExport,
    Job(jobs::JobMsg),
    Group(groups::GroupMsg),
    MeLoaded(Result<TechnicianInfo, String>),
    TicketLoaded(String, Result<TicketResponse, String>),
    Report(reports::ReportMsg),
    Compliance(compliance::ComplianceMsg),
}

/// How many endpoints a bulk run works on at once.
const BULK_PARALLEL: usize = 8;

/// Keep at most this much terminal scrollback in the Console.
const TERM_SCROLLBACK: usize = 512 * 1024;

/// A software change awaiting confirmation: (description, request).
#[derive(Debug, Clone)]
enum SwChange {
    Uninstall(String, UninstallRequest),
    Install(InstallRequest),
}

/// Meaning of common Windows Installer exit codes (msiexec).
fn msi_outcome(code: i32) -> &'static str {
    match code {
        0 => "succeeded",
        3010 => "succeeded; a restart is required to finish",
        1641 => "succeeded; the installer started a restart",
        1602 => "cancelled",
        1603 => "failed (fatal error during installation)",
        1605 => "the product is not installed",
        1618 => "another installation is already in progress; try again later",
        1619 | 1620 => "the package could not be opened (missing or corrupt .msi)",
        1625 | 1643 => "blocked by system policy",
        1638 => "another version of this product is already installed",
        _ => "finished with an installer-specific code",
    }
}

/// Joins a remote Windows directory and a name (`""` + `C:\` = `C:\`).
fn win_join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else {
        format!("{}\\{name}", dir.trim_end_matches('\\'))
    }
}

/// Parent of a remote Windows path; the parent of a drive root is the drive list (`""`).
fn win_parent(p: &str) -> String {
    let t = p.trim_end_matches('\\');
    match t.rsplit_once('\\') {
        // "C:\Users" -> "C:\" ; "C:\Users\x" -> "C:\Users"
        Some((head, _)) if head.ends_with(':') => format!("{head}\\"),
        Some((head, _)) => head.to_owned(),
        None => String::new(),
    }
}

fn human_size(b: u64) -> String {
    match b {
        0..1024 => format!("{b} B"),
        1024..1_048_576 => format!("{:.1} KB", b as f64 / 1024.0),
        1_048_576..1_073_741_824 => format!("{:.1} MB", b as f64 / 1_048_576.0),
        _ => format!("{:.2} GB", b as f64 / 1_073_741_824.0),
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct ShellChoice(Shell);

impl std::fmt::Display for ShellChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            Shell::Powershell => "PowerShell",
            Shell::Cmd => "Command Prompt",
        })
    }
}

const SHELLS: [ShellChoice; 2] = [ShellChoice(Shell::Powershell), ShellChoice(Shell::Cmd)];

#[derive(Debug, Clone, Copy, PartialEq)]
struct HiveChoice(RegHive);

impl std::fmt::Display for HiveChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(hive_label(self.0))
    }
}

const HIVES: [HiveChoice; 4] = [
    HiveChoice(RegHive::LocalMachine),
    HiveChoice(RegHive::Users),
    HiveChoice(RegHive::ClassesRoot),
    HiveChoice(RegHive::CurrentConfig),
];

fn hive_label(h: RegHive) -> &'static str {
    match h {
        RegHive::LocalMachine => "HKEY_LOCAL_MACHINE",
        RegHive::Users => "HKEY_USERS",
        RegHive::ClassesRoot => "HKEY_CLASSES_ROOT",
        RegHive::CurrentConfig => "HKEY_CURRENT_CONFIG",
    }
}

/// Value types the edit form can write.
#[derive(Debug, Clone, Copy, PartialEq)]
enum RegType {
    String,
    ExpandString,
    MultiString,
    Dword,
    Qword,
    Binary,
}

impl std::fmt::Display for RegType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RegType::String => "REG_SZ",
            RegType::ExpandString => "REG_EXPAND_SZ",
            RegType::MultiString => "REG_MULTI_SZ",
            RegType::Dword => "REG_DWORD",
            RegType::Qword => "REG_QWORD",
            RegType::Binary => "REG_BINARY",
        })
    }
}

const REG_TYPES: [RegType; 6] = [
    RegType::String,
    RegType::ExpandString,
    RegType::MultiString,
    RegType::Dword,
    RegType::Qword,
    RegType::Binary,
];

/// Type label and editable text for a value (multi-strings joined with `|`).
fn reg_display(d: &RegData) -> (String, String) {
    match d {
        RegData::String(s) => ("REG_SZ".into(), s.clone()),
        RegData::ExpandString(s) => ("REG_EXPAND_SZ".into(), s.clone()),
        RegData::MultiString(v) => ("REG_MULTI_SZ".into(), v.join("|")),
        RegData::Dword(v) => ("REG_DWORD".into(), format!("0x{v:08x} ({v})")),
        RegData::Qword(v) => ("REG_QWORD".into(), format!("0x{v:016x} ({v})")),
        RegData::Binary(h) => ("REG_BINARY".into(), h.clone()),
        RegData::None => ("REG_NONE".into(), String::new()),
        RegData::Other { type_id, hex } => (format!("type {type_id}"), hex.clone()),
    }
}

/// Parses the edit form into typed data.
fn reg_parse(ty: RegType, s: &str) -> Result<RegData, String> {
    let num = |s: &str| -> Result<u64, String> {
        let s = s.trim();
        // Accept what reg_display shows: "0x.. (dec)" → take the hex part.
        let s = s.split_whitespace().next().unwrap_or("");
        match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            Some(h) => u64::from_str_radix(h, 16),
            None => s.parse(),
        }
        .map_err(|_| format!("{s:?} is not a number (decimal or 0x-hex)"))
    };
    Ok(match ty {
        RegType::String => RegData::String(s.to_owned()),
        RegType::ExpandString => RegData::ExpandString(s.to_owned()),
        RegType::MultiString => RegData::MultiString(
            s.split('|')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_owned)
                .collect(),
        ),
        RegType::Dword => RegData::Dword(
            u32::try_from(num(s)?).map_err(|_| "value does not fit in a DWORD".to_string())?,
        ),
        RegType::Qword => RegData::Qword(num(s)?),
        RegType::Binary => {
            let h: String = s
                .chars()
                .filter(|c| !c.is_whitespace() && *c != ',')
                .collect();
            if !h.len().is_multiple_of(2) || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("binary data must be hex bytes, e.g. de ad be ef".into());
            }
            RegData::Binary(h.to_lowercase())
        }
    })
}

/// A registry change awaiting confirmation.
#[derive(Debug, Clone)]
enum RegChange {
    Set(RegSetValueRequest),
    DeleteValue(RegDeleteValueRequest),
    DeleteKey(RegDeleteKeyRequest),
}

fn reg_where(k: &RegKeyPath) -> String {
    let view = if k.view == RegView::Bits32 {
        " (32-bit view)"
    } else {
        ""
    };
    format!("{}\\{}{view}", hive_label(k.hive), k.path)
}

impl RegChange {
    fn describe(&self) -> String {
        let name = |n: &str| {
            if n.is_empty() {
                "(Default)".to_owned()
            } else {
                n.to_owned()
            }
        };
        match self {
            RegChange::Set(r) => format!(
                "Set {} = {} in {}",
                name(&r.name),
                reg_display(&r.data).1,
                reg_where(&r.key)
            ),
            RegChange::DeleteValue(r) => {
                format!("Delete value {} from {}", name(&r.name), reg_where(&r.key))
            }
            RegChange::DeleteKey(r) => format!(
                "Delete key {}{}",
                reg_where(&r.key),
                if r.recursive {
                    " and everything below it"
                } else {
                    ""
                }
            ),
        }
    }
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
    Software,
    Registry,
    Commands,
    Files,
    Peripherals,
    Updates,
    Wmi,
    Terminal,
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
    /// Server-stored inventory of the selected device.
    inventory: Option<(uuid::Uuid, Result<Option<InventoryReport>, String>)>,
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
    sw: Option<(String, Result<SoftwareInventory, String>)>,
    sw_filter: String,
    reg_hive: RegHive,
    reg_bits32: bool,
    /// Key currently shown (path within the hive).
    reg_path: String,
    reg_path_input: String,
    reg: Option<(String, Result<RegKeyContents, String>)>,
    reg_form_name: String,
    reg_form_type: RegType,
    reg_form_data: String,
    reg_recursive: bool,
    reg_confirm: Option<RegChange>,
    reg_notice: Option<Result<String, String>>,
    cmd_shell: Shell,
    cmd_script: text_editor::Content,
    cmd_timeout: String,
    cmd_confirm: bool,
    /// The command started from this Console on the selected endpoint, with its address.
    cmd_job: Option<(String, ExecStatus)>,
    cmd_notice: Option<String>,
    files_path: String,
    files_input: String,
    files: Option<(String, Result<DirListing, String>)>,
    /// What a running transfer is doing; transfers are one at a time.
    files_busy: Option<String>,
    files_notice: Option<Result<String, String>>,
    files_upload_path: String,
    files_overwrite: bool,
    files_new_folder: String,
    /// (entry name, new name) while renaming inline.
    files_rename: Option<(String, String)>,
    files_recursive: bool,
    files_confirm: Option<FileOp>,
    sw_confirm: Option<SwChange>,
    sw_msi_path: String,
    /// The software job started from the Software tab is tracked in `cmd_job`; this marks it.
    sw_job_label: Option<String>,
    periph: Option<(String, Result<Peripherals, String>)>,
    wmi_namespace: String,
    wmi_wql: String,
    wmi_class_filter: String,
    wmi_classes: Vec<String>,
    wmi_result: Option<Result<WmiTable, String>>,
    wmi_running: bool,
    updates: Option<(String, Result<UpdateStatus, String>)>,
    term_shell: Shell,
    /// (endpoint address, terminal id) of the open terminal.
    term: Option<(String, uuid::Uuid)>,
    term_text: String,
    term_next: u64,
    term_exited: Option<Option<i32>>,
    term_input: String,
    term_notice: Option<String>,
    /// Endpoints ticked for a bulk run (addresses).
    bulk_selected: std::collections::BTreeSet<String>,
    bulk_shell: Shell,
    bulk_script: text_editor::Content,
    bulk_timeout: String,
    bulk_confirm: bool,
    /// Per endpoint: `None` while running.
    bulk_results: Vec<(String, Option<Result<ExecStatus, String>>)>,
    bulk_notice: Option<Result<String, String>>,
    jobs: jobs::JobsState,
    groups: groups::GroupsState,
    /// The signed-in server technician's role and scope (`GET /api/v1/me`).
    me: Option<Result<TechnicianInfo, String>>,
    /// Server connection tickets per direct endpoint address: (ticket, expires_at).
    tickets: std::collections::HashMap<String, (String, Millis)>,
    reports: reports::ReportsState,
    compliance: compliance::ComplianceState,
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
            inventory: None,
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
            sw: None,
            sw_filter: String::new(),
            reg_hive: RegHive::LocalMachine,
            reg_bits32: false,
            reg_path: r"SOFTWARE\Microsoft\Windows NT\CurrentVersion".into(),
            reg_path_input: r"SOFTWARE\Microsoft\Windows NT\CurrentVersion".into(),
            reg: None,
            reg_form_name: String::new(),
            reg_form_type: RegType::String,
            reg_form_data: String::new(),
            reg_recursive: false,
            reg_confirm: None,
            reg_notice: None,
            cmd_shell: Shell::Powershell,
            cmd_script: text_editor::Content::new(),
            cmd_timeout: "60".into(),
            cmd_confirm: false,
            cmd_job: None,
            cmd_notice: None,
            files_path: String::new(),
            files_input: String::new(),
            files: None,
            files_busy: None,
            files_notice: None,
            files_upload_path: String::new(),
            files_overwrite: false,
            files_new_folder: String::new(),
            files_rename: None,
            files_recursive: false,
            files_confirm: None,
            sw_confirm: None,
            sw_msi_path: String::new(),
            sw_job_label: None,
            periph: None,
            wmi_namespace: r"ROOT\CIMV2".into(),
            wmi_wql: "SELECT Caption, Version, LastBootUpTime FROM Win32_OperatingSystem".into(),
            wmi_class_filter: String::new(),
            wmi_classes: Vec::new(),
            wmi_result: None,
            wmi_running: false,
            updates: None,
            term_shell: Shell::Powershell,
            term: None,
            term_text: String::new(),
            term_next: 0,
            term_exited: None,
            term_input: String::new(),
            term_notice: None,
            bulk_selected: Default::default(),
            bulk_shell: Shell::Powershell,
            bulk_script: text_editor::Content::new(),
            bulk_timeout: "120".into(),
            bulk_confirm: false,
            bulk_results: Vec::new(),
            bulk_notice: None,
            jobs: jobs::JobsState::new(),
            groups: groups::GroupsState::new(),
            me: None,
            tickets: Default::default(),
            reports: reports::ReportsState::new(),
            compliance: compliance::ComplianceState::new(),
        };
        let task = if configured {
            Task::batch([
                c.search(),
                c.load_groups(),
                c.load_me(),
                c.check_endpoints(),
            ])
        } else {
            c.check_endpoints()
        };
        (c, task)
    }

    fn client(&self) -> Result<api::Client, String> {
        api::Client::new(
            &self.settings.server_url,
            &self.settings.token,
            &self.settings.ca_cert,
        )
    }

    fn load_me(&self) -> Task<Message> {
        let client = self.client();
        Task::perform(async move { client?.me().await }, Message::MeLoaded)
    }

    /// Whether the technician's role allows `min`. Unknown (not loaded, or an older server
    /// without `/me`) allows it: the server decides either way, this only tidies the UI.
    fn can(&self, min: TechRole) -> bool {
        match &self.me {
            Some(Ok(me)) => me.role >= min,
            _ => true,
        }
    }

    fn can_edit_groups(&self) -> bool {
        self.can(TechRole::Operator) && !matches!(&self.me, Some(Ok(me)) if !me.scope.is_empty())
    }

    fn search(&mut self) -> Task<Message> {
        self.search_gen += 1;
        self.loading = true;
        let (generation, client, q, group) = (
            self.search_gen,
            self.client(),
            self.query.clone(),
            self.groups.active,
        );
        Task::perform(async move { client?.search(&q, group).await }, move |r| {
            Message::SearchDone(generation, r)
        })
    }

    fn load_details(&self, id: uuid::Uuid) -> Task<Message> {
        let client = self.client();
        let inv_client = self.client();
        Task::batch([
            Task::perform(
                async move { client?.details(id).await },
                Message::DetailsDone,
            ),
            Task::perform(async move { inv_client?.inventory(id).await }, move |r| {
                Message::InventoryDone(id, r)
            }),
        ])
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
            // A ticket about to expire is left out; the next endpoint check fetches a new one.
            ticket: self
                .tickets
                .get(&ep.address)
                .filter(|(_, expires)| *expires > now_millis() + 60_000)
                .map(|(t, _)| t.clone()),
        })
    }

    /// Reloads the selected endpoint's summary, plus its processes when that tab is open.
    /// Checks every direct endpoint once, so the list shows which agents answer without the
    /// technician having to open each one.
    fn check_endpoints(&self) -> Task<Message> {
        let checks = Task::batch(self.settings.endpoints.iter().filter_map(|e| {
            let t = self.target(&e.address)?;
            let addr = t.address.clone();
            Some(Task::perform(direct::device(t), move |r| {
                Message::DirectLoaded(addr.clone(), r)
            }))
        }));
        Task::batch([checks, self.refresh_tickets()])
    }

    /// When signed in to a Server, gets a connection ticket for each direct endpoint that has no
    /// fresh one. Agents that require tickets refuse requests until it arrives; others ignore it.
    fn refresh_tickets(&self) -> Task<Message> {
        if self.settings.token.is_empty() {
            return Task::none();
        }
        Task::batch(self.settings.endpoints.iter().filter_map(|e| {
            if self.target(&e.address)?.ticket.is_some() {
                return None;
            }
            let mut t = self.target(&e.address)?;
            t.ticket = None;
            let api = self.client();
            let addr = e.address.clone();
            Some(Task::perform(
                async move {
                    let id = direct::identity(t)
                        .await?
                        .device_id
                        .ok_or("the agent is not enrolled with a Tervano Server")?;
                    api?.ticket(id).await
                },
                move |r| Message::TicketLoaded(addr.clone(), r),
            ))
        }))
    }

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
            DirectTab::Software => Task::perform(direct::software(t), move |r| {
                Message::SwLoaded(addr.clone(), r)
            }),
            DirectTab::Registry => Task::perform(direct::reg_key(t, self.reg_key()), move |r| {
                Message::RegLoaded(addr.clone(), r)
            }),
            // Commands are run on demand; nothing to refresh on the 15 s tick.
            DirectTab::Commands => Task::none(),
            DirectTab::Peripherals => Task::perform(direct::peripherals(t), move |r| {
                Message::PeriphLoaded(addr.clone(), r)
            }),
            DirectTab::Updates => Task::perform(direct::updates(t), move |r| {
                Message::UpdatesLoaded(addr.clone(), r)
            }),
            // Queries run on demand; only fetch the class list once per endpoint.
            DirectTab::Wmi if self.wmi_classes.is_empty() => Task::perform(
                direct::wmi_classes(t, self.wmi_namespace.clone()),
                Message::WmiClasses,
            ),
            DirectTab::Wmi => Task::none(),
            // The terminal polls on its own subscription while open.
            DirectTab::Terminal => Task::none(),
            DirectTab::Files => {
                Task::perform(direct::files_list(t, self.files_path.clone()), move |r| {
                    Message::FilesLoaded(addr.clone(), r)
                })
            }
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
            Message::Nav(p) => {
                self.page = p;
                if p == Page::Direct {
                    return self.check_endpoints();
                }
                if p == Page::Jobs && !self.settings.token.is_empty() {
                    return self.jobs_refresh();
                }
                if p == Page::Reports && !self.settings.token.is_empty() {
                    return self.reports_load();
                }
            }
            Message::Job(m) => return self.jobs_update(m),
            Message::Group(m) => return self.groups_update(m),
            Message::MeLoaded(r) => self.me = Some(r),
            Message::TicketLoaded(addr, r) => match r {
                Ok(t) => {
                    tracing::info!(endpoint = %addr, level = ?t.level, "connection ticket received");
                    self.tickets.insert(addr.clone(), (t.ticket, t.expires_at));
                    // Re-check with the ticket; reload the open endpoint's current tab too.
                    if self.direct_selected.as_deref() == Some(addr.as_str()) {
                        return self.load_direct(&addr);
                    }
                    if let Some(t) = self.target(&addr) {
                        return Task::perform(direct::device(t), move |r| {
                            Message::DirectLoaded(addr.clone(), r)
                        });
                    }
                }
                // Expected for agents not enrolled or Servers without tickets; access may still
                // come from the agent's own lists.
                Err(e) => tracing::debug!(endpoint = %addr, "no connection ticket: {e}"),
            },
            Message::Report(m) => return self.reports_update(m),
            Message::Compliance(m) => return self.compliance_update(m),
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
            Message::InventoryDone(id, r) => {
                if Some(id) == self.selected {
                    self.inventory = Some((id, r));
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
                    self.me = None;
                    return Task::batch([self.search(), self.load_groups(), self.load_me()]);
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
                    self.sw = None;
                    self.reg = None;
                    self.reg_confirm = None;
                    self.reg_notice = None;
                    self.cmd_confirm = false;
                    self.cmd_notice = None;
                    self.files = None;
                    self.periph = None;
                    self.updates = None;
                    self.wmi_classes.clear();
                    self.wmi_result = None;
                    self.files_path.clear();
                    self.files_input.clear();
                    self.files_notice = None;
                    self.files_confirm = None;
                    self.files_rename = None;
                    // A running command keeps its job; it belongs to the endpoint it ran on.
                    if self.cmd_job.as_ref().is_some_and(|(a, _)| a != &address) {
                        self.cmd_job = None;
                    }
                    // A finished terminal's scrollback belongs to its endpoint; an open one stays
                    // open (term_view points back to it) rather than being killed silently.
                    if self.term_exited.is_some() {
                        self.term = None;
                        self.term_text.clear();
                        self.term_next = 0;
                        self.term_exited = None;
                        self.term_notice = None;
                    }
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
            Message::SwLoaded(address, r) => {
                if self.direct_selected.as_deref() == Some(address.as_str()) {
                    self.sw = Some((address, r));
                }
            }
            Message::SwFilter(f) => self.sw_filter = f,
            Message::RegHive(h) => {
                self.reg_hive = h.0;
                return self.reg_navigate(String::new());
            }
            Message::RegBits32(b) => {
                self.reg_bits32 = b;
                return self.reg_navigate(self.reg_path.clone());
            }
            Message::RegPathInput(p) => self.reg_path_input = p,
            Message::RegGo => {
                let p = self.reg_path_input.trim().trim_matches('\\').to_owned();
                // Accept pasted full paths like "HKEY_LOCAL_MACHINE\SOFTWARE\…".
                let (hive, rest) = match p.split_once('\\') {
                    Some((h, r)) => (h, r),
                    None => (p.as_str(), ""),
                };
                let found = HIVES.iter().find(|c| {
                    let l = hive_label(c.0);
                    hive.eq_ignore_ascii_case(l)
                        || hive.eq_ignore_ascii_case(&l.replace("HKEY_", "HK").replace('_', ""))
                        || (c.0 == RegHive::LocalMachine && hive.eq_ignore_ascii_case("HKLM"))
                        || (c.0 == RegHive::Users && hive.eq_ignore_ascii_case("HKU"))
                        || (c.0 == RegHive::ClassesRoot && hive.eq_ignore_ascii_case("HKCR"))
                        || (c.0 == RegHive::CurrentConfig && hive.eq_ignore_ascii_case("HKCC"))
                });
                let path = match found {
                    Some(c) => {
                        self.reg_hive = c.0;
                        rest.to_owned()
                    }
                    None => p,
                };
                return self.reg_navigate(path);
            }
            Message::RegUp => {
                let up = self
                    .reg_path
                    .rsplit_once('\\')
                    .map_or(String::new(), |(p, _)| p.to_owned());
                return self.reg_navigate(up);
            }
            Message::RegOpen(sub) => {
                let p = if self.reg_path.is_empty() {
                    sub
                } else {
                    format!("{}\\{sub}", self.reg_path)
                };
                return self.reg_navigate(p);
            }
            Message::RegLoaded(address, r) => {
                if self.direct_selected.as_deref() == Some(address.as_str()) {
                    self.reg = Some((address, r));
                }
            }
            Message::RegFormName(n) => self.reg_form_name = n,
            Message::RegFormType(t) => self.reg_form_type = t,
            Message::RegFormData(d) => self.reg_form_data = d,
            Message::RegEdit(v) => {
                self.reg_form_name = v.name.clone();
                self.reg_form_type = match v.data {
                    RegData::ExpandString(_) => RegType::ExpandString,
                    RegData::MultiString(_) => RegType::MultiString,
                    RegData::Dword(_) => RegType::Dword,
                    RegData::Qword(_) => RegType::Qword,
                    RegData::Binary(_) | RegData::Other { .. } | RegData::None => RegType::Binary,
                    RegData::String(_) => RegType::String,
                };
                self.reg_form_data = reg_display(&v.data).1;
            }
            Message::RegAskSet => match reg_parse(self.reg_form_type, &self.reg_form_data) {
                Ok(data) => {
                    self.reg_notice = None;
                    self.reg_confirm = Some(RegChange::Set(RegSetValueRequest {
                        key: self.reg_key(),
                        name: self.reg_form_name.clone(),
                        data,
                    }));
                }
                Err(e) => self.reg_notice = Some(Err(e)),
            },
            Message::RegAskDeleteValue(name) => {
                self.reg_notice = None;
                self.reg_confirm = Some(RegChange::DeleteValue(RegDeleteValueRequest {
                    key: self.reg_key(),
                    name,
                }));
            }
            Message::RegAskDeleteKey => {
                self.reg_notice = None;
                self.reg_confirm = Some(RegChange::DeleteKey(RegDeleteKeyRequest {
                    key: self.reg_key(),
                    recursive: self.reg_recursive,
                }));
            }
            Message::RegRecursive(b) => self.reg_recursive = b,
            Message::RegCancel => self.reg_confirm = None,
            Message::RegConfirm => {
                if let (Some(change), Some(t)) = (
                    self.reg_confirm.take(),
                    self.direct_selected.as_deref().and_then(|a| self.target(a)),
                ) {
                    let done = change.describe();
                    let deleted_key = matches!(change, RegChange::DeleteKey(_));
                    let to_msg = move |r: Result<(), String>| {
                        Message::RegDone(r.map(|()| format!("Done: {done}.")))
                    };
                    if deleted_key {
                        // Show the parent once the key is gone.
                        self.reg_path = self
                            .reg_path
                            .rsplit_once('\\')
                            .map_or(String::new(), |(p, _)| p.to_owned());
                        self.reg_path_input = self.reg_path.clone();
                    }
                    return match change {
                        RegChange::Set(r) => Task::perform(direct::reg_set(t, r), to_msg),
                        RegChange::DeleteValue(r) => {
                            Task::perform(direct::reg_delete_value(t, r), to_msg)
                        }
                        RegChange::DeleteKey(r) => {
                            Task::perform(direct::reg_delete_key(t, r), to_msg)
                        }
                    };
                }
            }
            Message::RegDone(r) => {
                self.reg_notice = Some(r);
                if let Some(addr) = self.direct_selected.clone() {
                    return self.load_direct(&addr);
                }
            }
            Message::RegExport => {
                if let Some(t) = self.direct_selected.as_deref().and_then(|a| self.target(a)) {
                    let k = self.reg_key();
                    let label = format!("{}-{}", t.address, k.path);
                    return Task::perform(direct::reg_export(t, k), move |r| {
                        Message::RegExported(r.and_then(|text| save_reg_file(&label, &text)))
                    });
                }
            }
            Message::RegExported(r) => self.reg_notice = Some(r),
            Message::CmdShell(s) => self.cmd_shell = s.0,
            Message::CmdEdit(a) => self.cmd_script.perform(a),
            Message::CmdTimeout(t) => {
                self.cmd_timeout = t.chars().filter(char::is_ascii_digit).take(4).collect()
            }
            Message::CmdAskRun => {
                self.cmd_notice = None;
                if self.cmd_script.text().trim().is_empty() {
                    self.cmd_notice = Some("Write a script first.".into());
                } else {
                    self.cmd_confirm = true;
                }
            }
            Message::CmdCancelConfirm => self.cmd_confirm = false,
            Message::CmdConfirm => {
                self.cmd_confirm = false;
                if let Some(t) = self.direct_selected.as_deref().and_then(|a| self.target(a)) {
                    let req = ExecRequest {
                        shell: self.cmd_shell,
                        script: self.cmd_script.text(),
                        context: ExecContext::Agent,
                        timeout_secs: self.cmd_timeout.parse().ok(),
                    };
                    self.cmd_job = None;
                    self.sw_job_label = None;
                    return Task::perform(direct::exec_start(t, req), Message::CmdUpdate);
                }
            }
            Message::CmdUpdate(r) => match r {
                Ok(s) => {
                    if let Some(addr) = self.direct_selected.clone() {
                        self.cmd_job = Some((addr, s));
                    }
                }
                Err(e) => self.cmd_notice = Some(e),
            },
            Message::CmdPoll => {
                if let Some((addr, s)) = &self.cmd_job
                    && let Some(t) = self.target(addr)
                {
                    return Task::perform(direct::exec_status(t, s.id), Message::CmdUpdate);
                }
            }
            Message::CmdStop => {
                if let Some((addr, s)) = &self.cmd_job
                    && let Some(t) = self.target(addr)
                {
                    return Task::perform(direct::exec_cancel(t, s.id), Message::CmdStopped);
                }
            }
            Message::CmdStopped(r) => {
                if let Err(e) = r {
                    self.cmd_notice = Some(e);
                }
            }
            Message::FilesInput(s) => self.files_input = s,
            Message::FilesGo => {
                let p = self.files_input.trim().to_owned();
                return self.files_navigate(p);
            }
            Message::FilesUp => return self.files_navigate(win_parent(&self.files_path)),
            Message::FilesDrives => return self.files_navigate(String::new()),
            Message::FilesOpen(name) => {
                let p = win_join(&self.files_path, &name);
                return self.files_navigate(p);
            }
            Message::FilesLoaded(address, r) => {
                if self.direct_selected.as_deref() == Some(address.as_str()) {
                    self.files = Some((address, r));
                }
            }
            Message::FilesDownload(name) => {
                if let (Some(t), Some(dir)) = (
                    self.direct_selected.as_deref().and_then(|a| self.target(a)),
                    downloads_dir(),
                ) {
                    self.files_busy = Some(format!("Downloading {name}…"));
                    self.files_notice = None;
                    let remote = win_join(&self.files_path, &name);
                    return Task::perform(
                        direct::download(t, remote, dir),
                        Message::FilesTransferDone,
                    );
                }
            }
            Message::FilesUploadPath(p) => self.files_upload_path = p,
            Message::FilesOverwrite(b) => self.files_overwrite = b,
            Message::FilesUpload => {
                let local =
                    std::path::PathBuf::from(self.files_upload_path.trim().trim_matches('"'));
                let Some(name) = local.file_name().map(|n| n.to_string_lossy().into_owned()) else {
                    self.files_notice =
                        Some(Err("Enter the full path of a local file to upload.".into()));
                    return Task::none();
                };
                if self.files_path.is_empty() {
                    self.files_notice = Some(Err("Open a folder on the agent first.".into()));
                    return Task::none();
                }
                if let Some(t) = self.direct_selected.as_deref().and_then(|a| self.target(a)) {
                    self.files_busy = Some(format!("Uploading {name}…"));
                    self.files_notice = None;
                    let remote = win_join(&self.files_path, &name);
                    return Task::perform(
                        direct::upload(t, local, remote, self.files_overwrite),
                        Message::FilesTransferDone,
                    );
                }
            }
            Message::FilesTransferDone(r) => {
                self.files_busy = None;
                self.files_notice = Some(r);
                if let Some(addr) = self.direct_selected.clone() {
                    return self.load_direct(&addr);
                }
            }
            Message::FilesNewFolder(n) => self.files_new_folder = n,
            Message::FilesMkdir => {
                let name = self.files_new_folder.trim().to_owned();
                if !name.is_empty() && !self.files_path.is_empty() {
                    let path = win_join(&self.files_path, &name);
                    self.files_new_folder.clear();
                    return self.files_run(FileOp::Mkdir { path });
                }
            }
            Message::FilesRenameStart(name) => self.files_rename = Some((name.clone(), name)),
            Message::FilesRenameInput(n) => {
                if let Some((_, new)) = &mut self.files_rename {
                    *new = n;
                }
            }
            Message::FilesRenameApply => {
                if let Some((old, new)) = self.files_rename.take()
                    && !new.trim().is_empty()
                    && new != old
                {
                    return self.files_run(FileOp::Rename {
                        from: win_join(&self.files_path, &old),
                        to: win_join(&self.files_path, new.trim()),
                    });
                }
            }
            Message::FilesAskDelete(name, is_dir) => {
                self.files_notice = None;
                self.files_confirm = Some(FileOp::Delete {
                    path: win_join(&self.files_path, &name),
                    recursive: is_dir && self.files_recursive,
                });
            }
            Message::FilesRecursive(b) => self.files_recursive = b,
            Message::FilesCancel => self.files_confirm = None,
            Message::FilesConfirm => {
                if let Some(op) = self.files_confirm.take() {
                    return self.files_run(op);
                }
            }
            Message::FilesOpDone(r) => {
                self.files_notice = Some(r);
                if let Some(addr) = self.direct_selected.clone() {
                    return self.load_direct(&addr);
                }
            }
            Message::SwAskUninstall(name, req) => {
                self.sw_confirm = Some(SwChange::Uninstall(name, req));
            }
            Message::SwMsiPath(p) => self.sw_msi_path = p,
            Message::SwAskInstall => {
                let msi_path = self.sw_msi_path.trim().trim_matches('"').to_owned();
                if !msi_path.is_empty() {
                    self.sw_confirm = Some(SwChange::Install(InstallRequest { msi_path }));
                }
            }
            Message::SwCancel => self.sw_confirm = None,
            Message::SwConfirm => {
                if let (Some(change), Some(t)) = (
                    self.sw_confirm.take(),
                    self.direct_selected.as_deref().and_then(|a| self.target(a)),
                ) {
                    self.cmd_job = None;
                    self.cmd_notice = None;
                    return match change {
                        SwChange::Uninstall(name, req) => {
                            self.sw_job_label = Some(format!("Uninstall {name}"));
                            Task::perform(direct::software_uninstall(t, req), Message::CmdUpdate)
                        }
                        SwChange::Install(req) => {
                            self.sw_job_label = Some(format!("Install {}", req.msi_path));
                            Task::perform(direct::software_install(t, req), Message::CmdUpdate)
                        }
                    };
                }
            }
            Message::PeriphLoaded(address, r) => {
                if self.direct_selected.as_deref() == Some(address.as_str()) {
                    self.periph = Some((address, r));
                }
            }
            Message::WmiNamespace(n) => {
                self.wmi_namespace = n;
                self.wmi_classes.clear();
            }
            Message::WmiWql(q) => self.wmi_wql = q,
            Message::WmiClassFilter(f) => {
                self.wmi_class_filter = f;
                // Namespace may have changed since the last class fetch.
                if self.wmi_classes.is_empty()
                    && let Some(t) = self.direct_selected.as_deref().and_then(|a| self.target(a))
                {
                    return Task::perform(
                        direct::wmi_classes(t, self.wmi_namespace.clone()),
                        Message::WmiClasses,
                    );
                }
            }
            Message::WmiPickClass(c) => {
                self.wmi_wql = format!("SELECT * FROM {c}");
                self.wmi_class_filter.clear();
            }
            Message::WmiRun => {
                if let Some(t) = self.direct_selected.as_deref().and_then(|a| self.target(a)) {
                    self.wmi_running = true;
                    let q = WmiQuery {
                        namespace: Some(self.wmi_namespace.trim().to_owned()),
                        wql: self.wmi_wql.trim().to_owned(),
                    };
                    return Task::perform(direct::wmi_query(t, q), Message::WmiLoaded);
                }
            }
            Message::WmiLoaded(r) => {
                self.wmi_running = false;
                self.wmi_result = Some(r);
            }
            Message::WmiClasses(r) => self.wmi_classes = r.unwrap_or_default(),
            Message::UpdatesLoaded(address, r) => {
                if self.direct_selected.as_deref() == Some(address.as_str()) {
                    self.updates = Some((address, r));
                }
            }
            Message::TermShell(s) => self.term_shell = s.0,
            Message::TermOpen => {
                if let Some(t) = self.direct_selected.as_deref().and_then(|a| self.target(a)) {
                    self.term = None;
                    self.term_text.clear();
                    self.term_next = 0;
                    self.term_exited = None;
                    self.term_notice = None;
                    return Task::perform(
                        direct::terminal_open(t, self.term_shell),
                        Message::TermUpdate,
                    );
                }
            }
            Message::TermInput(s) => self.term_input = s,
            Message::TermSend => {
                if let Some((addr, id)) = &self.term
                    && let Some(t) = self.target(addr)
                {
                    let text = format!("{}\r\n", self.term_input);
                    // The shell does not echo piped input; show what was sent in the scrollback.
                    self.term_text.push_str(&format!("> {}\n", self.term_input));
                    self.term_input.clear();
                    return Task::perform(direct::terminal_input(t, *id, text), Message::TermSent);
                }
            }
            Message::TermSent(r) => {
                if let Err(e) = r {
                    self.term_notice = Some(e);
                }
            }
            Message::TermPoll => {
                if let Some((addr, id)) = &self.term
                    && let Some(t) = self.target(addr)
                {
                    return Task::perform(
                        direct::terminal_output(t, *id, self.term_next),
                        Message::TermUpdate,
                    );
                }
            }
            Message::TermUpdate(r) => match r {
                Ok(o) => {
                    if self.term.is_none()
                        && let Some(addr) = self.direct_selected.clone()
                    {
                        self.term = Some((addr, o.id));
                    }
                    if o.skipped {
                        self.term_text
                            .push_str("\n[earlier output dropped by the agent]\n");
                    }
                    self.term_text.push_str(&o.output);
                    if self.term_text.len() > TERM_SCROLLBACK {
                        let cut = self.term_text.len() - TERM_SCROLLBACK;
                        let cut = (cut..self.term_text.len())
                            .find(|&i| self.term_text.is_char_boundary(i))
                            .unwrap_or(self.term_text.len());
                        self.term_text.drain(..cut);
                    }
                    self.term_next = o.next;
                    if o.exited {
                        self.term_exited = Some(o.exit_code);
                    }
                }
                Err(e) => self.term_notice = Some(e),
            },
            Message::TermClose => {
                if let Some((addr, id)) = &self.term
                    && let Some(t) = self.target(addr)
                {
                    return Task::perform(direct::terminal_close(t, *id), Message::TermSent);
                }
            }
            Message::BulkToggle(addr, on) => {
                if on {
                    self.bulk_selected.insert(addr);
                } else {
                    self.bulk_selected.remove(&addr);
                }
                self.bulk_confirm = false;
            }
            Message::BulkSelectAll(on) => {
                self.bulk_selected = if on {
                    self.settings
                        .endpoints
                        .iter()
                        .map(|e| e.address.clone())
                        .collect()
                } else {
                    Default::default()
                };
                self.bulk_confirm = false;
                // Clearing the selection after a finished run returns to the device view.
                if !on && self.bulk_results.iter().all(|(_, r)| r.is_some()) {
                    self.bulk_results.clear();
                    self.bulk_notice = None;
                }
            }
            Message::BulkShell(s) => self.bulk_shell = s.0,
            Message::BulkEdit(a) => self.bulk_script.perform(a),
            Message::BulkTimeout(t) => {
                self.bulk_timeout = t.chars().filter(char::is_ascii_digit).take(4).collect()
            }
            Message::BulkAsk => {
                self.bulk_notice = None;
                if self.bulk_script.text().trim().is_empty() {
                    self.bulk_notice = Some(Err("Write a script first.".into()));
                } else {
                    self.bulk_confirm = true;
                }
            }
            Message::BulkCancel => self.bulk_confirm = false,
            Message::BulkConfirm => {
                self.bulk_confirm = false;
                self.bulk_notice = None;
                let req = ExecRequest {
                    shell: self.bulk_shell,
                    script: self.bulk_script.text(),
                    context: ExecContext::Agent,
                    timeout_secs: self.bulk_timeout.parse().ok(),
                };
                let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(BULK_PARALLEL));
                self.bulk_results = self
                    .bulk_selected
                    .iter()
                    .map(|a| (a.clone(), None))
                    .collect();
                let tasks: Vec<Task<Message>> = self
                    .bulk_selected
                    .iter()
                    .map(|addr| {
                        let addr = addr.clone();
                        match self.target(&addr) {
                            Some(t) => Task::perform(
                                direct::run_to_completion(t, req.clone(), gate.clone()),
                                move |r| Message::BulkDone(addr.clone(), r),
                            ),
                            None => Task::done(Message::BulkDone(
                                addr,
                                Err("endpoint was removed".into()),
                            )),
                        }
                    })
                    .collect();
                return Task::batch(tasks);
            }
            Message::BulkDone(addr, r) => {
                if let Some(slot) = self.bulk_results.iter_mut().find(|(a, _)| *a == addr) {
                    slot.1 = Some(r);
                }
            }
            Message::BulkExport => {
                if let Some(dir) = downloads_dir() {
                    self.bulk_notice = Some(export_bulk_csv(&dir, &self.bulk_results));
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
        let cmd_tick = if self
            .cmd_job
            .as_ref()
            .is_some_and(|(_, s)| s.state == ExecState::Running)
        {
            iced::time::every(Duration::from_secs(1)).map(|_| Message::CmdPoll)
        } else {
            Subscription::none()
        };
        let term_tick = if self.term.is_some() && self.term_exited.is_none() {
            iced::time::every(Duration::from_millis(500)).map(|_| Message::TermPoll)
        } else {
            Subscription::none()
        };
        let direct_tick = Subscription::batch([direct_tick, cmd_tick, term_tick]);
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
        if self.page == Page::Jobs && self.jobs.live() {
            subs.push(
                iced::time::every(Duration::from_secs(3))
                    .map(|_| Message::Job(jobs::JobMsg::Refresh)),
            );
        }
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
                text(match &self.me {
                    Some(Ok(me)) if me.scope.is_empty() =>
                        format!("{} · {}", me.name, role_label(me.role)),
                    Some(Ok(me)) => format!(
                        "{} · {} · {}",
                        me.name,
                        role_label(me.role),
                        me.scope.join(", ")
                    ),
                    _ => String::new(),
                })
                .size(11)
                .style(text::secondary),
                Space::new().height(16),
                nav("Devices", Page::Devices),
                nav("Jobs", Page::Jobs),
                nav("Reports", Page::Reports),
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
            Page::Jobs => self.jobs_view(),
            Page::Reports => self.reports_view(),
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
                // With the details panel open the columns get narrow and addresses can't wrap.
                let compact = self.selected.is_some();
                let header = row![
                    text("").width(14 + 28),
                    text("Name").width(Length::FillPortion(3)),
                    text("User").width(Length::FillPortion(2)),
                    text("IP address").width(Length::FillPortion(2)),
                    (!compact).then(|| text("OS").width(Length::FillPortion(3))),
                    text("Last seen").width(Length::FillPortion(2)),
                ]
                .spacing(8)
                .padding([6, 10]);
                // shortcut: renders every row (server caps at 100); virtualization is T-307.
                let rows = devices.iter().map(|d| {
                    let selected = self.selected == Some(d.id);
                    let (id, host) = (d.id, d.hostname.clone());
                    let pick =
                        checkbox(self.jobs.selected.contains_key(&d.id)).on_toggle(move |on| {
                            Message::Job(jobs::JobMsg::Toggle(id, host.clone(), on))
                        });
                    let line = button(
                        row![
                            status_dot(d.online),
                            text(&d.hostname).width(Length::FillPortion(3)),
                            text(d.users.join(", ")).width(Length::FillPortion(2)),
                            text(d.primary_ip.as_deref().unwrap_or("—"))
                                .wrapping(text::Wrapping::WordOrGlyph)
                                .width(Length::FillPortion(2)),
                            (!compact).then(|| text(&d.os).width(Length::FillPortion(3))),
                            text(ago(d.last_seen)).width(Length::FillPortion(2)),
                        ]
                        .spacing(8)
                        .align_y(Alignment::Center),
                    )
                    .padding([8, 10])
                    .width(Length::Fill)
                    .style(if selected {
                        crate::selected_row
                    } else {
                        button::text
                    })
                    .on_press(Message::Select(d.id));
                    row![pick, line]
                        .spacing(6)
                        .align_y(Alignment::Center)
                        .into()
                });
                column![
                    self.jobs_selection_bar(),
                    container(header.width(Length::Fill)).style(container::rounded_box),
                    scroll(column(rows).spacing(2)).height(Length::Fill),
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
        column![self.groups_bar(), search, content]
            .spacing(12)
            .into()
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
        let mut extra = vec![
            ("Last seen", ago(d.last_seen)),
            ("Enrolled", ago(d.enrolled_at)),
            ("Device ID", d.id.to_string()),
        ];
        // Stored snapshot from the server; no direct connection needed.
        match self
            .inventory
            .as_ref()
            .filter(|(id, _)| *id == d.id)
            .map(|(_, r)| r)
        {
            None => extra.push(("Inventory", "loading…".into())),
            Some(Err(e)) => extra.push(("Inventory", format!("unavailable: {e}"))),
            Some(Ok(None)) => extra.push(("Inventory", "not received yet".into())),
            Some(Ok(Some(inv))) => {
                let hw = &inv.hardware;
                let gb = |b: u64| format!("{:.0} GB", b as f64 / 1_073_741_824.0);
                let model = [hw.manufacturer.as_deref(), hw.model.as_deref()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" ");
                extra.push((
                    "Model",
                    if model.is_empty() {
                        "unknown".into()
                    } else {
                        model
                    },
                ));
                extra.push((
                    "Serial",
                    hw.serial_number.clone().unwrap_or_else(|| "unknown".into()),
                ));
                extra.push((
                    "CPU",
                    format!("{} ({} logical)", hw.cpu_model, hw.cpu_logical_cores),
                ));
                extra.push(("Memory", gb(hw.memory_total_bytes)));
                extra.push((
                    "Disks",
                    hw.disks
                        .iter()
                        .map(|k| {
                            format!(
                                "{} {} free of {}",
                                k.mount_point,
                                gb(k.free_bytes),
                                gb(k.total_bytes)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" · "),
                ));
                extra.push((
                    "Security",
                    format!(
                        "TPM {} · Secure Boot {}",
                        hw.tpm_version.as_deref().unwrap_or("not detected"),
                        match hw.secure_boot {
                            Some(true) => "on",
                            Some(false) => "off",
                            None => "unknown",
                        }
                    ),
                ));
                extra.push((
                    "Software",
                    format!("{} applications", inv.software.apps.len()),
                ));
                extra.push((
                    "Restart",
                    if inv.software.reboot_pending.is_empty() {
                        "not pending".into()
                    } else {
                        format!("pending ({})", inv.software.reboot_pending.join("; "))
                    },
                ));
                extra.push(("Inventory", format!("collected {}", ago(inv.collected_at))));
            }
        }
        state_panel(
            &d.state,
            d.online,
            if d.online { "Online" } else { "Offline" },
            extra,
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
            // Matches the (1, 3) split below: the list is narrow while a tab other than Summary is open.
            let compact = self.direct_selected.is_some() && self.direct_tab != DirectTab::Summary;
            let rows = self.settings.endpoints.iter().map(|e| {
                let result = self.direct_results.get(&e.address);
                let (online, label) = match result {
                    Some(Ok(s)) => (true, s.hostname.clone()),
                    // A pin mismatch is a security event, not an outage; say so in the list too.
                    Some(Err(e)) if e.starts_with("Certificate changed") => {
                        (false, "certificate changed!".into())
                    }
                    Some(Err(_)) => (false, "unreachable or refused".into()),
                    None => (false, "not checked yet".into()),
                };
                let selected = self.direct_selected.as_deref() == Some(e.address.as_str());
                let addr = e.address.clone();
                row![
                    checkbox(self.bulk_selected.contains(&e.address))
                        .on_toggle(move |on| Message::BulkToggle(addr.clone(), on)),
                    button(if compact {
                        row![
                            status_dot(online),
                            column![
                                text(&e.address).size(13),
                                text(label).size(11).style(text::secondary),
                            ],
                        ]
                        .spacing(6)
                        .align_y(Alignment::Center)
                    } else {
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
                        .align_y(Alignment::Center)
                    })
                    .padding([8, 10])
                    .width(Length::Fill)
                    .style(if selected {
                        crate::selected_row
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
            column![
                checkbox(
                    !self.settings.endpoints.is_empty()
                        && self.bulk_selected.len() == self.settings.endpoints.len()
                )
                .label("Select all for a bulk run")
                .on_toggle(Message::BulkSelectAll),
                scroll(column(rows).spacing(2)).height(Length::Fill),
            ]
            .spacing(6)
            .into()
        };

        // Ticking endpoints switches the right-hand panel to the bulk runner.
        if !self.bulk_selected.is_empty() || !self.bulk_results.is_empty() {
            return column![
                top,
                row![
                    container(list).width(Length::FillPortion(1)),
                    rule::vertical(1),
                    container(self.bulk_view())
                        .width(Length::FillPortion(2))
                        .padding([0, 8]),
                ]
                .spacing(12)
            ]
            .spacing(12)
            .into();
        }

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
                            DirectTab::Software => self.sw_view(),
                            DirectTab::Registry => self.reg_view(),
                            DirectTab::Commands => self.cmd_view(),
                            DirectTab::Files => self.files_view(),
                            DirectTab::Peripherals => self.periph_view(),
                            DirectTab::Updates => self.updates_view(),
                            DirectTab::Wmi => self.wmi_view(),
                            DirectTab::Terminal => self.term_view(),
                        };
                        column![
                            row![
                                tab("Summary", DirectTab::Summary),
                                tab("Processes", DirectTab::Processes),
                                tab("Services", DirectTab::Services),
                                tab("Events", DirectTab::Events),
                                tab("Hardware", DirectTab::Hardware),
                                tab("Software", DirectTab::Software),
                                tab("Registry", DirectTab::Registry),
                                tab("Commands", DirectTab::Commands),
                                tab("Files", DirectTab::Files),
                                tab("Printers & drives", DirectTab::Peripherals),
                                tab("Updates", DirectTab::Updates),
                                tab("WMI", DirectTab::Wmi),
                                tab("Terminal", DirectTab::Terminal)
                            ]
                            .spacing(6)
                            .wrap()
                            .vertical_spacing(6),
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

    fn bulk_view(&self) -> Element<'_, Message> {
        let n = self.bulk_selected.len();
        let running = self.bulk_results.iter().any(|(_, r)| r.is_none());
        let mut col = column![
            row![
                text(format!("Run a command on {n} selected computer(s)")).size(16),
                Space::new().width(Length::Fill),
                button(text("Clear").size(12))
                    .style(button::subtle)
                    .on_press_maybe((!running).then_some(Message::BulkSelectAll(false))),
            ]
            .align_y(Alignment::Center),
            text("Runs as each agent's own account. Every agent checks your operator rights itself; computers where you are not an operator report \"Not authorized\".")
                .size(12)
                .style(text::secondary),
            row![
                pick_list(SHELLS, Some(ShellChoice(self.bulk_shell)), Message::BulkShell).text_size(13),
                text("Timeout (s)").size(13),
                text_input("120", &self.bulk_timeout)
                    .on_input(Message::BulkTimeout)
                    .padding(6)
                    .width(70),
                Space::new().width(Length::Fill),
                button(text(format!("Run on {n}")))
                    .style(button::primary)
                    .on_press_maybe((n > 0 && !running).then_some(Message::BulkAsk)),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
            text_editor(&self.bulk_script)
                .placeholder("Get-Service Spooler | Select-Object Status")
                .on_action(Message::BulkEdit)
                .font(iced::Font::MONOSPACE)
                .height(120),
        ]
        .spacing(8);
        if self.bulk_confirm {
            col = col.push(
                container(
                    column![
                        text(format!(
                            "Run this {} script on {n} computer(s) with each agent's privileges?",
                            ShellChoice(self.bulk_shell)
                        )),
                        row![
                            button(text(format!("Run on {n} computers")))
                                .style(button::danger)
                                .on_press(Message::BulkConfirm),
                            button(text("Cancel"))
                                .style(button::secondary)
                                .on_press(Message::BulkCancel),
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
        if let Some(note) = &self.bulk_notice {
            col = col.push(match note {
                Ok(m) => text(m.clone()).size(13).style(text::success),
                Err(e) => text(e.clone()).size(13).style(text::danger),
            });
        }
        if self.bulk_results.is_empty() {
            return col.into();
        }
        let (mut ok, mut failed, mut pending) = (0, 0, 0);
        let rows = self.bulk_results.iter().map(|(addr, r)| {
            let (status, detail, style): (String, String, fn(&Theme) -> text::Style) = match r {
                None => ("running…".into(), String::new(), text::secondary),
                Some(Err(e)) => ("failed".into(), e.clone(), text::danger),
                Some(Ok(s)) => {
                    let first = s
                        .stdout
                        .lines()
                        .chain(s.stderr.lines())
                        .find(|l| !l.trim().is_empty())
                        .unwrap_or("")
                        .to_owned();
                    match (s.state, s.exit_code) {
                        (ExecState::Exited, Some(0)) => ("exit 0".into(), first, text::success),
                        (ExecState::Exited, Some(c)) => (format!("exit {c}"), first, text::danger),
                        (state, _) => (format!("{state:?}").to_lowercase(), first, text::danger),
                    }
                }
            };
            match r {
                None => pending += 1,
                Some(Ok(s)) if s.state == ExecState::Exited && s.exit_code == Some(0) => ok += 1,
                Some(_) => failed += 1,
            }
            row![
                text(addr).size(13).width(Length::FillPortion(2)),
                text(status)
                    .size(13)
                    .style(style)
                    .width(Length::FillPortion(1)),
                text(detail.chars().take(160).collect::<String>())
                    .size(12)
                    .font(iced::Font::MONOSPACE)
                    .width(Length::FillPortion(4)),
            ]
            .spacing(6)
            .into()
        });
        let rows: Vec<Element<_>> = rows.collect();
        col.push(
            row![
                text(format!(
                    "{ok} succeeded · {failed} failed · {pending} running"
                ))
                .size(13),
                Space::new().width(Length::Fill),
                button(text("Export CSV"))
                    .style(button::secondary)
                    .on_press_maybe((pending == 0).then_some(Message::BulkExport)),
            ]
            .align_y(Alignment::Center),
        )
        .push(scroll(column(rows).spacing(3)).height(Length::Fill))
        .into()
    }

    fn term_view(&self) -> Element<'_, Message> {
        if let Some((addr, _)) = &self.term
            && self.term_exited.is_none()
            && self.direct_selected.as_deref() != Some(addr.as_str())
        {
            return column![
                text(format!(
                    "A terminal is open on {addr}. Close it there before opening one on this computer."
                ))
                .size(13),
                button(text(format!("Go to {addr}")).size(13))
                    .style(button::secondary)
                    .on_press(Message::DirectSelect(addr.clone())),
            ]
            .spacing(8)
            .into();
        }
        let open = self.term.is_some() && self.term_exited.is_none();
        let controls = row![
            pick_list(
                SHELLS,
                Some(ShellChoice(self.term_shell)),
                Message::TermShell
            )
            .text_size(13),
            button(text("Open terminal"))
                .style(button::primary)
                .on_press_maybe((!open).then_some(Message::TermOpen)),
            button(text("Close"))
                .style(button::danger)
                .on_press_maybe(open.then_some(Message::TermClose)),
            Space::new().width(Length::Fill),
            text(match self.term_exited {
                Some(Some(c)) => format!("exited (code {c})"),
                Some(None) => "closed".to_string(),
                None if open => "connected".to_string(),
                None => String::new(),
            })
            .size(12)
            .style(text::secondary),
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let mut col = column![
            text("An interactive shell as the agent's account (LocalSystem when installed as the service). Type one command per line; input is logged on the agent by hash, not content. Idle terminals close after 15 minutes.")
                .size(12)
                .style(text::secondary),
            controls,
        ]
        .spacing(8);
        if let Some(n) = &self.term_notice {
            col = col.push(text(n.clone()).size(13).style(text::danger));
        }
        col.push(
            container(
                scroll(text(&self.term_text).size(12).font(iced::Font::MONOSPACE))
                    .anchor_bottom()
                    .height(Length::Fill)
                    .width(Length::Fill),
            )
            .padding(8)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(container::bordered_box),
        )
        .push(
            text_input(
                if open {
                    "Type a command and press Enter"
                } else {
                    "Open a terminal first"
                },
                &self.term_input,
            )
            .on_input_maybe(open.then_some(Message::TermInput))
            .on_submit(Message::TermSend)
            .font(iced::Font::MONOSPACE)
            .padding(8),
        )
        .into()
    }

    fn updates_view(&self) -> Element<'_, Message> {
        let u = match &self.updates {
            None => return centered("Reading installed updates…"),
            Some((_, Err(e))) => return error_box(e),
            Some((_, Ok(u))) => u,
        };
        let mut col = column![].spacing(6);
        col = col.push(if u.reboot_pending.is_empty() {
            container(text("No restart pending.").size(13))
                .padding(8)
                .width(Length::Fill)
                .style(container::rounded_box)
        } else {
            container(text(format!("Restart pending: {}", u.reboot_pending.join("; "))).size(13))
                .padding(8)
                .width(Length::Fill)
                .style(container::warning)
        });
        let header = row![
            text("Update").size(12).width(Length::FillPortion(2)),
            text("Type").size(12).width(Length::FillPortion(2)),
            text("Installed").size(12).width(Length::FillPortion(2)),
            text("By").size(12).width(Length::FillPortion(3)),
        ]
        .spacing(4);
        let rows = u.hotfixes.iter().map(|h| {
            row![
                text(&h.id).size(13).width(Length::FillPortion(2)),
                text(h.description.as_deref().unwrap_or("—"))
                    .size(13)
                    .width(Length::FillPortion(2)),
                text(h.installed_on.as_deref().unwrap_or("—"))
                    .size(13)
                    .width(Length::FillPortion(2)),
                text(h.installed_by.as_deref().unwrap_or("—"))
                    .size(12)
                    .width(Length::FillPortion(3)),
            ]
            .spacing(4)
            .into()
        });
        col.push(container(header).style(container::rounded_box))
            .push(scroll(column(rows).spacing(3)).height(Length::Fill))
            .push(
                text(format!(
                    "{} installed updates (Windows' hotfix list; feature updates and Store apps are not included)",
                    u.hotfixes.len()
                ))
                .size(12)
                .style(text::secondary),
            )
            .into()
    }

    fn wmi_view(&self) -> Element<'_, Message> {
        let controls = column![
            row![
                text_input(r"ROOT\CIMV2", &self.wmi_namespace)
                    .on_input(Message::WmiNamespace)
                    .padding(6)
                    .width(200),
                text_input("SELECT … FROM …", &self.wmi_wql)
                    .on_input(Message::WmiWql)
                    .on_submit(Message::WmiRun)
                    .padding(6)
                    .font(iced::Font::MONOSPACE),
                button(text(if self.wmi_running {
                    "Running…"
                } else {
                    "Run"
                }))
                .style(button::primary)
                .on_press_maybe((!self.wmi_running).then_some(Message::WmiRun)),
            ]
            .spacing(6),
            text_input(
                "Find a class, e.g. bios, disk, network…",
                &self.wmi_class_filter
            )
            .on_input(Message::WmiClassFilter)
            .padding(6),
        ]
        .spacing(6);
        let mut col = column![
            text("Read-only WQL (SELECT, ASSOCIATORS OF, REFERENCES OF). Requires operator rights; queries are logged on the agent.")
                .size(12)
                .style(text::secondary),
            controls
        ]
        .spacing(8);
        let f = self.wmi_class_filter.trim().to_lowercase();
        if f.len() >= 2 {
            let matches: Vec<&String> = self
                .wmi_classes
                .iter()
                .filter(|c| c.to_lowercase().contains(&f))
                .take(12)
                .collect();
            col = col.push(matches.into_iter().fold(row![].spacing(4), |r, c| {
                r.push(
                    button(text(c).size(12))
                        .style(button::subtle)
                        .padding([2, 6])
                        .on_press(Message::WmiPickClass(c.clone())),
                )
            }));
        }
        let table = match &self.wmi_result {
            None => return col.into(),
            Some(Err(e)) => return col.push(error_box(e)).into(),
            Some(Ok(t)) => t,
        };
        // One card per instance with its non-empty properties: SELECT * is far too wide for a grid.
        let cards = table.rows.iter().map(|r| {
            let props = table
                .columns
                .iter()
                .zip(r)
                .filter(|(c, v)| !v.is_empty() && !c.starts_with("__"))
                .fold(column![].spacing(1), |col, (c, v)| {
                    col.push(
                        row![
                            text(c).size(12).style(text::secondary).width(220),
                            text(v).size(12).font(iced::Font::MONOSPACE),
                        ]
                        .spacing(8),
                    )
                });
            container(props)
                .padding(6)
                .width(Length::Fill)
                .style(container::bordered_box)
                .into()
        });
        col.push(scroll(column(cards).spacing(6)).height(Length::Fill))
            .push(
                text(format!(
                    "{} instance(s){}",
                    table.rows.len(),
                    if table.truncated {
                        " · truncated at 2000"
                    } else {
                        ""
                    }
                ))
                .size(12)
                .style(text::secondary),
            )
            .into()
    }

    fn periph_view(&self) -> Element<'_, Message> {
        let p = match &self.periph {
            None => return centered("Reading printers and drives…"),
            Some((_, Err(e))) => return error_box(e),
            Some((_, Ok(p))) => p,
        };
        let section = |t: &'static str| text(t).size(13).style(text::primary);
        let mut printers = column![section("Printers")].spacing(6);
        if p.printers.is_empty() {
            printers = printers.push(
                text("No printers installed.")
                    .size(13)
                    .style(text::secondary),
            );
        }
        for pr in &p.printers {
            let state = if pr.status.is_empty() {
                "ready".to_string()
            } else {
                pr.status.join(", ")
            };
            let mut tags = Vec::new();
            if pr.network {
                tags.push("network connection");
            }
            if pr.shared {
                tags.push("shared");
            }
            printers = printers.push(
                column![
                    row![
                        text(&pr.name).size(14),
                        text(state).size(12).style(if pr.status.is_empty() {
                            text::success
                        } else {
                            text::warning
                        }),
                        text(format!("{} job(s)", pr.jobs))
                            .size(12)
                            .style(text::secondary),
                    ]
                    .spacing(10)
                    .align_y(Alignment::Center),
                    text(format!(
                        "{} · port {}{}{}",
                        pr.driver.as_deref().unwrap_or("unknown driver"),
                        pr.port.as_deref().unwrap_or("?"),
                        pr.location
                            .as_deref()
                            .map(|l| format!(" · {l}"))
                            .unwrap_or_default(),
                        if tags.is_empty() {
                            String::new()
                        } else {
                            format!(" · {}", tags.join(", "))
                        }
                    ))
                    .size(12)
                    .style(text::secondary),
                ]
                .spacing(2),
            );
        }
        let mut drives = column![section("Mapped network drives (signed-in users)")].spacing(4);
        if p.mapped_drives.is_empty() {
            drives = drives.push(text("None.").size(13).style(text::secondary));
        }
        for d in &p.mapped_drives {
            drives = drives.push(
                text(format!(
                    "{}  {}  →  {}{}",
                    d.user,
                    d.letter,
                    d.remote_path,
                    d.connect_as
                        .as_deref()
                        .map(|u| format!("  (as {u})"))
                        .unwrap_or_default()
                ))
                .size(13),
            );
        }
        scroll(column![printers, rule::horizontal(1), drives].spacing(10)).into()
    }

    fn files_navigate(&mut self, path: String) -> Task<Message> {
        self.files_path = path;
        self.files_input = self.files_path.clone();
        self.files = None;
        self.files_rename = None;
        self.files_confirm = None;
        match self.direct_selected.clone() {
            Some(addr) => self.load_direct(&addr),
            None => Task::none(),
        }
    }

    fn files_run(&mut self, op: FileOp) -> Task<Message> {
        let Some(t) = self.direct_selected.as_deref().and_then(|a| self.target(a)) else {
            return Task::none();
        };
        let done = match &op {
            FileOp::Rename { from, to } => format!("Renamed {from} to {to}."),
            FileOp::Copy { from, to } => format!("Copied {from} to {to}."),
            FileOp::Delete { path, .. } => format!("Deleted {path}."),
            FileOp::Mkdir { path } => format!("Created {path}."),
        };
        Task::perform(direct::files_op(t, op), move |r| {
            Message::FilesOpDone(r.map(|()| done.clone()))
        })
    }

    fn files_view(&self) -> Element<'_, Message> {
        let busy = self.files_busy.is_some();
        let nav = row![
            button(text("Drives"))
                .style(button::secondary)
                .on_press(Message::FilesDrives),
            button(text("Up"))
                .style(button::secondary)
                .on_press_maybe((!self.files_path.is_empty()).then_some(Message::FilesUp)),
            text_input(r"C:\Users\Public", &self.files_input)
                .on_input(Message::FilesInput)
                .on_submit(Message::FilesGo)
                .padding(6),
            button(text("Go"))
                .style(button::secondary)
                .on_press(Message::FilesGo),
        ]
        .spacing(6)
        .align_y(Alignment::Center);
        let mut col = column![
            text("Downloads land in your Downloads folder and are SHA-256 verified. Reading or changing files requires operator rights on the agent.")
                .size(12)
                .style(text::secondary),
            nav
        ]
        .spacing(8);
        if !self.files_path.is_empty() {
            col = col.push(
                row![
                    text_input(
                        r"Local file to upload, e.g. C:\Tools\fix.ps1",
                        &self.files_upload_path
                    )
                    .on_input(Message::FilesUploadPath)
                    .on_submit(Message::FilesUpload)
                    .padding(6),
                    checkbox(self.files_overwrite)
                        .label("overwrite")
                        .on_toggle(Message::FilesOverwrite),
                    button(text("Upload here"))
                        .style(button::primary)
                        .on_press_maybe((!busy).then_some(Message::FilesUpload)),
                    text_input("New folder name", &self.files_new_folder)
                        .on_input(Message::FilesNewFolder)
                        .on_submit(Message::FilesMkdir)
                        .padding(6)
                        .width(160),
                    button(text("Create"))
                        .style(button::secondary)
                        .on_press(Message::FilesMkdir),
                    checkbox(self.files_recursive)
                        .label("delete folders with contents")
                        .on_toggle(Message::FilesRecursive),
                ]
                .spacing(6)
                .align_y(Alignment::Center),
            );
        }
        if let Some(op) = &self.files_confirm {
            let what = match op {
                FileOp::Delete {
                    path,
                    recursive: true,
                } => format!("Delete {path} and everything in it?"),
                FileOp::Delete { path, .. } => format!("Delete {path}?"),
                _ => "Apply this change?".into(),
            };
            col = col.push(
                container(
                    column![
                        text(what),
                        row![
                            button(text("Delete"))
                                .style(button::danger)
                                .on_press(Message::FilesConfirm),
                            button(text("Cancel"))
                                .style(button::secondary)
                                .on_press(Message::FilesCancel),
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
        if let Some(b) = &self.files_busy {
            col = col.push(text(b.clone()).size(13).style(text::secondary));
        }
        if let Some(n) = &self.files_notice {
            col = col.push(match n {
                Ok(m) => text(m.clone()).size(13).style(text::success),
                Err(e) => text(e.clone()).size(13).style(text::danger),
            });
        }
        let listing = match &self.files {
            None => return col.push(centered("Listing…")).into(),
            Some((_, Err(e))) => return col.push(error_box(e)).into(),
            Some((_, Ok(l))) => l,
        };
        let drives = listing.path.is_empty();
        // shortcut: renders every entry; folders with tens of thousands of files need T-307.
        let rows = listing.entries.iter().map(|e| {
            let name: Element<_> = match &self.files_rename {
                Some((old, new)) if old == &e.name => row![
                    text_input("New name", new)
                        .on_input(Message::FilesRenameInput)
                        .on_submit(Message::FilesRenameApply)
                        .padding(4),
                    button(text("Save").size(12))
                        .style(button::primary)
                        .on_press(Message::FilesRenameApply),
                ]
                .spacing(4)
                .into(),
                _ if e.is_dir => button(text(format!("📁 {}", e.name)).size(13))
                    .style(button::text)
                    .padding([2, 4])
                    .on_press(Message::FilesOpen(e.name.clone()))
                    .into(),
                _ => text(format!("📄 {}", e.name)).size(13).into(),
            };
            let mut r = row![
                container(name).width(Length::FillPortion(5)),
                text(if e.is_dir {
                    String::new()
                } else {
                    human_size(e.size)
                })
                .size(12)
                .width(Length::FillPortion(1)),
                text(e.modified.map(ago).unwrap_or_default())
                    .size(12)
                    .width(Length::FillPortion(1)),
            ]
            .spacing(4)
            .align_y(Alignment::Center);
            if !drives {
                if !e.is_dir {
                    r = r.push(
                        button(text("Download").size(12))
                            .style(button::subtle)
                            .padding([2, 6])
                            .on_press_maybe(
                                (!busy).then(|| Message::FilesDownload(e.name.clone())),
                            ),
                    );
                }
                r = r
                    .push(
                        button(text("Rename").size(12))
                            .style(button::subtle)
                            .padding([2, 6])
                            .on_press(Message::FilesRenameStart(e.name.clone())),
                    )
                    .push(
                        button(text("Delete").size(12))
                            .style(button::subtle)
                            .padding([2, 6])
                            .on_press(Message::FilesAskDelete(e.name.clone(), e.is_dir)),
                    );
            }
            r.into()
        });
        col.push(scroll(column(rows).spacing(2)).height(Length::Fill))
            .push(
                text(format!(
                    "{} {}",
                    listing.entries.len(),
                    if drives { "drives" } else { "items" }
                ))
                .size(12)
                .style(text::secondary),
            )
            .into()
    }

    fn cmd_view(&self) -> Element<'_, Message> {
        let running = self
            .cmd_job
            .as_ref()
            .is_some_and(|(_, s)| s.state == ExecState::Running);
        let controls = row![
            pick_list(SHELLS, Some(ShellChoice(self.cmd_shell)), Message::CmdShell).text_size(13),
            text("Timeout (s)").size(13),
            text_input("60", &self.cmd_timeout)
                .on_input(Message::CmdTimeout)
                .padding(6)
                .width(70),
            Space::new().width(Length::Fill),
            button(text("Run"))
                .style(button::primary)
                .on_press_maybe((!running).then_some(Message::CmdAskRun)),
            button(text("Stop"))
                .style(button::danger)
                .on_press_maybe(running.then_some(Message::CmdStop)),
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let mut col = column![
            text("Runs as the agent's own account (LocalSystem when installed as the service), not as the signed-in user. Output and exit code are captured; the script itself is not logged.")
                .size(12)
                .style(text::secondary),
            controls,
            text_editor(&self.cmd_script)
                .placeholder("Get-Service | Where-Object Status -eq 'Stopped'")
                .on_action(Message::CmdEdit)
                .font(iced::Font::MONOSPACE)
                .height(160),
        ]
        .spacing(8);
        if self.cmd_confirm {
            col = col.push(
                container(
                    column![
                        text(format!(
                            "Run this {} script on {} with the agent's privileges?",
                            ShellChoice(self.cmd_shell),
                            self.direct_selected.as_deref().unwrap_or("?")
                        )),
                        row![
                            button(text("Run"))
                                .style(button::danger)
                                .on_press(Message::CmdConfirm),
                            button(text("Cancel"))
                                .style(button::secondary)
                                .on_press(Message::CmdCancelConfirm),
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
        if let Some(n) = &self.cmd_notice {
            col = col.push(text(n.clone()).size(13).style(text::danger));
        }
        if let Some((_, s)) = &self.cmd_job {
            let state = match s.state {
                ExecState::Running => "running…".to_string(),
                ExecState::Exited => format!(
                    "exited with code {}",
                    s.exit_code.map_or("?".into(), |c| c.to_string())
                ),
                ExecState::TimedOut => "timed out (process tree terminated)".into(),
                ExecState::Cancelled => "stopped (process tree terminated)".into(),
                ExecState::Failed => {
                    format!("failed to start: {}", s.error.as_deref().unwrap_or(""))
                }
            };
            let style = match (s.state, s.exit_code) {
                (ExecState::Exited, Some(0)) => text::success,
                (ExecState::Running, _) => text::secondary,
                _ => text::danger,
            };
            let mut out = column![
                text(format!(
                    "{state}{}",
                    if s.truncated {
                        " · output truncated at 1 MiB"
                    } else {
                        ""
                    }
                ))
                .size(13)
                .style(style),
                text(&s.stdout).size(12).font(iced::Font::MONOSPACE),
            ]
            .spacing(6);
            if !s.stderr.is_empty() {
                out = out.push(
                    text(&s.stderr)
                        .size(12)
                        .font(iced::Font::MONOSPACE)
                        .style(text::danger),
                );
            }
            col = col.push(
                container(scroll(out).height(Length::Fill))
                    .padding(8)
                    .width(Length::Fill)
                    .style(container::bordered_box),
            );
        }
        col.into()
    }

    fn reg_key(&self) -> RegKeyPath {
        RegKeyPath {
            hive: self.reg_hive,
            path: self.reg_path.clone(),
            view: if self.reg_bits32 {
                RegView::Bits32
            } else {
                RegView::Bits64
            },
        }
    }

    fn reg_navigate(&mut self, path: String) -> Task<Message> {
        self.reg_path = path;
        self.reg_path_input = self.reg_path.clone();
        self.reg = None;
        self.reg_confirm = None;
        match self.direct_selected.clone() {
            Some(addr) => self.load_direct(&addr),
            None => Task::none(),
        }
    }

    fn reg_view(&self) -> Element<'_, Message> {
        let nav = row![
            pick_list(HIVES, Some(HiveChoice(self.reg_hive)), Message::RegHive).text_size(13),
            text_input("Key path, e.g. SOFTWARE\\Microsoft", &self.reg_path_input)
                .on_input(Message::RegPathInput)
                .on_submit(Message::RegGo)
                .padding(6),
            button(text("Go"))
                .style(button::secondary)
                .on_press(Message::RegGo),
            button(text("Up"))
                .style(button::secondary)
                .on_press_maybe((!self.reg_path.is_empty()).then_some(Message::RegUp)),
            checkbox(self.reg_bits32)
                .label("32-bit view")
                .on_toggle(Message::RegBits32),
            button(text("Export .reg"))
                .style(button::secondary)
                .on_press(Message::RegExport),
        ]
        .spacing(6)
        .align_y(Alignment::Center);

        let mut col = column![nav].spacing(8);
        if let Some(change) = &self.reg_confirm {
            col = col.push(
                container(
                    column![
                        text(format!("{}?", change.describe())),
                        row![
                            button(text("Confirm"))
                                .style(button::danger)
                                .on_press(Message::RegConfirm),
                            button(text("Cancel"))
                                .style(button::secondary)
                                .on_press(Message::RegCancel),
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
        if let Some(n) = &self.reg_notice {
            col = col.push(match n {
                Ok(m) => text(m.clone()).size(13).style(text::success),
                Err(e) => text(e.clone()).size(13).style(text::danger),
            });
        }
        let contents = match &self.reg {
            None => return col.push(centered("Reading key…")).into(),
            Some((_, Err(e))) => return col.push(error_box(e)).into(),
            Some((_, Ok(c))) => c,
        };

        let subkeys = contents.subkeys.iter().fold(column![].spacing(1), |c, k| {
            c.push(
                button(text(format!("▸ {k}")).size(13))
                    .style(button::text)
                    .padding([2, 4])
                    .width(Length::Fill)
                    .on_press(Message::RegOpen(k.clone())),
            )
        });
        let values = contents.values.iter().fold(column![].spacing(2), |c, v| {
            let (ty, shown) = reg_display(&v.data);
            c.push(
                row![
                    // Names and data rarely have spaces; break inside them rather than overlap.
                    text(if v.name.is_empty() {
                        "(Default)"
                    } else {
                        &v.name
                    })
                    .size(13)
                    .wrapping(text::Wrapping::WordOrGlyph)
                    .width(Length::FillPortion(3)),
                    text(ty).size(12).style(text::secondary).width(110),
                    text(shown.chars().take(200).collect::<String>())
                        .size(13)
                        .wrapping(text::Wrapping::WordOrGlyph)
                        .width(Length::FillPortion(5)),
                    button(text("Edit").size(12))
                        .style(button::subtle)
                        .padding([2, 6])
                        .on_press(Message::RegEdit(v.clone())),
                    button(text("Delete").size(12))
                        .style(button::subtle)
                        .padding([2, 6])
                        .on_press(Message::RegAskDeleteValue(v.name.clone())),
                ]
                .spacing(4)
                .align_y(Alignment::Center),
            )
        });
        let form = row![
            text_input("Value name (empty = default)", &self.reg_form_name)
                .on_input(Message::RegFormName)
                .padding(6)
                .width(Length::FillPortion(3)),
            pick_list(REG_TYPES, Some(self.reg_form_type), Message::RegFormType).text_size(13),
            text_input(
                match self.reg_form_type {
                    RegType::MultiString => "Entries separated by |",
                    RegType::Dword | RegType::Qword => "Decimal or 0x-hex",
                    RegType::Binary => "Hex bytes, e.g. de ad be ef",
                    _ => "Data",
                },
                &self.reg_form_data
            )
            .on_input(Message::RegFormData)
            .on_submit(Message::RegAskSet)
            .padding(6)
            .width(Length::FillPortion(4)),
            button(text("Set value"))
                .style(button::primary)
                .on_press(Message::RegAskSet),
        ]
        .spacing(6)
        .align_y(Alignment::Center);
        let key_actions = row![
            checkbox(self.reg_recursive)
                .label("include subkeys")
                .on_toggle(Message::RegRecursive),
            button(text("Delete this key").size(12))
                .style(button::danger)
                .on_press_maybe((!self.reg_path.is_empty()).then_some(Message::RegAskDeleteKey)),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        col.push(
            row![
                container(scroll(subkeys).height(Length::Fill))
                    .width(Length::FillPortion(1))
                    .style(container::bordered_box)
                    .padding(4),
                column![
                    text(format!("{} values", contents.values.len()))
                        .size(12)
                        .style(text::secondary),
                    scroll(values).height(Length::Fill),
                    form,
                    key_actions,
                ]
                .spacing(6)
                .width(Length::FillPortion(3)),
            ]
            .spacing(8)
            .height(Length::Fill),
        )
        .into()
    }

    fn sw_view(&self) -> Element<'_, Message> {
        let inv = match &self.sw {
            None => return centered("Reading installed software…"),
            Some((_, Err(e))) => return error_box(e),
            Some((_, Ok(inv))) => inv,
        };
        let mut col = column![
            row![
                text_input(
                    r"MSI on the agent to install silently, e.g. C:\Temp\app.msi (upload it in Files)",
                    &self.sw_msi_path
                )
                .on_input(Message::SwMsiPath)
                .on_submit(Message::SwAskInstall)
                .padding(6),
                button(text("Install"))
                    .style(button::primary)
                    .on_press(Message::SwAskInstall),
            ]
            .spacing(6)
        ]
        .spacing(6);
        if let Some(change) = &self.sw_confirm {
            let what = match change {
                SwChange::Uninstall(name, _) => {
                    format!("Silently uninstall {name}? Users of it will lose it immediately.")
                }
                SwChange::Install(r) => {
                    format!("Silently install {} on this computer?", r.msi_path)
                }
            };
            col = col.push(
                container(
                    column![
                        text(what),
                        row![
                            button(text("Confirm"))
                                .style(button::danger)
                                .on_press(Message::SwConfirm),
                            button(text("Cancel"))
                                .style(button::secondary)
                                .on_press(Message::SwCancel),
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
        if let (Some(label), Some((_, job))) = (&self.sw_job_label, &self.cmd_job) {
            let (msg, style): (String, fn(&Theme) -> text::Style) = match (job.state, job.exit_code)
            {
                (ExecState::Running, _) => (format!("{label}: running…"), text::secondary),
                (ExecState::Exited, Some(c)) => (
                    format!("{label}: {} (exit code {c})", msi_outcome(c)),
                    if matches!(c, 0 | 3010 | 1641) {
                        text::success
                    } else {
                        text::danger
                    },
                ),
                (state, _) => (format!("{label}: {state:?}"), text::danger),
            };
            col = col.push(text(msg).size(13).style(style));
        }
        if let Some(n) = &self.cmd_notice
            && self.sw_job_label.is_some()
        {
            col = col.push(text(n.clone()).size(13).style(text::danger));
        }
        if !inv.reboot_pending.is_empty() {
            col = col.push(
                container(
                    text(format!(
                        "Restart pending: {}",
                        inv.reboot_pending.join("; ")
                    ))
                    .size(13),
                )
                .padding(8)
                .width(Length::Fill)
                .style(container::warning),
            );
        }
        let f = self.sw_filter.to_lowercase();
        let shown: Vec<&InstalledApp> = inv
            .apps
            .iter()
            .filter(|a| {
                f.is_empty()
                    || a.name.to_lowercase().contains(&f)
                    || a.publisher
                        .as_deref()
                        .is_some_and(|p| p.to_lowercase().contains(&f))
            })
            .collect();
        let header = row![
            text("Name").size(12).width(Length::FillPortion(4)),
            text("Version").size(12).width(Length::FillPortion(2)),
            text("Publisher").size(12).width(Length::FillPortion(3)),
            // Fixed widths: dates and sizes never wrap, so a share of a narrow panel overlaps.
            text("Installed").size(12).width(80),
            text("Size").size(12).width(64),
            text("Scope").size(12).width(Length::FillPortion(2)),
            Space::new().width(80),
        ]
        .spacing(4);
        // shortcut: renders every matching row (a few hundred); virtualize with T-307.
        let rows = shown.iter().map(|a| {
            // YYYYMMDD → YYYY-MM-DD when it looks like one.
            let date = a.install_date.as_deref().map(|d| {
                if d.len() == 8 && d.bytes().all(|b| b.is_ascii_digit()) {
                    format!("{}-{}-{}", &d[..4], &d[4..6], &d[6..])
                } else {
                    d.to_owned()
                }
            });
            row![
                text(&a.name)
                    .size(13)
                    .wrapping(text::Wrapping::WordOrGlyph)
                    .width(Length::FillPortion(4)),
                text(a.version.as_deref().unwrap_or("—"))
                    .size(13)
                    .wrapping(text::Wrapping::WordOrGlyph)
                    .width(Length::FillPortion(2)),
                text(a.publisher.as_deref().unwrap_or("—"))
                    .size(13)
                    .wrapping(text::Wrapping::WordOrGlyph)
                    .width(Length::FillPortion(3)),
                text(date.unwrap_or_else(|| "—".into())).size(12).width(80),
                text(a.size_bytes.map_or("—".into(), |b| format!(
                    "{:.0} MB",
                    b as f64 / 1_048_576.0
                )))
                .size(12)
                .width(64),
                text(a.scope.strip_prefix("machine-").unwrap_or(&a.scope))
                    .size(12)
                    .width(Length::FillPortion(2)),
                button(text("Uninstall").size(12))
                    .style(button::subtle)
                    .padding([2, 6])
                    .width(80)
                    // Only machine-wide entries with an uninstaller can be removed silently from here.
                    .on_press_maybe((a.has_uninstaller && a.scope.starts_with("machine-")).then(
                        || {
                            Message::SwAskUninstall(
                                a.name.clone(),
                                UninstallRequest {
                                    uninstall_key: a.uninstall_key.clone(),
                                    scope: a.scope.clone(),
                                },
                            )
                        }
                    )),
            ]
            .spacing(4)
            .align_y(Alignment::Center)
            .into()
        });
        col.push(
            text_input("Filter by name or publisher…", &self.sw_filter)
                .on_input(Message::SwFilter)
                .padding(8),
        )
        .push(container(header).style(container::rounded_box))
        .push(scroll(column(rows).spacing(3)).height(Length::Fill))
        .push(
            text(format!(
                "{} of {} applications",
                shown.len(),
                inv.apps.len()
            ))
            .size(12)
            .style(text::secondary),
        )
        .into()
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
        scroll(
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
                crate::selected_row
            } else {
                button::text
            })
            .width(Length::Fill)
            .padding([4, 6])
            .on_press(Message::EvtToggle(e.record_id))
            .into()
        });
        col.push(scroll(column(rows).spacing(2)).height(Length::Fill))
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
            .push(scroll(column(rows).spacing(4)).height(Length::Fill))
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
            .push(scroll(column(rows).spacing(2)).height(Length::Fill))
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
    let kv = |k: &'a str, v: String| {
        row![
            text(k).width(120).style(text::secondary),
            text(v).wrapping(text::Wrapping::WordOrGlyph)
        ]
        .spacing(8)
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

    scroll(
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

/// Saves `.reg` text the way regedit expects it (UTF-16LE with BOM) into Downloads.
fn save_reg_file(label: &str, text: &str) -> Result<String, String> {
    let dir = downloads_dir().ok_or("USERPROFILE not set")?;
    let safe: String = label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .take(80)
        .collect();
    let path = dir.join(format!("tervano-{safe}-{}.reg", now_millis()));
    let mut bytes = vec![0xFF, 0xFE];
    bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    std::fs::write(&path, bytes).map_err(|e| format!("Export failed: {e}"))?;
    Ok(format!("Exported to {}", path.display()))
}

/// Writes bulk-run results (one row per computer, full output) as CSV into `dir`.
fn export_bulk_csv(
    dir: &std::path::Path,
    results: &[(String, Option<Result<ExecStatus, String>>)],
) -> Result<String, String> {
    let quote = csv_cell;
    let mut csv = String::from("endpoint,state,exit_code,stdout,stderr,error\r\n");
    for (addr, r) in results {
        let (state, code, out, err, error) = match r {
            None => ("running".to_string(), String::new(), "", "", String::new()),
            Some(Err(e)) => ("failed".into(), String::new(), "", "", e.clone()),
            Some(Ok(s)) => (
                format!("{:?}", s.state).to_lowercase(),
                s.exit_code.map(|c| c.to_string()).unwrap_or_default(),
                s.stdout.as_str(),
                s.stderr.as_str(),
                s.error.clone().unwrap_or_default(),
            ),
        };
        csv.push_str(&format!(
            "{},{},{},{},{},{}\r\n",
            quote(addr),
            state,
            code,
            quote(out),
            quote(err),
            quote(&error)
        ));
    }
    let path = dir.join(format!("tervano-bulk-{}.csv", now_millis()));
    std::fs::write(&path, csv).map_err(|e| format!("Export failed: {e}"))?;
    Ok(format!(
        "Exported {} results to {}",
        results.len(),
        path.display()
    ))
}

/// A quoted CSV cell. A leading = + - @ would make spreadsheets evaluate it (CSV injection).
fn csv_cell(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@']) {
        format!("'{s}")
    } else {
        s.to_owned()
    };
    format!("\"{}\"", s.replace('"', "\"\""))
}

fn role_label(r: TechRole) -> &'static str {
    match r {
        TechRole::Viewer => "viewer",
        TechRole::Operator => "operator",
        TechRole::Admin => "admin",
    }
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

/// A vertical scroll area whose scrollbar gets its own lane instead of covering the right edge
/// (where row buttons such as "Terminate" sit).
fn scroll<'a>(content: impl Into<Element<'a, Message>>) -> iced::widget::Scrollable<'a, Message> {
    scrollable(content).spacing(4)
}

/// Selected list row: a light tint of the accent colour, so normal and secondary text stay readable.
fn selected_row(theme: &Theme, status: button::Status) -> button::Style {
    let p = theme.extended_palette();
    let strength = match status {
        button::Status::Hovered | button::Status::Pressed => 0.32,
        _ => 0.22,
    };
    button::Style {
        background: Some(
            Color {
                a: strength,
                ..p.primary.base.color
            }
            .into(),
        ),
        text_color: p.background.base.text,
        border: iced::border::rounded(4),
        ..button::text(theme, status)
    }
}

fn status_dot<'a>(online: bool) -> Element<'a, Message> {
    let color = if online {
        Color::from_rgb8(0x2e, 0xa0, 0x43)
    } else {
        Color::from_rgb8(0x8a, 0x8f, 0x98)
    };
    // The styled box is the dot itself; the outer one only reserves the column width.
    let dot = container(Space::new())
        .width(10)
        .height(10)
        .style(move |_| container::Style {
            background: Some(color.into()),
            border: iced::border::rounded(5),
            ..Default::default()
        });
    container(dot).width(14).into()
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
