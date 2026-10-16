//! Wire types shared by Tervano Console, Agent and Server.
//!
//! Phase 1 transport is HTTP + JSON. Every request carries [`PROTOCOL_HEADER`];
//! peers reject a different major version.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// `major.minor`. Bump minor for additive changes, major for breaking ones.
pub const PROTOCOL_VERSION: &str = "1.16";
pub const PROTOCOL_HEADER: &str = "x-tervano-protocol";

/// True when `other` (a `major.minor` string) is wire-compatible with ours.
pub fn is_compatible(other: &str) -> bool {
    let major = |v: &str| v.split('.').next().map(str::to_owned);
    major(other).is_some() && major(other) == major(PROTOCOL_VERSION)
}

/// Plaintext `http://` is only acceptable to a loopback host; everything else must be `https://`.
pub fn url_transport_ok(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.rsplit_once(':').map_or(authority, |(h, _)| h),
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Unix time in milliseconds.
pub type Millis = i64;

pub fn now_millis() -> Millis {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: String,
    pub version: String,
    pub build: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetAddress {
    pub interface: String,
    /// Textual IPv4 or IPv6 address.
    pub address: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Active,
    Disconnected,
    Other,
}

/// An interactive Windows session as seen by the agent (not inferred from AD).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserSession {
    pub session_id: u32,
    pub username: String,
    pub domain: String,
    pub state: SessionState,
    /// "Console", "RDP-Tcp#0", ...
    pub station: String,
}

/// Everything the agent reports about itself. Sent whole; the server keeps the latest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceState {
    pub hostname: String,
    pub domain: Option<String>,
    pub os: OsInfo,
    pub addresses: Vec<NetAddress>,
    pub sessions: Vec<UserSession>,
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub token: String,
    pub state: DeviceState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub device_id: Uuid,
    /// Bearer secret for this device. Shown once; the server stores only its hash.
    pub device_secret: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    /// Agent (re)started; carries full state.
    Startup {
        state: DeviceState,
    },
    /// Something in the state changed; carries full state (small, simplest correct reconciliation).
    StateChanged {
        state: DeviceState,
    },
    Heartbeat,
    Shutdown,
}

/// `seq` is strictly increasing per device; the server ignores seq <= last seen,
/// which makes retries idempotent and rejects replays.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentEvent {
    pub seq: u64,
    pub at: Millis,
    #[serde(flatten)]
    pub kind: EventKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventAck {
    /// Highest seq the server has applied for this device.
    pub last_seq: u64,
}

/// An accepted device event, ordered by sequence number in the history API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceEventRecord {
    /// Server receipt time; `event.at` is supplied by the agent.
    pub received_at: Millis,
    pub event: AgentEvent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceSummary {
    pub id: Uuid,
    pub hostname: String,
    pub online: bool,
    pub last_seen: Millis,
    pub primary_ip: Option<String>,
    pub users: Vec<String>,
    pub os: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceDetails {
    pub id: Uuid,
    pub online: bool,
    pub enrolled_at: Millis,
    pub last_seen: Millis,
    pub state: DeviceState,
}

/// One running process, as listed by an agent (`GET /v1/processes` on the direct channel).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub exe: Option<String>,
    /// `DOMAIN\user` or bare user; `None` when the agent cannot read the process owner.
    pub user: Option<String>,
    /// Share of total machine CPU since the previous listing, 0–100.
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub started_at: Millis,
    /// "x64", "x86", "arm64"; `None` for processes the agent may not open.
    pub arch: Option<String>,
}

/// Kill request body. `name` must match the process currently holding `pid`, so a PID reused
/// since the technician's listing is never killed by mistake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillRequest {
    pub name: String,
}

/// One Windows service as reported by an agent (`GET /v1/services` on the direct channel).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceEntry {
    /// Key name, e.g. `Spooler`.
    pub name: String,
    pub display_name: String,
    /// "running", "stopped", "paused", "start_pending", "stop_pending", "pause_pending", "continue_pending".
    pub state: String,
    pub pid: Option<u32>,
    /// `None` when the agent could not read the service's configuration.
    pub start_type: Option<StartType>,
    pub account: Option<String>,
    pub executable: Option<String>,
    pub dependencies: Vec<String>,
    pub can_stop: bool,
    pub can_pause: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartType {
    Automatic,
    Manual,
    Disabled,
    /// Driver start types; reported, never set.
    Boot,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAction {
    Start,
    Stop,
    Pause,
    Resume,
    Restart,
}

/// Body of `POST /v1/services/{name}/control`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceControlRequest {
    pub action: ServiceAction,
}

/// Body of `POST /v1/services/{name}/start-type`. Only automatic, manual and disabled are accepted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartTypeRequest {
    pub start_type: StartType,
}

/// One Windows event log record (`GET /v1/eventlog/events` on the direct channel).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventRecord {
    pub record_id: u64,
    pub time: Millis,
    /// 1 critical, 2 error, 3 warning, 4 information, 5 verbose (0 = "log always", shown as information).
    pub level: u8,
    pub provider: String,
    pub event_id: u32,
    /// Rendered message; `None` when the provider's message resources are unavailable.
    pub message: Option<String>,
}

/// Query string of `GET /v1/eventlog/events`. Results are newest first.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventQuery {
    /// e.g. "System", "Application", "Microsoft-Windows-PowerShell/Operational".
    pub channel: String,
    /// Only this level or more severe (1–5).
    pub max_level: Option<u8>,
    pub provider: Option<String>,
    pub event_id: Option<u32>,
    /// Only events newer than this many minutes.
    pub within_minutes: Option<u32>,
    /// At most this many records (default 100, max 500).
    pub limit: Option<u32>,
}

/// Hardware and firmware facts reported by an agent (`GET /v1/inventory/hardware`).
/// `None` means "could not be determined", never "absent", unless documented otherwise.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HardwareInventory {
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub bios_vendor: Option<String>,
    pub bios_version: Option<String>,
    pub bios_date: Option<String>,
    pub cpu_model: String,
    pub cpu_physical_cores: Option<u32>,
    pub cpu_logical_cores: u32,
    pub cpu_usage_percent: f32,
    pub memory_total_bytes: u64,
    pub memory_used_bytes: u64,
    pub disks: Vec<DiskInfo>,
    pub boot_time: Millis,
    pub secure_boot: Option<bool>,
    /// "2.0" / "1.2"; `None` when no TPM is visible to Windows.
    pub tpm_version: Option<String>,
    /// `None` on machines without a battery.
    pub battery: Option<BatteryInfo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiskInfo {
    /// e.g. `C:\`.
    pub mount_point: String,
    pub label: String,
    pub file_system: String,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub removable: bool,
    /// "ssd", "hdd" or "unknown".
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatteryInfo {
    pub charge_percent: Option<u8>,
    pub on_ac_power: Option<bool>,
}

/// Installed software and reboot state (`GET /v1/inventory/software`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SoftwareInventory {
    pub apps: Vec<InstalledApp>,
    /// Why Windows wants a restart; empty when no reboot is pending.
    pub reboot_pending: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstalledApp {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    /// As recorded by the installer, usually `YYYYMMDD`.
    pub install_date: Option<String>,
    pub size_bytes: Option<u64>,
    /// "machine-x64", "machine-x86" or "user:DOMAIN\name".
    pub scope: String,
    /// Uninstall registry key name (MSI product code for MSI installs).
    pub uninstall_key: String,
    pub msi: bool,
    pub has_uninstaller: bool,
}

/// Registry roots the agent exposes. HKCU is deliberately absent: the agent runs as SYSTEM, so
/// a user's hive is reached through HKU\<SID>.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegHive {
    #[serde(rename = "HKLM")]
    LocalMachine,
    #[serde(rename = "HKU")]
    Users,
    #[serde(rename = "HKCR")]
    ClassesRoot,
    #[serde(rename = "HKCC")]
    CurrentConfig,
}

/// Registry view on 64-bit Windows; `bits64` is what 64-bit programs see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegView {
    #[default]
    Bits64,
    Bits32,
}

/// A registry key location, used as query string or request body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegKeyPath {
    pub hive: RegHive,
    /// Backslash-separated, no leading backslash; empty for the hive root.
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub view: RegView,
}

/// A typed registry value. Unusual types round-trip as `other` (raw bytes, hex).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum RegData {
    String(String),
    ExpandString(String),
    MultiString(Vec<String>),
    Dword(u32),
    Qword(u64),
    /// Hex-encoded bytes.
    Binary(String),
    None,
    Other {
        type_id: u32,
        hex: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegValue {
    /// Empty string = the key's default value.
    pub name: String,
    pub data: RegData,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegKeyContents {
    pub subkeys: Vec<String>,
    pub values: Vec<RegValue>,
}

/// Body of `POST /v1/registry/value` (creates the key if needed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegSetValueRequest {
    pub key: RegKeyPath,
    pub name: String,
    pub data: RegData,
}

/// Body of `POST /v1/registry/value/delete`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegDeleteValueRequest {
    pub key: RegKeyPath,
    pub name: String,
}

/// Body of `POST /v1/registry/key/delete`. A key with subkeys is only deleted when `recursive`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegDeleteKeyRequest {
    pub key: RegKeyPath,
    pub recursive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Shell {
    Powershell,
    Cmd,
}

/// Whose identity a remote command runs as (PLAN §7: never silently interchangeable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecContext {
    /// The agent's own account: LocalSystem when installed as the service.
    Agent,
    /// The signed-in user's session. Requires the session helper; refused until it exists.
    User,
}

/// Body of `POST /v1/exec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub shell: Shell,
    pub script: String,
    pub context: ExecContext,
    /// Default 60, max 3600.
    pub timeout_secs: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecState {
    Running,
    Exited,
    TimedOut,
    Cancelled,
    /// Could not be started.
    Failed,
}

/// `GET /v1/exec/{id}`: progress so far, final once `state` is not `running`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecStatus {
    pub id: Uuid,
    pub state: ExecState,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// Output beyond the per-stream cap (1 MiB) was dropped.
    pub truncated: bool,
    pub started_at: Millis,
    pub finished_at: Option<Millis>,
    pub error: Option<String>,
}

/// Max bytes per file chunk in either direction.
pub const FILE_CHUNK_MAX: u32 = 8 * 1024 * 1024;
/// Response header carrying the file's total size on `GET /v1/files/read`.
pub const FILE_SIZE_HEADER: &str = "x-tervano-file-size";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<Millis>,
    pub readonly: bool,
    pub hidden: bool,
}

/// `GET /v1/files/list?path=`. An empty `path` lists drives (entry names like `C:\`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirListing {
    pub path: String,
    pub entries: Vec<FileEntry>,
}

/// Query of `GET /v1/files/list` and `/hash`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePathQuery {
    #[serde(default)]
    pub path: String,
}

/// Query of `GET /v1/files/read` (body: raw bytes) and `POST /v1/files/upload` (body: raw bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunkQuery {
    pub path: String,
    pub offset: u64,
    /// Read length, at most FILE_CHUNK_MAX (default). Ignored for uploads.
    pub len: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileHash {
    pub size: u64,
    pub sha256: String,
}

/// Response of `POST /v1/files/upload`: bytes received so far (resume from here).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UploadProgress {
    pub part_size: u64,
}

/// Body of `POST /v1/files/upload/finish`: the upload only replaces `path` if the hash matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadFinish {
    pub path: String,
    pub sha256: String,
    pub overwrite: bool,
}

/// Body of `POST /v1/files/op`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum FileOp {
    Rename { from: String, to: String },
    Copy { from: String, to: String },
    Delete { path: String, recursive: bool },
    Mkdir { path: String },
}

/// Body of `POST /v1/software/uninstall`; identifies an entry from the software inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UninstallRequest {
    pub uninstall_key: String,
    pub scope: String,
}

/// Body of `POST /v1/software/install`: an MSI already on the endpoint (e.g. uploaded via files).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallRequest {
    pub msi_path: String,
}

/// Printers and mapped drives (`GET /v1/inventory/peripherals`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Peripherals {
    pub printers: Vec<PrinterInfo>,
    /// Network drive mappings of every signed-in user (their registry hive is loaded).
    pub mapped_drives: Vec<DriveMapping>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrinterInfo {
    pub name: String,
    pub driver: Option<String>,
    pub port: Option<String>,
    pub share_name: Option<String>,
    pub location: Option<String>,
    pub shared: bool,
    /// A connection to a printer on another computer.
    pub network: bool,
    pub offline: bool,
    /// Spooler conditions such as "paper jam" or "toner low"; empty when ready.
    pub status: Vec<String>,
    pub jobs: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DriveMapping {
    /// `DOMAIN\user` (or SID when it can't be resolved).
    pub user: String,
    /// e.g. "Z:".
    pub letter: String,
    pub remote_path: String,
    /// Alternate account the mapping connects as, if any.
    pub connect_as: Option<String>,
}

/// Query string of `GET /v1/wmi/query` (read-only WQL) and `/v1/wmi/classes`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WmiQuery {
    /// Default `ROOT\CIMV2`.
    pub namespace: Option<String>,
    #[serde(default)]
    pub wql: String,
}

/// WQL results as text, column order as first seen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WmiTable {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    /// More rows existed than the agent returns (2000).
    pub truncated: bool,
}

/// Installed updates and restart state (`GET /v1/updates`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpdateStatus {
    pub hotfixes: Vec<Hotfix>,
    pub reboot_pending: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hotfix {
    /// e.g. "KB5031455".
    pub id: String,
    pub description: Option<String>,
    /// As Windows reports it, usually `M/D/YYYY`.
    pub installed_on: Option<String>,
    pub installed_by: Option<String>,
}

/// Hardware + software snapshot an agent sends to the server (`POST /api/v1/inventory`) at
/// startup and daily — never on the heartbeat path. The server keeps the latest per device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InventoryReport {
    pub collected_at: Millis,
    pub hardware: HardwareInventory,
    pub software: SoftwareInventory,
}

/// Body of `POST /v1/terminal`: open an interactive shell as the agent's account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalStart {
    pub shell: Shell,
}

/// Body of `POST /v1/terminal/{id}/input`: bytes for the shell's stdin (include the newline).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalInput {
    pub text: String,
}

/// `GET /v1/terminal/{id}/output?since=N`: output from absolute offset `since`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TerminalOutput {
    pub id: Uuid,
    pub output: String,
    /// Pass as `since` next time.
    pub next: u64,
    /// Output older than the agent's buffer (256 KiB) was dropped before `since`.
    pub skipped: bool,
    pub exited: bool,
    pub exit_code: Option<i32>,
}

/// Query of `GET /v1/terminal/{id}/output`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TerminalSince {
    #[serde(default)]
    pub since: u64,
}

/// Most devices one server job may target.
pub const JOB_MAX_TARGETS: usize = 1000;
/// Each output stream of a job result is cut to this many bytes before upload.
pub const JOB_OUTPUT_CAP: usize = 64 * 1024;

/// Body of `POST /api/v1/jobs`: run a script on server-managed devices (T-800). Agents run it only
/// if they opted in to server jobs and allow the creating technician.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobCreate {
    pub name: String,
    pub shell: Shell,
    pub script: String,
    /// Default 300, max 3600.
    pub timeout_secs: Option<u32>,
    pub devices: Vec<Uuid>,
}

/// Where one device is in a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobTargetState {
    /// Waiting for the device to pick it up.
    Pending,
    Running,
    Exited,
    TimedOut,
    Cancelled,
    /// Could not run: refused by the device's policy, failed to start, or no result came back.
    Failed,
}

/// One job in `GET /api/v1/jobs`, with per-state target counts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobSummary {
    pub id: Uuid,
    pub name: String,
    pub created_by: String,
    pub created_at: Millis,
    pub shell: Shell,
    pub script_sha256: String,
    pub timeout_secs: u32,
    pub cancelled: bool,
    pub targets: u32,
    pub pending: u32,
    pub running: u32,
    /// Exited with code 0.
    pub succeeded: u32,
    /// Finished any other way.
    pub failed: u32,
}

/// One device's progress and output in a job.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobTarget {
    pub device_id: Uuid,
    pub hostname: String,
    pub state: JobTargetState,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub error: Option<String>,
    pub started_at: Option<Millis>,
    pub finished_at: Option<Millis>,
}

/// `GET /api/v1/jobs/{id}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobDetail {
    pub summary: JobSummary,
    pub script: String,
    pub targets: Vec<JobTarget>,
}

/// `POST /api/v1/agent/jobs/claim` (device auth): the next job for this device, or 204.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentJob {
    pub id: Uuid,
    /// Technician who created the job; the agent checks it against its own allow-list.
    pub created_by: String,
    pub shell: Shell,
    pub script: String,
    pub timeout_secs: u32,
}

/// Body of `POST /api/v1/agent/jobs/{id}/result`. `state` is never `running`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobResult {
    pub state: ExecState,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub error: Option<String>,
    pub started_at: Millis,
    pub finished_at: Millis,
}

/// SSE event names on `GET /api/v1/stream`.
pub const STREAM_DEVICE: &str = "device";
pub const STREAM_RESYNC: &str = "resync";

/// Data of a [`STREAM_DEVICE`] event: this device's summary may have changed; refetch it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceChanged {
    pub id: Uuid,
}

/// One row of the server's append-only audit log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: i64,
    pub at: Millis,
    /// `tech:<name>`, `device:<id>`, `cli:<os user>` or `anonymous`.
    pub actor: String,
    /// Dotted verb, e.g. `device.enroll`.
    pub action: String,
    pub target: String,
    pub ok: bool,
    pub detail: String,
    /// Socket peer IP, when the event originated from an HTTP request.
    #[serde(default)]
    pub client_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state() -> DeviceState {
        DeviceState {
            hostname: "PC-01".into(),
            domain: Some("corp.example".into()),
            os: OsInfo {
                name: "Windows 11 Pro".into(),
                version: "10.0".into(),
                build: "26200".into(),
            },
            addresses: vec![NetAddress {
                interface: "Ethernet".into(),
                address: "10.0.0.5".into(),
            }],
            sessions: vec![UserSession {
                session_id: 1,
                username: "jdoe".into(),
                domain: "CORP".into(),
                state: SessionState::Active,
                station: "Console".into(),
            }],
            agent_version: "0.1.0".into(),
        }
    }

    #[test]
    fn event_round_trip() {
        let ev = AgentEvent {
            seq: 7,
            at: 1,
            kind: EventKind::StateChanged {
                state: sample_state(),
            },
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains(r#""type":"state_changed""#));
        assert_eq!(serde_json::from_str::<AgentEvent>(&json).unwrap(), ev);

        let hb: AgentEvent =
            serde_json::from_str(r#"{"seq":1,"at":2,"type":"heartbeat"}"#).unwrap();
        assert_eq!(hb.kind, EventKind::Heartbeat);
    }

    #[test]
    fn rejects_unknown_event_type() {
        assert!(
            serde_json::from_str::<AgentEvent>(r#"{"seq":1,"at":2,"type":"run_shell"}"#).is_err()
        );
    }

    #[test]
    fn version_compat() {
        assert!(is_compatible("1.0"));
        assert!(is_compatible("1.7"));
        assert!(!is_compatible("2.0"));
        assert!(!is_compatible(""));
    }
}
