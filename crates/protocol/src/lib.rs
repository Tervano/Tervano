//! Wire types shared by Tervano Console, Agent and Server.
//!
//! Phase 1 transport is HTTP + JSON. Every request carries [`PROTOCOL_HEADER`];
//! peers reject a different major version.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// `major.minor`. Bump minor for additive changes, major for breaking ones.
pub const PROTOCOL_VERSION: &str = "1.4";
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
