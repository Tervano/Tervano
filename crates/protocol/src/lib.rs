//! Wire types shared by Tervano Console, Agent and Server.
//!
//! Phase 1 transport is HTTP + JSON. Every request carries [`PROTOCOL_HEADER`];
//! peers reject a different major version.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// `major.minor`. Bump minor for additive changes, major for breaking ones.
pub const PROTOCOL_VERSION: &str = "1.2";
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
