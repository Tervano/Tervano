# Architecture

Tervano currently has three Rust applications and one shared wire crate. The
[README diagram](../README.md#architecture) shows the two working paths:
Agent → Server → Console for indexed discovery, and Console → Agent for direct
reads and selected administration. The Server is optional for the direct path.

| Component | Current responsibility | State it owns |
|---|---|---|
| [Agent](../apps/agent/src/main.rs) | Collect Windows state, report events, and serve the direct HTTPS channel | Local config, enrolled identity, direct certificate/key |
| [Server](../apps/server/src/lib.rs) | Enroll devices, ingest events, index state, serve technician API/SSE/metrics | SQLite device projections, event history, tokens, audit |
| [Console](../apps/console/src/main.rs) | Native technician UI for search/details and direct endpoint operations | Local settings, trusted endpoint fingerprints |
| [Protocol](../crates/protocol/src/lib.rs) | Versioned Serde types shared by the applications | No persistent state |

## Indexed discovery path

The Agent enrolls with a use-limited bootstrap token, receives a device ID and
secret, and sends sequenced state events or heartbeats. The Server keeps the
latest device state and indexed address/session projections in SQLite. A
technician token lets the Console search, read details/history, and subscribe
to device-change SSE. The Server does not query domain controllers for these
searches. Device event snapshots use a configurable retention window.

## Direct endpoint path

The Agent can run without `server_url`. Its direct listener requires a
technician certificate from the configured CA. The Console pins the Agent's
certificate fingerprint on first trusted contact. Device, process, service,
event-log, hardware, software, pending-reboot, and registry reads use `allowed_technicians`; machine-changing
process/service/registry operations require an explicit `operators` entry. Server technician API tokens do not authorize the
direct channel. Service changes still await a successful elevated run
([T-701](../TASKS.md)).

## Boundaries and limits

TLS is required for non-loopback Server access. Server API tokens and device
secrets are stored as hashes; the Windows Agent protects its local device secret
with DPAPI. SQLite contains device and session data and needs file/backup access
controls. The [security model](security-model.md) records the active trust
boundaries and gaps. Remote screen/control transport, AD synchronization,
enterprise RBAC, and a Server relay are planned, not part of these paths.

The choices behind Iced, SQLite, and HTTP+JSON are in the [ADRs](adr/0001-iced-console.md).
