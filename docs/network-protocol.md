# Network protocol in the current build

The shared wire types and `PROTOCOL_VERSION` live in
[crates/protocol](../crates/protocol/src/lib.rs). The current Phase 1 API uses
HTTP+JSON. Clients send `X-Tervano-Protocol` with the shared
`PROTOCOL_VERSION` value on `/api/v1` and direct Agent requests; peers
accept the same major version. This is a compatibility check, not feature negotiation. Additive shared-wire changes bump
the minor version; breaking ones bump the major version.

## Server endpoints

| Endpoint | Credential | Current behavior |
|---|---|---|
| `GET /healthz`, `GET /readyz` | None | Process health and database readiness |
| `POST /api/v1/enroll` | Use-limited enrollment token in JSON | Returns device ID and secret once |
| `POST /api/v1/events` | Device bearer secret | Applies sequenced Agent events; replayed sequence numbers are skipped |
| `GET /api/v1/devices`, `GET /api/v1/devices/{id}` | Technician bearer token | Search and current details |
| `GET /api/v1/devices/{id}/events` | Technician bearer token | Newest-first retained event history, up to 100 rows per page |
| `GET /api/v1/audit` | Technician bearer token | Paginated audit records |
| `GET /api/v1/stream` | Technician bearer token | SSE `device` notifications and `resync` on lag |
| `GET /metrics` | Technician bearer token | Aggregate Prometheus text; no protocol header |

Server `/api/v1` request bodies are capped at 256 KiB. Event batches are capped
at 500; accepted events must have increasing `seq` values per device. The
Server returns the highest applied sequence in `EventAck`. Agent timestamps are
not trusted for retention: history uses Server receipt time. The metrics event
counter includes accepted heartbeats and resets on process restart.

Technician tokens expire and can be rotated or revoked from the Server CLI. A
long-lived SSE connection rechecks its token on notifications and at least
every 15 seconds; rotation or revocation closes the old stream. The Console
reconnects with its configured token, so replace that setting after rotation.

## Direct Agent channel

The direct listener is HTTPS with mandatory client certificates from the
Agent's configured technician CA. The Console checks a pinned Agent
fingerprint before sending application requests. The current routes are
`GET /v1/device`, process and service lists, event-log channel/event queries,
hardware and software inventory, pending-reboot status, process termination, and service control/start-type
operations. Authorization is checked at the Agent for each operation: read access follows `allowed_technicians`, while changes need
`operators`. [Direct implementation](../apps/agent/src/direct.rs) is the
source for exact request bodies and route names. Server bearer tokens and their
lifecycle are separate from these certificates.

There is no screen-streaming or remote-input protocol yet. QUIC and TCP/TLS
fallback are planned under [T-404](../TASKS.md).
