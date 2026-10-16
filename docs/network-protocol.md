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
| `POST /api/v1/events` | Device bearer secret (+ device certificate over TLS) | Applies sequenced Agent events; replayed sequence numbers are skipped |
| `POST /api/v1/device/certificate` | Device bearer secret; the current device certificate if it has one | Signs a CSR from the device's own key (device CA, CN = device id, client auth). `POST /api/v1/enroll` takes an optional `csr` too |
| `GET /api/v1/devices`, `GET /api/v1/devices/{id}` | Technician bearer token | Search (`q`, optional `group` to search within a device group, optional `ids` to ask which of up to 200 devices match, used for live row updates) and current details |
| `GET /api/v1/reports/software`, `/reports/software/devices`, `/reports/os`, `/reports/hardware` | Technician bearer token | Fleet reports from stored state and inventory, limited to the caller's device scope |
| `GET /api/v1/compliance`, `POST /api/v1/compliance`, `DELETE /api/v1/compliance/{id}`, `GET /api/v1/compliance/{id}/results` | Technician bearer token | Compliance checks evaluated over the caller's devices; writes need operator without a scope |
| `GET /api/v1/me` | Technician bearer token | Name, role, device scope and token expiry of the caller |
| `GET /api/v1/groups`, `POST /api/v1/groups`, `DELETE /api/v1/groups/{id}`, `POST /api/v1/groups/{id}/members` | Technician bearer token | Device groups: static (member list) or query (saved search evaluated on read) |
| `GET /api/v1/devices/{id}/events` | Technician bearer token | Newest-first retained event history, up to 100 rows per page |
| `GET /api/v1/audit` | Technician bearer token | Paginated audit records |
| `GET /api/v1/stream` | Technician bearer token | SSE `device` notifications and `resync` on lag |
| `POST /api/v1/jobs`, `GET /api/v1/jobs`, `GET /api/v1/jobs/{id}`, `POST /api/v1/jobs/{id}/cancel` | Technician bearer token | Queue a script for 1–1000 devices, list jobs, per-device results, cancel targets not yet picked up |
| `POST /api/v1/agent/jobs/claim`, `POST /api/v1/agent/jobs/{id}/progress`, `POST /api/v1/agent/jobs/{id}/result` | Device bearer secret | Next job for this device whose start time has come and whose `max_parallel` has room (204 if none); check-in every 5 s while running (reply says whether it was cancelled; 2 min without one marks it failed); its result (body up to 1 MiB, each output stream cut to 64 KiB) |
| `GET /metrics` | Technician bearer token | Aggregate Prometheus text; no protocol header |

Technician endpoints check the caller's role and device scope: insufficient role is 403 (audited), an out-of-scope device or another technician's job is 404. Server `/api/v1` request bodies are capped at 256 KiB (inventory 2 MiB, job results 1 MiB). Agents run server jobs only if their `[server_jobs]` section allows the creating technician; the Server stores the script to hand it out and audits it by SHA-256. Event batches are capped
at 500; accepted events must have increasing `seq` values per device. The
Server returns the highest applied sequence in `EventAck`. Agent timestamps are
not trusted for retention: history uses Server receipt time. The metrics event
counter includes accepted heartbeats and resets on process restart.

The Server limits API and metrics requests per socket peer, with a separate
enrollment rate. Excess requests return 429 with `Retry-After`; an in-flight
work cap can return 503. At most 256 SSE streams are active at once. The
[Server configuration](../apps/server/server.example.toml) sets the rate values.

Technician tokens expire and can be rotated or revoked from the Server CLI. A
long-lived SSE connection rechecks its token on notifications and at least
every 15 seconds; rotation or revocation closes the old stream. The Console
reconnects with its configured token, so replace that setting after rotation.

## Direct Agent channel

Agents with `[direct] ticket_key` also accept a Server connection ticket in the `x-tervano-ticket` header: `hex(claims JSON).hex(Ed25519 signature)`, issued by `POST /api/v1/devices/{id}/ticket` within the technician's role and scope. The agent checks it offline (signature, certificate CN, its own device id from `GET /v1/identity`, expiry) and grants read or operate; an invalid ticket is refused rather than ignored. `require_ticket = true` makes tickets the only grant.

The direct listener is HTTPS with mandatory client certificates from the
Agent's configured technician CA. The Console checks a pinned Agent
fingerprint before sending application requests. The current routes are
`GET /v1/device`, process and service lists, event-log channel/event queries,
hardware and software inventory, pending-reboot status, registry read/export,
process termination, service control/start-type, and registry write/delete
operations. Authorization is checked at the Agent for each operation: read access follows `allowed_technicians`, while changes need
`operators`. [Direct implementation](../apps/agent/src/direct.rs) is the
source for exact request bodies and route names. Server bearer tokens and their
lifecycle are separate from these certificates.

There is no screen-streaming or remote-input protocol yet. QUIC and TCP/TLS
fallback are planned under [T-404](../TASKS.md).
