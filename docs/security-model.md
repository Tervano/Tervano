# Security model and threat analysis

**Scope:** Phase 1 code as of 2026-10-15. This document describes implemented controls and known gaps; it is not a security certification. Tervano is for devices an organization is authorized to manage. Remote control, Active Directory administration, and classroom actions are not implemented. Direct process listing and termination are available with separate read and operator authorization. Service listing and control endpoints exist, with successful elevated changes still awaiting verification ([T-701](../TASKS.md)).

## Assets and trust boundaries

| Boundary | Credential and data crossing it | Current enforcement |
|---|---|---|
| Agent → Server enrollment | Bootstrap token and initial device state | `POST /api/v1/enroll` consumes a hashed, expiring, use-limited token. The server returns a new device ID and secret. TLS is required off loopback. |
| Agent → Server reporting | Device bearer secret, sequence numbers, device state | `POST /api/v1/events` checks the secret hash and rejects replayed sequence numbers. Accepted startup, state-change, and shutdown events are persisted. |
| Console → Server | Technician bearer token; device state, history, audit records, SSE notifications | Server API checks the token hash. All `/api/v1` requests require a compatible protocol header; the header is not a credential. |
| Console → Agent (direct mode) | Technician client certificate and live device state | Agent requires a certificate from its configured CA, derives the technician name from the certificate CN, and checks `allowed_technicians` for `device.read`. Console pins the agent certificate fingerprint. |
| Process → local storage | Secrets, keys, SQLite state, logs | Agent identity and direct TLS key use Windows DPAPI. Service mode attempts to restrict its state directory to SYSTEM and Administrators. Other local protections depend on file ACLs and deployment choices. |

The server's `/healthz` and `/readyz` endpoints are public. They expose health/readiness, not device data. `GET /metrics` requires a technician bearer token and exposes aggregate counters and gauges without device or user labels; it does not use the API protocol header. The server refuses a non-loopback listener without TLS; Agent and Console refuse non-loopback `http://` server URLs. Loopback HTTP is a development exception. The Server remains optional: direct Console → Agent access uses its own certificate checks and does not require a live Server.

The Server stores hashes of enrollment, device, and technician tokens, plus device state, session names, network addresses, event snapshots, and audit records in SQLite. Enrollment tokens and technician tokens are printed once when created. See [server API](../apps/server/src/lib.rs), [migrations](../apps/server/migrations/), and [protocol types](../crates/protocol/src/lib.rs).

## Attacker capabilities considered

- A network peer can send malformed requests, guess credentials, replay captured traffic, or impersonate a first-contact direct endpoint.
- A user with access to a technician workstation may read its files or use an unlocked Console. A local administrator, SYSTEM, or the process account may read process memory and files available to that account; DPAPI is not a boundary against those principals.
- A compromised Agent can report false state. A compromised Server or database owner can access stored personal data and can alter SQLite data or remove audit triggers.
- A stolen CA private key can mint trusted technician certificates. A stolen technician certificate and key can authenticate to agents trusting that CA, subject to their allowlist.

## Current defenses and limits

| Threat | Implemented control | Remaining exposure / work |
|---|---|---|
| Unauthorized enrollment | Random token, SHA-256 hash at rest, expiry, limited uses, atomic consumption. | A configured multi-use token can remain in plaintext `agent.toml` after enrollment ([T-219](../TASKS.md)); no request rate limit ([T-116](../TASKS.md)). Use one-use tokens for current development deployments. |
| Stolen or replayed device credential | Server stores a hash; event sequence numbers reject duplicates and older events. Agent encrypts its stored secret with account-scoped DPAPI on Windows. | Bearer identity has no certificate binding or supported revoke/re-enroll workflow ([T-808](../TASKS.md), [T-115](../TASKS.md)). Non-Windows Agent protection is a plaintext fallback and is not suitable for sensitive deployments ([T-957](../TASKS.md)). |
| Stolen technician API token | Random token and hash at the Server; TLS off loopback. | Console stores the token in plaintext under `%APPDATA%` ([T-306](../TASKS.md)). Tokens have no expiry, revocation API, role, or endpoint scope: any valid technician can read all current device data, history, audit records, metrics, and SSE device IDs ([T-122](../TASKS.md), [T-806](../TASKS.md)). |
| Direct endpoint impersonation | Console refuses application data until a certificate fingerprint is pinned; a changed certificate is rejected. Agent requires a CA-issued technician client certificate. | First use needs an out-of-band comparison with `TervanoAgent direct-fingerprint` on the intended endpoint. A network address or an unverified first fingerprint is not identity. An empty `allowed_technicians` list admits every valid client certificate from that CA. There is no certificate revocation list; use a nonempty allowlist while revocation/renewal is built ([T-808](../TASKS.md)). |
| CA or technician key theft | Separate ServerAuth and ClientAuth certificate purposes. Agent's own direct key is DPAPI-protected. | Generated CA, server, and technician private keys are PEM files; the issuer relies on directory ACLs. Protect the CA key offline and restrict key directories ([T-952](../TASKS.md)). A stolen CA key requires CA replacement across trusting agents; an allowlist alone does not contain it. The Console's direct technician key path refers to an unencrypted PEM file ([T-306](../TASKS.md)). |
| Request flood or storage exhaustion | API JSON body limit is 256 KiB; event batches are capped at 500. Device event history omits heartbeats, reads at most 100 rows per page, and purges rows older than `event_retention_days` (default 30) at startup and hourly. | No rate limiting or reconnect-storm control ([T-116](../TASKS.md)). A backlog purge runs in small batches, but retention does not cap the volume generated inside the window. |
| Personal-data exposure | Authenticated reads; direct Agent exposes only live device state. Event-history purge uses Server receipt time. | State and history include hostnames, addresses, and signed-in user/session data. SQLite has no application-level encryption; database, WAL files, and backups require OS access controls. Audit retention/export remains pending ([T-121](../TASKS.md)); purged rows can remain in old backups and deletion does not necessarily shrink the SQLite file. |
| Missing or altered audit trail | Server records enrollment decisions, unknown technician tokens, and CLI token/technician creation; rows include socket peer IP for HTTP events. SQLite triggers reject ordinary row UPDATE/DELETE. Direct Agent logs authorization decisions locally. | Server audit writes are best-effort, read-only searches/views are not logged, and direct logs are one unrotated local file ([T-216](../TASKS.md)). A DB owner can remove triggers or alter the file. Proxy deployments record the proxy's socket IP. Retention/export and protected archive are [T-121](../TASKS.md). |

Input parsing uses typed JSON and parameterized SQL, but these are not substitutes for rate limits and field-level validation. `POST /api/v1/events` rejects sequence values outside SQLite's signed range. The threat model should be revisited as new request types and operations are added.

## Privileged-operation gates

The direct Agent currently supports device, process, and service reads, plus process termination and service control/start-type changes. Read operations use `allowed_technicians` (empty admits any valid technician certificate); machine-changing operations require an explicit `operators` entry and log their result. Successful elevated service changes remain unverified ([T-701](../TASKS.md)). These two fixed roles are not configurable per-operation RBAC ([T-402](../TASKS.md), [T-806](../TASKS.md)). There is no screen capture, input injection, or file transfer endpoint. Before adding further privileged operations, enforce authorization at the Agent for each target and action, record the decision and result, and reject requests when required audit storage fails.

Remote interactive work additionally needs an access-controlled session helper and local IPC ([T-500](../TASKS.md)), a non-suppressible user notice ([T-504](../TASKS.md)), consent policy ([T-505](../TASKS.md)), and start/end session audit ([T-512](../TASKS.md)). It must not create hidden sessions or bypass Windows protections. These are release gates for remote control, not capabilities of the current build.

## Deployment handling today

Restrict access to Server SQLite files, TLS keys, and backups; keep the CA private key separate from ordinary Server runtime files. Restrict technician key files and protect workstation logins. Compare a direct Agent fingerprint through a trusted endpoint channel before accepting it in the Console. Remove bootstrap enrollment tokens from deployment material when no longer needed, especially when a token has multiple uses. Service-mode Agent directory ACL behavior still needs an elevated Windows run-through ([T-201](../TASKS.md)); foreground mode does not apply those service ACLs.

Review this model whenever authentication, Agent operations, remote sessions, storage, or deployment changes. Track closure and verification in [TASKS.md](../TASKS.md); the broader requirements are in [PLAN.md](../PLAN.md) §12.
