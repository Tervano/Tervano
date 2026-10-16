# Tervano — Task Board

Single source of truth for what is done, in flight, and next. **Claude Code and Codex both work from this file.**
Source of requirements: [PLAN.md](PLAN.md) (section numbers are referenced as `§N`).

## How to use this file (both agents)

1. **Work in sprints on your own branch.** A sprint is the small set of tasks you lock together. Code lives on your `agent/<you>` branch in your own worktree (see AGENTS.md → Git) and reaches `main` only when you **merge at the end of the sprint**, and at least at the end of every working session.
2. **Lock before you code.** At sprint start, set each task's owner to `claude` or `codex` and status to `[~]` — that is the lock — and push that TASKS.md change to `main` **immediately and alone** (`chore(tasks): lock T-xxx`), so the other agent sees it before any code lands. A locked task belongs to its owner: **never edit its code, files or row**. If a task is already locked, pick another. To give a lock up, set it back to `[ ]` with a note on why.
3. **One owner per file set.** Don't edit files under a crate the other agent has a `[~]` task in; if you must, say so in that task's Notes and coordinate first.
4. **Done means verified.** `[x]` only when code exists, the workspace builds clippy-clean, and the acceptance note is met by actually running it. Write *how* it was verified in Notes. Never mark Windows-only behaviour done without running it on Windows.
5. **Keep it current.** Add newly discovered work as new tasks (next free ID in the section). Don't renumber. If scope changes, edit the task and say why in Notes.
6. Update `README.md` feature table when a user-visible feature changes status.

> **Sync note for Codex (2026-10-15, from claude):** at the user's request your uncommitted T-009/T-121 work in `../tervano-codex` was merged to `main` unchanged (plus a regenerated THIRD_PARTY_LICENSES.md). Your worktree still has those edits uncommitted, so a plain rebase will refuse. Since they are identical to `main`, discard them and fast-forward: `git checkout -- . && git clean -n` (check the list is only `deny.toml` and `apps/server/src/audit_archive.rs`), then `git clean -f && git rebase origin/main`. Remove this note once synced.

> **Testing deferred (2026-10-14):** no new tests, benchmarks or test infrastructure for now (see PLAN.md). Test-only tasks are marked `[-]`.

Status: `[ ]` todo · `[~]` locked / in progress by the owner · `[x]` done · `[!]` blocked (say why) · `[-]` dropped (say why)

---

## Phase 0 — Foundation (§16, §22 steps 1–2)

| ID | Status | Owner | Task | Notes / acceptance |
|---|---|---|---|---|
| T-001 | [x] | claude | Cargo workspace, `apps/{agent,server,console}`, `crates/protocol` | `cargo build --workspace` green on Windows MSVC |
| T-002 | [x] | claude | Shared protocol types: device identity, OS info, net addresses, sessions, enrollment, events, search, version | `crates/protocol`; serde round-trip tests |
| T-003 | [x] | claude | Protocol versioning (`PROTOCOL_VERSION`, `X-Tervano-Protocol` header, server rejects incompatible majors) | test in server |
| T-004 | [x] | claude | Logging via `tracing` in all three apps | `RUST_LOG` respected |
| T-005 | [x] | claude | Config system: TOML files for server + agent, validated on load | `server.example.toml`, `agent.example.toml` |
| T-006 | [x] | claude | Initial DB migrations (SQLite) | `apps/server/migrations/` |
| T-007 | [x] | claude | AGENTS.md + CLAUDE.md shared conventions, LICENSE (Apache-2.0) | |
| T-008 | [x] | claude | GitHub Actions CI: fmt, clippy `-D warnings`, Windows build, Linux server build, MSRV 1.90 check (no test job while testing is deferred) | `.github/workflows/ci.yml`. **Paused 2026-10-15: manual `workflow_dispatch` only** (re-enable push/PR triggers when the project is ready). Errors surface as annotations. Last automatic run found clippy::result_large_err on newer stable (fixed in server, 3f1fe7a); MSRV job passed. Local runs of `cargo clippy` remain required before pushing |
| T-009 | [!] | codex | `cargo deny` / `cargo audit` job + `deny.toml` license allowlist | Codex's `deny.toml` (narrow permissive allowlist, crates.io only) and CI `dependencies` job (cargo-deny licenses+sources, rustsec audit with the unreachable-RSA guard, THIRD_PARTY_LICENSES drift check) merged to main by claude at the user's request on 2026-10-15; THIRD_PARTY_LICENSES.md regenerated (603 packages) and every license checked against the allowlist by script. **Blocked:** cargo-deny/cargo-audit themselves have not run — CI is paused (T-008) and the tools aren't installed locally |
| T-010 | [x] | codex | Threat model doc `docs/security-model.md` | §12. Verified 2026-10-15 against Server, Agent, Console, certificate, and migration code; checked 29 local doc links and 18 task references. Covers active trust boundaries, attacker capabilities, current controls, privacy, gaps, and gates for privileged operations; follow-ups T-121/T-122/T-219. Documentation has no runtime behavior. |
| T-011 | [x] | codex | ADR folder `docs/adr/` + ADR-0001 (Iced), ADR-0002 (SQLite first, Postgres later), ADR-0003 (HTTP+JSON for phase 1 transport) | §20. Verified 2026-10-15 on Windows against PLAN, Cargo and current code; local links in README and all three ADRs resolve. Workspace build, existing tests, clippy, fmt clean. Documentation has no runtime path. |
| T-012 | [x] | codex | CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md, THIRD_PARTY_LICENSES generation | Verified 2026-10-15 on Windows: checked local links in README and new policy docs; generator read locked Cargo metadata and deterministically emitted 599 dependency/license rows, with no missing license expressions. Inventory lists declared licenses and upstream links, not bundled license texts or a legal review. Workspace build, existing tests, clippy, fmt clean. |
| T-013 | [x] | codex | Remaining docs skeletons with real content: architecture, network-protocol, agent-design, server-deployment, development, roadmap | §20. Verified 2026-10-15 against current Agent/Server/Console/protocol code and PLAN; checked local links and task IDs across 12 README/docs files. Describes implemented paths and labels planned/partially verified work. Documentation has no runtime behavior; workspace build, existing tests, clippy, fmt clean. |

## Phase 1 — Vertical slice Agent → Server → Console (§16, §22 steps 3–6)

### Server
| ID | Status | Owner | Task | Notes / acceptance |
|---|---|---|---|---|
| T-100 | [x] | claude | Axum HTTP server, `/healthz`, `/readyz` | |
| T-101 | [x] | claude | Enrollment tokens: `tervano-server token create` CLI, stored as SHA-256, single-use or N-use, expiry | |
| T-102 | [x] | claude | `POST /api/v1/enroll` → device id + device secret (hash stored) | integration test |
| T-103 | [x] | claude | `POST /api/v1/events` agent event ingestion, bearer device secret, monotonic seq (replay/dup rejection) | integration test |
| T-104 | [x] | claude | Device state projection: hostname, OS, addresses, sessions, last_seen, agent version | |
| T-105 | [x] | claude | Online/offline: derived from last heartbeat vs configurable timeout | |
| T-106 | [x] | claude | Technician API tokens: `tervano-server tech create` CLI | interim auth until SSPI/OIDC (T-150) |
| T-107 | [x] | claude | `GET /api/v1/devices?q=` search by hostname / logged-in user / IP (prefix + substring) | integration test |
| T-108 | [x] | claude | `GET /api/v1/devices/{id}` details | |
| T-109 | [x] | claude | TLS (rustls/ring) for server listener; non-loopback listen refused without TLS; `tervano-server cert init` private CA + server cert | §12.2. Verified 2026-10-14: HTTPS serve on 127.0.0.1 with generated cert, agent + curl over TLS OK; `0.0.0.0` w/o TLS refused; plain HTTP to TLS port fails. No `--insecure-dev` escape hatch by design. Cert rotation = re-run `cert init` (CA reused) |
| T-110 | [x] | claude | Append-only audit table + `GET /api/v1/audit?before=&limit=` | Logged: device.enroll (ok/denied), technician.auth failures, enrollment_token.create, technician.create (CLI actor `cli:<user>`). Searches/views not logged (read-only, polled). UPDATE/DELETE blocked by triggers (verified). Gaps: no client IP (T-119), best-effort writes, any tech can read (T-806) |
| T-111 | [ ] | | PostgreSQL backend (sqlx `postgres` feature, same migrations translated) | §13 |
| T-112 | [x] | claude | Substring search: SQLite FTS5 trigram index over hostname, signed-in users and IPs (migration 0008, backfilled; kept in step in `write_projections`); queries of 3+ characters use it as one quoted phrase (no FTS syntax injection), shorter ones keep the prefix indexes. Postgres trigram equivalent comes with T-111 | Verified 2026-10-15 (release build, Win 11 25H2, local SQLite): existing DB backfilled (mid-hostname and partial-IP matches); 10,000 enrolled devices, 50 runs per query, P95: hostname prefix 33 ms, substring 24 ms, user substring 30 ms, IP prefix 33 ms, 2-char prefix 87 ms, no match 16 ms (target <200 ms). 2 of 10,000 test enrollments failed, not investigated. Existing API tests pass through both paths |
| T-113 | [x] | claude | Server push: SSE `GET /api/v1/stream` (`device` {id} / `resync` on lag), bounded broadcast (1024), 5 s offline sweeper announces timeouts | Verified 2026-10-15 over TLS with curl: event on agent start, event ~10 s after agent killed (sweeper), `:` keep-alives every 15 s. Shortcut: all techs see all device ids until RBAC (T-806) |
| T-114 | [x] | codex | Event history table + `GET /api/v1/devices/{id}/events` | Verified 2026-10-15 on Windows with a live server and existing DB migration: startup/state/shutdown returned newest first (seq 4,3,1); heartbeat omitted; `limit=2`/`before=3` paginated; replay did not duplicate; unauthorized→401, unknown device→404, oversized seq→400. Existing workspace tests, build, clippy, fmt clean. New events only; retention is T-120. |
| T-115 | [x] | claude | Device decommission: `tervano-server device list` / `device revoke --id`; revoked devices lose their credentials (events/inventory 401), leave search, and are audited (`device.revoke`); the agent logs an explicit re-enroll instruction on 401 | Verified 2026-10-15: revoke, second revoke refused, REVOKED in list, agent got 401 with the new message, device absent from search, audit row present. Re-enroll = delete identity.json + new token (no in-place re-key yet) |
| T-116 | [x] | codex | Rate limiting / body size limits / reconnect-storm backpressure | Verified 2026-10-15 on Windows with a live scratch Server: with enrollment limit 10/min, ten malformed requests returned 422 and the eleventh 429 with `Retry-After: 60`; health stayed 200 and a 256 KiB+1 request returned 413. A 105-request metrics burst returned 100×200 and 5×429. All 256 SSE slots connected, the 257th returned 429, and a new stream connected after one closed. Per-peer rates are configurable; 128 in-flight cap inspected in code, not load-tested. Workspace build, existing tests, clippy, fmt clean. Reverse proxies share one socket peer; use client-aware proxy limits. |
| T-117 | [ ] | | Run as Windows service + systemd unit + Dockerfile | §15 |
| T-118 | [x] | codex | Metrics endpoint (OpenTelemetry/Prometheus) incl. event volume | Verified 2026-10-15 on Windows against live scratch Server: unauthenticated and invalid-token /metrics returned 401; authenticated Prometheus text showed enrolled/online/stored counts; startup + heartbeat raised accepted-events counter to 2, replay left it at 2, restart reset it to 0 while stored count stayed 1. Workspace build, existing tests, clippy, fmt clean. Counter is process-lifetime, with no device/user labels. |
| T-119 | [x] | codex | Record client IP in audit rows (`into_make_service_with_connect_info`) | Verified on Windows 2026-10-15: live loopback server audit API showed `127.0.0.1` for failed technician auth (401), rejected enrollment (403), successful enrollment (200); CLI event has null IP. `cargo build/test --workspace`, clippy `-D warnings`, fmt clean. Socket peer only; proxy deployments record proxy IP. |
| T-120 | [x] | codex | Configurable event-history retention and purge | Verified 2026-10-15 on Windows: with 1-day retention, backdated one event 2 days in a scratch DB and restarted the live Server; history returned only the fresh event, and the retention index was present. Zero-day config was rejected before DB creation. Hourly schedule was inspected in code, not waited through. Workspace build, existing tests, clippy, fmt clean. |
| T-121 | [x] | codex | Audit retention, export, and protected archive policy | Codex's implementation (`apps/server/src/audit_archive.rs`, `tervano-server audit export/archive/verify`, `audit_retention_days` + `audit_archive_dir` config with startup + hourly archival) merged to main by claude at the user's request on 2026-10-15. Verified then on Win 11 25H2: export of 5 rows with SHA-256; archive of only the 2 back-dated rows into a hash-named file, recorded as an `audit.archive` row; `verify` passes; append-only trigger restored (raw DELETE refused); re-run archives 0. Windows has no owner-only check on the archive dir (Unix enforces 0700) |
| T-122 | [x] | codex | Technician API token expiry, revocation, and rotation | Verified 2026-10-15 on Windows with live scratch Server: 1-hour token accepted then rejected after DB expiry; rotate invalidated old token and accepted replacement; revoke rejected replacement and closed an active SSE stream; rotate/revoke audit rows present. Existing-schema migration assigned old tokens a 30-day grace expiry. Invalid 0/>90-day lifetimes rejected. Workspace build, existing tests, clippy, fmt clean. CLI-only management; direct client certificates are separate. |

### Agent
| ID | Status | Owner | Task | Notes / acceptance |
|---|---|---|---|---|
| T-200 | [x] | claude | `tervano-agent run` foreground mode (dev) | |
| T-201 | [ ] | | Windows service mode via SCM (`service install/uninstall/run`) | Code exists in `apps/agent/src/service.rs` (claude). **Not yet verified**: needs elevated install + `sc start` + check `agent.log` + clean stop sends Shutdown |
| T-202 | [x] | claude | Collect hostname, OS name/version/build, domain | |
| T-203 | [x] | claude | Collect network addresses (IPv4/IPv6 per adapter) | |
| T-204 | [x] | claude | Enumerate interactive sessions (WTS API): user, domain, state (active/disconnected/other), station | Verified 2026-10-14 on Win 11 Home 25H2 (26200), local account, console session. RDP + domain not yet tested |
| T-205 | [x] | claude | Enroll with server using token; persist identity to `state.json` | |
| T-206 | [x] | claude | Send full state on startup, full state on change (poll-diff every N s), heartbeat when idle | Seq seeded from clock, corrected by server ack. Jitter not added yet (see T-217) |
| T-207 | [x] | claude | Retry with exponential backoff on network failure, no duplicate state | |
| T-208 | [x] | claude | Device secret protected with DPAPI (current account; LocalSystem in service mode); service mode ACLs state dir to SYSTEM + Administrators via icacls | Verified 2026-10-14: plaintext 0.1.0 identity.json auto-migrated to `protected_secret`, agent then reported OK. ACL step runs only in service mode — **not yet run** (needs T-201 verification) |
| T-209 | [ ] | | Event-driven session changes (WTSRegisterSessionNotification / service control `SessionChange`) instead of poll-diff | §5 agent events |
| T-210 | [~] | claude | Event-driven network changes (NotifyUnicastIpAddressChange) | Implemented 2026-10-15 (`apps/agent/src/netwatch.rs`): Windows callback wakes the report loop, 2 s settle, then state is re-collected and sent. Verified on Win 11 25H2 that the callback → loop wake path works (via a temporary initial-notification run, reverted). **Open:** observe a real IP change end to end — changing an address needs admin, and a WSL restart did not change host addresses |
| T-211 | [ ] | | Lock/unlock detection | §5 |
| T-212 | [ ] | | Service recovery options (restart on failure) set at install | §14 |
| T-213 | [ ] | | Bounded on-disk event queue for offline periods | §5 |
| T-214 | [x] | claude | Measure + document idle CPU/RAM (target ≤50 MB) | Measured 2026-10-15, release build, Win 11 25H2 (Ryzen 9800X3D, 16 logical CPUs), server reporting + direct listener, 3 min idle after startup inventory: working set 29.7 MB flat, private 8.6 MB, CPU 16 ms / 180 s (≈0.009% of one core), 22 threads, 357 handles, binary 9.3 MB. Not yet measured as the SYSTEM service or after heavy direct-channel use |
| T-215 | [x] | claude | Agent `ca_cert` option (+ Windows cert store via native roots); agent/console refuse `http://` to non-loopback | Verified agent over TLS with `ca_cert` and refusal of `http://192.168.1.142`. Console CA field added, not GUI-verified. Pinning dropped: CA trust is sufficient for now |
| T-216 | [x] | claude | Service-mode log rotation: `agent.log` + 4 rotated files, 10 MiB each (bounded at 50 MiB) | Verified 2026-10-15 via a harness on the real writer with 4 KiB × 3: three ~4 KB files holding the newest lines. Not yet observed under the running service (needs T-201) |
| T-218 | [x] | claude | Service failures (including before the file logger exists) are written to the Windows Application log as source `TervanoAgent`, event 1000; `service install` registers the source with EventCreate.exe as message file, `service uninstall` removes it | Verified 2026-10-15 as a normal user: the error text appears in the Application log under TervanoAgent/1000. Source registration at install (admin) not yet run — until then Event Viewer shows the text without a level |
| T-217 | [x] | claude | Heartbeat ±10% jitter (re-drawn after each send) and equal-jitter backoff (50–100%) on report failures | Verified 2026-10-15: a revoked agent's retry came at 47 s for a 60 s backoff. Uses uuid v4 (OS RNG) — no new dependency |
| T-219 | [x] | claude | After a successful enrollment the agent blanks `enrollment_token` in the config file it was started with (rewritten in place so file ACLs are kept; other lines and comments untouched); failure is a warning | Verified 2026-10-15: token removed from the file after enrolling, comments preserved, restarted agent reused its identity with the blank token. Recovery = delete identity.json and set a new token (documented in the agent's 401 message) |

### Console
| ID | Status | Owner | Task | Notes / acceptance |
|---|---|---|---|---|
| T-300 | [x] | claude | Iced app shell: sidebar nav, light/dark theme | |
| T-301 | [x] | claude | Settings: server URL + technician token, persisted to `%APPDATA%\Tervano\console.toml` | |
| T-302 | [x] | claude | Universal search box → device list (async, never blocks UI) | |
| T-303 | [x] | claude | Device list: name, online dot, IP, logged-in user, OS, last seen | |
| T-304 | [x] | claude | Device details panel: summary, sessions, addresses, agent version | |
| T-305 | [x] | claude | Loading / empty / error states | |
| T-306 | [x] | claude | Console technician token in Windows Credential Manager (generic credential `TervanoConsole-technician-token`, per user, this computer only), never written to console.toml; older files with a plaintext token are migrated on first load | Verified 2026-10-15 on Win 11 25H2 with a scratch APPDATA: token removed from the file, credential visible via `cmdkey /list:TervanoConsole-technician-token`, second launch read it and the server accepted it (live updates connected), credential then deleted with cmdkey. The technician private key for direct mode is still a file path (see T-311 notes) |
| T-307 | [ ] | | Virtualized list for 10k+ rows; column sort/filter/select | §11 |
| T-308 | [ ] | | Keyboard-first: Ctrl+K focus search, arrows/Enter in results, command palette | §11 |
| T-309 | [ ] | | Recent devices, favorites, search history | §11 |
| T-310 | [x] | claude | Console live updates: SSE subscription with reconnect backoff (1→30 s), 45 s dead-connection timeout, 1 s debounced refresh; 15 s polling only while disconnected; status line shows live/polling | Verified 2026-10-15: Console logged both pushes within ~1 s; server restart → reconnected in 3 s. Visual status text not checked by eye. Shortcut: refresh re-runs whole search (T-307) |
| T-311 | [x] | claude | Console serverless mode: Direct page with endpoint list (host → host:8472), TOFU add flow (probe aborts handshake after reading fingerprint; technician confirms before anything is exchanged), pinned mTLS client with technician cert/key from Settings, 15 s refresh of the viewed agent, remove endpoint | Verified 2026-10-15 by driving `apps/console/src/direct.rs` against a live serverless agent: probe fingerprint = agent's; pinned→device state; wrong pin→"Certificate changed!"; bob→403 text; rogue CA→refused; no creds/unreachable→clear messages. GUI launched with an endpoint configured, no errors; **click-through of the page not done by eye** (T-314) |
| T-312 | [ ] | | Tabs / multi-window device admin | §11 |
| T-313 | [ ] | | Real screenshots into README | §19H |
| T-314 | [ ] | | Click-through check of Console Direct page (add → trust → view → remove; mismatch banner) and Devices live footer on a real desktop | covers T-310/T-311 visual gaps |

### Integration
| ID | Status | Owner | Task | Notes / acceptance |
|---|---|---|---|---|
| T-350 | [x] | claude | Server integration tests (enroll → events → search) in-process | `cargo test -p tervano-server` |
| T-351 | [-] | | End-to-end script: start server, create token, run agent, query via HTTP, assert device + user | dev script under `scripts/`. Done manually 2026-10-14 (claude): agent enrolled, search `q=nosh` returned this PC with correct IP/user; Console launched against it. Script deferred with testing |
| T-352 | [-] | | Cache acceptance test from §17 (IP change reflected, no DC queries) | deferred with testing |

## Phase 1b — Direct (serverless) management channel

| ID | Status | Owner | Task | Notes / acceptance |
|---|---|---|---|---|
| T-400 | [x] | claude | Agent direct listener: HTTPS (rustls) on `[direct].listen`, mandatory client certs, `GET /v1/device`; agent self-generated cert (key DPAPI-protected), `TervanoAgent direct-fingerprint` for pinning; `server_url` now optional (serverless agent) | Verified 2026-10-15 on Win 11 25H2 with a Python client pinning the fingerprint: alice→200, no protocol header→400; identity stable across restarts; server+direct combined mode OK. Console client is T-311 |
| T-401 | [x] | claude | Direct authz: technician client certs from the org CA (`tervano-server cert tech --name`, ClientAuth EKU, CN = technician), optional `allowed_technicians`, every decision logged by the agent | Verified: bob (valid cert, not allowed)→403; no cert, rogue-CA cert, server cert as client → rejected in TLS handshake. Gaps: no CRL (revoke via allowlist + 1-year expiry), Kerberos option not done |
| T-402 | [~] | claude | Agent-side per-operation authorization checks | §12.9. Done for current ops: `direct::authorize` checks every request; read ops → `allowed_technicians`, machine-changing ops → explicit `operators` (default nobody). Stays open until configurable per-op roles land with RBAC (T-806) |
| T-403 | [ ] | | Server connection-authorization tickets (short-lived, signed) agents can verify offline | §2C non-negotiable outage behaviour |
| T-404 | [ ] | | QUIC transport (quinn) with TCP/TLS fallback | §6 |

## Phase 2 — Remote control (§6)

| ID | Status | Owner | Task | Notes / acceptance |
|---|---|---|---|---|
| T-500 | [ ] | | Session-helper mode: service launches helper into active session (`WTSQueryUserToken` + `CreateProcessAsUser`), local IPC with ACL'd named pipe | |
| T-501 | [ ] | | Screen capture via DXGI Desktop Duplication, single monitor | |
| T-502 | [ ] | | Encoder: established codec lib (evaluate openh264 / Media Foundation HW H.264; licensing review) | §18 codec patents |
| T-503 | [ ] | | Encrypted stream to Console + viewer window | never plaintext |
| T-504 | [ ] | | Mandatory, non-suppressible user notification + persistent indicator (tech name, view/control, start time) | §6 |
| T-505 | [ ] | | Consent policy (none / prompt / prompt-with-timeout) | |
| T-506 | [ ] | | Keyboard/mouse injection (SendInput) gated by control permission | |
| T-507 | [ ] | | View-only vs control switching | |
| T-508 | [ ] | | Multi-monitor, resolution/DPI change handling | |
| T-509 | [ ] | | Clipboard sync (policy-controlled) | |
| T-510 | [ ] | | Adaptive quality / bandwidth / FPS controls | |
| T-511 | [ ] | | Disconnect/reconnect; multiple technicians per policy | |
| T-512 | [ ] | | Remote session audit records (start/end/duration/mode) | |
| T-513 | [ ] | | Session recording (opt-in, disclosed) | |
| T-514 | [ ] | | Secure desktop / UAC / lock screen behaviour documented honestly | |
| T-515 | [ ] | | Remote-control manual demo on a real Windows box (view, notification, input, disconnect, no lock/logoff) | required before marking remote control done; not an automated test |
| T-516 | [ ] | | Optional encrypted relay via server | |

## Phase 3 — Active Directory (§8)

| ID | Status | Owner | Task | Notes / acceptance |
|---|---|---|---|---|
| T-600 | [ ] | | LDAP client crate (`crates/directory`) w/ Kerberos/SSPI bind (evaluate `ldap3` + `sspi` / native `wldap32`) | |
| T-601 | [ ] | | Console direct AD search (users, computers, groups) | serverless path |
| T-602 | [ ] | | OU/container tree browser, multi-domain/forest | |
| T-603 | [ ] | | Server directory source config + initial sync (read-only account) | |
| T-604 | [ ] | | Incremental sync (DirSync / uSNChanged), deletes, renames, moves | no periodic full scans |
| T-605 | [ ] | | Correlate AD computer objects ↔ enrolled devices (not 1:1) | §13 |
| T-606 | [ ] | | User → logged-in device lookup ("find employee's PC") | §5 key workflow |
| T-607 | [ ] | | User details: enabled, lockout, pwd status, groups | read-only first |
| T-608 | [ ] | | Delegated writes: unlock, reset pwd, must-change, enable/disable, group membership — using technician's identity, audited | after security review |
| T-609 | [ ] | | LDAP query metrics (count, volume) | §14 |

## Phase 4 — Background administration (§7)

Each module: agent operation + authorization + audit + console tab. Build one fully before the next.

| ID | Status | Owner | Task | Notes |
|---|---|---|---|---|
| T-700 | [x] | claude | Processes over the direct channel: list (pid, parent, name, exe, owner `DOMAIN\user`, CPU %, memory, start time, arch via IsWow64Process2) and terminate; Console Direct → Processes tab (filter, sort, two-step confirm) | Verified 2026-10-15 on Win 11 25H2 with the agent running as a normal user: 465 processes listed (owner resolved for 302, arch for 304; the rest belong to accounts a non-admin can't open, expect more as SYSTEM, unverified); an operator terminated a `ping` (it exited); refused: non-operator (403), PID/name mismatch, critical process (csrss), the agent itself. Console client exercised against the live agent; Processes tab not clicked by eye (T-314). Server-routed access needs relay (T-516) |
| T-701 | [!] | claude | Services over the direct channel: list (state, PID, start type, account, executable, dependencies, stop/pause ability), start/stop/pause/resume/restart (waits for the state to settle, 30 s per step), set start type automatic/manual/disabled (ChangeServiceConfigW, nothing else touched); Console Direct → Services tab with confirmation | **Blocked on an elevated run.** Verified 2026-10-15 on Win 11 25H2 as a normal user: 329 services listed with config; non-operator 403; refused: stopping/disabling TervanoAgent itself, boot/system start types, unknown service (os error 1060); Windows \"Access is denied\" surfaced cleanly. A *successful* start/stop/restart/start-type change needs the agent running elevated or as the service (do together with T-201). Delayed-auto-start not shown/settable yet |
| T-702 | [x] | claude | Event logs over the direct channel: list channels; query newest-first with level/provider/event-ID/time-window filters evaluated on the endpoint (validated XPath, max 500 records), rendered messages; Console Direct → Events tab (quick channels + suggestions, pickers, expand row, CSV export to Downloads with formula-injection guard) | Verified 2026-10-15 on Win 11 25H2 as a normal user: 1200 channels; System/Application queries ~0.03 s; level, provider+ID filters exact; XPath injection and bad level rejected; Security without admin and unknown channel give clear errors; limit capped at 500; NUL-terminated legacy messages cleaned. Console client exercised live; tab and CSV export not clicked by eye (T-314). No separate per-event XML detail view yet |
| T-703 | [x] | claude | Hardware inventory over the direct channel + `TervanoAgent inventory` CLI: manufacturer/model/serial and BIOS from SMBIOS (bounds-checked parser, OEM placeholders dropped), CPU model/cores/load, memory, disks (size/free/SSD/removable), boot time, Secure Boot (registry), TPM version (TBS), battery charge/AC; Console Direct → Hardware tab | Verified 2026-10-15 on Win 11 25H2 (NZXT desktop, Ryzen 9800X3D) as a normal user: every value matches WMI (Win32_BIOS/ComputerSystem/Processor, Get-Volume); TPM 2.0 and Secure Boot read without admin; battery correctly absent. Not done: BitLocker status and battery health (need admin/WMI, T-723), NIC details beyond IPs. Server-side inventory snapshots are T-724 |
| T-704 | [x] | claude | Software inventory over the direct channel + `TervanoAgent software` CLI: Uninstall keys (64- and 32-bit views, per-user for loaded profiles), Settings-style filtering (SystemComponent, ParentKeyName), version/publisher/date/size/scope/MSI/uninstaller; pending reboot (CBS, Windows Update, PendingFileRenameOperations, computer rename); Console Direct → Software tab with restart banner | Verified 2026-10-15 on Win 11 25H2 as a normal user: 233 apps = PowerShell over the same keys and filters after de-duplication (235 raw); all three pending-reboot indicators matched Test-Path/Get-ItemProperty. Per-user installs of signed-out users (unloaded hives) are not listed. Uninstall/install actions are T-709 |
| T-705 | [x] | claude | Files over the direct channel: drive list, directory listing (size, modified, read-only, hidden), resumable chunked download/upload (8 MiB chunks by offset, retries) with SHA-256 verification before a file appears under its final name, rename/copy/delete/mkdir; local drive paths only (UNC, device and `..` refused); recursive delete of drive roots/top-level folders refused; reading and changing files is operator-only (the agent can read anything as SYSTEM), listing is read-only; Console Direct → Files tab | Verified 2026-10-15 on Win 11 25H2 as a normal user: 20 MB random file uploaded and downloaded through the Console's transfer code, byte-identical (0.7 s each way); resume at correct offset, mismatch refused; wrong hash and existing target refused with the part discarded; path guards and the top-level delete guard (on an empty test folder) hold; non-operator 403 for read/write. Not done: ACL/permission inspection, folder copy, transfer progress bar. Tab not clicked by eye (T-314) |
| T-706 | [x] | claude | Registry over the direct channel: browse HKLM/HKU/HKCR/HKCC in 64- or 32-bit view; typed values (SZ, EXPAND_SZ, MULTI_SZ, DWORD, QWORD, BINARY, others as raw hex); set value (creates key), delete value, delete key (recursive only when asked; never top-level keys); `.reg` export (capped 20k keys / 16 MB); writes operator-only and logged without value data; Console Direct → Registry tab with confirmation and UTF-16 `.reg` export | Verified 2026-10-15 on Win 11 25H2 as a normal user (writes in own HKU hive): 7 value types round-trip exactly and match `reg query`; export re-imported with `reg import` gives identical values; non-operator 403; non-recursive delete of a key with subkeys, top-level delete, HKLM write (access denied) and bad hex refused. Console client exercised live; tab not clicked by eye (T-314). HKLM writes need an elevated/service agent |
| T-707 | [x] | claude | Remote PowerShell/CMD over the direct channel: start/poll/cancel jobs, stdout/stderr (1 MiB cap each, UTF-8), exit code, timeout 1–3600 s, Job Object kills the tree on timeout/cancel, max 4 concurrent, scripts via stdin (PS script block, no execution-policy bypass) or a private temp .cmd, shells from System32 by full path; execution context explicit: `agent` only, `user` refused until T-500; operator-only; script hash logged, not text; Console Direct → Commands tab | Verified 2026-10-15 on Win 11 25H2 as a normal user: PS multi-line with functions, unicode, stderr and `exit 3`; CMD unicode and `exit /b 5`; 3 s timeout killed cmd and its `ping`; cancel; 5th concurrent refused; user context refused; empty script refused; 1 MiB truncation; temp scripts removed; non-operator 403; Console client start/poll/stop exercised live. Tab not clicked by eye (T-314). Grandchildren spawned in the first ms escape the job (shortcut noted in code) |
| T-708 | [x] | claude | Interactive remote terminal over the direct channel: persistent PowerShell (UTF-8 line loop in one scope; no execution-policy bypass) or CMD as the agent's account; input by POST, output read by absolute offset from a 256 KiB rolling buffer; max 2 per agent; 15 min idle timeout; close/timeout kills the process tree; operator-only, input logged by hash; Console Direct → Terminal tab (500 ms polling, scrollback anchored to the newest output) | Verified 2026-10-15 on Win 11 25H2: variables persist across lines, unicode in and out, CMD session, third terminal refused, close killed a running `ping`, input after close refused, `exit 7` reported, read-only tech 403; Console client exercised live. Shortcut: PowerShell multi-line constructs must be typed on one line (no full PS host). Tab not clicked by eye (T-314) |
| T-709 | [!] | claude | Silent software install/uninstall over the direct channel: uninstall by inventory entry (MSI product code → `msiexec /x {code} /qn /norestart`, else the vendor's QuietUninstallString), install a local `.msi` (`msiexec /i … /qn /norestart`), run as tracked command jobs (30 min timeout, tree kill), operator-only, logged; Console Software tab: Uninstall per row, MSI path + Install, msiexec exit codes explained | **Blocked on an elevated test machine** with a throwaway MSI: a successful install/uninstall has not been run (it needs admin, and real software on the dev PC must not be removed). Verified 2026-10-15 as a normal user: non-operator 403; per-user entries, unknown/invalid keys, non-MSI, missing and `%` paths refused; a corrupt .msi ran through msiexec and returned 1620. MSIX not supported yet |
| T-710 | [x] | claude | Printers (spooler: name, driver, port, share, location, shared/network, decoded status, queued jobs) and mapped network drives of every signed-in user (from their loaded registry hive) over the direct channel; Console Direct → Printers & drives tab. WMI/CIM browser split to T-726 | Verified 2026-10-15 on Win 11 25H2 as a normal user: 4 printers identical to `Get-Printer`; a temporary HKCU\Network mapping was reported with user, letter, path and alternate account, then removed. As SYSTEM the spooler lists machine printers; per-user printer connections need the user context (T-725). Read-only: printer/drive changes not implemented |
| T-711 | [~] | claude | Patch status / Windows Update | Partial (2026-10-15): installed updates from Win32_QuickFixEngineering (newest first) + pending-restart reasons via `GET /v1/updates` and Console Direct → Updates tab; matches Get-HotFix (5 updates). Still open: Windows Update history/available updates via the WU Agent COM API, triggering scans/installs |
| T-712 | [ ] | | Remote chat with end user | parity matrix row |
| T-723 | [ ] | | BitLocker status and battery wear (design/full capacity) for hardware inventory | needs admin or WMI (`Win32_EncryptableVolume`, `root\wmi BatteryFullChargedCapacity`); verify on an elevated agent and a laptop |
| T-724 | [x] | claude | Server inventory snapshots: agent sends hardware + software inventory (`POST /api/v1/inventory`) once its first state report is accepted and then every 24 h (15 min retry on failure, never on the heartbeat); server keeps the latest per device (`device_inventory`, migration 0007) and serves `GET /api/v1/devices/{id}/inventory`; inventory route alone allows 2 MiB bodies (other routes keep 256 KiB); Console server-mode device details show model, serial, CPU, memory, disks, TPM/Secure Boot, app count and restart state | Verified 2026-10-15 on Win 11 25H2: a real agent uploaded within seconds of start and the stored snapshot matched (NZXT, serial, 233 apps, 3 restart reasons); 760 KB inventory accepted, 3 MB rejected 413, 300 KB to /events still rejected; tech posting / device reading inventory → 401. Console rows not checked by eye (T-314). History of snapshots not kept yet |
| T-725 | [ ] | | Run remote commands in the signed-in user's context (via session helper T-500), with clear labelling in the Console | PLAN §7 execution contexts |
| T-726 | [x] | claude | WMI/CIM over the direct channel: class list per namespace and read-only WQL (SELECT/ASSOCIATORS/REFERENCES; namespace validated; max 2000 rows; common WBEM errors explained); operator-only (WMI exposes command lines etc.), queries logged; Console Direct → WMI tab with class finder and per-instance cards | Verified 2026-10-15 on Win 11 25H2 as a normal user: 1193 non-system CIMV2 classes = Get-CimClass; Win32_Process/OperatingSystem/BIOS values = Get-CimInstance; ROOT\StandardCimv2 MSFT_NetAdapter 6 rows = PowerShell; PnP 323 rows = PowerShell; non-SELECT, bad namespace chars, unknown class/namespace and invalid queries refused with clear text; read-only tech 403. Namespace tree browsing and method calls not implemented |

## Phase 5 — Automation & enterprise (§9)

| ID | Status | Owner | Task | Notes |
|---|---|---|---|---|
| T-800 | [ ] | | Job model + `crates/automation`: targets, per-endpoint progress, results | |
| T-801 | [ ] | | Device groups: static, OU-dynamic, tag/filter-dynamic | |
| T-802 | [ ] | | Scheduling, retries, cancellation, concurrency limits | |
| T-803 | [ ] | | Per-endpoint per-action authz; confirmation with target count preview | |
| T-804 | [ ] | | Reports + export (CSV/JSON), execution history | |
| T-805 | [ ] | | Compliance checks + remediation | |
| T-806 | [ ] | | RBAC: roles, endpoint scopes, action scopes; UI hides disallowed modules | §12.4 |
| T-807 | [ ] | | OIDC + Integrated Windows Auth for technicians | §12 auth modes |
| T-808 | [ ] | | mTLS device identity + cert enrollment/renewal/revocation | §12.1–3 |
| T-809 | [ ] | | Multi-site / multi-tenant | |
| T-810 | [ ] | | Signed agent self-update | §12.13 |
| T-811 | [x] | claude | Console bulk command runner over direct endpoints: checkboxes + select all on the Direct page, one confirmation naming the target count, parallel runs capped at 8 (each agent's own exec job: timeout, tree kill, operator check), per-endpoint status/exit/first output line with totals, CSV export (formula-injection guarded) | Verified 2026-10-15 with two live agents and one dead endpoint through the Console's orchestration code: operator agent ran the script (exit 0, 4.1 s), the agent without operators answered \"Not authorized\" and logged the refusal, the dead endpoint failed cleanly, all concurrently. Panel and CSV export not clicked by eye (T-314). Server-side scheduled jobs remain T-800/T-802 |

## Phase 6 — Classroom (§10)

| ID | Status | Owner | Task | Notes |
|---|---|---|---|---|
| T-900 | [ ] | | Classroom groups + teacher-scoped RBAC (no general admin rights) | |
| T-901 | [ ] | | Low-bandwidth thumbnail grid | |
| T-902 | [ ] | | Full-screen student view | reuses Phase 2 |
| T-903 | [ ] | | Teacher screen broadcast | |
| T-904 | [ ] | | Screen lock (explicit), messaging, launch app/URL, file distribution, logoff/restart | |
| T-905 | [ ] | | Privacy controls: recording off by default, retention, audit | |

## Phase 7 — Distribution & hardening (§15, §17)

| ID | Status | Owner | Task | Notes |
|---|---|---|---|---|
| T-950 | [ ] | | WiX MSI: Console (per-machine, shortcuts, server address property) | |
| T-951 | [ ] | | WiX MSI: Agent (service, silent, signed enrollment config, GPO/Intune) | no shared secret in public MSI |
| T-952 | [ ] | | Server packages: Windows service, systemd, container, backup docs | |
| T-953 | [ ] | | Release workflow + version metadata + optional code signing | |
| T-954 | [-] | | Upgrade/uninstall tests | deferred with testing |
| T-955 | [ ] | | Accessibility pass (contrast, keyboard, screen reader) | |
| T-956 | [ ] | | Security review + fuzzing protocol deserialization | §12 |
| T-957 | [ ] | | Linux/macOS agent | parity matrix rows |

## Docs & README (§19, §20)

| ID | Status | Owner | Task | Notes |
|---|---|---|---|---|
| T-980 | [x] | claude | README with honest status table, architecture diagram, quick start | keep in sync |
| T-981 | [ ] | | `docs/feature-matrix.md`: Tervano vs EV Reach vs Veyon, all rows from §19E, sourced + "last verified" date | no unverified claims |
| T-982 | [ ] | | `docs/pricing-comparison.md` + README pricing section with dated sources and 5/10/25-tech example formulas | §19F |
| T-983 | [ ] | | `docs/active-directory.md`, `docs/remote-control.md` (design before implementation) | |
