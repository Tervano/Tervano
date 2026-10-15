# Agent design

The [Windows Agent](../apps/agent/src/main.rs) runs in the foreground for
development or through the Windows Service Control Manager. It reads a TOML
[configuration](../apps/agent/agent.example.toml); `server_url` is optional
when the direct listener is configured. Service mode uses
`%ProgramData%\Tervano\Agent\agent.toml` by default.

## Collection and reporting

[collect.rs](../apps/agent/src/collect.rs) gathers the real hostname, OS,
network addresses, and interactive Windows sessions. The Agent currently
polls local state every `poll_secs` (default 15) and sends a full state on
startup or when the state changes. When idle, it sends a heartbeat at
`heartbeat_secs` (default 60). Each event carries a monotonically increasing
sequence number; the Server acknowledgement allows retries without duplicate
state changes. Network errors use exponential backoff up to five minutes.
Event-driven WTS/network notifications, jitter, and an on-disk offline queue
remain tracked in [TASKS.md](../TASKS.md).

Enrollment yields a device ID and secret in `identity.json` under `state_dir`.
On Windows the secret is protected with DPAPI for the process account; service
mode uses LocalSystem and attempts to restrict the directory to SYSTEM and
Administrators. The bootstrap enrollment token may remain in `agent.toml`
after enrollment ([T-219](../TASKS.md)); protect that file and use a
one-use token. Non-Windows secret protection is not equivalent to DPAPI.

## Direct mode

[direct.rs](../apps/agent/src/direct.rs) serves an HTTPS listener with a
self-generated Agent certificate and required technician client certificates.
The Console verifies and pins the Agent fingerprint. Read operations include
device state, process/service lists, event-log queries, hardware and software
inventory, and pending-reboot status. Process termination and service changes require the technician name in `operators`; an empty list permits no changing
operation. An empty `allowed_technicians` list permits any valid certificate
from the configured CA to use read operations. Each authorization decision is
logged locally. Service changes still need elevated end-to-end verification
([T-701](../TASKS.md)).

The direct certificate key and enrolled identity are protected with Windows
DPAPI. Server API technician tokens are unrelated to direct client certificates.
The current Agent has no remote screen/control implementation.
