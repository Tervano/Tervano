# Roadmap

The [task board](../TASKS.md) is the live source for ownership, status, and
verification. This page groups the work; it does not set release dates or claim
that a phase is complete because some tasks in it are done.

| Phase | Current position | Next gates |
|---|---|---|
| 0 — foundation | Rust workspace, protocol, migrations, conventions, and manual CI workflow exist | Dependency policy and remaining documentation ([T-009](../TASKS.md)) |
| 1 — Agent → Server → Console | Enrollment, reporting, search, details, event history, SSE, TLS, and basic audit work | Revocation/re-enrollment for devices, rate limits, packaging, and validation on target deployments ([T-115](../TASKS.md), [T-116](../TASKS.md), [T-117](../TASKS.md)) |
| 1b — direct channel | Pinned mTLS device/process/event-log/hardware/software reads work; service operations are partial | Elevated service change verification and fuller RBAC ([T-701](../TASKS.md), [T-806](../TASKS.md)) |
| 2 — remote control | Planned | Session helper, capture/transport, user notice and consent, authorization, audit, real Windows demo ([T-500](../TASKS.md), [T-515](../TASKS.md)) |
| 3 — Active Directory | Planned | Read-only source, incremental sync, correlation, search, delegated actions ([T-600](../TASKS.md)) |
| 4 — systems administration | Process, service, event-log, software inventory, pending-reboot detection, and partial hardware slices exist | Missing hardware fields, server snapshots, and other tools ([T-723](../TASKS.md), [T-724](../TASKS.md)) |
| 5–7 — automation, classroom, parity | Planned | Policy, privacy, performance, deployment, accessibility, and security review |

The [README feature table](../README.md#feature-status) describes what users
can run today. [Architecture](architecture.md) and
[network protocol](network-protocol.md) document the current implementation;
[PLAN.md](../PLAN.md) describes intended scope.
