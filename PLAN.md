\# TERVANO — MASTER DEVELOPMENT PROMPT

\## Open-Source Enterprise Remote Administration \& Endpoint Management Platform



\*\*Project:\*\* Tervano  

\*\*GitHub organization:\*\* `tervano`  

\*\*Primary language:\*\* Rust  

\*\*Target platforms:\*\* Windows 10/11 and Windows Server, with cross-platform expansion planned  

\*\*Product category:\*\* Enterprise remote administration, endpoint management, IT automation, and classroom management  

\*\*Distribution:\*\* Open source, self-hosted, free to use  

\*\*Reference products:\*\* EV Reach (formerly Goverlan Reach), Veyon, MeshCentral, and RustDesk



> \*\*TESTING DEFERRED (2026-10-14):\*\* Writing automated tests, test suites, benchmarks, load-test utilities, and CI test jobs is out of scope for now. Do not add new tests or test infrastructure. Section 17 and other test-related items below are kept for reference only and will be reinstated later. Existing tests may stay but need not be extended.



\---



\# 1. YOUR ROLE AND OBJECTIVE



You are the principal architect, senior Rust systems engineer, Windows internals engineer, security engineer, and desktop UI/UX engineer responsible for building \*\*Tervano\*\*.



You are not being asked to produce a mockup, proof-of-concept document, or speculative architecture.



\*\*You are being asked to begin implementing a real, production-oriented open-source software platform.\*\*



Tervano's ultimate objective is to achieve functional parity with EasyVista EV Reach / Goverlan Reach, with additional classroom-management capabilities inspired by Veyon.



The platform must support large organizations, school districts, enterprise IT departments, and managed Windows environments containing thousands or tens of thousands of endpoints.



Its fundamental goals are:



1\. Replace expensive proprietary remote administration suites with a free, open-source alternative.

2\. Combine endpoint discovery, remote control, Active Directory administration, background management, scripting, inventory, and bulk operations in one native desktop application.

3\. Provide an exceptionally fast technician experience, even when managing very large directories.

4\. Minimize endpoint resource consumption and network traffic.

5\. Support both centralized and decentralized operation.

6\. Avoid mandatory cloud services, subscription fees, endpoint licensing, and technician-seat restrictions.

7\. Deliver a modern, polished, professional user interface.

8\. Prioritize real functionality, maintainability, and security over demonstrations.

9\. Eventually support most practical EV Reach capabilities, while distinguishing completed features from planned features.

10\. Maintain comprehensive technical documentation and a continually updated feature-parity matrix.



Do not copy proprietary source code, branding, graphics, or other protected implementation assets from EV Reach. Reimplement comparable functionality independently using documented APIs and legitimate protocols.



Veyon may be studied for its feature set and architecture. Direct code reuse requires a license-compatibility review.



\*\*Critical instruction:\*\* Implement working code and progressively build the platform. Do not stop after producing a proposal or task list.



\---



\# 2. REQUIRED PRODUCT ARCHITECTURE



Tervano consists of three independently distributed applications.



\## A. Tervano Console



\*\*Proposed binary:\*\* `TervanoConsole.exe`



A native Windows desktop application installed on administrators' and technicians' workstations.



Responsibilities:



\- Authenticate the technician.

\- Search users, computers, and directory objects.

\- Discover endpoints.

\- Display computer and user information.

\- Launch remote control sessions.

\- Administer systems without interrupting the logged-in user.

\- Manage Active Directory objects with delegated privileges.

\- Execute authorized remote operations.

\- Display device health and inventory.

\- Run scripts and automation workflows.

\- Manage groups of endpoints.

\- Access classroom-management features where authorized.

\- Display audit history and troubleshooting information.

\- Configure connection profiles and local application settings.



The Console must work with or without Tervano Server.



When a server exists, use its cached directory and device data as the primary discovery source.



When no server exists, fall back to direct Active Directory queries, direct agent connections, DNS resolution, and manually configured endpoints.



Do not depend on a central server for local-network administration.



\## B. Tervano Agent



\*\*Proposed binary:\*\* `TervanoAgent.exe`



A lightweight Windows service installed on managed endpoints.



Responsibilities:



\- Run continuously with minimal resource consumption.

\- Receive authorized management requests.

\- Advertise relevant endpoint state changes.

\- Report hardware, software, session, and network information.

\- Provide remote screen viewing and control.

\- Perform background administrative operations.

\- Support file transfer and process/service inspection.

\- Track user session changes.

\- Send important updates to Tervano Server when configured.

\- Operate independently when no server exists.

\- Display clear, user-visible notifications for remote interactive connections.



The Agent must not require a permanent window or ordinary desktop application to remain open.



Use a native Windows service managed by the Service Control Manager.



\*\*Important Windows implementation detail:\*\* Windows services run in Session 0 and cannot directly render interactive UI inside a logged-in user's desktop.



Use the same Agent executable in two modes where practical:



\- Service mode: performs privileged background operations.

\- Session-helper mode: runs within an authorized interactive Windows session, displays notifications, and performs session-specific capture/control tasks.



The service should launch the session-mode process through supported Windows APIs and communicate through access-controlled local IPC.



This avoids requiring a fourth independently distributed product.



\## C. Tervano Server



\*\*Proposed binaries:\*\* `tervano-server.exe` on Windows or `tervano-server` on Linux.



An optional, strongly recommended centralized coordination, caching, and administration service.



Its primary purpose is \*\*directory acceleration, device-state caching, authentication/policy coordination, and efficient discovery\*\*.



It is not fundamentally required to proxy every remote control session.



Responsibilities:



\- Cache selected Active Directory information.

\- Index users, computers, groups, and organizational units.

\- Maintain an up-to-date endpoint inventory.

\- Receive state-change events from Agents.

\- Track online/offline state and current logged-in users.

\- Maintain current IP addresses and endpoint connection information.

\- Provide fast search APIs.

\- Manage enrollment and endpoint identities.

\- Manage technician roles and access policy.

\- Store append-only security-relevant audit records.

\- Optionally coordinate or relay connections when direct access is unavailable.

\- Support multi-site environments.

\- Minimize repetitive LDAP/domain controller queries.

\- Provide health, diagnostic, and administrative interfaces.



The Server must be independently deployable and self-hostable.



Prefer support for Linux services, Windows services, and containerized deployments.



\*\*Non-negotiable:\*\* A temporary Tervano Server outage must not automatically render all agents inaccessible. Previously authorized direct connections should remain possible under their established security policies.



\---



\# 3. TECHNOLOGY STACK



\## Primary language



Use \*\*Rust\*\* for the Console, Agent, Server, shared libraries, networking, and business logic wherever practical.



Goals:



\- Native compilation.

\- Low memory consumption.

\- High performance.

\- Predictable deployment.

\- Memory safety.

\- Shared protocol types.

\- Cross-platform foundations.

\- No mandatory garbage-collected application runtime.



Use platform-specific libraries where justified, but do not introduce an entirely separate application stack without a strong reason.



\## Desktop framework



Evaluate the latest stable, compatible versions of:



\- Iced

\- Slint

\- Native Windows UI technologies accessible from Rust



\*\*Default preference: Iced\*\*, because it supports a Rust-native desktop application without shipping Electron, Chromium, or an embedded browser runtime and uses a permissive MIT license.



Do not blindly use development-branch APIs. Pin compatible stable crate versions, verify APIs against current documentation, and include a reproducible lockfile.



The goal is a genuinely polished desktop application, not merely a collection of default widgets.



\## Supporting technology



Evaluate and choose appropriately:



| Requirement | Preferred approach |

|---|---|

| Async runtime | Tokio |

| Windows integration | `windows` / windows-rs |

| Serialization | Serde |

| Structured RPC | Tonic / gRPC where appropriate |

| Fast direct transport | QUIC using a maintained Rust implementation |

| HTTPS APIs | Axum or equivalent |

| Database | PostgreSQL for centralized deployments |

| Lightweight local database | SQLite where useful |

| Database access | SQLx or another maintained library |

| TLS | Rustls where suitable |

| Authentication | Windows SSPI/Kerberos, OIDC, and certificates as appropriate |

| Logging | tracing |

| Metrics | OpenTelemetry-compatible metrics |

| Installer | WiX MSI or another enterprise-friendly installer |

| CI/CD | GitHub Actions |



These are starting preferences, not mandatory dependencies.



Investigate feasibility and licensing before committing. Prefer maintained libraries and established standards.



Avoid unnecessary abstraction and excessive dependencies.



\---



\# 4. REPOSITORY STRUCTURE



Create a Cargo workspace designed for long-term maintenance.



Suggested layout:



\- `apps/console/` — native technician application

\- `apps/agent/` — Windows service and interactive-session helper

\- `apps/server/` — optional centralized server

\- `crates/core/` — common types and domain models

\- `crates/protocol/` — protocol definitions and version negotiation

\- `crates/network/` — connections, transports, and session management

\- `crates/auth/` — authentication and authorization

\- `crates/directory/` — Active Directory and LDAP abstraction

\- `crates/inventory/` — endpoint and software inventory

\- `crates/windows/` — safe wrappers around Windows-specific operations

\- `crates/remote/` — remote viewing and input handling

\- `crates/automation/` — job execution and scheduling

\- `crates/storage/` — persistence abstractions

\- `crates/audit/` — structured audit events

\- `crates/testing/` — test utilities and fixtures

\- `installers/` — Windows and server packaging

\- `docs/` — architecture, operations, security, and development documentation

\- `.github/workflows/` — CI and release automation



Keep privileged functionality separate from unprivileged presentation code.



Minimize unsafe Rust. Every unavoidable unsafe block must have documented safety assumptions.



Avoid cyclical crate dependencies and giant shared modules.



\---



\# 5. CRITICAL FEATURE: DIRECTORY AND ENDPOINT CACHE



This is one of Tervano's most important architectural advantages.



Traditional remote administration tools can become slow when technicians repeatedly search a large Active Directory environment.



Tervano should aggressively improve this experience without creating excessive server load.



\## Central caching architecture



When Tervano Server is installed:



1\. An administrator configures one or more Active Directory directory sources.

2\. The Server performs a controlled initial synchronization.

3\. Relevant directory objects are indexed locally.

4\. Incremental synchronization keeps those records current.

5\. Agents transmit endpoint-state changes.

6\. Technician Consoles query the Server rather than repeatedly contacting domain controllers.

7\. Search results return quickly, using indexed data.

8\. Details clearly identify whether data is live, recently cached, or stale.



Investigate supported AD synchronization mechanisms such as LDAP DirSync and other documented incremental-change facilities. Handle deletions, renamed objects, moved OUs, and failover correctly.



Do not implement an inefficient full-domain LDAP scan every few seconds.



\## Agent-driven events



Agents should report meaningful changes, including:



\- Device startup.

\- Graceful shutdown when observable.

\- User logon.

\- User logoff.

\- Session lock and unlock.

\- Active session changes.

\- IPv4 address changes.

\- IPv6 address changes.

\- Network-interface changes.

\- Hostname changes.

\- Domain membership changes.

\- Agent version changes.

\- Changes to selected inventory attributes.

\- Significant health-status transitions.



Use Windows event notifications and operating-system APIs wherever feasible instead of continuously polling every subsystem.



Periodic heartbeats are still necessary for liveness and reconciliation.



Use event coalescing, bounded queues, jitter, retries, backoff, and idempotent processing.



Events should include a device identity, timestamp, sequence or event identifier, event type, and minimal necessary payload.



Recover from network interruptions without generating duplicate state changes.



\## Device identity



Do not identify an endpoint solely by hostname or IP address.



Generate a stable enrollment identity and securely bind it to the installed agent.



Support:



\- Hostname changes.

\- IP changes.

\- Machine reimaging.

\- Computer-object recreation.

\- Multiple network adapters.

\- Device decommissioning.

\- Explicit reenrollment.



\## Search capabilities



The Console should support fast lookup by:



\- Hostname.

\- FQDN.

\- IPv4 or IPv6 address.

\- Logged-in username.

\- Display name.

\- UPN.

\- AD sAMAccountName.

\- OU.

\- Domain.

\- Asset identifier.

\- Serial number.

\- Device tag.

\- Operating system.

\- Site or organizational location.



Support exact, prefix, and appropriately indexed fuzzy matching.



A common workflow should be:



\*\*Search for an employee or student → find their currently signed-in computer → open that computer's management dashboard.\*\*



The logged-in user should come from actual endpoint session information, not be inferred solely from Active Directory's historical login attributes.



\## Performance expectations



Build the cache to scale to at least 10,000 managed endpoints initially, with a documented path toward 50,000–100,000.



Create benchmarks using generated directory data (deferred).



Initial performance targets:



\- Common indexed searches: P95 under 200 ms in a realistic local deployment.

\- Device state events visible in the Console within a few seconds under healthy conditions.

\- Virtualized lists with thousands of records.

\- Minimal unnecessary LDAP traffic.

\- Bounded server memory and database connection pools.

\- No full-directory query for each keystroke.



These are engineering targets, not claims of already achieved performance.



Record actual benchmark results and deployment assumptions.



\---



\# 6. REMOTE ACCESS AND USER SESSION BEHAVIOR



Remote access is a core product feature, not an optional afterthought.



\## Required behavior



When a technician connects to an endpoint's active desktop:



1\. Authenticate and authorize the technician.

2\. Resolve the correct active Windows session.

3\. Establish an encrypted remote session.

4\. Display a visible notification to the local user.

5\. Begin screen viewing or remote control according to permissions.

6\. Preserve the user's existing interactive desktop.

7\. Do not automatically lock, log off, or switch the user.

8\. End the session cleanly and record its duration and actions.



\*\*This is explicitly not intended to behave like ordinary RDP, which may create or switch sessions and affect the local desktop.\*\*



The administrator should be able to interact with an existing authorized user session without disrupting that session merely by connecting.



\## Notification requirements



When an interactive remote session starts, display a native, nonblocking notification such as:



\*\*Tervano Remote Support\*\*



"IT Administrator is connected to this computer."



Include:



\- Technician display name.

\- Whether the session is view-only or permits control.

\- Session start time.

\- Connection status.

\- Organization-defined support information.



Prefer a persistent, unobtrusive session indicator after the initial notification.



Do not show a blocking modal dialog by default in centrally managed unattended-support environments.



Support configurable consent policies for organizations that require explicit user approval.



Do not implement an invisible remote-access mode that suppresses the mandatory session indicator.



The notification should appear even when the technician initiates the connection while the local user is temporarily away, provided an appropriate interactive session is available.



\## Session handling



Support:



\- Existing console sessions.

\- Multiple monitors.

\- Resolution changes.

\- DPI scaling.

\- Clipboard synchronization.

\- Keyboard input.

\- Mouse input.

\- View-only mode.

\- Shared-control mode.

\- Technician disconnect and reconnection.

\- Multiple technician sessions subject to policy.

\- Session recording when explicitly enabled and disclosed.

\- Bandwidth and frame-rate controls.

\- Adaptive image quality.



Use documented Windows screen-capture APIs such as Desktop Duplication where suitable.



Investigate Windows.Graphics.Capture and hardware-assisted video encoding.



Do not invent a fragile custom video codec. Use maintained, established libraries and hardware encoding facilities.



Handle protected content, lock-screen limitations, secure desktop/UAC boundaries, and unsupported configurations honestly. Do not bypass Windows security boundaries to make remote viewing appear functional.



\## Transport



Prefer direct Console-to-Agent transport on reachable networks.



Use the Server primarily for discovery, authorization, policy, and optional coordination.



Provide an optional encrypted relay for environments where direct access is unavailable.



Provide TCP/TLS fallback when QUIC/UDP is unavailable.



Never send remote desktop frames or input events in plaintext.



\---



\# 7. BACKGROUND SYSTEMS MANAGEMENT



Tervano must support managing a computer \*\*without needing to take over its desktop\*\*.



This is a major requirement for functional parity with EV Reach.



Target capabilities:



\## Processes



\- Enumerate running processes.

\- Display process ID, executable, owner, CPU, and memory.

\- Identify process architecture and relevant metadata.

\- Terminate authorized processes.

\- Refresh process state without screen sharing.



\## Services



\- Enumerate Windows services.

\- Inspect running state.

\- Start, stop, pause, and restart supported services.

\- Modify startup type when authorized.

\- Display dependency and service account information.



\## Registry



\- Browse supported registry hives.

\- Read values and types.

\- Create, modify, and delete authorized entries.

\- Export selected keys.

\- Explicitly confirm destructive changes.



\## Event logs



\- Browse Windows Event Log channels.

\- Filter by timestamp, provider, severity, and event ID.

\- View event details.

\- Export selected results.

\- Avoid unnecessary full-log downloads.



\## File management



\- Browse authorized filesystem locations.

\- Upload and download files.

\- Inspect permissions and metadata.

\- Rename, move, copy, and delete files.

\- Support resumable, integrity-checked transfers.

\- Clearly distinguish remote and local paths.



\## Software



\- Inventory installed applications.

\- Display versions and publishers.

\- Identify available uninstall metadata.

\- Perform authorized installation/uninstallation.

\- Detect pending reboot conditions.

\- Support silent MSI/MSIX deployments and documented installer mechanisms.



\## Hardware and health



\- CPU model and utilization.

\- RAM capacity and consumption.

\- Storage devices and free space.

\- Network adapters.

\- OS version and build.

\- System uptime.

\- Battery health where available.

\- Firmware and BIOS information.

\- Hardware manufacturer and model.

\- Serial number.

\- TPM and Secure Boot state where accessible.

\- BitLocker status when authorized.



\## Remote command execution



Support:



\- PowerShell.

\- Command Prompt.

\- Script execution.

\- Structured output capture.

\- Exit codes.

\- Timeouts.

\- Cancellation.

\- Explicit choice of permitted execution context.

\- Concurrency limits.

\- Full action auditing.



Differentiate between operations running as an authorized service identity, delegated administrator, or explicitly permitted logged-in-user context.



Never silently assume that LocalSystem and the interactive user are interchangeable.



Never extract, store, or expose the logged-in user's password.



\---



\# 8. ACTIVE DIRECTORY MANAGEMENT



Active Directory integration is a first-class feature.



The application should feel like a purpose-built IT administration console rather than a generic LDAP browser.



\## Directory browser



Provide:



\- Domain tree.

\- Organizational units.

\- Containers.

\- Users.

\- Computers.

\- Groups.

\- Nested group membership.

\- Object details.

\- Attribute inspection.

\- Search and filters.



Support multiple domains and configured forests.



Do not assume every organization has a single flat domain.



\## User management



Target capabilities:



\- Find users quickly.

\- View account properties.

\- Inspect enabled/disabled status.

\- Review lockout state.

\- Inspect password-related status where permitted.

\- Unlock accounts.

\- Reset passwords with delegated authorization.

\- Require password change at next logon.

\- Enable/disable accounts.

\- View and edit selected authorized properties.

\- Manage group membership.

\- View associated managed devices.

\- Locate currently logged-in sessions from Agent data.



\## Computer management



\- Inspect computer objects.

\- Display domain membership and OU location.

\- View last known endpoint state.

\- View associated logged-in users.

\- Open remote administration.

\- Organize device records by site and OU.

\- Support authorized domain-object changes.



\## Security model



Use the technician's existing Windows identity where supported.



Support Kerberos/SSPI and secure LDAP.



Do not ask technicians to enter Domain Admin credentials as a general prerequisite.



Use delegated permissions and least privilege.



The Server's directory synchronization account should normally have read-only permissions.



Directory mutations must be separately authorized and carried out using appropriately delegated credentials, with clear audit attribution.



Do not let a read-only Server cache identity become an unrestricted domain administration identity.



\---



\# 9. BULK OPERATIONS AND AUTOMATION



Implement a modular job execution system.



Capabilities should eventually include:



\- Run actions against multiple endpoints.

\- Save named device groups.

\- Dynamically target OU membership.

\- Target by tags or search filters.

\- Schedule jobs.

\- Track progress per endpoint.

\- Collect success/failure results.

\- Retry failed endpoints under defined policies.

\- Export execution reports.

\- Maintain execution history.

\- Cancel queued or running operations where possible.



Example workflows:



\- Restart a specified service across selected computers.

\- Install an approved software package.

\- Collect hardware inventory.

\- Check a registry setting.

\- Detect noncompliant configuration.

\- Apply an authorized remediation.

\- Launch a troubleshooting script.

\- Generate a device health report.



Avoid implementing a generic unaudited command broadcast mechanism.



All bulk operations must pass authorization checks per endpoint and per action.



Destructive or disruptive operations should require explicit confirmation, with previews and clear target counts.



Design for incremental adoption: scripts, built-in operations, and reusable workflow definitions.



\---



\# 10. CLASSROOM MANAGEMENT MODULE



Create a modular classroom feature set inspired by Veyon.



These features must not complicate ordinary enterprise administration.



Target:



\- Live computer-grid view.

\- Low-bandwidth screen thumbnails.

\- Classroom/location grouping.

\- Full-screen student workstation viewing.

\- Teacher screen broadcasting.

\- Screen locking when explicitly invoked by authorized staff.

\- Messaging.

\- Launching approved applications and websites.

\- Distributing classroom files.

\- Remote logoff and restart.

\- Classroom-session management.



Classroom mode must be permission-controlled.



Teachers should not automatically receive general-purpose system administration rights.



Support organizational scoping, such as an individual teacher being authorized only for devices in designated classrooms.



School privacy controls are essential:



\- Screen viewing is explicitly policy-governed.

\- Staff actions are auditable.

\- Session indicators and notice policies are enforced.

\- Screen recording is disabled by default.

\- Sensitive student data is minimized.

\- Retention and access controls are configurable.



Consult Veyon's public documentation as a feature reference, but do not copy GPL-covered implementation code into an incompatible licensing arrangement.



\---



\# 11. CONSOLE UI/UX DESIGN



The Console must be visually competitive with modern desktop administration software.



Avoid Electron, embedded Chromium, generic web dashboards wrapped as desktop applications, excessive gradients, or dated Windows Forms styling.



\## Visual identity



Design language:



\- Clean and professional.

\- Fluent-inspired.

\- Neutral base colors.

\- Subtle accent color.

\- Rounded corners used appropriately.

\- Excellent information density.

\- Consistent spacing.

\- Crisp icons.

\- Light and dark themes.

\- Accessible contrast.

\- Keyboard-first workflows.



The interface should feel comfortable for technicians who use it throughout an entire workday.



\## Main application layout



\### Navigation sidebar



Suggested modules:



\- Home

\- Search

\- Computers

\- Users

\- Active Directory

\- Remote Sessions

\- Automation

\- Inventory

\- Classrooms

\- Activity / Audit

\- Settings



Only display actions/modules that the user is permitted to access.



\### Main search



Place a prominent universal search control in the interface.



Search across computers and users without forcing technicians to choose an object type first.



Provide fast suggestions and keyboard navigation.



\### Device details



Selecting a device should open an information-rich overview with sections for:



\- Summary

\- Active Users

\- Remote Control

\- Processes

\- Services

\- Software

\- Hardware

\- Registry

\- Events

\- Files

\- Network

\- Automation

\- History



\### Device list



Include:



\- Device name.

\- Online status.

\- Current IP.

\- Logged-in user.

\- Operating system.

\- OU/location.

\- Last-seen timestamp.

\- Relevant tags.



Support sorting, filtering, column selection, and virtualized scrolling.



\### Remote connection window



Support a proper toolbar for:



\- Monitor selection.

\- Fullscreen.

\- Fit/scale.

\- Keyboard shortcuts.

\- View-only/control switching.

\- Clipboard settings.

\- File transfer.

\- Session information.

\- Disconnect.



Do not make administrators navigate through multiple windows for common tasks unnecessarily.



\## Usability



Include:



\- Global keyboard shortcuts.

\- Search history.

\- Recently accessed devices.

\- Favorites.

\- Tabbed or multi-window device administration.

\- Context menus.

\- Command palette.

\- Nonblocking task progress.

\- Clear error messages.

\- Loading and empty states.

\- Connection diagnostics.



The UI must not freeze during LDAP searches, network requests, or long-running remote operations.



\---



\# 12. SECURITY REQUIREMENTS



Tervano is privileged administrative software and must be engineered accordingly.



Mandatory controls:



1\. Mutual authentication between management components.

2\. TLS for network connections.

3\. Certificate enrollment, renewal, and revocation.

4\. Role-based authorization with endpoint and action scopes.

5\. No default shared passwords.

6\. No hardcoded management secrets.

7\. No unauthenticated remote command endpoints.

8\. Strong replay protection for authenticated requests.

9\. Per-operation authorization on the Agent, not merely UI-level checks.

10\. Audit records for privileged operations and remote sessions.

11\. Secure storage for local identity material.

12\. Access-controlled local IPC.

13\. Secure software update verification.

14\. Explicit enrollment and unenrollment.

15\. No hidden remote desktop sessions.

16\. No stealth or defensive-software evasion.

17\. No automatic disabling of antivirus, firewall, UAC, or endpoint protection.

18\. No privilege escalation beyond Windows-authorized administrative paths.

19\. Server-side and agent-side validation of permissions.

20\. Protected handling of logs, personal data, and captured session content.



Use Windows Credential Manager, DPAPI, or appropriate supported credential-protection APIs where applicable.



Document all privileged operations.



Ensure that receiving a maliciously crafted message from another endpoint cannot cause unsafe deserialization, arbitrary local execution, or unauthorized privilege expansion.



\## Authentication modes



Investigate:



\- Integrated Windows Authentication for domain technicians.

\- Kerberos-based authentication where appropriate.

\- OIDC for centrally managed organizations.

\- Service identities with carefully scoped privileges.

\- Mutual TLS for enrolled endpoint identity.



Direct/serverless administration must still require authorization.



Do not treat knowledge of a machine's IP address as permission to control it.



\## Audit model



Capture structured events including:



\- Actor identity.

\- Target device.

\- Action category.

\- Action time.

\- Result.

\- Authorization decision.

\- Session ID where applicable.



Log sensitive command execution metadata according to configurable privacy policies.



Protect audit records from ordinary technician modification.



Provide retention policies and export capabilities.



\---



\# 13. SERVER DATABASE AND APIs



Design a normalized data model containing at least:



\- Organizations/tenants where applicable.

\- Sites.

\- Directory sources.

\- Users/principals.

\- Groups and memberships.

\- Directory computer objects.

\- Enrolled devices.

\- Network interfaces and addresses.

\- Interactive sessions.

\- Inventory snapshots.

\- Device events.

\- Enrollment records.

\- Technician identities.

\- Roles and policies.

\- Remote sessions.

\- Automation jobs.

\- Audit records.



Account for the distinction between a directory computer object and a Tervano-enrolled Agent.



They are not necessarily one-to-one.



Use stable identifiers and deliberate reconciliation logic.



\## API design



Create typed, versioned APIs for:



\- Authentication.

\- Device search.

\- User search.

\- Device details.

\- Directory browsing.

\- Enrollment.

\- Agent event ingestion.

\- Presence updates.

\- Connection authorization.

\- Inventory.

\- Remote session coordination.

\- Jobs.

\- Audit events.



Use pagination, filtering, and appropriate search indexes.



Never expose full directory contents to a caller lacking permission.



Support protocol version negotiation so Console, Agent, and Server versions can be upgraded independently within a documented compatibility window.



Provide server health and readiness endpoints.



\---



\# 14. PERFORMANCE AND RELIABILITY



A low-overhead client is essential.



\## Agent goals



\- Very low CPU utilization when idle.

\- No desktop rendering work unless necessary.

\- Minimal disk writes.

\- Efficient event-driven monitoring.

\- Bounded memory usage.

\- Configurable heartbeat intervals.

\- No expensive inventory scan on every heartbeat.

\- Efficient network reconnection.

\- Clean startup and shutdown.

\- Service recovery after unexpected failure.



Use an initial idle memory target of approximately 50 MB or less where realistically achievable, but measure and document actual consumption rather than treating this as a guaranteed limit.



\## Console goals



\- Fast startup.

\- Responsive search.

\- Minimal background resource use.

\- Virtualized tables.

\- Asynchronous operations.

\- Smooth navigation.

\- Efficient caching of recently retrieved details.



\## Server goals



\- Thousands of connected Agents.

\- Bounded event queues.

\- Efficient incremental updates.

\- Indexed searches.

\- Backpressure.

\- Connection pooling.

\- Resilience to reconnect storms.

\- Clear stale-data semantics.

\- Database migration support.



Provide load-test utilities that simulate large directories and many enrolled Agents (deferred).



Add metrics for LDAP query counts and directory synchronization volume.



The effectiveness of the caching architecture should be measurable.



\---



\# 15. INSTALLATION AND DISTRIBUTION



Produce three distinct installable products.



\## Console installer



\- Windows MSI.

\- Supports per-machine installation.

\- Appropriate Start Menu shortcuts.

\- Optional unattended deployment.

\- Configurable Server address.

\- No requirement for local administrator privileges merely to run the Console after installation.

\- Clean uninstall.



\## Agent installer



\- Windows MSI.

\- Creates and manages the Windows service.

\- Supports silent installation.

\- Supports signed enrollment configuration.

\- Supports deployment through GPO, Intune, Configuration Manager, and equivalent enterprise software deployment tools.

\- Includes the necessary user-session helper functionality.

\- Supports graceful upgrades.

\- Clean uninstall and identity revocation procedures.



Do not distribute insecure shared enrollment secrets embedded in a universal public MSI.



\## Server installer



\- Windows and Linux binaries where feasible.

\- Windows service support.

\- systemd service support.

\- Container deployment.

\- External PostgreSQL configuration.

\- TLS configuration.

\- Explicit initial administrator setup.

\- Configuration validation.

\- Database migrations.

\- Backup and recovery instructions.



Do not hardcode the deployment to a particular domain name, network, or school district.



\## Releases



Establish GitHub Actions workflows for:



\- Formatting.

\- Static analysis.

\- Windows builds.

\- Linux server builds.

\- Security/dependency auditing.

\- Reproducible version metadata.

\- Release artifact generation.



Add code signing support when certificates are available. Do not falsely claim unsigned artifacts are signed.



\---



\# 16. FEATURE IMPLEMENTATION ROADMAP



Build progressively, but maintain the architecture required for the final product.



\## Phase 0 — Foundation



Deliver:



\- Cargo workspace.

\- Three application entry points.

\- Shared domain types.

\- Logging framework.

\- Configuration system.

\- Build automation.

\- Development documentation.

\- Initial native Console design.

\- Protocol contracts.

\- Threat model.

\- Initial database migrations.



All three applications should compile.



\## Phase 1 — Minimum functional vertical slice



Deliver working integration between all three components.



Required functionality:



\- Install/start the Agent.

\- Start the Server.

\- Enroll an Agent securely.

\- Display its identity and hostname.

\- Report network addresses.

\- Report the logged-in user.

\- Track online/offline status.

\- Receive meaningful Agent events.

\- Persist data in the Server.

\- Query the device index from the Console.

\- Search by hostname or user.

\- Display device details in a functioning native GUI.

\- Support basic serverless direct discovery/connection setup.

\- Verify authorization paths.



Do not replace these with fake data in the production UI.



Mocks are allowed only in clearly separated development and test configurations.



\## Phase 2 — Remote control



Implement:



\- Actual desktop screen capture.

\- Encrypted streaming.

\- Remote viewing.

\- Authorized keyboard/mouse control.

\- The user-visible connection notification.

\- Same-session operation without automatically locking Windows.

\- Disconnect/reconnect handling.

\- View-only permissions.

\- Single-monitor support first, then multiple monitors.

\- Performance profiling.



Remote viewing and control must be demonstrated against a real Windows test system before marking the feature implemented.



\## Phase 3 — Directory integration



Deliver:



\- LDAP/AD discovery.

\- User/computer search.

\- OU browsing.

\- Initial Server directory synchronization.

\- Incremental updates.

\- Cached search.

\- Logged-in-user-to-device correlation.

\- Basic read-only account details.

\- Delegated write operations after security review.



\## Phase 4 — Background administration



Deliver:



\- Processes.

\- Services.

\- Event logs.

\- Inventory.

\- File management.

\- Registry inspection.

\- Remote terminals.

\- Script execution.

\- Software management.



Implement each module vertically before starting unrelated modules.



\## Phase 5 — Automation and enterprise features



Deliver:



\- Bulk targeting.

\- Job scheduling.

\- Software deployment.

\- Compliance checks.

\- Reports.

\- Policy management.

\- Multi-domain improvements.

\- Advanced authentication.

\- Optional connection relay.



\## Phase 6 — Classroom management



Deliver:



\- Classroom groups.

\- Thumbnail grid.

\- Remote viewing.

\- Teacher presentation mode.

\- Messaging.

\- File distribution.

\- Controlled screen locking.

\- Classroom-specific RBAC.



\## Phase 7 — Feature parity and hardening



Systematically close gaps against EV Reach and Veyon.



Focus on:



\- Advanced enterprise administration.

\- Performance.

\- Accessibility.

\- Usability.

\- Windows edge cases.

\- Deployment documentation.

\- High-availability requirements.

\- Security review.

\- Stable release readiness.



\---



\# 17. TESTING AND ACCEPTANCE CRITERIA — DEFERRED



> \*\*Deferred for now.\*\* Nothing in this section is currently required. Kept for reference until testing is reinstated.



Do not treat successful compilation as evidence that a feature works.



Create automated and manual testing procedures.



\## Required test categories



\- Unit tests.

\- Protocol serialization tests.

\- Authentication tests.

\- Authorization tests.

\- API integration tests.

\- Database migration tests.

\- Agent lifecycle tests.

\- Windows session tests.

\- Direct connection tests.

\- Connection interruption tests.

\- Multi-user session tests.

\- Directory synchronization tests.

\- Search performance benchmarks.

\- Installer/uninstaller tests.

\- Upgrade tests.

\- Security regression tests.



\## Windows testing



Test on representative supported versions of Windows 10/11 and Windows Server.



Include domain-joined environments when possible.



Document which OS versions were actually tested.



Do not claim broad Windows compatibility from a single development machine.



\## Remote-control acceptance test



A valid successful demonstration must include:



1\. A local user logged into a Windows workstation.

2\. Tervano Agent installed and active.

3\. An authorized technician using Tervano Console.

4\. A successful remote viewing session.

5\. A user-visible notification.

6\. No automatic workstation lock or user logoff.

7\. Remote input functioning in the existing authorized session.

8\. A successful disconnect.

9\. Accurate session audit records.



\## Cache acceptance test



1\. Enroll an Agent.

2\. Connect it to Tervano Server.

3\. Authenticate a user on that workstation.

4\. Verify that the Server receives and stores the session change.

5\. Search that username from Tervano Console.

6\. Confirm the workstation appears.

7\. Change the workstation's IP address.

8\. Confirm the Server updates its device record.

9\. Repeat searches.

10\. Confirm the searches do not generate unnecessary domain controller queries.



Record real outcomes and performance measurements.



\---



\# 18. OPEN-SOURCE LICENSING



Recommend a practical license for Tervano.



My default preference is \*\*Apache License 2.0\*\*, provided dependencies and incorporated code permit it.



Reasons:



\- Permissive distribution.

\- Enterprise-friendly adoption.

\- Commercial integration compatibility.

\- Explicit patent grant.

\- Encourages broad contribution and use.



However, investigate whether GPL-style copyleft better serves the project's long-term goals.



Do not introduce code under an incompatible license merely because it is available on GitHub.



In particular:



\- Review Veyon's GPL licensing before any source reuse.

\- Review remote desktop libraries individually.

\- Review codec and media patent implications.

\- Maintain a third-party license inventory.

\- Attribute external dependencies appropriately.

\- Do not imply endorsement by EasyVista, Goverlan, or Veyon.



Include a LICENSE file, CONTRIBUTING.md, CODE\_OF\_CONDUCT.md, SECURITY.md, and dependency attribution documentation.



\---



\# 19. REQUIRED README.md



\*\*Create a comprehensive, attractive GitHub README immediately and maintain it as development progresses.\*\*



The README is a central project deliverable, not optional marketing material.



It must include:



\## A. Project identity



Title:



\*\*Tervano — Open-Source Remote Administration \& Endpoint Management\*\*



Suggested tagline:



"One console. Every endpoint. No licensing barriers."



Provide a concise project description identifying the intended users, including IT departments, organizations, and school systems.



\## B. Project overview



Explain that Tervano aims to combine:



\- EV Reach-style systems administration.

\- Remote desktop control.

\- Directory management.

\- Endpoint state awareness.

\- Background troubleshooting.

\- IT automation.

\- Optional central caching.

\- Classroom functionality inspired by Veyon.



Make clear that the initial project is under active development.



Do not claim full EV Reach parity before it exists.



\## C. Architecture



Include a diagram showing:



\- Console.

\- Server.

\- Agent.

\- Active Directory.

\- Direct management connections.

\- Centralized cache/event flow.

\- Optional relay.



Explain why Tervano Server is optional.



\## D. Implemented features table



Maintain a detailed feature table using the following structure:



| Category | Feature | Status | Platform | Notes |

|---|---|---|---|---|

| Discovery | Find computers by hostname | Planned | Windows | Server and serverless |

| Discovery | Find computers by logged-in user | Planned | Windows | Agent session awareness |

| Directory | Active Directory browsing | Planned | Windows | LDAP/Kerberos |

| Agent | Background service | Planned | Windows | Native service |

| Remote | Screen viewing | Planned | Windows | Same-session streaming |

| Remote | Remote input | Planned | Windows | Permission-controlled |

| Remote | User notification | Planned | Windows | Nonblocking |

| Inventory | Hardware information | Planned | Windows | Agent-collected |

| Systems | Service management | Planned | Windows | Background operations |

| Automation | Bulk actions | Planned | Windows | Audited jobs |

| Classroom | Live thumbnail grid | Planned | Windows | Teacher role |



Expand this table as development proceeds.



Use consistent status labels:



\- Implemented

\- Partial

\- In progress

\- Planned

\- Blocked

\- Unsupported



A feature may be marked \*\*Implemented\*\* only when working code exists and the documented acceptance criteria pass.



If a feature is partially implemented, explain exactly what works.



Link implemented features to relevant documentation, tests, or source modules when practical.



\## E. Detailed EV Reach / Goverlan feature comparison



Create and continually maintain a competitor feature matrix.



Compare \*\*Tervano vs EV Reach / Goverlan Reach\*\*, with Veyon included where relevant.



The comparison should contain at least these rows:



| Feature category | Capability to compare |

|---|---|

| Remote control | Attended remote desktop |

| Remote control | Unattended remote access |

| Remote control | View existing logged-in session |

| Remote control | Multiple monitors |

| Remote control | Clipboard sharing |

| Remote control | File transfer |

| Remote control | Session recording |

| Remote control | Multiple technician sessions |

| Remote control | Remote audio |

| Remote control | Chat |

| Remote control | User-visible connection notice |

| Systems | Process management |

| Systems | Windows service management |

| Systems | Registry management |

| Systems | Event log browsing |

| Systems | File browser |

| Systems | Remote PowerShell |

| Systems | Remote CMD |

| Systems | WMI/CIM management |

| Systems | Printer management |

| Systems | Drive mappings |

| Systems | Software installation |

| Systems | Software uninstall |

| Systems | Patch management |

| Directory | AD discovery |

| Directory | OU browsing |

| Directory | User account management |

| Directory | Password resets |

| Directory | Account unlocking |

| Directory | Group membership management |

| Directory | Find machine by logged-in user |

| Inventory | Hardware inventory |

| Inventory | Software inventory |

| Inventory | Health monitoring |

| Automation | Multi-endpoint commands |

| Automation | Scheduled jobs |

| Automation | Software deployment |

| Automation | Compliance assessment |

| Automation | Compliance remediation |

| Infrastructure | Centralized directory cache |

| Infrastructure | Event-driven endpoint state |

| Infrastructure | Direct connections |

| Infrastructure | Optional relay |

| Infrastructure | Serverless mode |

| Infrastructure | Windows support |

| Infrastructure | Linux endpoint support |

| Infrastructure | macOS endpoint support |

| Classroom | Live thumbnails |

| Classroom | Screen broadcasting |

| Classroom | Screen locking |

| Classroom | Classroom messaging |

| Classroom | File distribution |

| Licensing | Open-source code |

| Licensing | Self-hosted deployment |

| Licensing | Technician licensing |

| Licensing | Endpoint licensing |



Use meaningful statuses rather than unverified checkmarks.



For commercial products, identify features as Supported, Edition-dependent, Not verified, or Not offered based on reliable vendor documentation.



Include source links and a "last verified" date.



Never claim the competitor lacks a feature merely because a documentation page did not mention it.



\## F. Pricing comparison — mandatory



\*\*The README must prominently compare Tervano's intended free licensing model against EV Reach's paid commercial licensing.\*\*



Include a dedicated section titled:



\### Pricing: Tervano vs EV Reach



Use a table similar to this:



| Pricing dimension | Tervano | EV Reach / Goverlan |

|---|---|---|

| Open-source license | Free | Proprietary commercial |

| Software license cost | $0 | Paid |

| Technician seat limits | None enforced by Tervano | Licensed per technician |

| Endpoint limits | No software-enforced endpoint cap | Review current vendor plan terms |

| Self-hosted server | Free software | Subject to vendor licensing |

| Active Directory caching | Included when implemented | Compare documented offering |

| Remote administration | Included when implemented | Edition-dependent |

| Automation | Included when implemented | Edition-dependent |

| Infrastructure/hosting | Organization's own costs | Contract/deployment-dependent |

| Commercial support | Community; paid support not promised | Vendor-provided offerings |



Below the table, add a clearly dated historical or indicative competitor price reference.



As a starting research reference, third-party listings show approximately:



\- EV Reach Standard: $40 per technician/month.

\- EV Reach Professional: $90 per technician/month.

\- EV Reach Enterprise: $170 per technician/month.



These figures are \*\*not verified current vendor quotes\*\*.



EasyVista's current official product page directs prospective customers to request a quote.



Check current prices during README maintenance, identify the billing assumptions, and do not claim old published figures remain valid.



Where reliable data exists, compare example deployments with 5, 10, and 25 technicians.



Show the actual assumptions and formulas.



Do not imply Tervano's total cost of ownership is zero: hosting, deployment, administration, hardware, and maintenance still have costs.



Do not claim Tervano already replaces commercial features that remain unimplemented.



Suggested reference URLs:



\- https://www.easyvista.com/products/remote-it-support/

\- https://www.softwareadvice.com/remote-support/goverlan-reach-profile/

\- https://github.com/veyon/veyon

\- https://docs.veyon.io/



Use current documentation wherever possible.



\## G. Installation



Document:



\- Prerequisites.

\- Console installation.

\- Agent installation.

\- Server installation.

\- Initial enrollment.

\- Serverless operation.

\- Domain configuration.

\- Firewall requirements.

\- Upgrade and uninstall procedures.



\## H. Screenshots



Include genuine application screenshots when the UI exists.



Do not use AI-generated images or unrelated mockups as evidence of implemented functionality.



\## I. Development



Include:



\- Local build instructions.

\- Rust toolchain requirements.

\- Workspace structure.

\- Test commands.

\- Coding conventions.

\- Contribution instructions.

\- Release process.



\## J. Roadmap



Maintain a checklist mapping current development milestones to planned work.



Keep it synchronized with actual progress.



\## K. Security and privacy



Explain the intended security model and relevant limitations.



Clearly state that Tervano is for administration of devices an organization is authorized to manage.



Explain user notifications, permissions, audit trails, and classroom privacy safeguards.



\---



\# 20. DOCUMENTATION REQUIREMENTS



Create and maintain:



\- `README.md`

\- `AGENTS.md`

\- `CLAUDE.md`

\- `CONTRIBUTING.md`

\- `SECURITY.md`

\- `LICENSE`

\- `docs/architecture.md`

\- `docs/security-model.md`

\- `docs/network-protocol.md`

\- `docs/active-directory.md`

\- `docs/agent-design.md`

\- `docs/remote-control.md`

\- `docs/server-deployment.md`

\- `docs/feature-matrix.md`

\- `docs/pricing-comparison.md`

\- `docs/roadmap.md`

\- `docs/development.md`



The two agent-instruction files should establish consistent coding standards and project conventions so Claude Code, Codex, and other contributors can work on the same repository.



Avoid contradictory instructions between them.



Architecture decisions should be documented through lightweight architecture decision records.



Update feature statuses when code changes.



\---



\# 21. WORKING STYLE AND AUTONOMY



Operate as an autonomous engineering agent.



Within the permissions of the development environment:



1\. Inspect the existing repository.

2\. Identify the existing toolchain and platform.

3\. Verify dependencies and platform API behavior.

4\. Write a short implementation plan.

5\. Begin creating actual source files.

6\. Build frequently.

7\. ~~Run tests.~~ (deferred)

8\. Fix compilation errors.

9\. Add integration coverage.

10\. Update documentation.

11\. Continue into the next concrete task.



Do not repeatedly request approval for ordinary development decisions.



Make reasonable, documented assumptions when information is missing.



Prefer functional vertical slices over broad collections of unfinished abstractions.



Avoid placeholder code that only prints "not implemented" unless it is clearly labeled and necessary to preserve the architecture.



Avoid presenting mocked demonstrations as working production functionality.



When blocked by a missing operating system, permission, credential, or test machine, implement what can be built and tested, then explicitly document the integration steps that require the proper environment.



Do not fabricate test results.



\## Progress reporting



At meaningful checkpoints, report:



\- What was implemented.

\- What compiles.

\- What was tested.

\- What failed.

\- What remains incomplete.

\- The next engineering priority.



Keep the feature matrices synchronized with reality.



\## Parallel engineering



When multiple agents or subagents are available, separate work across well-defined modules.



Potential independent workstreams:



\- Architecture and protocols.

\- Windows Agent.

\- Central Server/cache.

\- Native Console UI.

\- Active Directory integration.

\- Tests and documentation.



Avoid parallel modifications to the same files without coordination.



All merged changes must compile and follow shared protocol contracts.



\---



\# 22. FIRST EXECUTION — BEGIN NOW



\*\*Do not attempt to implement every enterprise feature simultaneously.\*\*



Begin by establishing the foundation for a working three-component product.



Your immediate objectives are:



\*\*Step 1 — Inspect and initialize\*\*



Inspect the repository and development environment.



Determine the installed Rust toolchain, operating system, available Windows SDK components, and current repository structure.



If necessary, initialize the Cargo workspace and Git repository files.



\*\*Step 2 — Establish the architecture\*\*



Implement the three application entry points and shared protocol types.



Define the minimum device identity, session information, network address, enrollment, and endpoint-status data structures.



Create initial protocol versioning.



\*\*Step 3 — Build Tervano Server\*\*



Create a working service exposing authenticated device enrollment, device event ingestion, and device search.



Provide database persistence and migrations.



Provide a development configuration that can run locally.



\*\*Step 4 — Build Tervano Agent\*\*



Implement a real Windows service capable of:



\- Starting and stopping correctly.

\- Loading validated configuration.

\- Reporting a stable identity.

\- Collecting hostname and OS information.

\- Collecting network addresses.

\- Querying supported interactive-session information.

\- Enrolling with the Server.

\- Sending initial state and relevant updates.

\- Maintaining a controlled heartbeat.



Implement the foundation for authorized direct management connections.



\*\*Step 5 — Build Tervano Console\*\*



Create a polished native desktop application with:



\- Functional navigation.

\- Server connection settings.

\- Search interface.

\- Device list.

\- Device details.

\- Online/offline indicators.

\- Current user information.

\- Current IP address.

\- Loading and error states.



The Console should use real Server API responses.



\*\*Step 6 — Integrate\*\*



Demonstrate the intended data flow:



Agent → Server → Console.



Verify enrollment, device information, logged-in-user tracking, IP updates, and search.



\*\*Step 7 — Prepare remote-control implementation\*\*



Create the actual remote session architecture and begin the next vertical slice for screen viewing, control, and user notifications.



Do not claim remote control is working until it has been tested on a Windows desktop.



\*\*Step 8 — Documentation\*\*



Produce the comprehensive README, feature matrix, pricing comparison, architecture documentation, and working developer instructions.



\*\*Step 9 — Continue\*\*



After the initial vertical slice, proceed through the roadmap in dependency order, building and testing real features.



Do not stop at scaffolding or documentation unless blocked by an actual environmental limitation.



\---



\# 23. DEFINITION OF SUCCESS



Tervano's initial foundation is successful when:



\- Three separate Rust applications compile.

\- The Server can run independently.

\- The Agent can run as a Windows service.

\- An Agent can securely enroll with the Server.

\- The Server stores and indexes endpoint information.

\- The Agent reports real user-session and network information.

\- The Console displays real enrolled devices.

\- Technicians can search for a computer or logged-in user through cached data.

\- The project supports a documented serverless deployment path.

\- The README accurately communicates the project's current state.

\- The EV Reach feature-parity matrix exists.

\- The pricing comparison exists with dated, qualified sources.

\- The architecture supports continued development without a fundamental rewrite.



Longer term, Tervano should allow an authorized technician to install one Console, optionally deploy one Server, enroll managed Agents, and administer their organization's Windows environment without proprietary software licensing or unnecessary infrastructure.



The end goal is not merely a remote desktop application.



\*\*Tervano should become a complete, fast, extensible, open-source administrative workspace capable of replacing the everyday functionality of EV Reach / Goverlan for organizations and school systems.\*\*



\*\*Begin implementation now.\*\*



