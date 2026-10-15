# Server deployment in the current build

The Server currently runs as a foreground `tervano-server serve` process. A
Windows service, systemd unit, container, and installer are planned
([T-117](../TASKS.md), [T-952](../TASKS.md)). The [example
configuration](../apps/server/server.example.toml) shows the current options.
Use a separate directory for `server.toml`, SQLite, and TLS material, and
restrict its filesystem permissions to the Server account and administrators.

## Listener and storage

The default listener is `127.0.0.1:8470` with loopback HTTP. A non-loopback
`listen` is rejected unless `tls_cert` and `tls_key` are configured. The
`tervano-server cert init --name <host>` command issues a Server certificate
from a local CA; protect the CA private key separately. You may use your own
PKI instead. Agents and Consoles need to trust that CA or an enterprise CA.

The Server uses SQLite migrations at startup/CLI connection. Its database
contains device state, signed-in users, event snapshots, token hashes, and
audit records. `event_retention_days` defaults to 30; old event snapshots are
purged at startup and hourly. Audit rows have no export/retention workflow yet
([T-121](../TASKS.md)). Do not copy a live SQLite database file alone: WAL
content may be needed. Stop the Server before file-based backup or use a
SQLite-aware online backup, then verify restore. Protect database, WAL,
backups, and TLS keys with OS access controls.

## Credentials and monitoring

`tervano-server token create` issues a use-limited enrollment token. New
technician API tokens from `tervano-server tech create --name alice` expire
after 30 days by default. Use `--hours` for 1 hour through 90 days. An
existing token receives a 30-day grace period when the lifecycle migration is
first applied. `tech rotate --name alice` replaces the hash and prints a new
token once; update the Console setting or Prometheus scraper. `tech revoke
--name alice` disables that identity, which cannot be rotated back into
service. Run these commands against the same `server.toml` and database as the
Server. Rotation and revocation are audited in the same database transaction.

`GET /metrics` requires a technician bearer token and exports aggregate
Prometheus metrics. `GET /healthz` and `GET /readyz` are public. Respect
`RUST_LOG` for diagnostic logging; do not put tokens in logs or shared command
histories. See [network-protocol.md](network-protocol.md) for endpoint details
and [security-model.md](security-model.md) for current trust limits.
