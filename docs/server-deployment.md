# Server deployment in the current build

The Server runs as a foreground `tervano-server serve` process or, on Linux,
as a systemd service (below). A Windows service, container image, and installer
are planned ([T-117](../TASKS.md), [T-952](../TASKS.md)). Ctrl+C or SIGTERM
stops it gracefully: it stops accepting connections and lets requests in flight
finish for up to 10 seconds. The [example
configuration](../apps/server/server.example.toml) shows the current options.
Use a separate directory for `server.toml`, SQLite, and TLS material, and
restrict its filesystem permissions to the Server account and administrators.

## Linux (systemd)

[packaging/linux](../packaging/linux) has a sandboxed unit and an example
`server.toml` for it. As root:

```bash
useradd --system --home-dir /var/lib/tervano --shell /usr/sbin/nologin tervano
install -m 0755 tervano-server /usr/local/bin/tervano-server
install -d -m 0750 -o root -g tervano /etc/tervano /etc/tervano/tls
install -m 0640 -o root -g tervano packaging/linux/server.example.toml /etc/tervano/server.toml
install -m 0644 packaging/linux/tervano-server.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now tervano-server
```

Put the TLS certificate and key in `/etc/tervano/tls` (key `0640 root:tervano`),
or set `listen` to a loopback address behind a TLS-terminating proxy. The
database lives in `/var/lib/tervano`. Run management commands as the service
user against the same configuration, for example
`sudo -u tervano tervano-server --config /etc/tervano/server.toml tech create --name alice`.
Logs go to the journal (`journalctl -u tervano-server`); set `RUST_LOG` with a
drop-in (`systemctl edit tervano-server`) to change verbosity.

The unit runs the Server without capabilities, with a read-only file system
except its state directory, private `/tmp` and devices, and a system-call
allow-list. `systemd-analyze security tervano-server` reports the result.

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

`requests_per_second` defaults to 100 per socket peer; enrollment has a
separate `enrollments_per_minute` limit of 60. Raise these values for large
deployments sharing a peer address. The Server also caps in-flight protected
requests at 128 and active SSE streams at 256. Excess requests return 429 or
503 with `Retry-After`; API JSON bodies are capped at 256 KiB. Health and
readiness checks remain available during request limiting. A reverse proxy
appears as one peer to the Server, so enforce client-aware limits at the proxy
and size the Server limits for its aggregate traffic. Do not trust unverified
forwarded IP headers for admission decisions.

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

Agent updates (T-810): create the release key once, away from the Server,
with `tervano-server release keygen --out release.pk8` and put the printed
public key in each agent's `[update]` section (`enabled = true`,
`public_key = "…"`, `check_minutes = 60`). For each release run `release sign
--key release.pk8 --file TervanoAgent.exe --version 0.2.0` where the key lives,
copy the binary with its `.manifest.json` and `.sig` to the Server and run
`release publish --file … --manifest … --signature …` against its database.
Agents pick up the newest release for their platform within `check_minutes`.

`GET /metrics` requires a technician bearer token and exports aggregate
Prometheus metrics. `GET /healthz` and `GET /readyz` are public. Respect
`RUST_LOG` for diagnostic logging; do not put tokens in logs or shared command
histories. See [network-protocol.md](network-protocol.md) for endpoint details
and [security-model.md](security-model.md) for current trust limits.
