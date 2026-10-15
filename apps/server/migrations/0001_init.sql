CREATE TABLE enrollment_tokens (
    token_hash  TEXT PRIMARY KEY,
    uses_left   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE technicians (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL
);

-- An enrolled agent. Not the same thing as an AD computer object (see PLAN §13).
CREATE TABLE devices (
    id           TEXT PRIMARY KEY,
    secret_hash  TEXT NOT NULL UNIQUE,
    hostname     TEXT NOT NULL,
    os           TEXT NOT NULL,
    enrolled_at  INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    last_seq     INTEGER NOT NULL DEFAULT 0,
    state_json   TEXT NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX devices_hostname ON devices (hostname COLLATE NOCASE);

-- Denormalised projections of state_json for indexed search.
CREATE TABLE device_addresses (
    device_id  TEXT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    interface  TEXT NOT NULL,
    address    TEXT NOT NULL
);
CREATE INDEX device_addresses_address ON device_addresses (address COLLATE NOCASE);
CREATE INDEX device_addresses_device ON device_addresses (device_id);

CREATE TABLE device_sessions (
    device_id  TEXT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    username   TEXT NOT NULL,
    domain     TEXT NOT NULL,
    state      TEXT NOT NULL,
    station    TEXT NOT NULL
);
CREATE INDEX device_sessions_username ON device_sessions (username COLLATE NOCASE);
CREATE INDEX device_sessions_device ON device_sessions (device_id);
