-- Keep accepted state changes and lifecycle events; heartbeats are liveness, not history.
CREATE TABLE device_events (
    device_id   TEXT NOT NULL REFERENCES devices(id),
    seq         INTEGER NOT NULL CHECK (seq > 0),
    received_at INTEGER NOT NULL,
    event_json  TEXT NOT NULL,
    PRIMARY KEY (device_id, seq)
);
