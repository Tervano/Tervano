-- Latest hardware/software snapshot per enrolled device (PLAN §13 inventory snapshots).
-- Agents send one at startup and daily; history is a later addition.
CREATE TABLE device_inventory (
    device_id     TEXT PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    collected_at  INTEGER NOT NULL,
    received_at   INTEGER NOT NULL,
    report_json   TEXT NOT NULL
);
