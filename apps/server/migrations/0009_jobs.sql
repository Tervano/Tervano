-- Server jobs (T-800): a script queued for many devices, picked up by agents on their poll.
-- The script is stored because agents fetch it later; the audit log records only its hash.
CREATE TABLE jobs (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    created_by     TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    shell          TEXT NOT NULL,
    script         TEXT NOT NULL,
    script_sha256  TEXT NOT NULL,
    timeout_secs   INTEGER NOT NULL,
    cancelled_at   INTEGER
);
CREATE INDEX jobs_created ON jobs (created_at DESC);

CREATE TABLE job_targets (
    job_id       TEXT NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    device_id    TEXT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    -- pending | running | exited | timed_out | cancelled | failed
    state        TEXT NOT NULL DEFAULT 'pending',
    claimed_at   INTEGER,
    started_at   INTEGER,
    finished_at  INTEGER,
    exit_code    INTEGER,
    stdout       TEXT NOT NULL DEFAULT '',
    stderr       TEXT NOT NULL DEFAULT '',
    truncated    INTEGER NOT NULL DEFAULT 0,
    error        TEXT,
    PRIMARY KEY (job_id, device_id)
);
CREATE INDEX job_targets_device_state ON job_targets (device_id, state);
