-- Device groups (T-801). A static group lists its members; a query group stores a device search
-- and is evaluated whenever it is listed, so it always reflects current state.
CREATE TABLE device_groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    kind        TEXT NOT NULL,          -- static | query
    query       TEXT,
    created_by  TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE group_members (
    group_id   TEXT NOT NULL REFERENCES device_groups (id) ON DELETE CASCADE,
    device_id  TEXT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, device_id)
);
CREATE INDEX group_members_device ON group_members (device_id);
