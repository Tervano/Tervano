-- Technician roles and device scopes (T-806). Existing technicians keep full rights (admin).
ALTER TABLE technicians ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';

-- A technician with any rows here sees only devices in these static groups. RESTRICT: deleting a
-- scope group must never silently widen what a technician can reach.
CREATE TABLE technician_scopes (
    technician  TEXT NOT NULL REFERENCES technicians (name) ON DELETE CASCADE,
    group_id    TEXT NOT NULL REFERENCES device_groups (id) ON DELETE RESTRICT,
    PRIMARY KEY (technician, group_id)
);
CREATE INDEX technician_scopes_group ON technician_scopes (group_id);
