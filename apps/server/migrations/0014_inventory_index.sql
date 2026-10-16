-- Inventory projections (T-813): reports and compliance read these instead of re-parsing every
-- device's inventory JSON on each request. Written on inventory ingest and removed when a device is
-- revoked, so they only ever describe live devices; backfilled here.

CREATE TABLE device_software (
    device_id   TEXT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    -- Lowercased name for case-insensitive matching (Unicode-aware when written by the server;
    -- the backfill below uses SQLite's ASCII lower(), corrected at the next inventory).
    name_lower  TEXT NOT NULL,
    version     TEXT,
    publisher   TEXT
);
CREATE INDEX device_software_device ON device_software (device_id);
-- Covering: the fleet software report groups and counts devices from the index alone.
CREATE INDEX device_software_entry ON device_software (name, version, publisher, device_id);

CREATE TABLE device_facts (
    device_id                TEXT PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    collected_at             INTEGER NOT NULL,
    manufacturer             TEXT,
    model                    TEXT,
    serial_number            TEXT,
    cpu_model                TEXT NOT NULL,
    cpu_logical_cores        INTEGER NOT NULL,
    memory_total_bytes       INTEGER NOT NULL,
    tpm_version              TEXT,
    secure_boot              INTEGER,
    -- Reasons joined with '; '; empty when no restart is pending.
    reboot_pending           TEXT NOT NULL,
    -- The Windows system drive (C:), else the first fixed disk.
    system_disk_mount        TEXT,
    system_disk_total_bytes  INTEGER,
    system_disk_free_bytes   INTEGER
);

INSERT INTO device_software (device_id, name, name_lower, version, publisher)
SELECT i.device_id,
       json_extract(a.value, '$.name'),
       lower(json_extract(a.value, '$.name')),
       json_extract(a.value, '$.version'),
       json_extract(a.value, '$.publisher')
FROM device_inventory i JOIN devices d ON d.id = i.device_id AND d.revoked = 0,
     json_each(i.report_json, '$.software.apps') a;

INSERT INTO device_facts (device_id, collected_at, manufacturer, model, serial_number, cpu_model,
                          cpu_logical_cores, memory_total_bytes, tpm_version, secure_boot,
                          reboot_pending, system_disk_mount, system_disk_total_bytes,
                          system_disk_free_bytes)
SELECT i.device_id, i.collected_at,
       json_extract(i.report_json, '$.hardware.manufacturer'),
       json_extract(i.report_json, '$.hardware.model'),
       json_extract(i.report_json, '$.hardware.serial_number'),
       IFNULL(json_extract(i.report_json, '$.hardware.cpu_model'), ''),
       IFNULL(json_extract(i.report_json, '$.hardware.cpu_logical_cores'), 0),
       IFNULL(json_extract(i.report_json, '$.hardware.memory_total_bytes'), 0),
       json_extract(i.report_json, '$.hardware.tpm_version'),
       json_extract(i.report_json, '$.hardware.secure_boot'),
       IFNULL((SELECT group_concat(r.value, '; ')
               FROM json_each(i.report_json, '$.software.reboot_pending') r), ''),
       json_extract(i.sd, '$.mount_point'),
       json_extract(i.sd, '$.total_bytes'),
       json_extract(i.sd, '$.free_bytes')
FROM (SELECT device_id, collected_at, report_json,
             COALESCE(
                 (SELECT d.value FROM json_each(report_json, '$.hardware.disks') d
                  WHERE upper(json_extract(d.value, '$.mount_point')) = 'C:\'),
                 (SELECT d.value FROM json_each(report_json, '$.hardware.disks') d
                  WHERE json_extract(d.value, '$.removable') = 0 LIMIT 1)) AS sd
      FROM device_inventory
      WHERE device_id IN (SELECT id FROM devices WHERE revoked = 0)) i;
