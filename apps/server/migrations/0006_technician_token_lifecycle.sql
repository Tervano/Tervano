-- Existing technician tokens get a 30-day grace period after this migration.
-- A zero expiry on a future malformed insert fails authentication closed.
ALTER TABLE technicians ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE technicians ADD COLUMN revoked_at INTEGER;
UPDATE technicians
SET expires_at = CAST(strftime('%s', 'now') AS INTEGER) * 1000 + 2592000000;
