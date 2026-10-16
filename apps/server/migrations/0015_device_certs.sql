-- Device certificates (T-808): the fingerprint each device must present over mutual TLS. During a
-- renewal the previous certificate stays valid until the new one is first used.
ALTER TABLE devices ADD COLUMN cert_sha256 TEXT;
ALTER TABLE devices ADD COLUMN prev_cert_sha256 TEXT;
ALTER TABLE devices ADD COLUMN cert_expires_at INTEGER;
