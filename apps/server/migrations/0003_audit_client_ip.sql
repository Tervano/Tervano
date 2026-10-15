-- Existing CLI audit rows have no network peer.
ALTER TABLE audit_log ADD COLUMN client_ip TEXT;
