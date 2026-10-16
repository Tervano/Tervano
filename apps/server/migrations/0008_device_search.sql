-- Substring search over hostname, signed-in users and IPs (T-112). The trigram tokenizer makes
-- "lab" match "PC-LAB-01" without scanning every device; queries shorter than 3 characters use
-- the prefix indexes from 0001 instead.
CREATE VIRTUAL TABLE device_search USING fts5(device_id UNINDEXED, body, tokenize = 'trigram');

INSERT INTO device_search (device_id, body)
SELECT d.id,
       d.hostname
       || ' ' || ifnull((SELECT group_concat(s.username, ' ') FROM device_sessions s WHERE s.device_id = d.id), '')
       || ' ' || ifnull((SELECT group_concat(a.address, ' ') FROM device_addresses a WHERE a.device_id = d.id), '')
FROM devices d;
