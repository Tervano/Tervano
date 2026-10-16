-- Compliance checks (T-805): a rule evaluated against each device's latest inventory, with an
-- optional remediation script the Console can queue as a job for failing devices.
CREATE TABLE compliance_checks (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE COLLATE NOCASE,
    rule_json           TEXT NOT NULL,
    remediation_shell   TEXT,
    remediation_script  TEXT,
    created_by          TEXT NOT NULL,
    created_at          INTEGER NOT NULL
);
