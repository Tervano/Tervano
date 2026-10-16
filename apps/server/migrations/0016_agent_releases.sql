-- Agent releases for signed self-update (T-810). The manifest and its signature come from the
-- release key holder (`tervano-server release sign`, ideally offline); the Server only stores and
-- serves them, and agents verify the signature with the release public key they are configured with.
CREATE TABLE agent_releases (
    platform      TEXT NOT NULL,
    version       TEXT NOT NULL,
    manifest      TEXT NOT NULL,
    signature     TEXT NOT NULL,
    binary        BLOB NOT NULL,
    published_at  INTEGER NOT NULL,
    published_by  TEXT NOT NULL,
    PRIMARY KEY (platform, version)
);
