CREATE TABLE provisioning_challenges (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES provisioning_devices(id),
    nonce_digest BLOB NOT NULL UNIQUE CHECK (length(nonce_digest) = 32),
    audience TEXT NOT NULL CHECK (length(audience) BETWEEN 1 AND 512),
    purpose TEXT NOT NULL CHECK (purpose = 'session.refresh'),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
) STRICT;

CREATE INDEX provisioning_challenges_active_idx
    ON provisioning_challenges (device_id, expires_at)
    WHERE consumed_at IS NULL;

