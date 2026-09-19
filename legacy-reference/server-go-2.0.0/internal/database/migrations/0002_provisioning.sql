CREATE TABLE provisioning_invitations (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES family_users(username),
    token_digest BLOB NOT NULL UNIQUE CHECK (length(token_digest) = 32),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    redeemed_at TEXT,
    redeemed_by_device_id TEXT,
    CHECK (username IN ('grisha', 'papa', 'mama', 'yura', 'vasya')),
    CHECK (expires_at > created_at),
    CHECK (
        (redeemed_at IS NULL AND redeemed_by_device_id IS NULL)
        OR (redeemed_at IS NOT NULL AND redeemed_by_device_id IS NOT NULL)
    ),
    FOREIGN KEY (redeemed_by_device_id)
        REFERENCES provisioning_devices(id)
        DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE INDEX provisioning_invitations_expiry_idx
    ON provisioning_invitations (expires_at)
    WHERE redeemed_at IS NULL;

CREATE TABLE provisioning_devices (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES family_users(username),
    invitation_id TEXT NOT NULL UNIQUE REFERENCES provisioning_invitations(id),
    key_algorithm TEXT NOT NULL,
    public_key_spki BLOB NOT NULL CHECK (length(public_key_spki) BETWEEN 32 AND 512),
    public_key_fingerprint BLOB NOT NULL UNIQUE CHECK (length(public_key_fingerprint) = 32),
    bound_at TEXT NOT NULL,
    revoked_at TEXT,
    CHECK (username IN ('grisha', 'papa', 'mama', 'yura', 'vasya')),
    CHECK (key_algorithm IN ('ed25519', 'ecdsa-p256-sha256')),
    CHECK (revoked_at IS NULL OR revoked_at >= bound_at)
) STRICT;

CREATE INDEX provisioning_devices_username_active_idx
    ON provisioning_devices (username)
    WHERE revoked_at IS NULL;

CREATE TABLE provisioning_sessions (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES provisioning_devices(id),
    token_digest BLOB NOT NULL UNIQUE CHECK (length(token_digest) = 32),
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    CHECK (expires_at > issued_at),
    CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
) STRICT;

CREATE INDEX provisioning_sessions_device_active_idx
    ON provisioning_sessions (device_id, expires_at)
    WHERE revoked_at IS NULL;
