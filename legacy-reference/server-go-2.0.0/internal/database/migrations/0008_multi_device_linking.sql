ALTER TABLE provisioning_devices
    ADD COLUMN display_name TEXT NOT NULL DEFAULT 'Android';

ALTER TABLE provisioning_devices
    ADD COLUMN platform TEXT NOT NULL DEFAULT 'android';

ALTER TABLE provisioning_devices
    ADD COLUMN last_seen_at TEXT;

ALTER TABLE provisioning_devices
    ADD COLUMN approved_by_device_id TEXT REFERENCES provisioning_devices(id);

CREATE TABLE device_link_requests (
    id TEXT PRIMARY KEY,
    secret_digest BLOB NOT NULL UNIQUE CHECK (length(secret_digest) = 32),
    identity_algorithm TEXT NOT NULL CHECK (identity_algorithm IN ('ed25519', 'ecdsa-p256-sha256')),
    identity_public_key_spki BLOB NOT NULL CHECK (length(identity_public_key_spki) BETWEEN 32 AND 512),
    identity_fingerprint BLOB NOT NULL CHECK (length(identity_fingerprint) = 32),
    encryption_algorithm TEXT NOT NULL CHECK (encryption_algorithm = 'rsa-oaep-sha256'),
    encryption_public_key_spki BLOB NOT NULL CHECK (length(encryption_public_key_spki) BETWEEN 256 AND 1024),
    encryption_fingerprint BLOB NOT NULL CHECK (length(encryption_fingerprint) = 32),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 64),
    platform TEXT NOT NULL CHECK (platform IN ('windows', 'linux', 'macos')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    approved_at TEXT,
    approved_by_device_id TEXT REFERENCES provisioning_devices(id),
    username TEXT REFERENCES family_users(username),
    linked_device_id TEXT REFERENCES provisioning_devices(id),
    linked_session_id TEXT REFERENCES provisioning_sessions(id),
    encrypted_session_token BLOB,
    session_expires_at TEXT,
    result_expires_at TEXT,
    consumed_at TEXT,
    cancelled_at TEXT,
    CHECK (expires_at > created_at),
    CHECK (username IS NULL OR username IN ('grisha', 'papa', 'mama', 'yura', 'vasya')),
    CHECK (
        (approved_at IS NULL AND approved_by_device_id IS NULL AND username IS NULL
            AND linked_device_id IS NULL AND linked_session_id IS NULL
            AND encrypted_session_token IS NULL AND session_expires_at IS NULL AND result_expires_at IS NULL)
        OR
        (approved_at IS NOT NULL AND approved_by_device_id IS NOT NULL AND username IS NOT NULL
            AND linked_device_id IS NOT NULL AND linked_session_id IS NOT NULL
            AND (encrypted_session_token IS NOT NULL OR consumed_at IS NOT NULL)
            AND session_expires_at IS NOT NULL AND result_expires_at IS NOT NULL)
    ),
    CHECK (consumed_at IS NULL OR approved_at IS NOT NULL),
    CHECK (cancelled_at IS NULL OR approved_at IS NULL)
) STRICT;

CREATE INDEX device_link_requests_pending_idx
    ON device_link_requests(expires_at)
    WHERE approved_at IS NULL AND cancelled_at IS NULL;

CREATE INDEX device_link_requests_result_idx
    ON device_link_requests(result_expires_at)
    WHERE approved_at IS NOT NULL AND consumed_at IS NULL;

CREATE INDEX provisioning_devices_username_live_idx
    ON provisioning_devices(username, last_seen_at)
    WHERE revoked_at IS NULL;
