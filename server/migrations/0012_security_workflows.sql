-- FedMes 1.0.6 build 10014 security workflow completion.
-- Additive only: no legacy records are removed or rewritten.

ALTER TABLE provisioning_devices
    ADD COLUMN approved_at TEXT;

ALTER TABLE registration_attempts
    ADD COLUMN authentication_state TEXT NOT NULL DEFAULT 'READY'
    CHECK (authentication_state IN (
        'UNREGISTERED',
        'REGISTRATION_PENDING',
        'AUTHENTICATED_NO_KEYS',
        'KEY_TRANSFER_PENDING',
        'KEYS_RESTORED',
        'READY',
        'REVOKED',
        'RECOVERY_REQUIRED'
    ));

ALTER TABLE account_security_state
    ADD COLUMN recovery_configured INTEGER NOT NULL DEFAULT 0 CHECK (recovery_configured IN (0,1));

ALTER TABLE account_security_state
    ADD COLUMN opaque_enrolled INTEGER NOT NULL DEFAULT 0 CHECK (opaque_enrolled IN (0,1));

ALTER TABLE account_security_state
    ADD COLUMN last_ready_device_id TEXT REFERENCES provisioning_devices(id);

ALTER TABLE device_provisioning_requests
    ADD COLUMN display_name TEXT NOT NULL DEFAULT '' CHECK (length(display_name) <= 96);

ALTER TABLE device_provisioning_requests
    ADD COLUMN platform TEXT NOT NULL DEFAULT '' CHECK (length(platform) <= 64);

ALTER TABLE device_provisioning_requests
    ADD COLUMN network_hint TEXT NOT NULL DEFAULT '' CHECK (length(network_hint) <= 128);

ALTER TABLE device_provisioning_requests
    ADD COLUMN completed_at TEXT;

ALTER TABLE recovery_packages
    ADD COLUMN ciphertext_sha256 BLOB CHECK (ciphertext_sha256 IS NULL OR length(ciphertext_sha256) = 32);

ALTER TABLE encrypted_key_vaults
    ADD COLUMN access_verifier BLOB CHECK (access_verifier IS NULL OR length(access_verifier) = 32);

CREATE UNIQUE INDEX recovery_packages_one_active_per_user_idx
    ON recovery_packages(username)
    WHERE revoked_at IS NULL;

CREATE TABLE security_request_replays (
    request_id TEXT PRIMARY KEY CHECK (length(request_id) BETWEEN 16 AND 128),
    username TEXT NOT NULL REFERENCES family_users(username) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES provisioning_devices(id) ON DELETE CASCADE,
    operation TEXT NOT NULL CHECK (length(operation) BETWEEN 3 AND 96),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    response_status INTEGER NOT NULL CHECK (response_status BETWEEN 200 AND 599),
    response_body BLOB NOT NULL CHECK (length(response_body) BETWEEN 2 AND 1048576),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    CHECK (expires_at > created_at),
    UNIQUE(username, device_id, operation, request_id)
) STRICT;

CREATE INDEX security_request_replays_expiry_idx
    ON security_request_replays(expires_at);

CREATE TABLE server_backup_snapshots (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    manifest_sha256 BLOB NOT NULL CHECK (length(manifest_sha256) = 32),
    archive_sha256 BLOB NOT NULL CHECK (length(archive_sha256) = 32),
    archive_size_bytes INTEGER NOT NULL CHECK (archive_size_bytes > 0),
    storage_hint TEXT NOT NULL DEFAULT '' CHECK (length(storage_hint) <= 256),
    verified_at TEXT,
    restore_tested_at TEXT,
    CHECK (verified_at IS NULL OR verified_at >= created_at),
    CHECK (restore_tested_at IS NULL OR restore_tested_at >= created_at)
) STRICT;

CREATE INDEX provisioning_devices_user_security_idx
    ON provisioning_devices(username, security_state, revoked_at);

CREATE INDEX device_provisioning_requests_target_idx
    ON device_provisioning_requests(target_device_id, requested_at DESC);

UPDATE registration_attempts
SET authentication_state = COALESCE((
    SELECT security_state FROM provisioning_devices d WHERE d.id = registration_attempts.device_id
), 'READY');
