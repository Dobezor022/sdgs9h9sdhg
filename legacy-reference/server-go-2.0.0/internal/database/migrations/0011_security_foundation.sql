-- FedMes 1.0.6 / protocol security foundation.
-- This migration is strictly additive and preserves every 1.0.5 build 10012 record.

ALTER TABLE provisioning_devices
    ADD COLUMN security_state TEXT NOT NULL DEFAULT 'READY'
    CHECK (security_state IN (
        'UNREGISTERED',
        'REGISTRATION_PENDING',
        'AUTHENTICATED_NO_KEYS',
        'KEY_TRANSFER_PENDING',
        'KEYS_RESTORED',
        'READY',
        'REVOKED',
        'RECOVERY_REQUIRED'
    ));

ALTER TABLE provisioning_sessions
    ADD COLUMN protocol_version INTEGER NOT NULL DEFAULT 2
    CHECK (protocol_version BETWEEN 1 AND 64);

ALTER TABLE messages
    ADD COLUMN crypto_version INTEGER NOT NULL DEFAULT 1
    CHECK (crypto_version BETWEEN 1 AND 64);

ALTER TABLE messages
    ADD COLUMN room_key_version INTEGER NOT NULL DEFAULT 1
    CHECK (room_key_version > 0);

ALTER TABLE messages
    ADD COLUMN aad_version INTEGER NOT NULL DEFAULT 1
    CHECK (aad_version BETWEEN 1 AND 64);

ALTER TABLE media_objects
    ADD COLUMN crypto_version INTEGER NOT NULL DEFAULT 1
    CHECK (crypto_version BETWEEN 1 AND 64);

CREATE TABLE account_security_state (
    username TEXT PRIMARY KEY REFERENCES family_users(username) ON DELETE CASCADE,
    state TEXT NOT NULL DEFAULT 'READY' CHECK (state IN (
        'UNREGISTERED',
        'REGISTRATION_PENDING',
        'AUTHENTICATED_NO_KEYS',
        'KEY_TRANSFER_PENDING',
        'KEYS_RESTORED',
        'READY',
        'REVOKED',
        'RECOVERY_REQUIRED'
    )),
    protocol_version INTEGER NOT NULL DEFAULT 2 CHECK (protocol_version BETWEEN 1 AND 64),
    crypto_version INTEGER NOT NULL DEFAULT 1 CHECK (crypto_version BETWEEN 1 AND 64),
    vault_revision INTEGER NOT NULL DEFAULT 0 CHECK (vault_revision >= 0),
    updated_at TEXT NOT NULL,
    CHECK (username IN ('grisha', 'papa', 'mama', 'yura', 'vasya'))
) STRICT;

INSERT OR IGNORE INTO account_security_state(username, state, protocol_version, crypto_version, vault_revision, updated_at)
SELECT username, 'READY', 2, 1, 0, strftime('%Y-%m-%dT%H:%M:%fZ','now')
FROM family_users;

-- Stores only an encrypted replayable result. The registration session token is
-- protected by a server-side AES-256-GCM key kept outside SQLite.
CREATE TABLE registration_attempts (
    idempotency_key TEXT PRIMARY KEY CHECK (length(idempotency_key) BETWEEN 16 AND 128),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    invitation_id TEXT NOT NULL UNIQUE REFERENCES provisioning_invitations(id),
    username TEXT NOT NULL REFERENCES family_users(username),
    device_id TEXT NOT NULL REFERENCES provisioning_devices(id),
    session_id TEXT NOT NULL UNIQUE REFERENCES provisioning_sessions(id),
    protected_session_token BLOB NOT NULL CHECK (length(protected_session_token) BETWEEN 61 AND 512),
    protocol_version INTEGER NOT NULL CHECK (protocol_version BETWEEN 2 AND 64),
    created_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    CHECK (completed_at >= created_at),
    CHECK (username IN ('grisha', 'papa', 'mama', 'yura', 'vasya'))
) STRICT;

CREATE INDEX registration_attempts_username_created_idx
    ON registration_attempts(username, created_at DESC);

-- Canonical purpose-separated public-key registry. Existing signing and RSA
-- key-agreement keys are copied without changing their original tables so old
-- clients remain compatible during migration.
CREATE TABLE device_keys (
    device_id TEXT NOT NULL REFERENCES provisioning_devices(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('signing', 'key_agreement')),
    algorithm TEXT NOT NULL CHECK (length(algorithm) BETWEEN 3 AND 64),
    public_key_spki BLOB NOT NULL CHECK (length(public_key_spki) BETWEEN 32 AND 2048),
    fingerprint BLOB NOT NULL CHECK (length(fingerprint) = 32),
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    PRIMARY KEY (device_id, purpose),
    UNIQUE (purpose, fingerprint),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
) STRICT;

INSERT OR IGNORE INTO device_keys(device_id, purpose, algorithm, public_key_spki, fingerprint, created_at, revoked_at)
SELECT id, 'signing', key_algorithm, public_key_spki, public_key_fingerprint, bound_at, revoked_at
FROM provisioning_devices;

INSERT OR IGNORE INTO device_keys(device_id, purpose, algorithm, public_key_spki, fingerprint, created_at, revoked_at)
SELECT key.device_id, 'key_agreement', key.algorithm, key.public_key_spki, key.fingerprint,
       key.registered_at, device.revoked_at
FROM device_encryption_keys key
JOIN provisioning_devices device ON device.id = key.device_id;

CREATE TABLE device_certificates (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES family_users(username),
    subject_device_id TEXT NOT NULL REFERENCES provisioning_devices(id) ON DELETE CASCADE,
    issuer_device_id TEXT NOT NULL REFERENCES provisioning_devices(id),
    certificate_version INTEGER NOT NULL CHECK (certificate_version BETWEEN 1 AND 64),
    certificate_payload BLOB NOT NULL CHECK (length(certificate_payload) BETWEEN 32 AND 16384),
    signature_algorithm TEXT NOT NULL CHECK (length(signature_algorithm) BETWEEN 3 AND 64),
    signature BLOB NOT NULL CHECK (length(signature) BETWEEN 32 AND 2048),
    issued_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    UNIQUE(subject_device_id, certificate_version),
    CHECK (username IN ('grisha', 'papa', 'mama', 'yura', 'vasya')),
    CHECK (expires_at IS NULL OR expires_at > issued_at),
    CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
) STRICT;

CREATE TABLE device_provisioning_requests (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES family_users(username),
    target_device_id TEXT NOT NULL REFERENCES provisioning_devices(id) ON DELETE CASCADE,
    request_digest BLOB NOT NULL UNIQUE CHECK (length(request_digest) = 32),
    protocol_version INTEGER NOT NULL CHECK (protocol_version BETWEEN 2 AND 64),
    requested_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    approved_at TEXT,
    approved_by_device_id TEXT REFERENCES provisioning_devices(id),
    rejected_at TEXT,
    CHECK (username IN ('grisha', 'papa', 'mama', 'yura', 'vasya')),
    CHECK (expires_at > requested_at),
    CHECK (approved_at IS NULL OR approved_at >= requested_at),
    CHECK (rejected_at IS NULL OR rejected_at >= requested_at),
    CHECK (NOT (approved_at IS NOT NULL AND rejected_at IS NOT NULL))
) STRICT;

CREATE INDEX device_provisioning_requests_pending_idx
    ON device_provisioning_requests(username, expires_at)
    WHERE approved_at IS NULL AND rejected_at IS NULL;

CREATE TABLE device_provisioning_packages (
    request_id TEXT PRIMARY KEY REFERENCES device_provisioning_requests(id) ON DELETE CASCADE,
    target_device_id TEXT NOT NULL REFERENCES provisioning_devices(id) ON DELETE CASCADE,
    encrypted_package BLOB NOT NULL CHECK (length(encrypted_package) BETWEEN 48 AND 1048576),
    nonce BLOB NOT NULL CHECK (length(nonce) BETWEEN 12 AND 24),
    aad_version INTEGER NOT NULL CHECK (aad_version BETWEEN 1 AND 64),
    package_version INTEGER NOT NULL CHECK (package_version BETWEEN 1 AND 64),
    created_at TEXT NOT NULL,
    consumed_at TEXT
) STRICT;

CREATE TABLE encrypted_key_vaults (
    username TEXT NOT NULL REFERENCES family_users(username) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK (revision > 0),
    vault_version INTEGER NOT NULL CHECK (vault_version BETWEEN 1 AND 64),
    crypto_version INTEGER NOT NULL CHECK (crypto_version BETWEEN 1 AND 64),
    aad_version INTEGER NOT NULL CHECK (aad_version BETWEEN 1 AND 64),
    nonce BLOB NOT NULL CHECK (length(nonce) BETWEEN 12 AND 24),
    ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 16 AND 16777216),
    ciphertext_sha256 BLOB NOT NULL CHECK (length(ciphertext_sha256) = 32),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (username, revision),
    CHECK (username IN ('grisha', 'papa', 'mama', 'yura', 'vasya')),
    CHECK (updated_at >= created_at)
) STRICT;

CREATE INDEX encrypted_key_vaults_latest_idx
    ON encrypted_key_vaults(username, revision DESC);

CREATE TABLE recovery_packages (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES family_users(username) ON DELETE CASCADE,
    vault_revision INTEGER NOT NULL CHECK (vault_revision > 0),
    package_version INTEGER NOT NULL CHECK (package_version BETWEEN 1 AND 64),
    crypto_version INTEGER NOT NULL CHECK (crypto_version BETWEEN 1 AND 64),
    aad_version INTEGER NOT NULL CHECK (aad_version BETWEEN 1 AND 64),
    kdf_name TEXT NOT NULL CHECK (length(kdf_name) BETWEEN 3 AND 64),
    kdf_parameters TEXT NOT NULL CHECK (length(kdf_parameters) BETWEEN 2 AND 4096),
    salt BLOB NOT NULL CHECK (length(salt) BETWEEN 16 AND 64),
    nonce BLOB NOT NULL CHECK (length(nonce) BETWEEN 12 AND 24),
    ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 16 AND 1048576),
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    UNIQUE(username, vault_revision, package_version),
    CHECK (username IN ('grisha', 'papa', 'mama', 'yura', 'vasya')),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
) STRICT;

-- OPAQUE records are opaque byte strings. No password, export key, recovery key,
-- or Account Root Key is represented by this table.
CREATE TABLE opaque_records (
    username TEXT PRIMARY KEY REFERENCES family_users(username) ON DELETE CASCADE,
    suite TEXT NOT NULL CHECK (length(suite) BETWEEN 3 AND 128),
    record_version INTEGER NOT NULL CHECK (record_version BETWEEN 1 AND 64),
    registration_record BLOB NOT NULL CHECK (length(registration_record) BETWEEN 32 AND 65536),
    credential_identifier BLOB NOT NULL UNIQUE CHECK (length(credential_identifier) BETWEEN 16 AND 128),
    enrolled_by_device_id TEXT NOT NULL REFERENCES provisioning_devices(id),
    enrolled_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    disabled_at TEXT,
    CHECK (username IN ('grisha', 'papa', 'mama', 'yura', 'vasya')),
    CHECK (updated_at >= enrolled_at),
    CHECK (disabled_at IS NULL OR disabled_at >= enrolled_at)
) STRICT;

CREATE TABLE room_key_versions (
    chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    version INTEGER NOT NULL CHECK (version > 0),
    crypto_version INTEGER NOT NULL CHECK (crypto_version BETWEEN 1 AND 64),
    rotation_id TEXT NOT NULL UNIQUE,
    created_by_device_id TEXT NOT NULL REFERENCES provisioning_devices(id),
    created_at TEXT NOT NULL,
    activated_at TEXT,
    retired_at TEXT,
    PRIMARY KEY(chat_id, version),
    CHECK (activated_at IS NULL OR activated_at >= created_at),
    CHECK (retired_at IS NULL OR retired_at >= created_at)
) STRICT;

CREATE TABLE crypto_migrations (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES family_users(username),
    migration_kind TEXT NOT NULL CHECK (migration_kind IN ('legacy_fmk', 'message_crypto_v2', 'media_crypto_v2')),
    source_version INTEGER NOT NULL CHECK (source_version > 0),
    target_version INTEGER NOT NULL CHECK (target_version > source_version),
    state TEXT NOT NULL CHECK (state IN ('pending', 'running', 'paused', 'completed', 'failed')),
    last_sequence INTEGER NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    processed_count INTEGER NOT NULL DEFAULT 0 CHECK (processed_count >= 0),
    verified_count INTEGER NOT NULL DEFAULT 0 CHECK (verified_count >= 0),
    failure_code TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(username, migration_kind, source_version, target_version),
    CHECK (username IN ('grisha', 'papa', 'mama', 'yura', 'vasya')),
    CHECK (updated_at >= created_at),
    CHECK (completed_at IS NULL OR completed_at >= created_at)
) STRICT;

CREATE TABLE security_audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    username TEXT REFERENCES family_users(username),
    device_id TEXT REFERENCES provisioning_devices(id),
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 3 AND 96),
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'rejected', 'failed')),
    protocol_version INTEGER NOT NULL CHECK (protocol_version BETWEEN 1 AND 64),
    occurred_at TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}' CHECK (length(metadata) BETWEEN 2 AND 4096),
    CHECK (username IS NULL OR username IN ('grisha', 'papa', 'mama', 'yura', 'vasya'))
) STRICT;

CREATE INDEX security_audit_events_user_time_idx
    ON security_audit_events(username, occurred_at DESC);
