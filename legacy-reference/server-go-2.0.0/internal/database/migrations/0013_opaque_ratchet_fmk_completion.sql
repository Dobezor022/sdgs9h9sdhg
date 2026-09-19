-- FedMes 1.0.6 build 10015.
-- Additive completion of OPAQUE authentication, ratchet key transport and
-- resumable legacy crypto migration. Existing ciphertext is preserved.

ALTER TABLE provisioning_sessions
    ADD COLUMN opaque_authenticated_at TEXT;

ALTER TABLE provisioning_sessions
    ADD COLUMN authentication_method TEXT NOT NULL DEFAULT 'device_signature'
    CHECK (authentication_method IN ('device_signature', 'opaque'));

ALTER TABLE messages
    ADD COLUMN encryption_algorithm TEXT NOT NULL DEFAULT 'fedmes-aes256gcm-rsa-oaep-v1'
    CHECK (length(encryption_algorithm) BETWEEN 8 AND 96);

ALTER TABLE messages
    ADD COLUMN ciphertext_sha256 BLOB
    CHECK (ciphertext_sha256 IS NULL OR length(ciphertext_sha256) = 32);

ALTER TABLE messages
    ADD COLUMN legacy_retired_at TEXT;

ALTER TABLE media_objects
    ADD COLUMN encryption_algorithm TEXT NOT NULL DEFAULT 'fedmes-aes256gcm-file-v1'
    CHECK (length(encryption_algorithm) BETWEEN 8 AND 96);

ALTER TABLE media_objects
    ADD COLUMN ciphertext_sha256 BLOB
    CHECK (ciphertext_sha256 IS NULL OR length(ciphertext_sha256) = 32);

ALTER TABLE media_objects
    ADD COLUMN legacy_retired_at TEXT;

CREATE TABLE opaque_registration_attempts (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES family_users(username) ON DELETE CASCADE,
    authorizing_device_id TEXT NOT NULL REFERENCES provisioning_devices(id),
    operation TEXT NOT NULL CHECK (operation IN ('enroll', 'password_change')),
    suite TEXT NOT NULL CHECK (length(suite) BETWEEN 16 AND 128),
    credential_identifier BLOB NOT NULL CHECK (length(credential_identifier) BETWEEN 16 AND 128),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    response_message BLOB NOT NULL CHECK (length(response_message) BETWEEN 16 AND 65536),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    completed_at TEXT,
    CHECK (expires_at > created_at),
    CHECK (completed_at IS NULL OR completed_at >= created_at),
    UNIQUE(username, request_digest)
) STRICT;

CREATE INDEX opaque_registration_attempts_expiry_idx
    ON opaque_registration_attempts(expires_at)
    WHERE completed_at IS NULL;

CREATE TABLE opaque_login_attempts (
    id TEXT PRIMARY KEY,
    username_hint_digest BLOB NOT NULL CHECK (length(username_hint_digest) = 32),
    request_digest BLOB NOT NULL UNIQUE CHECK (length(request_digest) = 32),
    suite TEXT NOT NULL CHECK (length(suite) BETWEEN 16 AND 128),
    known_credential INTEGER NOT NULL CHECK (known_credential IN (0,1)),
    proposed_device_id TEXT NOT NULL CHECK (length(proposed_device_id) BETWEEN 16 AND 128),
    proposed_display_name TEXT NOT NULL CHECK (length(proposed_display_name) <= 96),
    proposed_platform TEXT NOT NULL CHECK (length(proposed_platform) BETWEEN 2 AND 64),
    signing_algorithm TEXT NOT NULL CHECK (length(signing_algorithm) BETWEEN 3 AND 64),
    signing_public_key_spki BLOB NOT NULL CHECK (length(signing_public_key_spki) BETWEEN 32 AND 2048),
    key_agreement_algorithm TEXT NOT NULL CHECK (length(key_agreement_algorithm) BETWEEN 3 AND 64),
    key_agreement_public_key_spki BLOB NOT NULL CHECK (length(key_agreement_public_key_spki) BETWEEN 32 AND 2048),
    response_message BLOB NOT NULL CHECK (length(response_message) BETWEEN 16 AND 65536),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    completed_at TEXT,
    failure_count INTEGER NOT NULL DEFAULT 0 CHECK (failure_count BETWEEN 0 AND 32),
    CHECK (expires_at > created_at),
    CHECK (completed_at IS NULL OR completed_at >= created_at)
) STRICT;

CREATE INDEX opaque_login_attempts_expiry_idx
    ON opaque_login_attempts(expires_at)
    WHERE completed_at IS NULL;

-- OPAQUE KE2 continuation state is encrypted with registration-result.key.
-- This allows a valid login to survive a server restart without storing
-- plaintext session secrets or client MACs in SQLite.
CREATE TABLE opaque_login_continuations (
    attempt_id TEXT PRIMARY KEY REFERENCES opaque_login_attempts(id) ON DELETE CASCADE,
    protected_state BLOB NOT NULL CHECK (length(protected_state) BETWEEN 96 AND 4096),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    CHECK (expires_at > created_at)
) STRICT;

CREATE INDEX opaque_login_continuations_expiry_idx
    ON opaque_login_continuations(expires_at);

-- The token is encrypted with registration-result.key, never stored as plaintext.
CREATE TABLE opaque_login_results (
    attempt_id TEXT PRIMARY KEY REFERENCES opaque_login_attempts(id) ON DELETE CASCADE,
    username TEXT NOT NULL REFERENCES family_users(username) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES provisioning_devices(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL UNIQUE REFERENCES provisioning_sessions(id) ON DELETE CASCADE,
    protected_session_token BLOB NOT NULL CHECK (length(protected_session_token) BETWEEN 61 AND 512),
    server_session_proof BLOB NOT NULL CHECK (length(server_session_proof) = 32),
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE opaque_recovery_packages (
    username TEXT PRIMARY KEY REFERENCES family_users(username) ON DELETE CASCADE,
    vault_revision INTEGER NOT NULL CHECK (vault_revision > 0),
    package_version INTEGER NOT NULL CHECK (package_version BETWEEN 1 AND 64),
    nonce BLOB NOT NULL CHECK (length(nonce) BETWEEN 12 AND 24),
    ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 48 AND 1048576),
    ciphertext_sha256 BLOB NOT NULL CHECK (length(ciphertext_sha256) = 32),
    enrolled_by_device_id TEXT NOT NULL REFERENCES provisioning_devices(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (updated_at >= created_at)
) STRICT;

CREATE TABLE ratchet_device_bundles (
    device_id TEXT PRIMARY KEY REFERENCES provisioning_devices(id) ON DELETE CASCADE,
    username TEXT NOT NULL REFERENCES family_users(username) ON DELETE CASCADE,
    bundle_version INTEGER NOT NULL CHECK (bundle_version BETWEEN 1 AND 64),
    curve25519_identity_key TEXT NOT NULL CHECK (length(curve25519_identity_key) BETWEEN 32 AND 128),
    ed25519_identity_key TEXT NOT NULL CHECK (length(ed25519_identity_key) BETWEEN 32 AND 128),
    signed_payload BLOB NOT NULL CHECK (length(signed_payload) BETWEEN 32 AND 65536),
    signature BLOB NOT NULL CHECK (length(signature) BETWEEN 32 AND 2048),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    revoked_at TEXT,
    UNIQUE(curve25519_identity_key),
    UNIQUE(ed25519_identity_key),
    CHECK (updated_at >= created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
) STRICT;

CREATE TABLE ratchet_one_time_keys (
    device_id TEXT NOT NULL REFERENCES provisioning_devices(id) ON DELETE CASCADE,
    key_id TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 128),
    public_key TEXT NOT NULL CHECK (length(public_key) BETWEEN 32 AND 128),
    signature BLOB NOT NULL CHECK (length(signature) BETWEEN 32 AND 2048),
    created_at TEXT NOT NULL,
    claimed_at TEXT,
    claimed_by_device_id TEXT REFERENCES provisioning_devices(id),
    PRIMARY KEY(device_id, key_id),
    UNIQUE(public_key),
    CHECK (claimed_at IS NULL OR claimed_at >= created_at),
    CHECK ((claimed_at IS NULL) = (claimed_by_device_id IS NULL))
) STRICT;

CREATE INDEX ratchet_one_time_keys_unclaimed_idx
    ON ratchet_one_time_keys(device_id, created_at)
    WHERE claimed_at IS NULL;

CREATE TABLE ratchet_sessions (
    owner_device_id TEXT NOT NULL REFERENCES provisioning_devices(id) ON DELETE CASCADE,
    peer_device_id TEXT NOT NULL REFERENCES provisioning_devices(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 16 AND 256),
    created_at TEXT NOT NULL,
    last_message_at TEXT,
    retired_at TEXT,
    PRIMARY KEY(owner_device_id, peer_device_id, session_id),
    CHECK (owner_device_id <> peer_device_id),
    CHECK (last_message_at IS NULL OR last_message_at >= created_at),
    CHECK (retired_at IS NULL OR retired_at >= created_at)
) STRICT;

CREATE TABLE ratchet_message_envelopes (
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    recipient_device_id TEXT NOT NULL REFERENCES provisioning_devices(id),
    sender_curve25519_key TEXT NOT NULL CHECK (length(sender_curve25519_key) BETWEEN 32 AND 128),
    session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 16 AND 256),
    message_type INTEGER NOT NULL CHECK (message_type IN (0,1)),
    ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 16 AND 1048576),
    ciphertext_sha256 BLOB NOT NULL CHECK (length(ciphertext_sha256) = 32),
    created_at TEXT NOT NULL,
    PRIMARY KEY(message_id, recipient_device_id)
) STRICT;

CREATE TABLE megolm_rotation_reservations (
    rotation_id TEXT PRIMARY KEY CHECK (length(rotation_id) BETWEEN 16 AND 128),
    chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    sender_device_id TEXT NOT NULL REFERENCES provisioning_devices(id) ON DELETE CASCADE,
    room_key_version INTEGER NOT NULL CHECK (room_key_version > 0),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    UNIQUE(chat_id, room_key_version),
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
) STRICT;

CREATE INDEX megolm_rotation_reservations_expiry_idx
    ON megolm_rotation_reservations(expires_at)
    WHERE consumed_at IS NULL;

CREATE TABLE megolm_group_sessions (
    chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    room_key_version INTEGER NOT NULL CHECK (room_key_version > 0),
    session_id TEXT NOT NULL UNIQUE CHECK (length(session_id) BETWEEN 16 AND 256),
    sender_device_id TEXT NOT NULL REFERENCES provisioning_devices(id),
    rotation_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    retired_at TEXT,
    PRIMARY KEY(chat_id, room_key_version),
    CHECK (retired_at IS NULL OR retired_at >= created_at)
) STRICT;

CREATE TABLE megolm_key_packages (
    chat_id TEXT NOT NULL,
    room_key_version INTEGER NOT NULL,
    recipient_device_id TEXT NOT NULL REFERENCES provisioning_devices(id) ON DELETE CASCADE,
    olm_session_id TEXT NOT NULL CHECK (length(olm_session_id) BETWEEN 16 AND 256),
    message_type INTEGER NOT NULL CHECK (message_type IN (0,1)),
    encrypted_session_key BLOB NOT NULL CHECK (length(encrypted_session_key) BETWEEN 16 AND 65536),
    created_at TEXT NOT NULL,
    consumed_at TEXT,
    PRIMARY KEY(chat_id, room_key_version, recipient_device_id),
    FOREIGN KEY(chat_id, room_key_version)
        REFERENCES megolm_group_sessions(chat_id, room_key_version) ON DELETE CASCADE,
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
) STRICT;

CREATE TABLE crypto_migration_records (
    migration_id TEXT NOT NULL REFERENCES crypto_migrations(id) ON DELETE CASCADE,
    object_kind TEXT NOT NULL CHECK (object_kind IN ('message','media')),
    object_id TEXT NOT NULL,
    source_crypto_version INTEGER NOT NULL CHECK (source_crypto_version > 0),
    target_crypto_version INTEGER NOT NULL CHECK (target_crypto_version > source_crypto_version),
    source_ciphertext_sha256 BLOB NOT NULL CHECK (length(source_ciphertext_sha256) = 32),
    target_ciphertext_sha256 BLOB CHECK (target_ciphertext_sha256 IS NULL OR length(target_ciphertext_sha256) = 32),
    verified_by_device_id TEXT REFERENCES provisioning_devices(id),
    device_signature BLOB CHECK (device_signature IS NULL OR length(device_signature) BETWEEN 32 AND 2048),
    state TEXT NOT NULL CHECK (state IN ('pending','uploaded','verified','retired','failed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(migration_id, object_kind, object_id),
    CHECK (updated_at >= created_at)
) STRICT;

CREATE INDEX crypto_migration_records_progress_idx
    ON crypto_migration_records(migration_id, state, object_kind, object_id);

CREATE TABLE room_rotation_events (
    id TEXT PRIMARY KEY,
    chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    reason TEXT NOT NULL CHECK (reason IN ('device_revoked','scheduled','manual','migration')),
    revoked_device_id TEXT REFERENCES provisioning_devices(id),
    previous_key_version INTEGER NOT NULL CHECK (previous_key_version >= 0),
    new_key_version INTEGER NOT NULL CHECK (new_key_version > previous_key_version),
    created_by_device_id TEXT REFERENCES provisioning_devices(id),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    CHECK (completed_at IS NULL OR completed_at >= created_at)
) STRICT;

-- Message SHA-256 values are backfilled by the Go migration worker in bounded batches.

UPDATE media_objects
SET ciphertext_sha256 = sha256_digest
WHERE ciphertext_sha256 IS NULL;

-- Client-verified, resumable replacements. The source ciphertext remains in the
-- original table until a READY device signs a successful local round-trip and
-- the final transaction atomically swaps the target into place.
CREATE TABLE crypto_message_replacements (
    migration_id TEXT NOT NULL REFERENCES crypto_migrations(id) ON DELETE CASCADE,
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    source_ciphertext_sha256 BLOB NOT NULL CHECK (length(source_ciphertext_sha256) = 32),
    target_ciphertext BLOB NOT NULL CHECK (length(target_ciphertext) BETWEEN 16 AND 1048576),
    target_nonce BLOB NOT NULL CHECK (length(target_nonce) = 12),
    target_aad TEXT NOT NULL CHECK (length(target_aad) BETWEEN 1 AND 4096),
    target_crypto_version INTEGER NOT NULL CHECK (target_crypto_version >= 2),
    target_room_key_version INTEGER NOT NULL CHECK (target_room_key_version > 0),
    target_aad_version INTEGER NOT NULL CHECK (target_aad_version >= 2),
    target_encryption_algorithm TEXT NOT NULL CHECK (length(target_encryption_algorithm) BETWEEN 8 AND 96),
    target_ciphertext_sha256 BLOB NOT NULL CHECK (length(target_ciphertext_sha256) = 32),
    uploaded_by_device_id TEXT NOT NULL REFERENCES provisioning_devices(id),
    upload_signature BLOB NOT NULL CHECK (length(upload_signature) BETWEEN 32 AND 2048),
    uploaded_at TEXT NOT NULL,
    verified_by_device_id TEXT REFERENCES provisioning_devices(id),
    verification_signature BLOB CHECK (verification_signature IS NULL OR length(verification_signature) BETWEEN 32 AND 2048),
    verified_at TEXT,
    PRIMARY KEY(migration_id, message_id),
    CHECK ((verified_by_device_id IS NULL) = (verification_signature IS NULL)),
    CHECK ((verified_by_device_id IS NULL) = (verified_at IS NULL))
) STRICT;

CREATE TABLE crypto_media_replacements (
    migration_id TEXT NOT NULL REFERENCES crypto_migrations(id) ON DELETE CASCADE,
    media_id TEXT NOT NULL REFERENCES media_objects(id) ON DELETE CASCADE,
    source_ciphertext_sha256 BLOB NOT NULL CHECK (length(source_ciphertext_sha256) = 32),
    staged_blob_name TEXT NOT NULL UNIQUE CHECK (length(staged_blob_name) BETWEEN 16 AND 192),
    target_size_bytes INTEGER NOT NULL CHECK (target_size_bytes BETWEEN 1 AND 268435456),
    target_ciphertext_sha256 BLOB NOT NULL CHECK (length(target_ciphertext_sha256) = 32),
    target_crypto_version INTEGER NOT NULL CHECK (target_crypto_version >= 2),
    target_encryption_algorithm TEXT NOT NULL CHECK (length(target_encryption_algorithm) BETWEEN 8 AND 96),
    uploaded_by_device_id TEXT NOT NULL REFERENCES provisioning_devices(id),
    upload_signature BLOB NOT NULL CHECK (length(upload_signature) BETWEEN 32 AND 2048),
    uploaded_at TEXT NOT NULL,
    verified_by_device_id TEXT REFERENCES provisioning_devices(id),
    verification_signature BLOB CHECK (verification_signature IS NULL OR length(verification_signature) BETWEEN 32 AND 2048),
    verified_at TEXT,
    PRIMARY KEY(migration_id, media_id),
    CHECK ((verified_by_device_id IS NULL) = (verification_signature IS NULL)),
    CHECK ((verified_by_device_id IS NULL) = (verified_at IS NULL))
) STRICT;

CREATE INDEX crypto_message_replacements_pending_idx
    ON crypto_message_replacements(migration_id, verified_at, message_id);
CREATE INDEX crypto_media_replacements_pending_idx
    ON crypto_media_replacements(migration_id, verified_at, media_id);

-- A revoked device can no longer publish or claim ratchet keys. Every affected
-- room receives a monotonic rotation event; a READY device must publish the new
-- Megolm session and per-device key packages before sending further v2 data.
CREATE TRIGGER provisioning_device_ratchet_revoke
AFTER UPDATE OF revoked_at ON provisioning_devices
WHEN OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
BEGIN
    UPDATE ratchet_device_bundles SET revoked_at=NEW.revoked_at WHERE device_id=NEW.id AND revoked_at IS NULL;
    UPDATE device_keys SET revoked_at=NEW.revoked_at WHERE device_id=NEW.id AND revoked_at IS NULL;
    INSERT INTO room_rotation_events(
        id,chat_id,reason,revoked_device_id,previous_key_version,new_key_version,created_by_device_id,created_at
    )
    SELECT lower(hex(randomblob(16))), member.chat_id, 'device_revoked', NEW.id,
           COALESCE((SELECT MAX(version) FROM room_key_versions WHERE chat_id=member.chat_id),0),
           COALESCE((SELECT MAX(version) FROM room_key_versions WHERE chat_id=member.chat_id),0)+1,
           NULL, NEW.revoked_at
    FROM chat_members member
    WHERE member.username=NEW.username
      AND NOT EXISTS (
          SELECT 1 FROM room_rotation_events pending
          WHERE pending.chat_id=member.chat_id AND pending.completed_at IS NULL
      );
END;

ALTER TABLE messages
    ADD COLUMN crypto_sequence INTEGER NOT NULL DEFAULT 0 CHECK (crypto_sequence >= 0);

CREATE UNIQUE INDEX messages_crypto_sequence_unique_idx
    ON messages(chat_id, sender_device_id, crypto_sequence)
    WHERE crypto_sequence > 0;

CREATE TABLE room_device_sequence_state (
    chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES provisioning_devices(id) ON DELETE CASCADE,
    next_sequence INTEGER NOT NULL CHECK (next_sequence > 0),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(chat_id, device_id)
) STRICT;

CREATE TABLE message_sequence_reservations (
    request_id TEXT PRIMARY KEY CHECK (length(request_id) BETWEEN 16 AND 128),
    message_id TEXT NOT NULL CHECK (length(message_id) BETWEEN 16 AND 128),
    chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    sender_device_id TEXT NOT NULL REFERENCES provisioning_devices(id) ON DELETE CASCADE,
    crypto_sequence INTEGER NOT NULL CHECK (crypto_sequence > 0),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    UNIQUE(chat_id, sender_device_id, crypto_sequence),
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
) STRICT;

CREATE INDEX message_sequence_reservations_expiry_idx
    ON message_sequence_reservations(expires_at)
    WHERE consumed_at IS NULL;

ALTER TABLE account_security_state
    ADD COLUMN minimum_crypto_version INTEGER NOT NULL DEFAULT 1 CHECK (minimum_crypto_version BETWEEN 1 AND 64);

ALTER TABLE account_security_state
    ADD COLUMN legacy_fmk_removed_at TEXT;
