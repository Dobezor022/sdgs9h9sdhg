CREATE TABLE device_encryption_keys (
    device_id TEXT PRIMARY KEY REFERENCES provisioning_devices(id) ON DELETE CASCADE,
    algorithm TEXT NOT NULL CHECK (algorithm = 'rsa-oaep-sha256'),
    public_key_spki BLOB NOT NULL CHECK (length(public_key_spki) BETWEEN 256 AND 1024),
    fingerprint BLOB NOT NULL UNIQUE CHECK (length(fingerprint) = 32),
    registered_at TEXT NOT NULL
) STRICT;

CREATE TABLE chats (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('direct', 'favorites', 'family')),
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 128),
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE chat_members (
    chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    username TEXT NOT NULL REFERENCES family_users(username),
    PRIMARY KEY (chat_id, username),
    CHECK (username IN ('grisha', 'papa', 'mama', 'yura', 'vasya'))
) STRICT;

CREATE TABLE messages (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    sender_username TEXT NOT NULL REFERENCES family_users(username),
    sender_device_id TEXT NOT NULL REFERENCES provisioning_devices(id),
    ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 16 AND 1048576),
    nonce BLOB NOT NULL CHECK (length(nonce) = 12),
    aad TEXT NOT NULL CHECK (length(aad) BETWEEN 1 AND 2048),
    created_at TEXT NOT NULL,
    edited_at TEXT,
    deleted_at TEXT,
    CHECK (sender_username IN ('grisha', 'papa', 'mama', 'yura', 'vasya')),
    CHECK (edited_at IS NULL OR edited_at >= created_at),
    CHECK (deleted_at IS NULL OR deleted_at >= created_at)
) STRICT;

CREATE INDEX messages_chat_sequence_idx ON messages(chat_id, sequence);
CREATE INDEX messages_sender_idx ON messages(sender_username, created_at);

CREATE TABLE message_envelopes (
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES provisioning_devices(id),
    algorithm TEXT NOT NULL CHECK (algorithm = 'rsa-oaep-sha256'),
    ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 256 AND 1024),
    PRIMARY KEY (message_id, device_id)
) STRICT;

CREATE TABLE pinned_messages (
    chat_id TEXT PRIMARY KEY REFERENCES chats(id) ON DELETE CASCADE,
    message_id TEXT NOT NULL UNIQUE REFERENCES messages(id) ON DELETE CASCADE,
    pinned_by TEXT NOT NULL REFERENCES family_users(username),
    pinned_at TEXT NOT NULL
) STRICT;

CREATE TABLE presence (
    username TEXT PRIMARY KEY REFERENCES family_users(username),
    last_seen_at TEXT,
    show_exact INTEGER NOT NULL DEFAULT 1 CHECK (show_exact IN (0, 1)),
    updated_at TEXT NOT NULL,
    CHECK (username IN ('grisha', 'papa', 'mama', 'yura', 'vasya'))
) STRICT;

CREATE TABLE media_objects (
    id TEXT PRIMARY KEY,
    chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    uploader_username TEXT NOT NULL REFERENCES family_users(username),
    uploader_device_id TEXT NOT NULL REFERENCES provisioning_devices(id),
    blob_name TEXT NOT NULL UNIQUE CHECK (length(blob_name) BETWEEN 1 AND 128),
    size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 1 AND 268435456),
    sha256_digest BLOB NOT NULL CHECK (length(sha256_digest) = 32),
    created_at TEXT NOT NULL,
    deleted_at TEXT,
    CHECK (uploader_username IN ('grisha', 'papa', 'mama', 'yura', 'vasya'))
) STRICT;

CREATE INDEX media_objects_chat_idx ON media_objects(chat_id, created_at);

INSERT INTO chats(id, kind, title, created_at) VALUES
('favorites:grisha', 'favorites', 'Избранное', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('favorites:papa', 'favorites', 'Избранное', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('favorites:mama', 'favorites', 'Избранное', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('favorites:yura', 'favorites', 'Избранное', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('favorites:vasya', 'favorites', 'Избранное', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('dm:grisha:papa', 'direct', 'grisha · papa', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('dm:grisha:mama', 'direct', 'grisha · mama', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('dm:grisha:yura', 'direct', 'grisha · yura', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('dm:grisha:vasya', 'direct', 'grisha · vasya', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('dm:mama:papa', 'direct', 'mama · papa', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('dm:papa:yura', 'direct', 'papa · yura', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('dm:papa:vasya', 'direct', 'papa · vasya', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('dm:mama:yura', 'direct', 'mama · yura', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('dm:mama:vasya', 'direct', 'mama · vasya', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('dm:vasya:yura', 'direct', 'vasya · yura', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('family', 'family', 'Семья', strftime('%Y-%m-%dT%H:%M:%fZ','now'));

INSERT INTO chat_members(chat_id, username) VALUES
('favorites:grisha','grisha'),('favorites:papa','papa'),('favorites:mama','mama'),('favorites:yura','yura'),('favorites:vasya','vasya'),
('dm:grisha:papa','grisha'),('dm:grisha:papa','papa'),
('dm:grisha:mama','grisha'),('dm:grisha:mama','mama'),
('dm:grisha:yura','grisha'),('dm:grisha:yura','yura'),
('dm:grisha:vasya','grisha'),('dm:grisha:vasya','vasya'),
('dm:mama:papa','mama'),('dm:mama:papa','papa'),
('dm:papa:yura','papa'),('dm:papa:yura','yura'),
('dm:papa:vasya','papa'),('dm:papa:vasya','vasya'),
('dm:mama:yura','mama'),('dm:mama:yura','yura'),
('dm:mama:vasya','mama'),('dm:mama:vasya','vasya'),
('dm:vasya:yura','vasya'),('dm:vasya:yura','yura'),
('family','grisha'),('family','papa'),('family','mama'),('family','yura'),('family','vasya');

INSERT INTO presence(username, updated_at) VALUES
('grisha', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('papa', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('mama', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('yura', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('vasya', strftime('%Y-%m-%dT%H:%M:%fZ','now'));
