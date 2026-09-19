CREATE TABLE media_objects_unlimited (
    id TEXT PRIMARY KEY,
    chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    uploader_username TEXT NOT NULL REFERENCES family_users(username),
    uploader_device_id TEXT NOT NULL REFERENCES provisioning_devices(id),
    blob_name TEXT NOT NULL UNIQUE CHECK (length(blob_name) BETWEEN 1 AND 128),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 1),
    sha256_digest BLOB NOT NULL CHECK (length(sha256_digest) = 32),
    created_at TEXT NOT NULL,
    deleted_at TEXT,
    CHECK (uploader_username IN ('grisha', 'papa', 'mama', 'yura', 'vasya'))
) STRICT;

INSERT INTO media_objects_unlimited(
    id, chat_id, uploader_username, uploader_device_id,
    blob_name, size_bytes, sha256_digest, created_at, deleted_at
)
SELECT
    id, chat_id, uploader_username, uploader_device_id,
    blob_name, size_bytes, sha256_digest, created_at, deleted_at
FROM media_objects;

DROP TABLE media_objects;
ALTER TABLE media_objects_unlimited RENAME TO media_objects;
CREATE INDEX media_objects_chat_idx ON media_objects(chat_id, created_at);
