-- FedMes 2.0 blind object fabric.
-- No username, chat id, message type, sender, recipient, filename or media type
-- is stored in these tables. Route secrets are never stored; only SHA-256
-- digests of 32-byte capability tokens are persisted.

CREATE TABLE blind_routes (
    route_digest BLOB PRIMARY KEY CHECK (length(route_digest) = 32),
    generation INTEGER NOT NULL CHECK (generation > 0),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    max_object_bytes INTEGER NOT NULL CHECK (max_object_bytes BETWEEN 1024 AND 8388608),
    max_pending_objects INTEGER NOT NULL CHECK (max_pending_objects BETWEEN 1 AND 4096),
    revoked_at TEXT,
    CHECK (expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
) STRICT;

CREATE INDEX blind_routes_expiry_idx
    ON blind_routes(expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE blind_objects (
    object_id TEXT PRIMARY KEY CHECK (length(object_id) BETWEEN 20 AND 64),
    route_digest BLOB NOT NULL REFERENCES blind_routes(route_digest) ON DELETE CASCADE,
    length_class INTEGER NOT NULL CHECK (length_class BETWEEN 1 AND 16),
    ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 16 AND 8388608),
    ciphertext_sha256 BLOB NOT NULL CHECK (length(ciphertext_sha256) = 32),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    CHECK (expires_at > created_at)
) STRICT;

CREATE INDEX blind_objects_route_idx
    ON blind_objects(route_digest, created_at, object_id);
CREATE INDEX blind_objects_expiry_idx
    ON blind_objects(expires_at);
