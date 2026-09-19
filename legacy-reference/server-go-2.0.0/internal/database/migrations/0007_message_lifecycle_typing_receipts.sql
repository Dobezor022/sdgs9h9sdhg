CREATE TABLE message_user_deletions (
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    username TEXT NOT NULL REFERENCES family_users(username),
    deleted_at TEXT NOT NULL,
    PRIMARY KEY (message_id, username),
    CHECK (username IN ('grisha', 'papa', 'mama', 'yura', 'vasya'))
) STRICT;

CREATE INDEX message_user_deletions_username_idx
ON message_user_deletions(username, message_id);

CREATE TABLE message_receipts (
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    username TEXT NOT NULL REFERENCES family_users(username),
    delivered_at TEXT,
    read_at TEXT,
    PRIMARY KEY (message_id, username),
    CHECK (username IN ('grisha', 'papa', 'mama', 'yura', 'vasya')),
    CHECK (read_at IS NULL OR delivered_at IS NOT NULL)
) STRICT;

CREATE INDEX message_receipts_message_idx
ON message_receipts(message_id, delivered_at, read_at);

CREATE TABLE typing_state (
    chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    username TEXT NOT NULL REFERENCES family_users(username),
    expires_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (chat_id, username),
    CHECK (username IN ('grisha', 'papa', 'mama', 'yura', 'vasya'))
) STRICT;

CREATE INDEX typing_state_expiry_idx ON typing_state(expires_at);

CREATE TRIGGER messages_change_clock_delete
AFTER DELETE ON messages
BEGIN
    UPDATE messaging_change_clock
    SET value = value + 1,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE id = 1;
END;

CREATE TRIGGER envelopes_change_clock_insert
AFTER INSERT ON message_envelopes
BEGIN
    UPDATE messaging_change_clock
    SET value = value + 1,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE id = 1;
END;

CREATE TRIGGER envelopes_change_clock_delete
AFTER DELETE ON message_envelopes
BEGIN
    UPDATE messaging_change_clock
    SET value = value + 1,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE id = 1;
END;

CREATE TRIGGER user_deletions_change_clock_insert
AFTER INSERT ON message_user_deletions
BEGIN
    UPDATE messaging_change_clock
    SET value = value + 1,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE id = 1;
END;

CREATE TRIGGER encryption_keys_change_clock_insert
AFTER INSERT ON device_encryption_keys
BEGIN
    UPDATE messaging_change_clock
    SET value = value + 1,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE id = 1;
END;

CREATE TRIGGER encryption_keys_change_clock_update
AFTER UPDATE ON device_encryption_keys
BEGIN
    UPDATE messaging_change_clock
    SET value = value + 1,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE id = 1;
END;
