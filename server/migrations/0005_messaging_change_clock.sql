CREATE TABLE messaging_change_clock (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    value INTEGER NOT NULL CHECK (value >= 0),
    updated_at TEXT NOT NULL
) STRICT;

INSERT INTO messaging_change_clock(id, value, updated_at)
VALUES (
    1,
    COALESCE((SELECT MAX(sequence) FROM messages), 0),
    strftime('%Y-%m-%dT%H:%M:%fZ','now')
);

CREATE TRIGGER messages_change_clock_insert
AFTER INSERT ON messages
BEGIN
    UPDATE messaging_change_clock
    SET value = CASE WHEN NEW.sequence > value THEN NEW.sequence ELSE value + 1 END,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE id = 1;
END;

CREATE TRIGGER messages_change_clock_update
AFTER UPDATE OF ciphertext, nonce, aad, edited_at, deleted_at ON messages
BEGIN
    UPDATE messaging_change_clock
    SET value = value + 1,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE id = 1;
END;

CREATE TRIGGER pinned_change_clock_insert
AFTER INSERT ON pinned_messages
BEGIN
    UPDATE messaging_change_clock
    SET value = value + 1,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE id = 1;
END;

CREATE TRIGGER pinned_change_clock_update
AFTER UPDATE ON pinned_messages
BEGIN
    UPDATE messaging_change_clock
    SET value = value + 1,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE id = 1;
END;

CREATE TRIGGER pinned_change_clock_delete
AFTER DELETE ON pinned_messages
BEGIN
    UPDATE messaging_change_clock
    SET value = value + 1,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE id = 1;
END;
