-- FedMes 1.0.4 build 10009: monotonic per-chat read high-water marks.
-- A cursor row replaces O(messages) read receipt writes with one upsert.
CREATE TABLE chat_read_cursors (
    chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    username TEXT NOT NULL REFERENCES family_users(username),
    max_read_sequence INTEGER NOT NULL DEFAULT 0 CHECK (max_read_sequence >= 0),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (chat_id, username),
    CHECK (username IN ('grisha', 'papa', 'mama', 'yura', 'vasya'))
) STRICT;

CREATE INDEX chat_read_cursors_sequence_idx
ON chat_read_cursors(chat_id, max_read_sequence, username);

-- Preserve read state from clients that used per-message receipts before 10009.
INSERT INTO chat_read_cursors(chat_id, username, max_read_sequence, updated_at)
SELECT m.chat_id, mr.username, MAX(m.sequence), MAX(mr.read_at)
FROM message_receipts mr
JOIN messages m ON m.id=mr.message_id
WHERE mr.read_at IS NOT NULL
GROUP BY m.chat_id, mr.username;

CREATE TRIGGER chat_read_cursors_change_clock_insert
AFTER INSERT ON chat_read_cursors
BEGIN
    UPDATE messaging_change_clock
    SET value = value + 1,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE id = 1;
END;

CREATE TRIGGER chat_read_cursors_change_clock_update
AFTER UPDATE OF max_read_sequence ON chat_read_cursors
WHEN NEW.max_read_sequence <> OLD.max_read_sequence
BEGIN
    UPDATE messaging_change_clock
    SET value = value + 1,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE id = 1;
END;
