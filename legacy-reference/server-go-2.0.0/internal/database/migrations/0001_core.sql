CREATE TABLE family_users (
    username TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
) STRICT;

INSERT INTO family_users (username, created_at)
VALUES
    ('grisha', CURRENT_TIMESTAMP),
    ('papa', CURRENT_TIMESTAMP),
    ('mama', CURRENT_TIMESTAMP),
    ('yura', CURRENT_TIMESTAMP),
    ('vasya', CURRENT_TIMESTAMP);
