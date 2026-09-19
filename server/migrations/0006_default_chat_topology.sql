-- Repair/seed the fixed FedMes family topology for databases created by older
-- builds. The statements are idempotent and therefore safe for an existing
-- installation with messages and device bindings.

INSERT OR IGNORE INTO chats(id, kind, title, created_at) VALUES
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

INSERT OR IGNORE INTO chat_members(chat_id, username) VALUES
('favorites:grisha','grisha'),
('favorites:papa','papa'),
('favorites:mama','mama'),
('favorites:yura','yura'),
('favorites:vasya','vasya'),
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

INSERT OR IGNORE INTO presence(username, updated_at) VALUES
('grisha', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('papa', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('mama', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('yura', strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('vasya', strftime('%Y-%m-%dT%H:%M:%fZ','now'));
