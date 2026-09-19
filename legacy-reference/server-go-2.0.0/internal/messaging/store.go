package messaging

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

type Store struct{ DB *sql.DB }

func NewStore(db *sql.DB) *Store { return &Store{DB: db} }

func (s *Store) Authenticate(ctx context.Context, bearer string, now time.Time) (Principal, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSpace(bearer))
	if err != nil || len(raw) != 32 {
		return Principal{}, errors.New("invalid session")
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	var p Principal
	var expires string
	var sessionRevoked, deviceRevoked sql.NullString
	err = s.DB.QueryRowContext(ctx, `
		SELECT d.username, d.id, s.id, d.security_state, s.expires_at, s.revoked_at, d.revoked_at
		FROM provisioning_sessions s JOIN provisioning_devices d ON d.id=s.device_id
		WHERE s.token_digest=?`, digest[:]).Scan(&p.Username, &p.DeviceID, &p.SessionID, &p.SecurityState, &expires, &sessionRevoked, &deviceRevoked)
	if err != nil {
		return Principal{}, errors.New("invalid session")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || !now.Before(expiresAt) || sessionRevoked.Valid || deviceRevoked.Valid {
		return Principal{}, errors.New("expired session")
	}
	// Keep device activity fresh without turning every API call into a write.
	_, _ = s.DB.ExecContext(ctx, `
		UPDATE provisioning_devices SET last_seen_at=?
		WHERE id=? AND revoked_at IS NULL
			AND (last_seen_at IS NULL OR last_seen_at<?)`,
		now.UTC().Format(time.RFC3339Nano), p.DeviceID,
		now.Add(-time.Minute).UTC().Format(time.RFC3339Nano))
	return p, nil
}

func (s *Store) IsMember(ctx context.Context, chatID, username string) (bool, error) {
	var count int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM chat_members WHERE chat_id=? AND username=?`, chatID, username).Scan(&count)
	return count == 1, err
}

func (s *Store) ListChats(ctx context.Context, username string) ([]Chat, error) {
	chatRows, err := s.DB.QueryContext(ctx, `
		SELECT c.id,c.kind,c.title,COALESCE(MAX(m.sequence),0),MAX(m.created_at),
			COALESCE(MAX(CASE WHEN m.id=p.message_id THEN p.message_id ELSE '' END),''),
			(
				SELECT COUNT(*) FROM messages unread
				WHERE unread.chat_id=c.id AND unread.deleted_at IS NULL
					AND unread.sender_username<>?
					AND unread.sequence > COALESCE((
						SELECT cursor.max_read_sequence FROM chat_read_cursors cursor
						WHERE cursor.chat_id=c.id AND cursor.username=?
					), 0)
					AND NOT EXISTS (
						SELECT 1 FROM message_user_deletions hidden
						WHERE hidden.message_id=unread.id AND hidden.username=?
					)
			)
		FROM chats c
		JOIN chat_members me ON me.chat_id=c.id
		LEFT JOIN messages m ON m.chat_id=c.id AND m.deleted_at IS NULL
			AND NOT EXISTS (
				SELECT 1 FROM message_user_deletions mud
				WHERE mud.message_id=m.id AND mud.username=?
			)
		LEFT JOIN pinned_messages p ON p.chat_id=c.id
		WHERE me.username=?
		GROUP BY c.id,c.kind,c.title
		ORDER BY COALESCE(MAX(m.sequence),0) DESC,
			CASE c.kind WHEN 'favorites' THEN 0 WHEN 'family' THEN 1 ELSE 2 END,
			c.title`, username, username, username, username, username)
	if err != nil {
		return nil, err
	}

	result := make([]Chat, 0, 6)
	chatIndex := make(map[string]int, 6)
	for chatRows.Next() {
		var c Chat
		var last sql.NullString
		if err := chatRows.Scan(
			&c.ID, &c.Kind, &c.Title, &c.LastSequence, &last, &c.PinnedMessageID, &c.UnreadCount,
		); err != nil {
			_ = chatRows.Close()
			return nil, err
		}
		if last.Valid {
			t, parseErr := time.Parse(time.RFC3339Nano, last.String)
			if parseErr == nil {
				c.LastMessageAt = &t
			}
		}
		chatIndex[c.ID] = len(result)
		result = append(result, c)
	}
	if err := chatRows.Err(); err != nil {
		_ = chatRows.Close()
		return nil, err
	}
	if err := chatRows.Close(); err != nil {
		return nil, err
	}

	memberRows, err := s.DB.QueryContext(ctx, `
		SELECT member.chat_id,member.username
		FROM chat_members member
		JOIN chat_members visible
			ON visible.chat_id=member.chat_id AND visible.username=?
		ORDER BY member.chat_id,member.username`, username)
	if err != nil {
		return nil, err
	}
	defer memberRows.Close()
	for memberRows.Next() {
		var chatID, member string
		if err := memberRows.Scan(&chatID, &member); err != nil {
			return nil, err
		}
		if index, ok := chatIndex[chatID]; ok {
			result[index].Members = append(result[index].Members, member)
		}
	}
	if err := memberRows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) ListDevices(ctx context.Context, chatID string) ([]Device, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT d.id,d.username,d.key_algorithm,d.public_key_spki,COALESCE(k.algorithm,''),k.public_key_spki,COALESCE(r.bundle_version,0)
		FROM provisioning_devices d
		JOIN chat_members cm ON cm.username=d.username
		LEFT JOIN device_encryption_keys k ON k.device_id=d.id
		LEFT JOIN ratchet_device_bundles r ON r.device_id=d.id AND r.revoked_at IS NULL
		WHERE cm.chat_id=? AND d.revoked_at IS NULL AND d.security_state='READY'
		ORDER BY d.username,d.bound_at`, chatID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Device, 0)
	for rows.Next() {
		var d Device
		var identitySPKI, encryptionSPKI []byte
		if err := rows.Scan(&d.ID, &d.Username, &d.IdentityAlgorithm, &identitySPKI, &d.EncryptionAlgorithm, &encryptionSPKI, &d.RatchetBundleVersion); err != nil {
			return nil, err
		}
		d.IdentityPublicKeySPKI = base64.StdEncoding.EncodeToString(identitySPKI)
		if len(encryptionSPKI) > 0 {
			d.EncryptionPublicKeySPKI = base64.StdEncoding.EncodeToString(encryptionSPKI)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) RegisterEncryptionKey(ctx context.Context, principal Principal, algorithm string, publicKey []byte, now time.Time) error {
	if algorithm != "rsa-oaep-sha256" || len(publicKey) < 256 || len(publicKey) > 1024 {
		return errors.New("invalid encryption key")
	}
	fingerprint := sha256.Sum256(publicKey)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var owner string
	var revoked sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT username, revoked_at FROM provisioning_devices WHERE id = ?
	`, principal.DeviceID).Scan(&owner, &revoked); err != nil || owner != principal.Username || revoked.Valid {
		return errors.New("invalid device")
	}

	var existingAlgorithm string
	var existingPublicKey []byte
	err = tx.QueryRowContext(ctx, `
		SELECT algorithm, public_key_spki FROM device_encryption_keys WHERE device_id = ?
	`, principal.DeviceID).Scan(&existingAlgorithm, &existingPublicKey)
	switch {
	case err == nil:
		if existingAlgorithm != algorithm || !bytes.Equal(existingPublicKey, publicKey) {
			return errors.New("encryption key replacement requires a new QR")
		}
		return tx.Commit()
	case errors.Is(err, sql.ErrNoRows):
		// Legacy devices created before QR-bound encryption keys are allowed to
		// register once. If the same key was bound to a previous device for this
		// username, inherit its envelopes without decrypting them server-side.
	case err != nil:
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO message_envelopes(message_id, device_id, algorithm, ciphertext)
		SELECT envelope.message_id, ?, envelope.algorithm, envelope.ciphertext
		FROM message_envelopes envelope
		JOIN device_encryption_keys old_key ON old_key.device_id = envelope.device_id
		JOIN provisioning_devices old_device ON old_device.id = envelope.device_id
		WHERE old_device.username = ?
			AND old_key.fingerprint = ?
			AND envelope.device_id <> ?
		ON CONFLICT(message_id, device_id) DO NOTHING
	`, principal.DeviceID, principal.Username, fingerprint[:], principal.DeviceID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM device_encryption_keys
		WHERE fingerprint = ? AND device_id <> ? AND device_id IN (
			SELECT id FROM provisioning_devices WHERE username = ?
		)
	`, fingerprint[:], principal.DeviceID, principal.Username); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO device_encryption_keys(device_id,algorithm,public_key_spki,fingerprint,registered_at)
		VALUES(?,?,?,?,?)
	`, principal.DeviceID, algorithm, publicKey, fingerprint[:], now.UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ReserveCryptoSequence(ctx context.Context, chatID string, principal Principal, requestID, messageID string, now time.Time) (int64, bool, error) {
	if chatID == "" || !ValidateUUID(messageID) || len(requestID) < 16 || len(requestID) > 128 {
		return 0, false, errors.New("invalid sequence reservation")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	var owner, state string
	var revoked sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT username,security_state,revoked_at FROM provisioning_devices WHERE id=?`, principal.DeviceID).Scan(&owner, &state, &revoked); err != nil || owner != principal.Username || revoked.Valid || state != "READY" {
		return 0, false, errors.New("invalid device")
	}
	var member int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM chat_members WHERE chat_id=? AND username=?`, chatID, principal.Username).Scan(&member); err != nil || member != 1 {
		return 0, false, errors.New("not a chat member")
	}
	var existing int64
	var existingMessage, existingChat, existingDevice string
	err = tx.QueryRowContext(ctx, `SELECT crypto_sequence,message_id,chat_id,sender_device_id FROM message_sequence_reservations WHERE request_id=?`, requestID).Scan(&existing, &existingMessage, &existingChat, &existingDevice)
	if err == nil {
		if existingMessage != messageID || existingChat != chatID || existingDevice != principal.DeviceID {
			return 0, false, errors.New("reservation replay conflict")
		}
		return existing, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, false, err
	}
	var next int64
	err = tx.QueryRowContext(ctx, `SELECT next_sequence FROM room_device_sequence_state WHERE chat_id=? AND device_id=?`, chatID, principal.DeviceID).Scan(&next)
	if errors.Is(err, sql.ErrNoRows) {
		next = 1
		if _, err := tx.ExecContext(ctx, `INSERT INTO room_device_sequence_state(chat_id,device_id,next_sequence,updated_at) VALUES(?,?,?,?)`, chatID, principal.DeviceID, int64(2), now.UTC().Format(time.RFC3339Nano)); err != nil {
			return 0, false, err
		}
	} else if err != nil {
		return 0, false, err
	} else {
		if _, err := tx.ExecContext(ctx, `UPDATE room_device_sequence_state SET next_sequence=?,updated_at=? WHERE chat_id=? AND device_id=?`, next+1, now.UTC().Format(time.RFC3339Nano), chatID, principal.DeviceID); err != nil {
			return 0, false, err
		}
	}
	created := now.UTC()
	if _, err := tx.ExecContext(ctx, `INSERT INTO message_sequence_reservations(request_id,message_id,chat_id,sender_device_id,crypto_sequence,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`, requestID, messageID, chatID, principal.DeviceID, next, created.Format(time.RFC3339Nano), created.Add(10*time.Minute).Format(time.RFC3339Nano)); err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return next, false, nil
}

func (s *Store) CreateMessage(ctx context.Context, input NewMessage, now time.Time) (Message, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Message{}, err
	}
	defer tx.Rollback()
	var owner, securityState string
	var revoked sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT username,security_state,revoked_at FROM provisioning_devices WHERE id=?`, input.Sender.DeviceID).Scan(&owner, &securityState, &revoked); err != nil || owner != input.Sender.Username || revoked.Valid || securityState != "READY" {
		return Message{}, errors.New("invalid device")
	}
	// Legacy callers created before crypto_version was explicit leave the field at
	// its Go zero value. Normalize that representation to protocol v1 before
	// enforcing the account downgrade floor. Negative values are always invalid.
	if input.CryptoVersion == 0 {
		input.CryptoVersion = 1
	}
	if input.CryptoVersion < 1 {
		return Message{}, errors.New("invalid crypto version")
	}
	var minimumCryptoVersion int
	if err := tx.QueryRowContext(ctx, `SELECT minimum_crypto_version FROM account_security_state WHERE username=?`, input.Sender.Username).Scan(&minimumCryptoVersion); err != nil {
		return Message{}, err
	}
	if input.CryptoVersion < minimumCryptoVersion {
		return Message{}, errors.New("crypto downgrade rejected")
	}
	if input.CryptoVersion == 1 {
		input.RoomKeyVersion = 1
		input.AADVersion = 1
		input.EncryptionAlgorithm = "fedmes-aes256gcm-rsa-oaep-v1"
		if err := validateEnvelopeSetTx(ctx, tx, input.ChatID, input.Sender.DeviceID, input.Envelopes); err != nil {
			return Message{}, err
		}
	} else {
		if input.CryptoVersion != 2 || input.AADVersion != 2 || input.RoomKeyVersion <= 0 || input.CryptoSequence <= 0 || len(input.SequenceRequestID) < 16 || len(input.SequenceRequestID) > 128 || len(input.MessageType) == 0 || len(input.MessageType) > 64 {
			return Message{}, errors.New("invalid crypto v2 metadata")
		}
		var reservedMessage, reservedChat, reservedDevice, expires string
		var consumed sql.NullString
		var reservedSequence int64
		if err := tx.QueryRowContext(ctx, `SELECT message_id,chat_id,sender_device_id,crypto_sequence,expires_at,consumed_at FROM message_sequence_reservations WHERE request_id=?`, input.SequenceRequestID).Scan(&reservedMessage, &reservedChat, &reservedDevice, &reservedSequence, &expires, &consumed); err != nil {
			return Message{}, errors.New("sequence reservation not found")
		}
		expiresAt, _ := time.Parse(time.RFC3339Nano, expires)
		if consumed.Valid || !now.UTC().Before(expiresAt) || reservedMessage != input.ID || reservedChat != input.ChatID || reservedDevice != input.Sender.DeviceID || reservedSequence != input.CryptoSequence {
			return Message{}, errors.New("sequence reservation invalid")
		}
		expectedAAD := CanonicalMessageAADV2(input.ChatID, input.Sender.Username, input.Sender.DeviceID, input.ID, input.MessageType, input.CryptoSequence, input.RoomKeyVersion)
		if input.AAD != expectedAAD {
			return Message{}, errors.New("aad mismatch")
		}
		var chatKind string
		if err := tx.QueryRowContext(ctx, `SELECT kind FROM chats WHERE id=?`, input.ChatID).Scan(&chatKind); err != nil {
			return Message{}, err
		}
		switch chatKind {
		case "family":
			if input.EncryptionAlgorithm != "fedmes-megolm-v1" || len(input.RatchetEnvelopes) != 0 {
				return Message{}, errors.New("family room requires Megolm")
			}
			var count int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM megolm_group_sessions WHERE chat_id=? AND room_key_version=? AND retired_at IS NULL`, input.ChatID, input.RoomKeyVersion).Scan(&count); err != nil || count != 1 {
				return Message{}, errors.New("group key not active")
			}
		case "direct", "favorites":
			if input.EncryptionAlgorithm != "fedmes-olm-v1" || len(input.RatchetEnvelopes) == 0 {
				return Message{}, errors.New("direct room requires Olm envelopes")
			}
			if err := validateRatchetEnvelopeSetTx(ctx, tx, input.ChatID, input.RatchetEnvelopes); err != nil {
				return Message{}, err
			}
		default:
			return Message{}, errors.New("unsupported chat kind")
		}
	}
	cipherHash := sha256.Sum256(input.Ciphertext)
	res, err := tx.ExecContext(ctx, `
		INSERT INTO messages(id,chat_id,sender_username,sender_device_id,ciphertext,nonce,aad,created_at,crypto_version,room_key_version,aad_version,encryption_algorithm,ciphertext_sha256,crypto_sequence)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		input.ID, input.ChatID, input.Sender.Username, input.Sender.DeviceID,
		input.Ciphertext, input.Nonce, input.AAD, now.UTC().Format(time.RFC3339Nano), input.CryptoVersion,
		input.RoomKeyVersion, input.AADVersion, input.EncryptionAlgorithm, cipherHash[:], input.CryptoSequence)
	if err != nil {
		return Message{}, err
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return Message{}, err
	}
	for _, e := range input.Envelopes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO message_envelopes(message_id,device_id,algorithm,ciphertext) VALUES(?,?,?,?)`, input.ID, e.DeviceID, e.Algorithm, e.Ciphertext); err != nil {
			return Message{}, err
		}
	}
	for _, e := range input.RatchetEnvelopes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ratchet_message_envelopes(message_id,recipient_device_id,sender_curve25519_key,session_id,message_type,ciphertext,ciphertext_sha256,created_at) VALUES(?,?,?,?,?,?,?,?)`, input.ID, e.RecipientDeviceID, e.SenderCurve25519Key, e.SessionID, e.MessageType, e.Ciphertext, e.CiphertextSHA256[:], now.UTC().Format(time.RFC3339Nano)); err != nil {
			return Message{}, err
		}
	}
	if input.CryptoVersion >= 2 {
		result, err := tx.ExecContext(ctx, `UPDATE message_sequence_reservations SET consumed_at=? WHERE request_id=? AND consumed_at IS NULL`, now.UTC().Format(time.RFC3339Nano), input.SequenceRequestID)
		if err != nil {
			return Message{}, err
		}
		rows, _ := result.RowsAffected()
		if rows != 1 {
			return Message{}, errors.New("sequence reservation already consumed")
		}
	}
	if err := tx.Commit(); err != nil {
		return Message{}, err
	}
	return Message{
		Sequence: seq, ID: input.ID, ChatID: input.ChatID,
		SenderUsername: input.Sender.Username, SenderDeviceID: input.Sender.DeviceID,
		CiphertextBase64: base64.StdEncoding.EncodeToString(input.Ciphertext),
		NonceBase64:      base64.StdEncoding.EncodeToString(input.Nonce), AAD: input.AAD,
		CryptoVersion: input.CryptoVersion, RoomKeyVersion: input.RoomKeyVersion, AADVersion: input.AADVersion,
		CryptoSequence: input.CryptoSequence, EncryptionAlgorithm: input.EncryptionAlgorithm, MessageType: input.MessageType,
		CreatedAt: now.UTC(), EnvelopeDeviceIDs: envelopeIDs(input.Envelopes),
	}, nil
}

func validateRatchetEnvelopeSetTx(ctx context.Context, tx *sql.Tx, chatID string, envelopes []DecodedRatchetEnvelope) error {
	seen := make(map[string]struct{}, len(envelopes))
	for _, envelope := range envelopes {
		if envelope.RecipientDeviceID == "" || len(envelope.SenderCurve25519Key) < 32 || len(envelope.SenderCurve25519Key) > 128 || len(envelope.SessionID) < 16 || len(envelope.SessionID) > 256 || (envelope.MessageType != 0 && envelope.MessageType != 1) || len(envelope.Ciphertext) < 16 || len(envelope.Ciphertext) > 1<<20 || sha256.Sum256(envelope.Ciphertext) != envelope.CiphertextSHA256 {
			return errors.New("invalid ratchet envelope")
		}
		if _, exists := seen[envelope.RecipientDeviceID]; exists {
			return errors.New("duplicate ratchet envelope")
		}
		seen[envelope.RecipientDeviceID] = struct{}{}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM provisioning_devices d JOIN chat_members m ON m.username=d.username JOIN ratchet_device_bundles b ON b.device_id=d.id AND b.revoked_at IS NULL WHERE d.id=? AND m.chat_id=? AND d.revoked_at IS NULL AND d.security_state='READY'`, envelope.RecipientDeviceID, chatID).Scan(&count); err != nil || count != 1 {
			return errors.New("invalid ratchet recipient")
		}
	}
	var expected int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM provisioning_devices d JOIN chat_members m ON m.username=d.username JOIN ratchet_device_bundles b ON b.device_id=d.id AND b.revoked_at IS NULL WHERE m.chat_id=? AND d.revoked_at IS NULL AND d.security_state='READY'`, chatID).Scan(&expected); err != nil {
		return err
	}
	if len(seen) != expected {
		return errors.New("ratchet envelopes must cover every ready device")
	}
	return nil
}

func (s *Store) ListMessages(
	ctx context.Context,
	chatID, username, deviceID string,
	after, before int64,
	limit int,
) (MessagePage, error) {
	return s.listMessages(ctx, chatID, username, deviceID, after, before, limit, false)
}

func (s *Store) ListOwnedMessagesForEnvelopeRepair(
	ctx context.Context,
	chatID, username, deviceID string,
	before int64,
	limit int,
) (MessagePage, error) {
	// Kept for source compatibility. Multi-device linking needs every message
	// that the approving device can decrypt, not only messages it sent.
	return s.ListMessagesForEnvelopeRepair(ctx, chatID, username, deviceID, before, limit)
}

func (s *Store) ListMessagesForEnvelopeRepair(
	ctx context.Context,
	chatID, username, deviceID string,
	before int64,
	limit int,
) (MessagePage, error) {
	return s.listMessages(ctx, chatID, username, deviceID, 0, before, limit, true)
}

func (s *Store) listMessages(
	ctx context.Context,
	chatID, username, deviceID string,
	after, before int64,
	limit int,
	ownedRepair bool,
) (MessagePage, error) {
	query := `
		SELECT m.sequence,m.id,m.chat_id,m.sender_username,m.sender_device_id,
			m.ciphertext,m.nonce,m.aad,m.crypto_version,m.room_key_version,m.aad_version,m.crypto_sequence,m.encryption_algorithm,m.created_at,m.edited_at,
			e.device_id,e.algorithm,e.ciphertext,
			r.recipient_device_id,r.sender_curve25519_key,r.session_id,r.message_type,r.ciphertext,r.ciphertext_sha256,
			COALESCE((SELECT group_concat(all_env.device_id, ',') FROM message_envelopes all_env WHERE all_env.message_id=m.id),''),
			(SELECT COUNT(*) FROM chat_members cm WHERE cm.chat_id=m.chat_id AND cm.username<>m.sender_username),
			(SELECT COUNT(*) FROM chat_read_cursors crc WHERE crc.chat_id=m.chat_id AND crc.username<>m.sender_username AND crc.max_read_sequence>=m.sequence),
			(SELECT COUNT(*) FROM chat_read_cursors crc WHERE crc.chat_id=m.chat_id AND crc.username<>m.sender_username AND crc.max_read_sequence>=m.sequence)
		FROM messages m
		LEFT JOIN message_envelopes e ON e.message_id=m.id AND e.device_id=?
		LEFT JOIN ratchet_message_envelopes r ON r.message_id=m.id AND r.recipient_device_id=?
		WHERE m.chat_id=? AND m.deleted_at IS NULL`
	args := []any{deviceID, deviceID, chatID}
	if ownedRepair {
		query += ` AND e.device_id IS NOT NULL
			AND NOT EXISTS (
				SELECT 1 FROM message_user_deletions mud
				WHERE mud.message_id=m.id AND mud.username=?
			)`
		args = append(args, username)
	} else {
		query += ` AND NOT EXISTS (
			SELECT 1 FROM message_user_deletions mud
			WHERE mud.message_id=m.id AND mud.username=?
		)`
		args = append(args, username)
	}

	switch {
	case after > 0:
		query += ` AND m.sequence>? ORDER BY m.sequence ASC LIMIT ?`
		args = append(args, after, limit)
	case before > 0:
		query += ` AND m.sequence<? ORDER BY m.sequence DESC LIMIT ?`
		args = append(args, before, limit)
	default:
		query += ` ORDER BY m.sequence DESC LIMIT ?`
		args = append(args, limit)
	}

	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return MessagePage{}, err
	}
	out := make([]Message, 0, limit)
	for rows.Next() {
		var m Message
		var cipher, nonce []byte
		var created string
		var edited sql.NullString
		var envDevice, envAlgorithm sql.NullString
		var ecipher []byte
		var ratchetRecipient, ratchetSenderKey, ratchetSession sql.NullString
		var ratchetType sql.NullInt64
		var ratchetCipher, ratchetHash []byte
		var allEnvelopeIDs string
		if err := rows.Scan(
			&m.Sequence, &m.ID, &m.ChatID, &m.SenderUsername, &m.SenderDeviceID,
			&cipher, &nonce, &m.AAD, &m.CryptoVersion, &m.RoomKeyVersion, &m.AADVersion, &m.CryptoSequence, &m.EncryptionAlgorithm, &created, &edited,
			&envDevice, &envAlgorithm, &ecipher,
			&ratchetRecipient, &ratchetSenderKey, &ratchetSession, &ratchetType, &ratchetCipher, &ratchetHash,
			&allEnvelopeIDs, &m.RecipientCount, &m.DeliveredCount, &m.ReadCount,
		); err != nil {
			_ = rows.Close()
			return MessagePage{}, err
		}
		m.CiphertextBase64 = base64.StdEncoding.EncodeToString(cipher)
		m.NonceBase64 = base64.StdEncoding.EncodeToString(nonce)
		m.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		if edited.Valid {
			t, _ := time.Parse(time.RFC3339Nano, edited.String)
			m.EditedAt = &t
		}
		if envDevice.Valid {
			m.Envelope = &Envelope{
				DeviceID: envDevice.String, Algorithm: envAlgorithm.String,
				CiphertextBase64: base64.StdEncoding.EncodeToString(ecipher),
			}
		}
		if ratchetRecipient.Valid {
			m.RatchetEnvelope = &RatchetEnvelope{
				RecipientDeviceID: ratchetRecipient.String, SenderCurve25519Key: ratchetSenderKey.String,
				SessionID: ratchetSession.String, MessageType: int(ratchetType.Int64),
				CiphertextBase64: base64.RawURLEncoding.EncodeToString(ratchetCipher),
				CiphertextSHA256: hex.EncodeToString(ratchetHash),
			}
		}
		if m.CryptoVersion >= 2 {
			m.MessageType = messageTypeFromAAD(m.AAD)
		}
		if allEnvelopeIDs != "" {
			m.EnvelopeDeviceIDs = strings.Split(allEnvelopeIDs, ",")
		} else {
			m.EnvelopeDeviceIDs = make([]string, 0)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return MessagePage{}, err
	}
	if err := rows.Close(); err != nil {
		return MessagePage{}, err
	}
	if before > 0 || after == 0 {
		reverseMessages(out)
	}

	hasMore := false
	if len(out) > 0 {
		oldest := out[0].Sequence
		moreQuery := `SELECT EXISTS(
			SELECT 1 FROM messages m
			WHERE m.chat_id=? AND m.sequence<? AND m.deleted_at IS NULL`
		moreArgs := []any{chatID, oldest}
		if ownedRepair {
			moreQuery += ` AND EXISTS (
				SELECT 1 FROM message_envelopes repair_env
				WHERE repair_env.message_id=m.id AND repair_env.device_id=?
			) AND NOT EXISTS (
				SELECT 1 FROM message_user_deletions mud
				WHERE mud.message_id=m.id AND mud.username=?
			)`
			moreArgs = append(moreArgs, deviceID, username)
		} else {
			moreQuery += ` AND NOT EXISTS (
				SELECT 1 FROM message_user_deletions mud
				WHERE mud.message_id=m.id AND mud.username=?
			)`
			moreArgs = append(moreArgs, username)
		}
		moreQuery += `)`
		if err := s.DB.QueryRowContext(ctx, moreQuery, moreArgs...).Scan(&hasMore); err != nil {
			return MessagePage{}, err
		}
	}
	return MessagePage{Messages: out, HasMoreBefore: hasMore}, nil
}

func (s *Store) UpdateMessage(ctx context.Context, input NewMessage, now time.Time) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var sender string
	var currentCrypto int
	if err := tx.QueryRowContext(ctx, `SELECT sender_username,crypto_version FROM messages WHERE id=? AND chat_id=? AND deleted_at IS NULL`, input.ID, input.ChatID).Scan(&sender, &currentCrypto); err != nil {
		return err
	}
	if sender != input.Sender.Username {
		return errors.New("not message owner")
	}
	if currentCrypto <= 1 {
		if input.CryptoVersion != 1 || input.AADVersion != 1 || input.RoomKeyVersion != 1 {
			return errors.New("legacy message metadata is immutable")
		}
		if err := validateEnvelopeSetTx(ctx, tx, input.ChatID, input.Sender.DeviceID, input.Envelopes); err != nil {
			return err
		}
	} else {
		if input.CryptoVersion != 2 || input.AADVersion != 2 || input.RoomKeyVersion <= 0 || input.CryptoSequence <= 0 || len(input.SequenceRequestID) < 16 || len(input.SequenceRequestID) > 128 {
			return errors.New("invalid crypto v2 edit metadata")
		}
		var reservedMessage, reservedChat, reservedDevice, expires string
		var reservedSequence int64
		var consumed sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT message_id,chat_id,sender_device_id,crypto_sequence,expires_at,consumed_at FROM message_sequence_reservations WHERE request_id=?`, input.SequenceRequestID).Scan(&reservedMessage, &reservedChat, &reservedDevice, &reservedSequence, &expires, &consumed); err != nil {
			return errors.New("sequence reservation not found")
		}
		expiresAt, parseErr := time.Parse(time.RFC3339Nano, expires)
		if parseErr != nil || consumed.Valid || !now.UTC().Before(expiresAt) || reservedMessage != input.ID || reservedChat != input.ChatID || reservedDevice != input.Sender.DeviceID || reservedSequence != input.CryptoSequence {
			return errors.New("sequence reservation invalid")
		}
		expectedAAD := CanonicalMessageAADV2(input.ChatID, input.Sender.Username, input.Sender.DeviceID, input.ID, input.MessageType, input.CryptoSequence, input.RoomKeyVersion)
		if input.AAD != expectedAAD {
			return errors.New("aad mismatch")
		}
		var kind string
		if err := tx.QueryRowContext(ctx, `SELECT kind FROM chats WHERE id=?`, input.ChatID).Scan(&kind); err != nil {
			return err
		}
		if kind == "family" {
			if input.EncryptionAlgorithm != "fedmes-megolm-v1" || len(input.RatchetEnvelopes) != 0 {
				return errors.New("invalid group edit")
			}
			var active int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM megolm_group_sessions WHERE chat_id=? AND room_key_version=? AND retired_at IS NULL`, input.ChatID, input.RoomKeyVersion).Scan(&active); err != nil || active != 1 {
				return errors.New("group key not active")
			}
		} else {
			if input.EncryptionAlgorithm != "fedmes-olm-v1" {
				return errors.New("invalid direct edit")
			}
			if err := validateRatchetEnvelopeSetTx(ctx, tx, input.ChatID, input.RatchetEnvelopes); err != nil {
				return err
			}
		}
	}
	hash := sha256.Sum256(input.Ciphertext)
	if _, err := tx.ExecContext(ctx, `UPDATE messages SET sender_device_id=?,ciphertext=?,nonce=?,aad=?,edited_at=?,crypto_version=?,room_key_version=?,aad_version=?,crypto_sequence=?,encryption_algorithm=?,ciphertext_sha256=? WHERE id=?`, input.Sender.DeviceID, input.Ciphertext, input.Nonce, input.AAD, now.UTC().Format(time.RFC3339Nano), input.CryptoVersion, input.RoomKeyVersion, input.AADVersion, input.CryptoSequence, input.EncryptionAlgorithm, hash[:], input.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM message_envelopes WHERE message_id=?`, input.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ratchet_message_envelopes WHERE message_id=?`, input.ID); err != nil {
		return err
	}
	for _, e := range input.Envelopes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO message_envelopes(message_id,device_id,algorithm,ciphertext) VALUES(?,?,?,?)`, input.ID, e.DeviceID, e.Algorithm, e.Ciphertext); err != nil {
			return err
		}
	}
	for _, e := range input.RatchetEnvelopes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ratchet_message_envelopes(message_id,recipient_device_id,sender_curve25519_key,session_id,message_type,ciphertext,ciphertext_sha256,created_at) VALUES(?,?,?,?,?,?,?,?)`, input.ID, e.RecipientDeviceID, e.SenderCurve25519Key, e.SessionID, e.MessageType, e.Ciphertext, e.CiphertextSHA256[:], now.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	if input.CryptoVersion >= 2 {
		result, err := tx.ExecContext(ctx, `UPDATE message_sequence_reservations SET consumed_at=? WHERE request_id=? AND consumed_at IS NULL`, now.UTC().Format(time.RFC3339Nano), input.SequenceRequestID)
		if err != nil {
			return err
		}
		if rows, _ := result.RowsAffected(); rows != 1 {
			return errors.New("sequence reservation already consumed")
		}
	}
	return tx.Commit()
}

func (s *Store) AddMessageEnvelopes(
	ctx context.Context,
	chatID, messageID string,
	principal Principal,
	envelopes []DecodedEnvelope,
) error {
	if len(envelopes) == 0 {
		return nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var sender string
	if err := tx.QueryRowContext(ctx, `
		SELECT sender_username FROM messages
		WHERE id=? AND chat_id=? AND deleted_at IS NULL`, messageID, chatID).Scan(&sender); err != nil {
		return err
	}
	if err := validateEnvelopeTargetsTx(ctx, tx, chatID, envelopes); err != nil {
		return err
	}
	if sender != principal.Username {
		// A device may transfer a decryptable message key only to another
		// active device of the same account. This enables phone-approved
		// desktop history without allowing one family member to expand the
		// recipient set for another family member.
		for _, envelope := range envelopes {
			var targetUsername string
			var revoked sql.NullString
			if err := tx.QueryRowContext(ctx, `
				SELECT username,revoked_at FROM provisioning_devices WHERE id=?`,
				envelope.DeviceID).Scan(&targetUsername, &revoked); err != nil ||
				targetUsername != principal.Username || revoked.Valid {
				return errors.New("envelope target is not owned by principal")
			}
		}
	}
	for _, envelope := range envelopes {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO message_envelopes(message_id,device_id,algorithm,ciphertext)
			VALUES(?,?,?,?)
			ON CONFLICT(message_id,device_id) DO NOTHING`,
			messageID, envelope.DeviceID, envelope.Algorithm, envelope.Ciphertext); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DeleteMessage(ctx context.Context, chatID, messageID, username, scope string, now time.Time) error {
	switch scope {
	case "me":
		res, err := s.DB.ExecContext(ctx, `
			INSERT INTO message_user_deletions(message_id,username,deleted_at)
			SELECT id,?,? FROM messages
			WHERE id=? AND chat_id=? AND deleted_at IS NULL
			ON CONFLICT(message_id,username) DO NOTHING`,
			username, now.UTC().Format(time.RFC3339Nano), messageID, chatID)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			var exists int
			if err := s.DB.QueryRowContext(ctx, `
				SELECT COUNT(*) FROM messages WHERE id=? AND chat_id=? AND deleted_at IS NULL`,
				messageID, chatID).Scan(&exists); err != nil || exists == 0 {
				return errors.New("message not found")
			}
		}
		return nil
	case "everyone":
		res, err := s.DB.ExecContext(ctx, `DELETE FROM messages WHERE id=? AND chat_id=?`, messageID, chatID)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return errors.New("message not found")
		}
		return nil
	default:
		return errors.New("invalid delete scope")
	}
}

func (s *Store) PinMessage(ctx context.Context, chatID, messageID, username string, now time.Time) error {
	var count int
	if err := s.DB.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM messages
		WHERE id=? AND chat_id=? AND deleted_at IS NULL`, messageID, chatID).Scan(&count); err != nil || count != 1 {
		return errors.New("message not found")
	}
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO pinned_messages(chat_id,message_id,pinned_by,pinned_at)
		VALUES(?,?,?,?)
		ON CONFLICT(chat_id) DO UPDATE SET
			message_id=excluded.message_id,
			pinned_by=excluded.pinned_by,
			pinned_at=excluded.pinned_at`,
		chatID, messageID, username, now.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) UnpinMessage(ctx context.Context, chatID string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM pinned_messages WHERE chat_id=?`, chatID)
	return err
}

func (s *Store) MarkReceipts(
	ctx context.Context,
	chatID, username string,
	deliveredIDs, readIDs []string,
	now time.Time,
) error {
	if len(deliveredIDs) > 200 || len(readIDs) > 200 {
		return errors.New("too many receipts")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	timestamp := now.UTC().Format(time.RFC3339Nano)
	if err := upsertReceipts(ctx, tx, chatID, username, deliveredIDs, false, timestamp); err != nil {
		return err
	}
	if err := upsertReceipts(ctx, tx, chatID, username, readIDs, true, timestamp); err != nil {
		return err
	}
	if len(readIDs) > 0 {
		var maxSequence int64
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(uniqueValidUUIDs(readIDs))), ",")
		if placeholders != "" {
			args := make([]any, 0, len(readIDs)+1)
			args = append(args, chatID)
			for _, id := range uniqueValidUUIDs(readIDs) {
				args = append(args, id)
			}
			query := `SELECT COALESCE(MAX(sequence),0) FROM messages WHERE chat_id=? AND id IN (` + placeholders + `)`
			if err := tx.QueryRowContext(ctx, query, args...).Scan(&maxSequence); err != nil {
				return err
			}
			if maxSequence > 0 {
				if err := upsertReadCursorTx(ctx, tx, chatID, username, maxSequence, timestamp); err != nil {
					return err
				}
			}
		}
	}
	return tx.Commit()
}

func upsertReceipts(
	ctx context.Context,
	tx *sql.Tx,
	chatID, username string,
	ids []string,
	read bool,
	timestamp string,
) error {
	for _, id := range uniqueValidUUIDs(ids) {
		if read {
			_, err := tx.ExecContext(ctx, `
				INSERT INTO message_receipts(message_id,username,delivered_at,read_at)
				SELECT id,?,?,? FROM messages
				WHERE id=? AND chat_id=? AND sender_username<>? AND deleted_at IS NULL
				ON CONFLICT(message_id,username) DO UPDATE SET
					delivered_at=COALESCE(message_receipts.delivered_at,excluded.delivered_at),
					read_at=COALESCE(message_receipts.read_at,excluded.read_at)`,
				username, timestamp, timestamp, id, chatID, username)
			if err != nil {
				return err
			}
		} else {
			_, err := tx.ExecContext(ctx, `
				INSERT INTO message_receipts(message_id,username,delivered_at,read_at)
				SELECT id,?,?,NULL FROM messages
				WHERE id=? AND chat_id=? AND sender_username<>? AND deleted_at IS NULL
				ON CONFLICT(message_id,username) DO UPDATE SET
					delivered_at=COALESCE(message_receipts.delivered_at,excluded.delivered_at)`,
				username, timestamp, id, chatID, username)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// MarkReadCursor monotonically advances the caller's read high-water mark.
// The requested sequence is clamped to an existing message in this chat.
func (s *Store) MarkReadCursor(
	ctx context.Context,
	chatID, username string,
	requestedSequence int64,
	now time.Time,
) (int64, error) {
	if requestedSequence <= 0 {
		return 0, errors.New("invalid read cursor")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var memberCount int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM chat_members WHERE chat_id=? AND username=?`,
		chatID, username,
	).Scan(&memberCount); err != nil {
		return 0, err
	}
	if memberCount != 1 {
		return 0, errors.New("not a chat member")
	}
	var clamped int64
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(sequence),0)
		FROM messages
		WHERE chat_id=? AND sequence<=? AND deleted_at IS NULL`,
		chatID, requestedSequence,
	).Scan(&clamped); err != nil {
		return 0, err
	}
	if clamped == 0 {
		return 0, errors.New("read cursor message not found")
	}
	if err := upsertReadCursorTx(
		ctx, tx, chatID, username, clamped, now.UTC().Format(time.RFC3339Nano),
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return clamped, nil
}

func upsertReadCursorTx(
	ctx context.Context,
	tx *sql.Tx,
	chatID, username string,
	sequence int64,
	timestamp string,
) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO chat_read_cursors(chat_id,username,max_read_sequence,updated_at)
		VALUES(?,?,?,?)
		ON CONFLICT(chat_id,username) DO UPDATE SET
			max_read_sequence=CASE
				WHEN excluded.max_read_sequence>chat_read_cursors.max_read_sequence
				THEN excluded.max_read_sequence
				ELSE chat_read_cursors.max_read_sequence
			END,
			updated_at=CASE
				WHEN excluded.max_read_sequence>chat_read_cursors.max_read_sequence
				THEN excluded.updated_at
				ELSE chat_read_cursors.updated_at
			END`,
		chatID, username, sequence, timestamp,
	)
	return err
}

func (s *Store) SetTyping(ctx context.Context, chatID, username string, typing bool, now time.Time) error {
	if !typing {
		_, err := s.DB.ExecContext(ctx, `DELETE FROM typing_state WHERE chat_id=? AND username=?`, chatID, username)
		return err
	}
	expires := now.Add(6 * time.Second).UTC().Format(time.RFC3339Nano)
	updated := now.UTC().Format(time.RFC3339Nano)
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO typing_state(chat_id,username,expires_at,updated_at)
		VALUES(?,?,?,?)
		ON CONFLICT(chat_id,username) DO UPDATE SET
			expires_at=excluded.expires_at,
			updated_at=excluded.updated_at`, chatID, username, expires, updated)
	return err
}

func (s *Store) ListTyping(ctx context.Context, chatID, viewer string, now time.Time) ([]TypingUser, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT username FROM typing_state
		WHERE chat_id=? AND username<>? AND expires_at>?
		ORDER BY username`, chatID, viewer, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TypingUser, 0, 4)
	for rows.Next() {
		var item TypingUser
		if err := rows.Scan(&item.Username); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) Heartbeat(ctx context.Context, username string, showExact bool, now time.Time) error {
	exact := 0
	if showExact {
		exact = 1
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE presence SET last_seen_at=?,show_exact=?,updated_at=? WHERE username=?`,
		now.UTC().Format(time.RFC3339Nano), exact,
		now.UTC().Format(time.RFC3339Nano), username)
	return err
}

func (s *Store) ListPresence(ctx context.Context, viewer string, now time.Time) ([]Presence, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT username,last_seen_at,show_exact FROM presence ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Presence, 0, 5)
	for rows.Next() {
		var p Presence
		var last sql.NullString
		var exact int
		if err := rows.Scan(&p.Username, &last, &exact); err != nil {
			return nil, err
		}
		p.ShowExact = exact == 1
		p.LastSeenCategory = "long_ago"
		if last.Valid {
			t, parseErr := time.Parse(time.RFC3339Nano, last.String)
			if parseErr == nil {
				p.Online = now.Sub(t) <= 45*time.Second
				p.LastSeenCategory = presenceCategory(now, t)
				if p.ShowExact || p.Username == viewer {
					p.LastSeen = &t
				}
			}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func presenceCategory(now, last time.Time) string {
	if now.Sub(last) <= 45*time.Second {
		return "online"
	}
	nowLocal := now.Local()
	lastLocal := last.In(nowLocal.Location())
	nowDate := time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day(), 0, 0, 0, 0, nowLocal.Location())
	lastDate := time.Date(lastLocal.Year(), lastLocal.Month(), lastLocal.Day(), 0, 0, 0, 0, lastLocal.Location())
	days := int(nowDate.Sub(lastDate) / (24 * time.Hour))
	switch {
	case days <= 0:
		return "today"
	case days == 1:
		return "yesterday"
	case days <= 7:
		return "week"
	case nowLocal.Year() == lastLocal.Year() && nowLocal.Month() == lastLocal.Month():
		return "month"
	default:
		return "long_ago"
	}
}

func (s *Store) CreateMedia(ctx context.Context, m MediaObject) error {
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO media_objects(id,chat_id,uploader_username,uploader_device_id,blob_name,size_bytes,sha256_digest,created_at)
		VALUES(?,?,?,?,?,?,?,?)`, m.ID, m.ChatID, m.UploaderUsername, m.UploaderDeviceID,
		m.BlobName, m.SizeBytes, m.SHA256[:], m.CreatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) LoadMedia(ctx context.Context, id, chatID string) (MediaObject, error) {
	var m MediaObject
	var digest []byte
	var created string
	err := s.DB.QueryRowContext(ctx, `
		SELECT id,chat_id,uploader_username,uploader_device_id,blob_name,size_bytes,sha256_digest,created_at
		FROM media_objects WHERE id=? AND chat_id=? AND deleted_at IS NULL`, id, chatID).Scan(
		&m.ID, &m.ChatID, &m.UploaderUsername, &m.UploaderDeviceID,
		&m.BlobName, &m.SizeBytes, &digest, &created)
	if err != nil {
		return m, err
	}
	copy(m.SHA256[:], digest)
	m.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return m, nil
}

func (s *Store) DeleteMedia(ctx context.Context, id, chatID string) (MediaObject, error) {
	m, err := s.LoadMedia(ctx, id, chatID)
	if err != nil {
		return MediaObject{}, err
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM media_objects WHERE id=? AND chat_id=?`, id, chatID); err != nil {
		return MediaObject{}, err
	}
	return m, nil
}

func (s *Store) WaitForSequence(ctx context.Context, username string, after int64, wait time.Duration) (int64, error) {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	ticker := time.NewTicker(350 * time.Millisecond)
	defer ticker.Stop()
	for {
		var seq int64
		err := s.DB.QueryRowContext(ctx, `
			SELECT c.value FROM messaging_change_clock c
			WHERE c.id=1 AND EXISTS (SELECT 1 FROM chat_members WHERE username=?)`, username).Scan(&seq)
		if errors.Is(err, sql.ErrNoRows) {
			seq = 0
			err = nil
		}
		if err != nil {
			return 0, err
		}
		if seq > after {
			return seq, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-deadline.C:
			return seq, nil
		case <-ticker.C:
		}
	}
}

func validateEnvelopeSetTx(
	ctx context.Context,
	tx *sql.Tx,
	chatID, senderDeviceID string,
	envelopes []DecodedEnvelope,
) error {
	if len(envelopes) == 0 {
		return errors.New("message requires at least the sender envelope")
	}
	if err := validateEnvelopeTargetsTx(ctx, tx, chatID, envelopes); err != nil {
		return err
	}
	for _, envelope := range envelopes {
		if envelope.DeviceID == senderDeviceID {
			return nil
		}
	}
	return errors.New("message does not include the sender device envelope")
}

func validateEnvelopeTargetsTx(ctx context.Context, tx *sql.Tx, chatID string, envelopes []DecodedEnvelope) error {
	provided := make(map[string]struct{}, len(envelopes))
	for _, envelope := range envelopes {
		if envelope.Algorithm != "rsa-oaep-sha256" {
			return errors.New("unsupported envelope algorithm")
		}
		if _, duplicate := provided[envelope.DeviceID]; duplicate {
			return errors.New("duplicate envelope device")
		}
		provided[envelope.DeviceID] = struct{}{}
		var count int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM provisioning_devices d
			JOIN chat_members cm ON cm.username=d.username
			JOIN device_encryption_keys k ON k.device_id=d.id
			WHERE cm.chat_id=? AND d.id=? AND d.revoked_at IS NULL`,
			chatID, envelope.DeviceID).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return errors.New("envelope device is not an active encryption-ready chat member")
		}
	}
	return nil
}

func envelopeIDs(envelopes []DecodedEnvelope) []string {
	out := make([]string, 0, len(envelopes))
	for _, envelope := range envelopes {
		out = append(out, envelope.DeviceID)
	}
	return out
}

func reverseMessages(messages []Message) {
	for left, right := 0, len(messages)-1; left < right; left, right = left+1, right-1 {
		messages[left], messages[right] = messages[right], messages[left]
	}
}

func uniqueValidUUIDs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !ValidateUUID(value) {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func ValidateUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func messageTypeFromAAD(aad string) string {
	parts := strings.Split(aad, "\n")
	if len(parts) >= 6 && parts[0] == MessageProtocolVersionV2 {
		return parts[5]
	}
	return "legacy"
}
