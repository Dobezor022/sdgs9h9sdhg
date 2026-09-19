package ratchet

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type Store struct {
	db  *sql.DB
	now func() time.Time
}

func NewStore(db *sql.DB) *Store { return &Store{db: db, now: time.Now} }

func (s *Store) PutBundle(ctx context.Context, principal Principal, input BundleWrite) error {
	if input.BundleVersion < 1 || input.BundleVersion > 64 ||
		!validCurveKey(input.Curve25519IdentityKey) || !validCurveKey(input.Ed25519IdentityKey) ||
		len(input.SignedPayload) < 32 || len(input.SignedPayload) > 65536 || len(input.Signature) < 32 || len(input.Signature) > 2048 ||
		len(input.OneTimeKeys) > 100 {
		return ErrInvalid
	}
	if err := s.requireReady(ctx, principal); err != nil {
		return err
	}
	canonical := canonicalBundle(principal.DeviceID, input.BundleVersion, input.Curve25519IdentityKey, input.Ed25519IdentityKey)
	if string(input.SignedPayload) != string(canonical) || !s.verifyDeviceSignature(ctx, principal.DeviceID, canonical, input.Signature) {
		return ErrForbidden
	}
	seen := make(map[string]struct{}, len(input.OneTimeKeys))
	for _, key := range input.OneTimeKeys {
		if len(key.KeyID) < 1 || len(key.KeyID) > 128 || !validCurveKey(key.PublicKey) || len(key.Signature) < 32 || len(key.Signature) > 2048 {
			return ErrInvalid
		}
		if _, ok := seen[key.KeyID]; ok {
			return ErrInvalid
		}
		seen[key.KeyID] = struct{}{}
		if !s.verifyDeviceSignature(ctx, principal.DeviceID, canonicalOTK(principal.DeviceID, key.KeyID, key.PublicKey), key.Signature) {
			return ErrForbidden
		}
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO ratchet_device_bundles(device_id,username,bundle_version,curve25519_identity_key,ed25519_identity_key,signed_payload,signature,created_at,updated_at,revoked_at)
		VALUES(?,?,?,?,?,?,?,?,?,NULL)
		ON CONFLICT(device_id) DO UPDATE SET
			bundle_version=excluded.bundle_version,curve25519_identity_key=excluded.curve25519_identity_key,
			ed25519_identity_key=excluded.ed25519_identity_key,signed_payload=excluded.signed_payload,
			signature=excluded.signature,updated_at=excluded.updated_at,revoked_at=NULL`,
		principal.DeviceID, principal.Username, input.BundleVersion, input.Curve25519IdentityKey,
		input.Ed25519IdentityKey, input.SignedPayload, input.Signature, now, now)
	if err != nil {
		return mapConstraint(err)
	}
	for _, key := range input.OneTimeKeys {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO ratchet_one_time_keys(device_id,key_id,public_key,signature,created_at)
			VALUES(?,?,?,?,?) ON CONFLICT(device_id,key_id) DO NOTHING`,
			principal.DeviceID, key.KeyID, key.PublicKey, key.Signature, now)
		if err != nil {
			return mapConstraint(err)
		}
	}
	return tx.Commit()
}

func (s *Store) ClaimOneTimeKey(ctx context.Context, principal Principal, targetDeviceID string) (ClaimedKey, error) {
	if targetDeviceID == "" || targetDeviceID == principal.DeviceID {
		return ClaimedKey{}, ErrInvalid
	}
	if err := s.requireReady(ctx, principal); err != nil {
		return ClaimedKey{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ClaimedKey{}, err
	}
	defer tx.Rollback()
	var out ClaimedKey
	var created string
	err = tx.QueryRowContext(ctx, `
		SELECT b.device_id,b.username,b.bundle_version,b.curve25519_identity_key,b.ed25519_identity_key,
			b.signed_payload,b.signature,k.key_id,k.public_key,k.signature,k.created_at
		FROM ratchet_device_bundles b
		JOIN provisioning_devices d ON d.id=b.device_id
		JOIN ratchet_one_time_keys k ON k.device_id=b.device_id AND k.claimed_at IS NULL
		WHERE b.device_id=? AND b.revoked_at IS NULL AND d.revoked_at IS NULL AND d.security_state='READY'
			AND EXISTS (
				SELECT 1 FROM chat_members mine JOIN chat_members theirs ON theirs.chat_id=mine.chat_id
				WHERE mine.username=? AND theirs.username=b.username
			)
		ORDER BY k.created_at,k.key_id LIMIT 1`, targetDeviceID, principal.Username).Scan(
		&out.DeviceID, &out.Username, &out.BundleVersion, &out.Curve25519IdentityKey, &out.Ed25519IdentityKey,
		&out.SignedPayload, &out.BundleSignature, &out.OneTimeKey.KeyID, &out.OneTimeKey.PublicKey, &out.OneTimeKey.Signature, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return ClaimedKey{}, ErrNoKey
	}
	if err != nil {
		return ClaimedKey{}, err
	}
	now := s.now().UTC()
	result, err := tx.ExecContext(ctx, `UPDATE ratchet_one_time_keys SET claimed_at=?,claimed_by_device_id=? WHERE device_id=? AND key_id=? AND claimed_at IS NULL`,
		now.Format(time.RFC3339Nano), principal.DeviceID, targetDeviceID, out.OneTimeKey.KeyID)
	if err != nil {
		return ClaimedKey{}, err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return ClaimedKey{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return ClaimedKey{}, err
	}
	out.ClaimedAt = now
	return out, nil
}

func (s *Store) PutMessageEnvelopes(ctx context.Context, principal Principal, envelopes []MessageEnvelope) error {
	if len(envelopes) == 0 || len(envelopes) > 64 {
		return ErrInvalid
	}
	if err := s.requireReady(ctx, principal); err != nil {
		return err
	}
	messageID := envelopes[0].MessageID
	for _, envelope := range envelopes {
		if envelope.MessageID != messageID || envelope.RecipientDeviceID == "" || !validCurveKey(envelope.SenderCurve25519Key) ||
			len(envelope.SessionID) < 16 || len(envelope.SessionID) > 256 || (envelope.MessageType != 0 && envelope.MessageType != 1) ||
			len(envelope.Ciphertext) < 16 || len(envelope.Ciphertext) > 1<<20 || sha256.Sum256(envelope.Ciphertext) != envelope.CiphertextSHA256 {
			return ErrInvalid
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var chatID, senderDevice string
	if err := tx.QueryRowContext(ctx, `SELECT chat_id,sender_device_id FROM messages WHERE id=? AND deleted_at IS NULL`, messageID).Scan(&chatID, &senderDevice); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if senderDevice != principal.DeviceID {
		return ErrForbidden
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	seen := map[string]struct{}{}
	for _, envelope := range envelopes {
		if _, ok := seen[envelope.RecipientDeviceID]; ok {
			return ErrInvalid
		}
		seen[envelope.RecipientDeviceID] = struct{}{}
		var count int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM provisioning_devices d JOIN chat_members m ON m.username=d.username
			JOIN ratchet_device_bundles b ON b.device_id=d.id AND b.revoked_at IS NULL
			WHERE d.id=? AND m.chat_id=? AND d.revoked_at IS NULL AND d.security_state='READY'`, envelope.RecipientDeviceID, chatID).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return ErrForbidden
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO ratchet_message_envelopes(message_id,recipient_device_id,sender_curve25519_key,session_id,message_type,ciphertext,ciphertext_sha256,created_at)
			VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(message_id,recipient_device_id) DO NOTHING`,
			envelope.MessageID, envelope.RecipientDeviceID, envelope.SenderCurve25519Key, envelope.SessionID, envelope.MessageType, envelope.Ciphertext, envelope.CiphertextSHA256[:], now)
		if err != nil {
			return mapConstraint(err)
		}
	}
	return tx.Commit()
}

func (s *Store) ListPendingEnvelopes(ctx context.Context, principal Principal, afterSequence int64, limit int) ([]PendingEnvelope, error) {
	if afterSequence < 0 || limit < 1 || limit > 200 {
		return nil, ErrInvalid
	}
	if err := s.requireReady(ctx, principal); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.message_id,e.recipient_device_id,e.sender_curve25519_key,e.session_id,e.message_type,e.ciphertext,e.ciphertext_sha256,
			m.chat_id,m.sender_device_id,e.created_at
		FROM ratchet_message_envelopes e JOIN messages m ON m.id=e.message_id
		WHERE e.recipient_device_id=? AND m.sequence>? AND m.deleted_at IS NULL
		ORDER BY m.sequence LIMIT ?`, principal.DeviceID, afterSequence, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]PendingEnvelope, 0)
	for rows.Next() {
		var item PendingEnvelope
		var hash []byte
		var created string
		if err := rows.Scan(&item.MessageID, &item.RecipientDeviceID, &item.SenderCurve25519Key, &item.SessionID, &item.MessageType, &item.Ciphertext, &hash, &item.ChatID, &item.SenderDeviceID, &created); err != nil {
			return nil, err
		}
		if len(hash) != 32 {
			return nil, ErrInvalid
		}
		copy(item.CiphertextSHA256[:], hash)
		item.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) ReserveGroupVersion(ctx context.Context, principal Principal, chatID, rotationID string) (GroupVersionReservation, error) {
	if chatID == "" || len(rotationID) < 16 || len(rotationID) > 128 {
		return GroupVersionReservation{}, ErrInvalid
	}
	if err := s.requireReady(ctx, principal); err != nil {
		return GroupVersionReservation{}, err
	}
	var member int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM chat_members WHERE chat_id=? AND username=?`, chatID, principal.Username).Scan(&member); err != nil {
		return GroupVersionReservation{}, err
	}
	if member != 1 {
		return GroupVersionReservation{}, ErrForbidden
	}
	for attempt := 0; attempt < 8; attempt++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return GroupVersionReservation{}, err
		}
		var existingChat, existingDevice, expires string
		var existingVersion int64
		var consumed sql.NullString
		err = tx.QueryRowContext(ctx, `SELECT chat_id,sender_device_id,room_key_version,expires_at,consumed_at FROM megolm_rotation_reservations WHERE rotation_id=?`, rotationID).Scan(&existingChat, &existingDevice, &existingVersion, &expires, &consumed)
		if err == nil {
			_ = tx.Rollback()
			if existingChat != chatID || existingDevice != principal.DeviceID {
				return GroupVersionReservation{}, ErrConflict
			}
			expiresAt, parseErr := time.Parse(time.RFC3339Nano, expires)
			if parseErr != nil || (!consumed.Valid && !expiresAt.After(s.now().UTC())) {
				return GroupVersionReservation{}, ErrConflict
			}
			return GroupVersionReservation{RotationID: rotationID, ChatID: chatID, RoomKeyVersion: existingVersion, ExpiresAt: expiresAt, Replayed: true}, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			_ = tx.Rollback()
			return GroupVersionReservation{}, err
		}
		var next int64
		if err := tx.QueryRowContext(ctx, `
			SELECT COALESCE(MAX(version),0)+1 FROM (
				SELECT room_key_version AS version FROM megolm_group_sessions WHERE chat_id=?
				UNION ALL
				SELECT room_key_version AS version FROM megolm_rotation_reservations WHERE chat_id=?
			)`, chatID, chatID).Scan(&next); err != nil {
			_ = tx.Rollback()
			return GroupVersionReservation{}, err
		}
		now := s.now().UTC()
		expiresAt := now.Add(10 * time.Minute)
		_, err = tx.ExecContext(ctx, `INSERT INTO megolm_rotation_reservations(rotation_id,chat_id,sender_device_id,room_key_version,created_at,expires_at) VALUES(?,?,?,?,?,?)`, rotationID, chatID, principal.DeviceID, next, now.Format(time.RFC3339Nano), expiresAt.Format(time.RFC3339Nano))
		if err != nil {
			_ = tx.Rollback()
			if mapped := mapConstraint(err); errors.Is(mapped, ErrConflict) {
				continue
			}
			return GroupVersionReservation{}, err
		}
		if err := tx.Commit(); err != nil {
			if errors.Is(mapConstraint(err), ErrConflict) {
				continue
			}
			return GroupVersionReservation{}, err
		}
		return GroupVersionReservation{RotationID: rotationID, ChatID: chatID, RoomKeyVersion: next, ExpiresAt: expiresAt}, nil
	}
	return GroupVersionReservation{}, ErrConflict
}

func (s *Store) PutGroupSession(ctx context.Context, principal Principal, input GroupSessionWrite) error {
	if input.ChatID == "" || input.RoomKeyVersion < 1 || len(input.SessionID) < 16 || len(input.SessionID) > 256 || len(input.RotationID) < 16 || len(input.RotationID) > 128 || len(input.Packages) == 0 || len(input.Packages) > 64 {
		return ErrInvalid
	}
	if err := s.requireReady(ctx, principal); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existingChat, existingSession, existingDevice string
	var existingVersion int64
	err = tx.QueryRowContext(ctx, `SELECT chat_id,room_key_version,session_id,sender_device_id FROM megolm_group_sessions WHERE rotation_id=?`, input.RotationID).Scan(&existingChat, &existingVersion, &existingSession, &existingDevice)
	if err == nil {
		if existingChat == input.ChatID && existingVersion == input.RoomKeyVersion && existingSession == input.SessionID && existingDevice == principal.DeviceID {
			return nil
		}
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var reservedChat, reservedDevice, reservedExpires string
	var reservedVersion int64
	var reservedConsumed sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT chat_id,sender_device_id,room_key_version,expires_at,consumed_at FROM megolm_rotation_reservations WHERE rotation_id=?`, input.RotationID).Scan(&reservedChat, &reservedDevice, &reservedVersion, &reservedExpires, &reservedConsumed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrConflict
		}
		return err
	}
	reservedExpiry, err := time.Parse(time.RFC3339Nano, reservedExpires)
	if err != nil || reservedConsumed.Valid || !reservedExpiry.After(s.now().UTC()) || reservedChat != input.ChatID || reservedDevice != principal.DeviceID || reservedVersion != input.RoomKeyVersion {
		return ErrConflict
	}
	var member int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM chat_members WHERE chat_id=? AND username=?`, input.ChatID, principal.Username).Scan(&member); err != nil {
		return err
	}
	if member != 1 {
		return ErrForbidden
	}
	var expected int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM provisioning_devices d JOIN chat_members m ON m.username=d.username JOIN ratchet_device_bundles b ON b.device_id=d.id AND b.revoked_at IS NULL WHERE m.chat_id=? AND d.revoked_at IS NULL AND d.security_state='READY'`, input.ChatID).Scan(&expected); err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for _, p := range input.Packages {
		if p.RecipientDeviceID == "" || len(p.OlmSessionID) < 16 || len(p.OlmSessionID) > 256 || (p.MessageType != 0 && p.MessageType != 1) || len(p.EncryptedSessionKey) < 16 || len(p.EncryptedSessionKey) > 65536 {
			return ErrInvalid
		}
		seen[p.RecipientDeviceID] = struct{}{}
	}
	if len(seen) != expected {
		return ErrConflict
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	_, err = tx.ExecContext(ctx, `INSERT INTO megolm_group_sessions(chat_id,room_key_version,session_id,sender_device_id,rotation_id,created_at) VALUES(?,?,?,?,?,?)`, input.ChatID, input.RoomKeyVersion, input.SessionID, principal.DeviceID, input.RotationID, now)
	if err != nil {
		return mapConstraint(err)
	}
	for _, p := range input.Packages {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM provisioning_devices d JOIN chat_members m ON m.username=d.username JOIN ratchet_device_bundles b ON b.device_id=d.id AND b.revoked_at IS NULL WHERE d.id=? AND m.chat_id=? AND d.revoked_at IS NULL AND d.security_state='READY'`, p.RecipientDeviceID, input.ChatID).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return ErrForbidden
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO megolm_key_packages(chat_id,room_key_version,recipient_device_id,olm_session_id,message_type,encrypted_session_key,created_at) VALUES(?,?,?,?,?,?,?)`, input.ChatID, input.RoomKeyVersion, p.RecipientDeviceID, p.OlmSessionID, p.MessageType, p.EncryptedSessionKey, now)
		if err != nil {
			return mapConstraint(err)
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE megolm_rotation_reservations SET consumed_at=? WHERE rotation_id=? AND consumed_at IS NULL`, now, input.RotationID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrConflict
	}
	_, _ = tx.ExecContext(ctx, `UPDATE room_rotation_events SET completed_at=? WHERE chat_id=? AND new_key_version=? AND completed_at IS NULL`, now, input.ChatID, input.RoomKeyVersion)
	return tx.Commit()
}

func (s *Store) ListPendingGroupKeys(ctx context.Context, principal Principal, limit int) ([]PendingGroupKeyPackage, error) {
	if limit < 1 || limit > 200 {
		return nil, ErrInvalid
	}
	if err := s.requireReady(ctx, principal); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.chat_id,p.room_key_version,g.session_id,g.sender_device_id,b.curve25519_identity_key,g.rotation_id,p.olm_session_id,p.message_type,p.encrypted_session_key,p.created_at
		FROM megolm_key_packages p
		JOIN megolm_group_sessions g ON g.chat_id=p.chat_id AND g.room_key_version=p.room_key_version
		JOIN ratchet_device_bundles b ON b.device_id=g.sender_device_id AND b.revoked_at IS NULL
		WHERE p.recipient_device_id=? AND p.consumed_at IS NULL ORDER BY p.created_at LIMIT ?`, principal.DeviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]PendingGroupKeyPackage, 0)
	for rows.Next() {
		var x PendingGroupKeyPackage
		var created string
		if err := rows.Scan(&x.ChatID, &x.RoomKeyVersion, &x.SessionID, &x.SenderDeviceID, &x.SenderCurve25519Key, &x.RotationID, &x.OlmSessionID, &x.MessageType, &x.EncryptedSessionKey, &created); err != nil {
			return nil, err
		}
		x.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Store) ConsumeGroupKey(ctx context.Context, principal Principal, chatID string, version int64) error {
	if chatID == "" || version < 1 {
		return ErrInvalid
	}
	if err := s.requireReady(ctx, principal); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE megolm_key_packages SET consumed_at=? WHERE chat_id=? AND room_key_version=? AND recipient_device_id=? AND consumed_at IS NULL`, s.now().UTC().Format(time.RFC3339Nano), chatID, version, principal.DeviceID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) requireReady(ctx context.Context, p Principal) error {
	var owner, state string
	var revoked sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT username,security_state,revoked_at FROM provisioning_devices WHERE id=?`, p.DeviceID).Scan(&owner, &state, &revoked)
	if err != nil || owner != p.Username || revoked.Valid || state != "READY" {
		return ErrForbidden
	}
	return nil
}
func (s *Store) verifyDeviceSignature(ctx context.Context, deviceID string, message, signature []byte) bool {
	var algorithm string
	var spki []byte
	if err := s.db.QueryRowContext(ctx, `SELECT key_algorithm,public_key_spki FROM provisioning_devices WHERE id=? AND revoked_at IS NULL`, deviceID).Scan(&algorithm, &spki); err != nil {
		return false
	}
	key, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(message)
	switch algorithm {
	case "ed25519":
		pub, ok := key.(ed25519.PublicKey)
		return ok && ed25519.Verify(pub, message, signature)
	case "ecdsa-p256-sha256":
		pub, ok := key.(*ecdsa.PublicKey)
		return ok && ecdsa.VerifyASN1(pub, digest[:], signature)
	default:
		return false
	}
}
func canonicalBundle(deviceID string, version int, curve, ed string) []byte {
	return []byte(fmt.Sprintf("fedmes-ratchet-bundle-v1\n%s\n%d\n%s\n%s", deviceID, version, curve, ed))
}
func canonicalOTK(deviceID, keyID, key string) []byte {
	return []byte("fedmes-olm-otk-v1\n" + deviceID + "\n" + keyID + "\n" + key)
}
func validCurveKey(value string) bool {
	if len(value) < 32 || len(value) > 128 || strings.ContainsAny(value, "\r\n\t ") {
		return false
	}
	decoded, err := base64.RawStdEncoding.DecodeString(value)
	return err == nil && len(decoded) >= 32 && len(decoded) <= 64
}
func mapConstraint(err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unique") || strings.Contains(message, "constraint") {
		return ErrConflict
	}
	return err
}
func SortedDeviceIDs(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
