package messaging

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"fedmes/server/internal/accountsecurity"
	"fedmes/server/internal/provisioning"
)

var (
	ErrDeviceLinkNotFound = errors.New("device link not found")
	ErrDeviceLinkExpired  = errors.New("device link expired")
	ErrDeviceLinkUsed     = errors.New("device link already used")
	ErrDeviceLinkConflict = errors.New("device link conflict")
	ErrDeviceNotFound     = errors.New("device not found")
	ErrCurrentDevice      = errors.New("current device cannot be revoked here")
)

type DeviceLinkRecord struct {
	ID                      string
	SecretDigest            [32]byte
	IdentityAlgorithm       string
	IdentityPublicKeySPKI   []byte
	IdentityFingerprint     [32]byte
	EncryptionAlgorithm     string
	EncryptionPublicKeySPKI []byte
	EncryptionFingerprint   [32]byte
	DisplayName             string
	Platform                string
	CreatedAt               time.Time
	ExpiresAt               time.Time
	ApprovedAt              *time.Time
	ApprovedByDeviceID      string
	Username                string
	LinkedDeviceID          string
	LinkedSessionID         string
	EncryptedSessionToken   []byte
	SessionExpiresAt        *time.Time
	ResultExpiresAt         *time.Time
	ConsumedAt              *time.Time
	CancelledAt             *time.Time
}

type DeviceLinkApproval struct {
	LinkID                string
	SecretDigest          [32]byte
	Approver              Principal
	InvitationID          string
	DeviceID              string
	SessionID             string
	SessionTokenDigest    [32]byte
	EncryptedSessionToken []byte
	SessionExpiresAt      time.Time
	ResultExpiresAt       time.Time
	ApprovedAt            time.Time
}

type AccountDevice struct {
	ID                  string     `json:"id"`
	DisplayName         string     `json:"display_name"`
	Platform            string     `json:"platform"`
	BoundAt             time.Time  `json:"bound_at"`
	LastSeenAt          *time.Time `json:"last_seen_at,omitempty"`
	Current             bool       `json:"current"`
	ApprovedByDeviceID  string     `json:"approved_by_device_id,omitempty"`
	IdentityFingerprint string     `json:"identity_fingerprint"`
}

func (s *Store) CreateDeviceLink(ctx context.Context, record DeviceLinkRecord) error {
	if record.ID == "" || record.DisplayName == "" || record.Platform == "" ||
		record.CreatedAt.IsZero() || !record.ExpiresAt.After(record.CreatedAt) ||
		len(record.IdentityPublicKeySPKI) == 0 || len(record.EncryptionPublicKeySPKI) == 0 {
		return ErrDeviceLinkConflict
	}
	var active int
	if err := s.DB.QueryRowContext(ctx, `
        SELECT COUNT(*) FROM provisioning_devices
        WHERE public_key_fingerprint=? AND revoked_at IS NULL
    `, record.IdentityFingerprint[:]).Scan(&active); err != nil {
		return err
	}
	if active != 0 {
		return ErrDeviceLinkConflict
	}
	_, err := s.DB.ExecContext(ctx, `
        INSERT INTO device_link_requests(
            id,secret_digest,identity_algorithm,identity_public_key_spki,identity_fingerprint,
            encryption_algorithm,encryption_public_key_spki,encryption_fingerprint,
            display_name,platform,created_at,expires_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
    `,
		record.ID, record.SecretDigest[:], record.IdentityAlgorithm, record.IdentityPublicKeySPKI,
		record.IdentityFingerprint[:], record.EncryptionAlgorithm, record.EncryptionPublicKeySPKI,
		record.EncryptionFingerprint[:], record.DisplayName, record.Platform,
		record.CreatedAt.UTC().Format(time.RFC3339Nano), record.ExpiresAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return ErrDeviceLinkConflict
	}
	return nil
}

func (s *Store) LoadDeviceLink(ctx context.Context, id string, secretDigest [32]byte) (DeviceLinkRecord, error) {
	row := s.DB.QueryRowContext(ctx, `
        SELECT id,secret_digest,identity_algorithm,identity_public_key_spki,identity_fingerprint,
            encryption_algorithm,encryption_public_key_spki,encryption_fingerprint,
            display_name,platform,created_at,expires_at,approved_at,approved_by_device_id,
            username,linked_device_id,linked_session_id,encrypted_session_token,
            session_expires_at,result_expires_at,consumed_at,cancelled_at
        FROM device_link_requests WHERE id=? AND secret_digest=?
    `, id, secretDigest[:])
	return scanDeviceLink(row)
}

func scanDeviceLink(row *sql.Row) (DeviceLinkRecord, error) {
	var record DeviceLinkRecord
	var secret, identityFingerprint, encryptionFingerprint []byte
	var created, expires string
	var approved, sessionExpires, resultExpires, consumed, cancelled sql.NullString
	var approvedBy, username, linkedDevice, linkedSession sql.NullString
	var encryptedToken []byte
	err := row.Scan(
		&record.ID, &secret, &record.IdentityAlgorithm, &record.IdentityPublicKeySPKI, &identityFingerprint,
		&record.EncryptionAlgorithm, &record.EncryptionPublicKeySPKI, &encryptionFingerprint,
		&record.DisplayName, &record.Platform, &created, &expires, &approved, &approvedBy,
		&username, &linkedDevice, &linkedSession, &encryptedToken,
		&sessionExpires, &resultExpires, &consumed, &cancelled,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceLinkRecord{}, ErrDeviceLinkNotFound
	}
	if err != nil {
		return DeviceLinkRecord{}, err
	}
	if len(secret) != 32 || len(identityFingerprint) != 32 || len(encryptionFingerprint) != 32 {
		return DeviceLinkRecord{}, ErrDeviceLinkConflict
	}
	copy(record.SecretDigest[:], secret)
	copy(record.IdentityFingerprint[:], identityFingerprint)
	copy(record.EncryptionFingerprint[:], encryptionFingerprint)
	var parseErr error
	if record.CreatedAt, parseErr = time.Parse(time.RFC3339Nano, created); parseErr != nil {
		return DeviceLinkRecord{}, parseErr
	}
	if record.ExpiresAt, parseErr = time.Parse(time.RFC3339Nano, expires); parseErr != nil {
		return DeviceLinkRecord{}, parseErr
	}
	record.ApprovedByDeviceID = approvedBy.String
	record.Username = username.String
	record.LinkedDeviceID = linkedDevice.String
	record.LinkedSessionID = linkedSession.String
	record.EncryptedSessionToken = append([]byte(nil), encryptedToken...)
	record.ApprovedAt, parseErr = parseOptionalTime(approved)
	if parseErr != nil {
		return DeviceLinkRecord{}, parseErr
	}
	record.SessionExpiresAt, parseErr = parseOptionalTime(sessionExpires)
	if parseErr != nil {
		return DeviceLinkRecord{}, parseErr
	}
	record.ResultExpiresAt, parseErr = parseOptionalTime(resultExpires)
	if parseErr != nil {
		return DeviceLinkRecord{}, parseErr
	}
	record.ConsumedAt, parseErr = parseOptionalTime(consumed)
	if parseErr != nil {
		return DeviceLinkRecord{}, parseErr
	}
	record.CancelledAt, parseErr = parseOptionalTime(cancelled)
	if parseErr != nil {
		return DeviceLinkRecord{}, parseErr
	}
	return record, nil
}

func parseOptionalTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func DeviceLinkState(record DeviceLinkRecord, now time.Time) string {
	switch {
	case record.CancelledAt != nil:
		return "cancelled"
	case record.ConsumedAt != nil:
		return "consumed"
	case record.ApprovedAt != nil && record.ResultExpiresAt != nil && now.Before(*record.ResultExpiresAt):
		return "approved"
	case record.ApprovedAt != nil:
		return "expired"
	case !now.Before(record.ExpiresAt):
		return "expired"
	default:
		return "pending"
	}
}

func (s *Store) LoadActiveDeviceIdentity(ctx context.Context, principal Principal) (string, []byte, error) {
	var username, algorithm string
	var publicKey []byte
	var revoked sql.NullString
	err := s.DB.QueryRowContext(ctx, `
        SELECT username,key_algorithm,public_key_spki,revoked_at
        FROM provisioning_devices WHERE id=?
    `, principal.DeviceID).Scan(&username, &algorithm, &publicKey, &revoked)
	if err != nil || username != principal.Username || revoked.Valid {
		return "", nil, ErrDeviceNotFound
	}
	return algorithm, publicKey, nil
}

func VerifyDeviceLinkApprovalSignature(algorithm string, publicKeyDER, payload, signature []byte) bool {
	parsed, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return false
	}
	switch key := parsed.(type) {
	case *ecdsa.PublicKey:
		if algorithm != string(provisioning.DeviceKeyECDSAP256) {
			return false
		}
		digest := sha256.Sum256(payload)
		return ecdsa.VerifyASN1(key, digest[:], signature)
	case ed25519.PublicKey:
		return algorithm == string(provisioning.DeviceKeyEd25519) && ed25519.Verify(key, payload, signature)
	default:
		return false
	}
}

func (s *Store) ApproveDeviceLink(ctx context.Context, input DeviceLinkApproval) (AccountDevice, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return AccountDevice{}, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx, `
        SELECT id,secret_digest,identity_algorithm,identity_public_key_spki,identity_fingerprint,
            encryption_algorithm,encryption_public_key_spki,encryption_fingerprint,
            display_name,platform,created_at,expires_at,approved_at,approved_by_device_id,
            username,linked_device_id,linked_session_id,encrypted_session_token,
            session_expires_at,result_expires_at,consumed_at,cancelled_at
        FROM device_link_requests WHERE id=? AND secret_digest=?
    `, input.LinkID, input.SecretDigest[:])
	record, err := scanDeviceLinkTx(row)
	if err != nil {
		return AccountDevice{}, err
	}
	state := DeviceLinkState(record, input.ApprovedAt)
	if state == "expired" {
		return AccountDevice{}, ErrDeviceLinkExpired
	}
	if state != "pending" {
		return AccountDevice{}, ErrDeviceLinkUsed
	}

	var approverUsername, approverSecurityState string
	var approverRevoked sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT username,revoked_at,security_state FROM provisioning_devices WHERE id=?
	`, input.Approver.DeviceID).Scan(&approverUsername, &approverRevoked, &approverSecurityState); err != nil ||
		approverUsername != input.Approver.Username || approverRevoked.Valid ||
		approverSecurityState != accountsecurity.StateReady {
		return AccountDevice{}, ErrDeviceNotFound
	}

	var vaultRevision int64
	if err := tx.QueryRowContext(ctx, `
		SELECT vault_revision FROM account_security_state WHERE username=?
	`, input.Approver.Username).Scan(&vaultRevision); err != nil {
		return AccountDevice{}, err
	}
	linkedSecurityState := accountsecurity.StateReady
	if vaultRevision > 0 {
		linkedSecurityState = accountsecurity.StateAuthenticatedNoKeys
	}

	timestamp := input.ApprovedAt.UTC().Format(time.RFC3339Nano)
	linkedDeviceID := input.DeviceID
	var existingDeviceID, existingUsername string
	var existingRevoked sql.NullString
	var existingEncryptionFingerprint []byte
	existingErr := tx.QueryRowContext(ctx, `
        SELECT d.id,d.username,d.revoked_at,k.fingerprint
        FROM provisioning_devices d
        JOIN device_encryption_keys k ON k.device_id=d.id
        WHERE d.public_key_fingerprint=?
    `, record.IdentityFingerprint[:]).Scan(
		&existingDeviceID, &existingUsername, &existingRevoked, &existingEncryptionFingerprint,
	)
	switch {
	case existingErr == nil:
		if !existingRevoked.Valid || existingUsername != input.Approver.Username ||
			!bytes.Equal(existingEncryptionFingerprint, record.EncryptionFingerprint[:]) {
			return AccountDevice{}, ErrDeviceLinkConflict
		}
		linkedDeviceID = existingDeviceID
		if _, err := tx.ExecContext(ctx, `
            UPDATE provisioning_sessions SET revoked_at=?
            WHERE device_id=? AND revoked_at IS NULL
        `, timestamp, linkedDeviceID); err != nil {
			return AccountDevice{}, err
		}
		if _, err := tx.ExecContext(ctx, `
            UPDATE provisioning_devices SET
                revoked_at=NULL,display_name=?,platform=?,last_seen_at=?,approved_by_device_id=?,
                approved_at=NULL,security_state=?
            WHERE id=? AND revoked_at IS NOT NULL
        `, record.DisplayName, record.Platform, timestamp, input.Approver.DeviceID,
			linkedSecurityState, linkedDeviceID); err != nil {
			return AccountDevice{}, err
		}
	case errors.Is(existingErr, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO provisioning_invitations(
                id,username,token_digest,created_at,expires_at,redeemed_at,redeemed_by_device_id
            ) VALUES(?,?,?,?,?,?,?)
        `, input.InvitationID, input.Approver.Username, input.SecretDigest[:],
			record.CreatedAt.UTC().Format(time.RFC3339Nano), record.ExpiresAt.UTC().Format(time.RFC3339Nano),
			timestamp, linkedDeviceID); err != nil {
			return AccountDevice{}, fmt.Errorf("create linked-device audit invitation: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO provisioning_devices(
                id,username,invitation_id,key_algorithm,public_key_spki,public_key_fingerprint,
                bound_at,display_name,platform,last_seen_at,approved_by_device_id,security_state,approved_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL)
        `, linkedDeviceID, input.Approver.Username, input.InvitationID, record.IdentityAlgorithm,
			record.IdentityPublicKeySPKI, record.IdentityFingerprint[:], timestamp,
			record.DisplayName, record.Platform, timestamp, input.Approver.DeviceID,
			linkedSecurityState); err != nil {
			return AccountDevice{}, ErrDeviceLinkConflict
		}
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO device_encryption_keys(device_id,algorithm,public_key_spki,fingerprint,registered_at)
            VALUES(?,?,?,?,?)
        `, linkedDeviceID, record.EncryptionAlgorithm, record.EncryptionPublicKeySPKI,
			record.EncryptionFingerprint[:], timestamp); err != nil {
			return AccountDevice{}, ErrDeviceLinkConflict
		}
	default:
		return AccountDevice{}, existingErr
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO device_keys(device_id,purpose,algorithm,public_key_spki,fingerprint,created_at,revoked_at)
		VALUES(?,?,?,?,?,?,NULL)
		ON CONFLICT(device_id,purpose) DO UPDATE SET
			algorithm=excluded.algorithm,public_key_spki=excluded.public_key_spki,
			fingerprint=excluded.fingerprint,created_at=excluded.created_at,revoked_at=NULL
	`, linkedDeviceID, "signing", record.IdentityAlgorithm, record.IdentityPublicKeySPKI,
		record.IdentityFingerprint[:], timestamp); err != nil {
		return AccountDevice{}, ErrDeviceLinkConflict
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO device_keys(device_id,purpose,algorithm,public_key_spki,fingerprint,created_at,revoked_at)
		VALUES(?,?,?,?,?,?,NULL)
		ON CONFLICT(device_id,purpose) DO UPDATE SET
			algorithm=excluded.algorithm,public_key_spki=excluded.public_key_spki,
			fingerprint=excluded.fingerprint,created_at=excluded.created_at,revoked_at=NULL
	`, linkedDeviceID, "key_agreement", record.EncryptionAlgorithm, record.EncryptionPublicKeySPKI,
		record.EncryptionFingerprint[:], timestamp); err != nil {
		return AccountDevice{}, ErrDeviceLinkConflict
	}

	if linkedSecurityState != accountsecurity.StateReady {
		requestDigest := sha256.Sum256(bytes.Join([][]byte{
			[]byte(input.LinkID), record.IdentityFingerprint[:], record.EncryptionFingerprint[:],
		}, []byte{0}))
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO device_provisioning_requests(
				id,username,target_device_id,request_digest,protocol_version,requested_at,expires_at,
				display_name,platform,network_hint
			) VALUES(?,?,?,?,?,?,?,?,?,?)
		`, input.LinkID, input.Approver.Username, linkedDeviceID, requestDigest[:], 3,
			timestamp, input.ApprovedAt.UTC().Add(24*time.Hour).Format(time.RFC3339Nano),
			record.DisplayName, record.Platform, ""); err != nil {
			return AccountDevice{}, ErrDeviceLinkConflict
		}
	} else {
		if _, err := tx.ExecContext(ctx, `
			UPDATE account_security_state SET last_ready_device_id=?,updated_at=? WHERE username=?
		`, linkedDeviceID, timestamp, input.Approver.Username); err != nil {
			return AccountDevice{}, err
		}
	}

	if _, err := tx.ExecContext(ctx, `
        INSERT INTO provisioning_sessions(id,device_id,token_digest,issued_at,expires_at,protocol_version)
        VALUES(?,?,?,?,?,?)
    `, input.SessionID, linkedDeviceID, input.SessionTokenDigest[:], timestamp,
		input.SessionExpiresAt.UTC().Format(time.RFC3339Nano), 3); err != nil {
		return AccountDevice{}, ErrDeviceLinkConflict
	}
	result, err := tx.ExecContext(ctx, `
        UPDATE device_link_requests SET
            approved_at=?,approved_by_device_id=?,username=?,linked_device_id=?,linked_session_id=?,
            encrypted_session_token=?,session_expires_at=?,result_expires_at=?
        WHERE id=? AND secret_digest=? AND approved_at IS NULL AND cancelled_at IS NULL
    `, timestamp, input.Approver.DeviceID, input.Approver.Username, linkedDeviceID, input.SessionID,
		input.EncryptedSessionToken, input.SessionExpiresAt.UTC().Format(time.RFC3339Nano),
		input.ResultExpiresAt.UTC().Format(time.RFC3339Nano), input.LinkID, input.SecretDigest[:])
	if err != nil {
		return AccountDevice{}, err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return AccountDevice{}, ErrDeviceLinkUsed
	}
	if err := tx.Commit(); err != nil {
		return AccountDevice{}, err
	}

	fingerprint := fmt.Sprintf("%x", record.IdentityFingerprint[:])
	lastSeen := input.ApprovedAt.UTC()
	return AccountDevice{
		ID: linkedDeviceID, DisplayName: record.DisplayName, Platform: record.Platform,
		BoundAt: input.ApprovedAt.UTC(), LastSeenAt: &lastSeen,
		ApprovedByDeviceID: input.Approver.DeviceID, IdentityFingerprint: fingerprint,
	}, nil
}

func scanDeviceLinkTx(row *sql.Row) (DeviceLinkRecord, error) { return scanDeviceLink(row) }

func (s *Store) CancelDeviceLink(ctx context.Context, id string, secretDigest [32]byte, now time.Time) error {
	result, err := s.DB.ExecContext(ctx, `
        UPDATE device_link_requests SET cancelled_at=?
        WHERE id=? AND secret_digest=? AND approved_at IS NULL AND cancelled_at IS NULL AND expires_at>?
    `, now.UTC().Format(time.RFC3339Nano), id, secretDigest[:], now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return ErrDeviceLinkUsed
	}
	return nil
}

func (s *Store) CompleteDeviceLink(ctx context.Context, id string, secretDigest [32]byte, now time.Time) error {
	result, err := s.DB.ExecContext(ctx, `
        UPDATE device_link_requests SET consumed_at=?,encrypted_session_token=NULL
        WHERE id=? AND secret_digest=? AND approved_at IS NOT NULL AND consumed_at IS NULL
            AND result_expires_at>?
    `, now.UTC().Format(time.RFC3339Nano), id, secretDigest[:], now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return ErrDeviceLinkUsed
	}
	return nil
}

func (s *Store) ListAccountDevices(ctx context.Context, principal Principal) ([]AccountDevice, error) {
	rows, err := s.DB.QueryContext(ctx, `
        SELECT id,display_name,platform,bound_at,last_seen_at,approved_by_device_id,public_key_fingerprint
        FROM provisioning_devices
        WHERE username=? AND revoked_at IS NULL
        ORDER BY CASE WHEN id=? THEN 0 ELSE 1 END, COALESCE(last_seen_at,bound_at) DESC
    `, principal.Username, principal.DeviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AccountDevice, 0, 4)
	for rows.Next() {
		var item AccountDevice
		var bound string
		var lastSeen, approvedBy sql.NullString
		var fingerprint []byte
		if err := rows.Scan(&item.ID, &item.DisplayName, &item.Platform, &bound, &lastSeen, &approvedBy, &fingerprint); err != nil {
			return nil, err
		}
		item.BoundAt, err = time.Parse(time.RFC3339Nano, bound)
		if err != nil {
			return nil, err
		}
		if lastSeen.Valid {
			parsed, parseErr := time.Parse(time.RFC3339Nano, lastSeen.String)
			if parseErr != nil {
				return nil, parseErr
			}
			item.LastSeenAt = &parsed
		}
		item.Current = item.ID == principal.DeviceID
		item.ApprovedByDeviceID = approvedBy.String
		item.IdentityFingerprint = fmt.Sprintf("%x", fingerprint)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAccountDevice(ctx context.Context, principal Principal, deviceID string, now time.Time) error {
	if deviceID == principal.DeviceID {
		return ErrCurrentDevice
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var owner string
	var revoked sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT username,revoked_at FROM provisioning_devices WHERE id=?`, deviceID).
		Scan(&owner, &revoked); err != nil || owner != principal.Username || revoked.Valid {
		return ErrDeviceNotFound
	}
	timestamp := now.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE provisioning_sessions SET revoked_at=? WHERE device_id=? AND revoked_at IS NULL`, timestamp, deviceID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE provisioning_challenges SET consumed_at=? WHERE device_id=? AND consumed_at IS NULL`, timestamp, deviceID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE provisioning_devices SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, timestamp, deviceID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RevokeOtherAccountDevices(ctx context.Context, principal Principal, now time.Time) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	timestamp := now.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
        UPDATE provisioning_sessions SET revoked_at=?
        WHERE revoked_at IS NULL AND device_id IN (
            SELECT id FROM provisioning_devices WHERE username=? AND id<>? AND revoked_at IS NULL
        )
    `, timestamp, principal.Username, principal.DeviceID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
        UPDATE provisioning_challenges SET consumed_at=?
        WHERE consumed_at IS NULL AND device_id IN (
            SELECT id FROM provisioning_devices WHERE username=? AND id<>? AND revoked_at IS NULL
        )
    `, timestamp, principal.Username, principal.DeviceID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
        UPDATE provisioning_devices SET revoked_at=?
        WHERE username=? AND id<>? AND revoked_at IS NULL
    `, timestamp, principal.Username, principal.DeviceID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RevokeCurrentDevice(ctx context.Context, principal Principal, now time.Time) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	timestamp := now.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
        UPDATE provisioning_sessions SET revoked_at=?
        WHERE device_id=? AND revoked_at IS NULL
    `, timestamp, principal.DeviceID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
        UPDATE provisioning_challenges SET consumed_at=?
        WHERE device_id=? AND consumed_at IS NULL
    `, timestamp, principal.DeviceID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
        UPDATE provisioning_devices SET revoked_at=?
        WHERE id=? AND username=? AND revoked_at IS NULL
    `, timestamp, principal.DeviceID, principal.Username)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return ErrDeviceNotFound
	}
	return tx.Commit()
}

func (s *Store) ExpireApprovedDeviceLink(ctx context.Context, record DeviceLinkRecord, now time.Time) error {
	if record.ApprovedAt == nil || record.ConsumedAt != nil || record.LinkedDeviceID == "" || record.LinkedSessionID == "" {
		return nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	timestamp := now.UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `
		UPDATE device_link_requests
		SET consumed_at=?,encrypted_session_token=NULL
		WHERE id=? AND approved_at IS NOT NULL AND consumed_at IS NULL
			AND result_expires_at IS NOT NULL AND result_expires_at<=?
	`, timestamp, record.ID, timestamp)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE provisioning_sessions SET revoked_at=?
		WHERE id=? AND device_id=? AND revoked_at IS NULL
	`, timestamp, record.LinkedSessionID, record.LinkedDeviceID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE provisioning_challenges SET consumed_at=?
		WHERE device_id=? AND consumed_at IS NULL
	`, timestamp, record.LinkedDeviceID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE provisioning_devices SET revoked_at=?
		WHERE id=? AND revoked_at IS NULL
	`, timestamp, record.LinkedDeviceID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ExpireApprovedDeviceLinks(ctx context.Context, now time.Time) error {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id,linked_device_id,linked_session_id
		FROM device_link_requests
		WHERE approved_at IS NOT NULL AND consumed_at IS NULL
			AND result_expires_at IS NOT NULL AND result_expires_at<=?
	`, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	records := make([]DeviceLinkRecord, 0, 8)
	for rows.Next() {
		var record DeviceLinkRecord
		if err := rows.Scan(&record.ID, &record.LinkedDeviceID, &record.LinkedSessionID); err != nil {
			_ = rows.Close()
			return err
		}
		approved := now.Add(-time.Second)
		record.ApprovedAt = &approved
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, record := range records {
		if err := s.ExpireApprovedDeviceLink(ctx, record, now); err != nil {
			return err
		}
	}
	return nil
}
