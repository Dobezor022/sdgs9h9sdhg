package database

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"fedmes/server/internal/provisioning"

	moderncsqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

func (s *Store) CreateInvitation(ctx context.Context, invitation provisioning.InvitationRecord) error {
	if invitation.ID == "" || invitation.CreatedAt.IsZero() || !invitation.ExpiresAt.After(invitation.CreatedAt) || invitation.RedeemedAt != nil || invitation.RedeemedByDeviceID != "" {
		return provisioning.RepositoryError(provisioning.CodeInvariantViolation, "invitation", nil)
	}
	username, err := provisioning.ParseUsername(string(invitation.Username))
	if err != nil || username != invitation.Username {
		return provisioning.RepositoryError(provisioning.CodeInvariantViolation, "invitation", err)
	}

	connection, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("reserve invitation connection: %w", err)
	}
	defer connection.Close()
	if _, err := connection.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("begin invitation issuance: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = connection.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	// Only the newest unredeemed QR for a user remains valid. Redeemed
	// invitations are retained for audit and device binding history.
	if _, err := connection.ExecContext(ctx, `
		DELETE FROM provisioning_invitations
		WHERE username = ? AND redeemed_at IS NULL
	`, string(invitation.Username)); err != nil {
		return fmt.Errorf("invalidate previous invitations: %w", err)
	}
	if _, err := connection.ExecContext(ctx, `
		INSERT INTO provisioning_invitations (
			id, username, token_digest, created_at, expires_at
		) VALUES (?, ?, ?, ?, ?)
	`, string(invitation.ID), string(invitation.Username), invitation.TokenDigest.Bytes(), formatTime(invitation.CreatedAt), formatTime(invitation.ExpiresAt)); err != nil {
		if isConstraintError(err) {
			return provisioning.RepositoryError(provisioning.CodeConflict, "invitation", err)
		}
		return fmt.Errorf("create provisioning invitation: %w", err)
	}
	if _, err := connection.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("commit invitation issuance: %w", err)
	}
	committed = true
	return nil
}

func (s *Store) FindActiveDeviceByFingerprint(
	ctx context.Context,
	username provisioning.Username,
	fingerprint [32]byte,
) (provisioning.DeviceRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, invitation_id, key_algorithm, public_key_spki, bound_at, revoked_at
		FROM provisioning_devices
		WHERE username = ? AND public_key_fingerprint = ? AND revoked_at IS NULL
	`, string(username), fingerprint[:])
	device, err := scanProvisioningDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return provisioning.DeviceRecord{}, provisioning.RepositoryError(provisioning.CodeUnknownDevice, "device_key", nil)
	}
	if err != nil {
		return provisioning.DeviceRecord{}, fmt.Errorf("find provisioning device: %w", err)
	}
	return device, nil
}

func (s *Store) CreateChallenge(ctx context.Context, challenge provisioning.ChallengeRecord) error {
	if challenge.ID == "" || challenge.DeviceID == "" || challenge.Audience == "" ||
		challenge.Purpose != provisioning.ChallengePurposeSessionRefresh || challenge.CreatedAt.IsZero() ||
		!challenge.ExpiresAt.After(challenge.CreatedAt) || challenge.ConsumedAt != nil {
		return provisioning.RepositoryError(provisioning.CodeInvariantViolation, "challenge", nil)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO provisioning_challenges (
			id, device_id, nonce_digest, audience, purpose, created_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`, string(challenge.ID), string(challenge.DeviceID), challenge.NonceDigest.Bytes(), challenge.Audience,
		string(challenge.Purpose), formatTime(challenge.CreatedAt), formatTime(challenge.ExpiresAt))
	if err != nil {
		if isConstraintError(err) {
			return provisioning.RepositoryError(provisioning.CodeConflict, "challenge", err)
		}
		return fmt.Errorf("create provisioning challenge: %w", err)
	}
	return nil
}

func (s *Store) LoadChallenge(
	ctx context.Context,
	challengeID provisioning.ChallengeID,
) (provisioning.ChallengeRecord, provisioning.DeviceRecord, error) {
	return loadChallengeAndDevice(ctx, s.db, challengeID)
}

func (s *Store) ConsumeChallengeAndCreateSession(
	ctx context.Context,
	command provisioning.RefreshSessionCommand,
) (provisioning.DeviceRecord, error) {
	connection, err := s.db.Conn(ctx)
	if err != nil {
		return provisioning.DeviceRecord{}, fmt.Errorf("reserve authentication connection: %w", err)
	}
	defer connection.Close()
	if _, err := connection.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return provisioning.DeviceRecord{}, fmt.Errorf("begin session refresh: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = connection.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	challenge, device, err := loadChallengeAndDevice(ctx, connection, command.ChallengeID)
	if err != nil {
		return provisioning.DeviceRecord{}, err
	}
	if device.ID != command.DeviceID || device.Username != command.Username || device.RevokedAt != nil {
		return provisioning.DeviceRecord{}, provisioning.RepositoryError(provisioning.CodeUnknownDevice, "device_id", nil)
	}
	if challenge.ConsumedAt != nil {
		return provisioning.DeviceRecord{}, provisioning.RepositoryError(provisioning.CodeChallengeUsed, "challenge_id", nil)
	}
	if !command.ConsumedAt.Before(challenge.ExpiresAt) {
		return provisioning.DeviceRecord{}, provisioning.RepositoryError(provisioning.CodeChallengeExpired, "challenge_id", nil)
	}
	if challenge.DeviceID != command.DeviceID || challenge.NonceDigest != command.NonceDigest ||
		challenge.Audience != command.Audience || challenge.Purpose != command.Purpose {
		return provisioning.DeviceRecord{}, provisioning.RepositoryError(provisioning.CodeChallengeContext, "challenge", nil)
	}
	result, err := connection.ExecContext(ctx, `
		UPDATE provisioning_challenges
		SET consumed_at = ?
		WHERE id = ? AND consumed_at IS NULL
	`, formatTime(command.ConsumedAt), string(command.ChallengeID))
	if err != nil {
		return provisioning.DeviceRecord{}, mapRedemptionWriteError("challenge", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return provisioning.DeviceRecord{}, fmt.Errorf("inspect challenge consumption: %w", err)
	}
	if rows != 1 {
		return provisioning.DeviceRecord{}, provisioning.RepositoryError(provisioning.CodeChallengeUsed, "challenge_id", nil)
	}
	if _, err := connection.ExecContext(ctx, `
		INSERT INTO provisioning_sessions (
			id, device_id, token_digest, issued_at, expires_at
		) VALUES (?, ?, ?, ?, ?)
	`, string(command.SessionID), string(command.DeviceID), command.SessionTokenDigest.Bytes(),
		formatTime(command.ConsumedAt), formatTime(command.SessionExpiresAt)); err != nil {
		return provisioning.DeviceRecord{}, mapRedemptionWriteError("session", err)
	}
	if _, err := connection.ExecContext(ctx, "COMMIT"); err != nil {
		return provisioning.DeviceRecord{}, fmt.Errorf("commit session refresh: %w", err)
	}
	committed = true
	return device, nil
}

type sqlRowScanner interface {
	Scan(dest ...any) error
}

func scanProvisioningDevice(row sqlRowScanner) (provisioning.DeviceRecord, error) {
	var (
		id            string
		usernameValue string
		invitationID  string
		algorithm     string
		publicKeySPKI []byte
		boundAtText   string
		revokedAtText sql.NullString
	)
	if err := row.Scan(&id, &usernameValue, &invitationID, &algorithm, &publicKeySPKI, &boundAtText, &revokedAtText); err != nil {
		return provisioning.DeviceRecord{}, err
	}
	return provisioningDeviceFromValues(
		id,
		usernameValue,
		invitationID,
		algorithm,
		publicKeySPKI,
		boundAtText,
		revokedAtText,
	)
}

func provisioningDeviceFromValues(
	id string,
	usernameValue string,
	invitationID string,
	algorithm string,
	publicKeySPKI []byte,
	boundAtText string,
	revokedAtText sql.NullString,
) (provisioning.DeviceRecord, error) {
	defer clear(publicKeySPKI)
	username, err := provisioning.ParseUsername(usernameValue)
	if err != nil {
		return provisioning.DeviceRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "device_username", err)
	}
	publicKey, err := provisioning.ValidateDevicePublicKey(provisioning.DevicePublicKeyInput{
		Algorithm:            provisioning.DeviceKeyAlgorithm(algorithm),
		SubjectPublicKeyInfo: publicKeySPKI,
	})
	if err != nil {
		return provisioning.DeviceRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "device_key", err)
	}
	boundAt, err := parseTime(boundAtText)
	if err != nil {
		return provisioning.DeviceRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "bound_at", err)
	}
	device := provisioning.DeviceRecord{
		ID:                  provisioning.DeviceID(id),
		Username:            username,
		PublicKey:           publicKey,
		BoundByInvitationID: provisioning.InvitationID(invitationID),
		BoundAt:             boundAt,
	}
	if revokedAtText.Valid {
		revokedAt, err := parseTime(revokedAtText.String)
		if err != nil {
			return provisioning.DeviceRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "revoked_at", err)
		}
		device.RevokedAt = &revokedAt
	}
	return device, nil
}

type queryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func loadChallengeAndDevice(
	ctx context.Context,
	queryer queryRower,
	challengeID provisioning.ChallengeID,
) (provisioning.ChallengeRecord, provisioning.DeviceRecord, error) {
	var (
		deviceID       string
		nonceDigest    []byte
		audience       string
		purpose        string
		createdAtText  string
		expiresAtText  string
		consumedAtText sql.NullString
		id             string
		usernameValue  string
		invitationID   string
		algorithm      string
		publicKeySPKI  []byte
		boundAtText    string
		revokedAtText  sql.NullString
	)
	err := queryer.QueryRowContext(ctx, `
		SELECT c.device_id, c.nonce_digest, c.audience, c.purpose, c.created_at, c.expires_at, c.consumed_at,
		       d.id, d.username, d.invitation_id, d.key_algorithm, d.public_key_spki, d.bound_at, d.revoked_at
		FROM provisioning_challenges c
		JOIN provisioning_devices d ON d.id = c.device_id
		WHERE c.id = ?
	`, string(challengeID)).Scan(
		&deviceID, &nonceDigest, &audience, &purpose, &createdAtText, &expiresAtText, &consumedAtText,
		&id, &usernameValue, &invitationID, &algorithm, &publicKeySPKI, &boundAtText, &revokedAtText,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return provisioning.ChallengeRecord{}, provisioning.DeviceRecord{}, provisioning.RepositoryError(provisioning.CodeChallengeNotFound, "challenge_id", nil)
	}
	if err != nil {
		return provisioning.ChallengeRecord{}, provisioning.DeviceRecord{}, fmt.Errorf("load provisioning challenge: %w", err)
	}
	if len(nonceDigest) != 32 {
		return provisioning.ChallengeRecord{}, provisioning.DeviceRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "nonce_digest", nil)
	}
	var digest provisioning.TokenDigest
	copy(digest[:], nonceDigest)
	createdAt, err := parseTime(createdAtText)
	if err != nil {
		return provisioning.ChallengeRecord{}, provisioning.DeviceRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "challenge_created_at", err)
	}
	expiresAt, err := parseTime(expiresAtText)
	if err != nil {
		return provisioning.ChallengeRecord{}, provisioning.DeviceRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "challenge_expires_at", err)
	}
	challenge := provisioning.ChallengeRecord{
		ID:          challengeID,
		DeviceID:    provisioning.DeviceID(deviceID),
		NonceDigest: digest,
		Audience:    audience,
		Purpose:     provisioning.ChallengePurpose(purpose),
		CreatedAt:   createdAt,
		ExpiresAt:   expiresAt,
	}
	if consumedAtText.Valid {
		consumedAt, err := parseTime(consumedAtText.String)
		if err != nil {
			return provisioning.ChallengeRecord{}, provisioning.DeviceRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "challenge_consumed_at", err)
		}
		challenge.ConsumedAt = &consumedAt
	}
	device, err := provisioningDeviceFromValues(
		id,
		usernameValue,
		invitationID,
		algorithm,
		publicKeySPKI,
		boundAtText,
		revokedAtText,
	)
	if err != nil {
		return provisioning.ChallengeRecord{}, provisioning.DeviceRecord{}, err
	}
	return challenge, device, nil
}

func (s *Store) RedeemInvitation(ctx context.Context, command provisioning.RedeemCommand) (provisioning.RedemptionRecord, error) {
	if command.ProtocolVersion < 2 || command.ProtocolVersion > 3 ||
		!validRegistrationIdempotencyKey(command.IdempotencyKey) || command.DeviceID == "" || command.SessionID == "" ||
		command.RedeemedAt.IsZero() || !command.SessionExpiresAt.After(command.RedeemedAt) ||
		len(command.ProtectedSessionToken) < 61 || len(command.ProtectedSessionToken) > 512 {
		return provisioning.RedemptionRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "redemption", nil)
	}
	username, err := provisioning.ParseUsername(string(command.Username))
	if err != nil || username != command.Username {
		return provisioning.RedemptionRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "redemption", err)
	}
	identityPublicKey := command.DeviceKey.SubjectPublicKeyInfo()
	if len(identityPublicKey) == 0 {
		return provisioning.RedemptionRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "redemption", nil)
	}
	defer clear(identityPublicKey)
	encryptionPublicKey := command.EncryptionKey.SubjectPublicKeyInfo()
	if len(encryptionPublicKey) == 0 {
		return provisioning.RedemptionRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "encryption_key", nil)
	}
	defer clear(encryptionPublicKey)

	connection, err := s.db.Conn(ctx)
	if err != nil {
		return provisioning.RedemptionRecord{}, fmt.Errorf("reserve provisioning connection: %w", err)
	}
	defer connection.Close()
	if _, err := connection.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return provisioning.RedemptionRecord{}, fmt.Errorf("begin provisioning redemption: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = connection.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	if existing, found, err := loadRegistrationAttempt(ctx, connection, command); err != nil {
		return provisioning.RedemptionRecord{}, err
	} else if found {
		if _, err := connection.ExecContext(ctx, "COMMIT"); err != nil {
			return provisioning.RedemptionRecord{}, fmt.Errorf("commit registration replay: %w", err)
		}
		committed = true
		return existing, nil
	}

	invitation, err := loadInvitationForRedemption(ctx, connection, command.TokenDigest)
	if err != nil {
		return provisioning.RedemptionRecord{}, err
	}
	if invitation.Username != command.Username {
		return provisioning.RedemptionRecord{}, provisioning.RepositoryError(provisioning.CodeInvitationUser, "username", nil)
	}
	if invitation.RedeemedAt != nil {
		return provisioning.RedemptionRecord{}, provisioning.RepositoryError(provisioning.CodeInvitationUsed, "token", nil)
	}
	if !command.RedeemedAt.Before(invitation.ExpiresAt) {
		return provisioning.RedemptionRecord{}, provisioning.RepositoryError(provisioning.CodeInvitationExpired, "token", nil)
	}

	identityFingerprint := command.DeviceKey.Fingerprint()
	encryptionFingerprint := command.EncryptionKey.Fingerprint()
	actualDeviceID := command.DeviceID
	var existingDeviceID string
	var existingRevokedAt sql.NullString
	var existingSecurityState string
	err = connection.QueryRowContext(ctx, `
		SELECT id, revoked_at, security_state FROM provisioning_devices
		WHERE username = ? AND public_key_fingerprint = ?
	`, string(command.Username), identityFingerprint[:]).Scan(&existingDeviceID, &existingRevokedAt, &existingSecurityState)
	switch {
	case err == nil:
		if existingRevokedAt.Valid {
			return provisioning.RedemptionRecord{}, provisioning.RepositoryError(provisioning.CodeUnknownDevice, "device_key", nil)
		}
		actualDeviceID = provisioning.DeviceID(existingDeviceID)
		var storedEncryptionFingerprint []byte
		err = connection.QueryRowContext(ctx, `
			SELECT fingerprint FROM device_encryption_keys WHERE device_id = ?
		`, existingDeviceID).Scan(&storedEncryptionFingerprint)
		if err == nil {
			defer clear(storedEncryptionFingerprint)
			if !hmac.Equal(storedEncryptionFingerprint, encryptionFingerprint[:]) {
				return provisioning.RedemptionRecord{}, provisioning.RepositoryError(provisioning.CodeConflict, "encryption_key", nil)
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return provisioning.RedemptionRecord{}, fmt.Errorf("load existing encryption key: %w", err)
		}
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return provisioning.RedemptionRecord{}, fmt.Errorf("find existing device: %w", err)
	}

	authenticationState := provisioning.AuthenticationStateReady
	if existingDeviceID != "" {
		authenticationState = provisioning.AuthenticationState(existingSecurityState)
	} else if command.ProtocolVersion >= 3 {
		var readyDeviceCount int
		if err := connection.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM provisioning_devices
			WHERE username = ? AND revoked_at IS NULL AND security_state = 'READY'
		`, string(command.Username)).Scan(&readyDeviceCount); err != nil {
			return provisioning.RedemptionRecord{}, fmt.Errorf("count trusted devices: %w", err)
		}
		if readyDeviceCount > 0 {
			authenticationState = provisioning.AuthenticationStateAuthenticatedNoKeys
		}
	}

	if existingDeviceID == "" {
		if _, err := connection.ExecContext(ctx, `
			INSERT INTO provisioning_devices (
				id, username, invitation_id, key_algorithm, public_key_spki,
				public_key_fingerprint, bound_at, security_state
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, string(actualDeviceID), string(command.Username), string(invitation.ID),
			string(command.DeviceKey.Algorithm()), identityPublicKey, identityFingerprint[:],
			formatTime(command.RedeemedAt), string(authenticationState)); err != nil {
			return provisioning.RedemptionRecord{}, mapRedemptionWriteError("device", err)
		}
	}

	if _, err := connection.ExecContext(ctx, `
		INSERT INTO device_encryption_keys(device_id, algorithm, public_key_spki, fingerprint, registered_at)
		VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(device_id) DO NOTHING
	`, string(actualDeviceID), command.EncryptionKey.Algorithm(), encryptionPublicKey,
		encryptionFingerprint[:], formatTime(command.RedeemedAt)); err != nil {
		return provisioning.RedemptionRecord{}, mapRedemptionWriteError("encryption_key", err)
	}
	if _, err := connection.ExecContext(ctx, `
		INSERT INTO device_keys(device_id, purpose, algorithm, public_key_spki, fingerprint, created_at)
		VALUES(?, 'signing', ?, ?, ?, ?)
		ON CONFLICT(device_id, purpose) DO NOTHING
	`, string(actualDeviceID), string(command.DeviceKey.Algorithm()), identityPublicKey,
		identityFingerprint[:], formatTime(command.RedeemedAt)); err != nil {
		return provisioning.RedemptionRecord{}, mapRedemptionWriteError("signing_key", err)
	}
	if _, err := connection.ExecContext(ctx, `
		INSERT INTO device_keys(device_id, purpose, algorithm, public_key_spki, fingerprint, created_at)
		VALUES(?, 'key_agreement', ?, ?, ?, ?)
		ON CONFLICT(device_id, purpose) DO NOTHING
	`, string(actualDeviceID), command.EncryptionKey.Algorithm(), encryptionPublicKey,
		encryptionFingerprint[:], formatTime(command.RedeemedAt)); err != nil {
		return provisioning.RedemptionRecord{}, mapRedemptionWriteError("key_agreement_key", err)
	}

	if _, err := connection.ExecContext(ctx, `
		INSERT INTO provisioning_sessions (
			id, device_id, token_digest, issued_at, expires_at, protocol_version
		) VALUES (?, ?, ?, ?, ?, ?)
	`, string(command.SessionID), string(actualDeviceID), command.SessionTokenDigest.Bytes(),
		formatTime(command.RedeemedAt), formatTime(command.SessionExpiresAt), command.ProtocolVersion); err != nil {
		return provisioning.RedemptionRecord{}, mapRedemptionWriteError("session", err)
	}
	result, err := connection.ExecContext(ctx, `
		UPDATE provisioning_invitations
		SET redeemed_at = ?, redeemed_by_device_id = ?
		WHERE id = ? AND redeemed_at IS NULL
	`, formatTime(command.RedeemedAt), string(actualDeviceID), string(invitation.ID))
	if err != nil {
		return provisioning.RedemptionRecord{}, mapRedemptionWriteError("invitation", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return provisioning.RedemptionRecord{}, fmt.Errorf("inspect invitation redemption: %w", err)
	}
	if rows != 1 {
		return provisioning.RedemptionRecord{}, provisioning.RepositoryError(provisioning.CodeInvitationUsed, "token", nil)
	}
	if authenticationState == provisioning.AuthenticationStateAuthenticatedNoKeys {
		if _, err := connection.ExecContext(ctx, `
			INSERT INTO device_provisioning_requests(
				id, username, target_device_id, request_digest, protocol_version,
				requested_at, expires_at, display_name, platform, network_hint
			) VALUES(lower(hex(randomblob(16))), ?, ?, ?, ?, ?, ?, '', '', '')
		`, string(command.Username), string(actualDeviceID), command.RequestDigest.Bytes(), command.ProtocolVersion,
			formatTime(command.RedeemedAt), formatTime(command.RedeemedAt.Add(15*time.Minute))); err != nil {
			return provisioning.RedemptionRecord{}, mapRedemptionWriteError("provisioning_request", err)
		}
	}
	if _, err := connection.ExecContext(ctx, `
		INSERT INTO registration_attempts (
			idempotency_key, request_digest, invitation_id, username, device_id,
			session_id, protected_session_token, protocol_version, created_at, completed_at,
			authentication_state
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, command.IdempotencyKey, command.RequestDigest.Bytes(), string(invitation.ID), string(command.Username),
		string(actualDeviceID), string(command.SessionID), command.ProtectedSessionToken, command.ProtocolVersion,
		formatTime(command.RedeemedAt), formatTime(command.RedeemedAt), string(authenticationState)); err != nil {
		return provisioning.RedemptionRecord{}, mapRedemptionWriteError("registration_attempt", err)
	}
	if _, err := connection.ExecContext(ctx, `
		INSERT INTO security_audit_events(event_id, username, device_id, event_type, outcome, protocol_version, occurred_at, metadata)
		VALUES(lower(hex(randomblob(16))), ?, ?, 'device.registration', 'success', ?, ?, '{}')
	`, string(command.Username), string(actualDeviceID), command.ProtocolVersion, formatTime(command.RedeemedAt)); err != nil {
		return provisioning.RedemptionRecord{}, fmt.Errorf("record registration audit event: %w", err)
	}
	if _, err := connection.ExecContext(ctx, "COMMIT"); err != nil {
		return provisioning.RedemptionRecord{}, fmt.Errorf("commit provisioning redemption: %w", err)
	}
	committed = true

	redeemedAt := command.RedeemedAt
	device := provisioning.DeviceRecord{
		ID:                  actualDeviceID,
		Username:            command.Username,
		PublicKey:           command.DeviceKey,
		BoundByInvitationID: invitation.ID,
		BoundAt:             redeemedAt,
	}
	if existingDeviceID != "" {
		loaded, err := loadProvisioningDeviceByID(ctx, s.db, actualDeviceID)
		if err != nil {
			return provisioning.RedemptionRecord{}, err
		}
		device = loaded
	}
	invitation.RedeemedAt = &redeemedAt
	invitation.RedeemedByDeviceID = device.ID
	return provisioning.RedemptionRecord{
		Invitation:            invitation.Redacted(),
		Device:                device.Redacted(),
		Session:               provisioning.SessionView{ID: command.SessionID, IssuedAt: command.RedeemedAt, ExpiresAt: command.SessionExpiresAt},
		AuthenticationState:   authenticationState,
		ProtectedSessionToken: append([]byte(nil), command.ProtectedSessionToken...),
	}, nil
}

func loadRegistrationAttempt(
	ctx context.Context,
	connection *sql.Conn,
	command provisioning.RedeemCommand,
) (provisioning.RedemptionRecord, bool, error) {
	var (
		requestDigest         []byte
		invitationID          string
		username              string
		deviceID              string
		sessionID             string
		protectedSessionToken []byte
		protocolVersion       int
		authenticationState   string
	)
	err := connection.QueryRowContext(ctx, `
		SELECT request_digest, invitation_id, username, device_id, session_id,
		       protected_session_token, protocol_version, authentication_state
		FROM registration_attempts
		WHERE idempotency_key = ?
	`, command.IdempotencyKey).Scan(
		&requestDigest,
		&invitationID,
		&username,
		&deviceID,
		&sessionID,
		&protectedSessionToken,
		&protocolVersion,
		&authenticationState,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return provisioning.RedemptionRecord{}, false, nil
	}
	if err != nil {
		return provisioning.RedemptionRecord{}, false, fmt.Errorf("load registration attempt: %w", err)
	}
	defer clear(requestDigest)
	if !hmac.Equal(requestDigest, command.RequestDigest[:]) || username != string(command.Username) || protocolVersion != command.ProtocolVersion {
		clear(protectedSessionToken)
		return provisioning.RedemptionRecord{}, false, provisioning.RepositoryError(provisioning.CodeConflict, "idempotency_key", nil)
	}
	invitation, err := loadInvitationByID(ctx, connection, provisioning.InvitationID(invitationID))
	if err != nil {
		clear(protectedSessionToken)
		return provisioning.RedemptionRecord{}, false, err
	}
	device, err := loadProvisioningDeviceByID(ctx, connection, provisioning.DeviceID(deviceID))
	if err != nil {
		clear(protectedSessionToken)
		return provisioning.RedemptionRecord{}, false, err
	}
	var issuedAtText, expiresAtText string
	if err := connection.QueryRowContext(ctx, `
		SELECT issued_at, expires_at FROM provisioning_sessions WHERE id = ? AND device_id = ?
	`, sessionID, deviceID).Scan(&issuedAtText, &expiresAtText); err != nil {
		clear(protectedSessionToken)
		return provisioning.RedemptionRecord{}, false, fmt.Errorf("load replayed registration session: %w", err)
	}
	issuedAt, err := parseTime(issuedAtText)
	if err != nil {
		clear(protectedSessionToken)
		return provisioning.RedemptionRecord{}, false, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "session_issued_at", err)
	}
	expiresAt, err := parseTime(expiresAtText)
	if err != nil {
		clear(protectedSessionToken)
		return provisioning.RedemptionRecord{}, false, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "session_expires_at", err)
	}
	return provisioning.RedemptionRecord{
		Invitation:            invitation.Redacted(),
		Device:                device.Redacted(),
		Session:               provisioning.SessionView{ID: provisioning.SessionID(sessionID), IssuedAt: issuedAt, ExpiresAt: expiresAt},
		AuthenticationState:   provisioning.AuthenticationState(authenticationState),
		ProtectedSessionToken: protectedSessionToken,
	}, true, nil
}

func loadProvisioningDeviceByID(
	ctx context.Context,
	queryer queryRower,
	deviceID provisioning.DeviceID,
) (provisioning.DeviceRecord, error) {
	row := queryer.QueryRowContext(ctx, `
		SELECT id, username, invitation_id, key_algorithm, public_key_spki, bound_at, revoked_at
		FROM provisioning_devices WHERE id = ?
	`, string(deviceID))
	device, err := scanProvisioningDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return provisioning.DeviceRecord{}, provisioning.RepositoryError(provisioning.CodeUnknownDevice, "device_id", nil)
	}
	if err != nil {
		return provisioning.DeviceRecord{}, fmt.Errorf("load provisioning device: %w", err)
	}
	return device, nil
}

func loadInvitationByID(
	ctx context.Context,
	queryer queryRower,
	invitationID provisioning.InvitationID,
) (provisioning.InvitationRecord, error) {
	var (
		id                 string
		username           string
		tokenDigest        []byte
		createdAtText      string
		expiresAtText      string
		redeemedAtText     sql.NullString
		redeemedByDeviceID sql.NullString
	)
	err := queryer.QueryRowContext(ctx, `
		SELECT id, username, token_digest, created_at, expires_at, redeemed_at, redeemed_by_device_id
		FROM provisioning_invitations WHERE id = ?
	`, string(invitationID)).Scan(
		&id, &username, &tokenDigest, &createdAtText, &expiresAtText, &redeemedAtText, &redeemedByDeviceID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return provisioning.InvitationRecord{}, provisioning.RepositoryError(provisioning.CodeInvitationNotFound, "invitation_id", nil)
	}
	if err != nil {
		return provisioning.InvitationRecord{}, fmt.Errorf("load provisioning invitation by id: %w", err)
	}
	defer clear(tokenDigest)
	if len(tokenDigest) != 32 {
		return provisioning.InvitationRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "token_digest", nil)
	}
	parsedUsername, err := provisioning.ParseUsername(username)
	if err != nil {
		return provisioning.InvitationRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "invitation_username", err)
	}
	createdAt, err := parseTime(createdAtText)
	if err != nil {
		return provisioning.InvitationRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "created_at", err)
	}
	expiresAt, err := parseTime(expiresAtText)
	if err != nil {
		return provisioning.InvitationRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "expires_at", err)
	}
	var digest provisioning.TokenDigest
	copy(digest[:], tokenDigest)
	record := provisioning.InvitationRecord{
		ID: provisioning.InvitationID(id), Username: parsedUsername, TokenDigest: digest,
		CreatedAt: createdAt, ExpiresAt: expiresAt,
	}
	if redeemedAtText.Valid {
		value, err := parseTime(redeemedAtText.String)
		if err != nil {
			return provisioning.InvitationRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "redeemed_at", err)
		}
		record.RedeemedAt = &value
	}
	if redeemedByDeviceID.Valid {
		record.RedeemedByDeviceID = provisioning.DeviceID(redeemedByDeviceID.String)
	}
	return record, nil
}

func validRegistrationIdempotencyKey(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func loadInvitationForRedemption(ctx context.Context, connection *sql.Conn, digest provisioning.TokenDigest) (provisioning.InvitationRecord, error) {
	var (
		id                 string
		username           string
		createdAtText      string
		expiresAtText      string
		redeemedAtText     sql.NullString
		redeemedByDeviceID sql.NullString
	)
	err := connection.QueryRowContext(ctx, `
		SELECT id, username, created_at, expires_at, redeemed_at, redeemed_by_device_id
		FROM provisioning_invitations
		WHERE token_digest = ?
	`, digest.Bytes()).Scan(&id, &username, &createdAtText, &expiresAtText, &redeemedAtText, &redeemedByDeviceID)
	if errors.Is(err, sql.ErrNoRows) {
		return provisioning.InvitationRecord{}, provisioning.RepositoryError(provisioning.CodeInvitationNotFound, "token", nil)
	}
	if err != nil {
		return provisioning.InvitationRecord{}, fmt.Errorf("load provisioning invitation: %w", err)
	}
	parsedUsername, err := provisioning.ParseUsername(username)
	if err != nil {
		return provisioning.InvitationRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "invitation", err)
	}
	createdAt, err := parseTime(createdAtText)
	if err != nil {
		return provisioning.InvitationRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "created_at", err)
	}
	expiresAt, err := parseTime(expiresAtText)
	if err != nil {
		return provisioning.InvitationRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "expires_at", err)
	}
	record := provisioning.InvitationRecord{
		ID:          provisioning.InvitationID(id),
		Username:    parsedUsername,
		TokenDigest: digest,
		CreatedAt:   createdAt,
		ExpiresAt:   expiresAt,
	}
	if redeemedAtText.Valid {
		value, err := parseTime(redeemedAtText.String)
		if err != nil {
			return provisioning.InvitationRecord{}, provisioning.RepositoryError(provisioning.CodeInvariantViolation, "redeemed_at", err)
		}
		record.RedeemedAt = &value
	}
	if redeemedByDeviceID.Valid {
		record.RedeemedByDeviceID = provisioning.DeviceID(redeemedByDeviceID.String)
	}
	return record, nil
}

func mapRedemptionWriteError(field string, err error) error {
	if isConstraintError(err) {
		return provisioning.RepositoryError(provisioning.CodeConflict, field, err)
	}
	return fmt.Errorf("write provisioning %s: %w", field, err)
}

func isConstraintError(err error) bool {
	var sqliteError *moderncsqlite.Error
	if !errors.As(err, &sqliteError) {
		return false
	}
	code := sqliteError.Code()
	return code == sqlite3.SQLITE_CONSTRAINT || code&0xff == sqlite3.SQLITE_CONSTRAINT
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, value)
}
