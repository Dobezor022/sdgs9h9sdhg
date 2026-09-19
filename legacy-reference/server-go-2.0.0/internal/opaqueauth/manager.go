package opaqueauth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	cryptocore "fedmes/crypto/core"

	"github.com/bytemare/opaque"
	"github.com/google/uuid"
)

const (
	keyMaterialFileName = "opaque-server-key-material.bin"
	attemptTTL          = 5 * time.Minute
	sessionTTL          = 24 * time.Hour
)

type loginSecret struct {
	ExpectedClientMAC []byte
	SessionSecret     []byte
	Known             bool
	Username          string
	ExpiresAt         time.Time
}

type Manager struct {
	db             *sql.DB
	configuration  *opaque.Configuration
	server         *opaque.Server
	keyMaterial    *opaque.ServerKeyMaterial
	serverIdentity []byte
	resultKey      []byte
	now            func() time.Time
	mu             sync.Mutex
	loginSecrets   map[string]loginSecret
}

func Open(db *sql.DB, dataDirectory, serverIdentity string, resultKey []byte) (*Manager, error) {
	if db == nil || len(resultKey) != 32 || strings.TrimSpace(serverIdentity) == "" {
		return nil, ErrInvalidRequest
	}
	configuration := opaque.DefaultConfiguration()
	material, err := loadOrCreateKeyMaterial(configuration, dataDirectory, []byte(serverIdentity))
	if err != nil {
		return nil, err
	}
	server, err := configuration.Server()
	if err != nil {
		material.Flush()
		return nil, err
	}
	if err := server.SetKeyMaterial(material); err != nil {
		material.Flush()
		return nil, err
	}
	return &Manager{
		db: db, configuration: configuration, server: server, keyMaterial: material,
		serverIdentity: []byte(serverIdentity), resultKey: append([]byte(nil), resultKey...),
		now: time.Now, loginSecrets: make(map[string]loginSecret),
	}, nil
}

func (m *Manager) Close() {
	m.mu.Lock()
	for id, secret := range m.loginSecrets {
		zero(secret.ExpectedClientMAC)
		zero(secret.SessionSecret)
		delete(m.loginSecrets, id)
	}
	m.mu.Unlock()
	zero(m.serverIdentity)
	zero(m.resultKey)
	if m.keyMaterial != nil {
		m.keyMaterial.Flush()
	}
}

func (m *Manager) ServerIdentity() string { return string(m.serverIdentity) }

func (m *Manager) RegistrationStart(ctx context.Context, principal Principal, input RegistrationStartInput) (RegistrationStartResult, error) {
	if principal.Username == "" || principal.DeviceID == "" || input.Username != principal.Username ||
		(input.Operation != "enroll" && input.Operation != "password_change") || len(input.RegistrationRequest) < 16 ||
		len(input.RegistrationRequest) > 65536 || len(input.RequestID) < 16 || len(input.RequestID) > 128 {
		return RegistrationStartResult{}, ErrInvalidRequest
	}
	if err := m.requireReadyDevice(ctx, principal); err != nil {
		return RegistrationStartResult{}, err
	}

	now := m.now().UTC()
	var existing RegistrationStartResult
	var existingDigest []byte
	var response []byte
	var expires string
	err := m.db.QueryRowContext(ctx, `
		SELECT id, request_digest, response_message, expires_at, completed_at
		FROM opaque_registration_attempts
		WHERE username=? AND request_digest=?
		ORDER BY created_at DESC LIMIT 1`, input.Username, input.RequestDigest[:]).Scan(
		&existing.AttemptID, &existingDigest, &response, &expires, new(sql.NullString),
	)
	if err == nil {
		if !hmac.Equal(existingDigest, input.RequestDigest[:]) {
			return RegistrationStartResult{}, ErrReplayed
		}
		existing.Response = response
		existing.Suite = Suite
		existing.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
		existing.Replayed = true
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return RegistrationStartResult{}, err
	}

	request, err := m.server.Deserialize.RegistrationRequest(input.RegistrationRequest)
	if err != nil {
		return RegistrationStartResult{}, ErrInvalidRequest
	}
	credentialID := opaque.RandomBytes(64)
	defer zero(credentialID)
	registrationResponse, err := m.server.RegistrationResponse(request, credentialID, nil)
	if err != nil {
		return RegistrationStartResult{}, err
	}
	attemptID := uuid.NewString()
	expiresAt := now.Add(attemptTTL)
	response = registrationResponse.Serialize()
	_, err = m.db.ExecContext(ctx, `
		INSERT INTO opaque_registration_attempts(
			id,username,authorizing_device_id,operation,suite,credential_identifier,
			request_digest,response_message,created_at,expires_at
		) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		attemptID, input.Username, principal.DeviceID, input.Operation, Suite, credentialID,
		input.RequestDigest[:], response, now.Format(time.RFC3339Nano), expiresAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return RegistrationStartResult{}, err
	}
	return RegistrationStartResult{AttemptID: attemptID, Response: response, Suite: Suite, ExpiresAt: expiresAt}, nil
}

func (m *Manager) RegistrationFinish(ctx context.Context, principal Principal, input RegistrationFinishInput) error {
	if principal.Username == "" || principal.DeviceID == "" || len(input.AttemptID) < 16 ||
		len(input.RegistrationRecord) < 32 || len(input.RegistrationRecord) > 65536 {
		return ErrInvalidRequest
	}
	if err := m.requireReadyDevice(ctx, principal); err != nil {
		return err
	}
	now := m.now().UTC()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var username, authorizingDevice, operation, suite, expires string
	var credentialID []byte
	var completed sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT username,authorizing_device_id,operation,suite,credential_identifier,expires_at,completed_at
		FROM opaque_registration_attempts WHERE id=?`, input.AttemptID).Scan(
		&username, &authorizingDevice, &operation, &suite, &credentialID, &expires, &completed,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if username != principal.Username || authorizingDevice != principal.DeviceID || suite != Suite {
		return ErrForbidden
	}
	if completed.Valid {
		return nil
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || !now.Before(expiresAt) {
		return ErrExpired
	}
	record, err := m.server.Deserialize.RegistrationRecord(input.RegistrationRecord)
	if err != nil {
		return ErrInvalidRequest
	}
	// Deserialization validates the record in the configured OPAQUE suite. The
	// server stores only this opaque envelope and the stable credential id.
	_ = record
	timestamp := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO opaque_records(
			username,suite,record_version,registration_record,credential_identifier,
			enrolled_by_device_id,enrolled_at,updated_at,disabled_at
		) VALUES(?,?,?,?,?,?,?,?,NULL)
		ON CONFLICT(username) DO UPDATE SET
			suite=excluded.suite,record_version=excluded.record_version,
			registration_record=excluded.registration_record,
			credential_identifier=excluded.credential_identifier,
			enrolled_by_device_id=excluded.enrolled_by_device_id,
			updated_at=excluded.updated_at,disabled_at=NULL`,
		username, Suite, 1, input.RegistrationRecord, credentialID, principal.DeviceID, timestamp, timestamp,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE opaque_registration_attempts SET completed_at=? WHERE id=?`, timestamp, input.AttemptID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE account_security_state SET opaque_enrolled=1,updated_at=? WHERE username=?`, timestamp, username); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO security_audit_events(event_id,username,device_id,event_type,outcome,protocol_version,occurred_at,metadata)
		VALUES(?,?,?,?,?,?,?,?)`, uuid.NewString(), username, principal.DeviceID, "opaque."+operation, "success", ProtocolVersion, timestamp, `{}`); err != nil {
		return err
	}
	return tx.Commit()
}

func (m *Manager) LoginStart(ctx context.Context, input LoginStartInput) (LoginStartResult, error) {
	if !validUsername(input.Username) || len(input.KE1) < 16 || len(input.KE1) > 65536 ||
		len(input.ProposedDeviceID) < 16 || len(input.ProposedDeviceID) > 128 || len(input.DisplayName) > 96 ||
		len(input.Platform) < 2 || len(input.Platform) > 64 || !validSigningAlgorithm(input.SigningAlgorithm) ||
		!validAgreementAlgorithm(input.AgreementAlgorithm) || len(input.SigningPublicKeySPKI) < 32 || len(input.SigningPublicKeySPKI) > 2048 ||
		len(input.AgreementPublicKeySPKI) < 32 || len(input.AgreementPublicKeySPKI) > 2048 || len(input.RequestID) < 16 || len(input.RequestID) > 128 {
		return LoginStartResult{}, ErrInvalidRequest
	}
	now := m.now().UTC()
	var existing LoginStartResult
	var existingDigest []byte
	var expires string
	var existingResponse []byte
	err := m.db.QueryRowContext(ctx, `
		SELECT id,request_digest,response_message,expires_at
		FROM opaque_login_attempts WHERE request_digest=?`, input.RequestDigest[:]).Scan(
		&existing.AttemptID, &existingDigest, &existingResponse, &expires,
	)
	if err == nil {
		if !hmac.Equal(existingDigest, input.RequestDigest[:]) {
			return LoginStartResult{}, ErrReplayed
		}
		existing.KE2 = existingResponse
		existing.Suite = Suite
		existing.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
		existing.Replayed = true
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return LoginStartResult{}, err
	}

	ke1, err := m.server.Deserialize.KE1(input.KE1)
	if err != nil {
		return LoginStartResult{}, ErrAuthentication
	}
	credentialDigest := sha256.Sum256([]byte("fedmes-opaque-credential-v1\n" + input.Username))
	credentialID := credentialDigest[:]
	var registrationRecord []byte
	var storedCredentialID []byte
	var disabled sql.NullString
	err = m.db.QueryRowContext(ctx, `
		SELECT registration_record,credential_identifier,disabled_at
		FROM opaque_records WHERE username=?`, input.Username).Scan(&registrationRecord, &storedCredentialID, &disabled)
	known := err == nil && !disabled.Valid
	var record *opaque.ClientRecord
	if known {
		decodedRecord, decodeErr := m.server.Deserialize.RegistrationRecord(registrationRecord)
		if decodeErr != nil {
			return LoginStartResult{}, decodeErr
		}
		record = &opaque.ClientRecord{
			CredentialIdentifier: storedCredentialID,
			ClientIdentity:       []byte(input.Username),
			RegistrationRecord:   decodedRecord,
		}
	} else {
		record, err = m.configuration.GetFakeRecord(credentialID)
		if err != nil {
			return LoginStartResult{}, err
		}
	}
	ke2, output, err := m.server.GenerateKE2(ke1, record)
	if err != nil {
		return LoginStartResult{}, ErrAuthentication
	}
	attemptID := uuid.NewString()
	expiresAt := now.Add(attemptTTL)
	response := ke2.Serialize()
	usernameHintDigest := sha256.Sum256([]byte(strings.ToLower(input.Username)))
	secret := loginSecret{
		ExpectedClientMAC: append([]byte(nil), output.ClientMAC...),
		SessionSecret:     append([]byte(nil), output.SessionSecret...),
		Known:             known, Username: input.Username, ExpiresAt: expiresAt,
	}
	protectedState, err := m.protectLoginContinuation(attemptID, secret)
	if err != nil {
		zero(secret.ExpectedClientMAC)
		zero(secret.SessionSecret)
		return LoginStartResult{}, err
	}
	defer zero(protectedState)
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		zero(secret.ExpectedClientMAC)
		zero(secret.SessionSecret)
		return LoginStartResult{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO opaque_login_attempts(
			id,username_hint_digest,request_digest,suite,known_credential,proposed_device_id,
			proposed_display_name,proposed_platform,signing_algorithm,signing_public_key_spki,
			key_agreement_algorithm,key_agreement_public_key_spki,response_message,created_at,expires_at
		) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		attemptID, usernameHintDigest[:], input.RequestDigest[:], Suite, boolInt(known), input.ProposedDeviceID,
		input.DisplayName, input.Platform, input.SigningAlgorithm, input.SigningPublicKeySPKI,
		input.AgreementAlgorithm, input.AgreementPublicKeySPKI, response,
		now.Format(time.RFC3339Nano), expiresAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		zero(secret.ExpectedClientMAC)
		zero(secret.SessionSecret)
		return LoginStartResult{}, err
	}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO opaque_login_continuations(attempt_id,protected_state,created_at,expires_at)
		VALUES(?,?,?,?)`, attemptID, protectedState, now.Format(time.RFC3339Nano), expiresAt.Format(time.RFC3339Nano)); err != nil {
		zero(secret.ExpectedClientMAC)
		zero(secret.SessionSecret)
		return LoginStartResult{}, err
	}
	if err = tx.Commit(); err != nil {
		zero(secret.ExpectedClientMAC)
		zero(secret.SessionSecret)
		return LoginStartResult{}, err
	}
	m.storeLoginSecret(attemptID, secret)
	zero(output.ClientMAC)
	zero(output.SessionSecret)
	return LoginStartResult{AttemptID: attemptID, KE2: response, Suite: Suite, ExpiresAt: expiresAt}, nil
}

func (m *Manager) LoginFinish(ctx context.Context, attemptID string, ke3Bytes []byte) (LoginFinishResult, error) {
	if len(attemptID) < 16 || len(ke3Bytes) < 16 || len(ke3Bytes) > 65536 {
		return LoginFinishResult{}, ErrAuthentication
	}
	if replay, ok, err := m.loadLoginResult(ctx, attemptID); err != nil {
		return LoginFinishResult{}, err
	} else if ok {
		replay.Replayed = true
		return replay, nil
	}
	secret, ok := m.loadLoginSecret(ctx, attemptID)
	if !ok {
		return LoginFinishResult{}, ErrServerStateMissing
	}
	defer zero(secret.ExpectedClientMAC)
	defer zero(secret.SessionSecret)
	if !m.now().UTC().Before(secret.ExpiresAt) {
		m.forgetLoginSecret(ctx, attemptID)
		return LoginFinishResult{}, ErrExpired
	}
	ke3, err := m.server.Deserialize.KE3(ke3Bytes)
	if err != nil || m.server.LoginFinish(ke3, secret.ExpectedClientMAC) != nil || !secret.Known {
		m.incrementFailure(ctx, attemptID)
		m.forgetLoginSecret(ctx, attemptID)
		return LoginFinishResult{}, ErrAuthentication
	}

	now := m.now().UTC()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return LoginFinishResult{}, err
	}
	defer tx.Rollback()
	var known int
	var proposedDeviceID, displayName, platform, signingAlgorithm, agreementAlgorithm, expires string
	var signingKey, agreementKey []byte
	var completed sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT known_credential,proposed_device_id,proposed_display_name,proposed_platform,
			signing_algorithm,signing_public_key_spki,key_agreement_algorithm,key_agreement_public_key_spki,
			expires_at,completed_at
		FROM opaque_login_attempts WHERE id=?`, attemptID).Scan(
		&known, &proposedDeviceID, &displayName, &platform, &signingAlgorithm, &signingKey,
		&agreementAlgorithm, &agreementKey, &expires, &completed,
	); err != nil {
		return LoginFinishResult{}, err
	}
	if known != 1 || completed.Valid {
		return LoginFinishResult{}, ErrAuthentication
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, expires)
	if !now.Before(expiresAt) {
		return LoginFinishResult{}, ErrExpired
	}

	// A password login creates a new pending device, never a READY device. History
	// is unlocked only after Recovery Key or a signed provisioning package.
	deviceID := proposedDeviceID
	provisioningRequestID := ""
	var existingUsername string
	var existingRevoked sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT username,revoked_at FROM provisioning_devices WHERE id=?`, deviceID).Scan(&existingUsername, &existingRevoked)
	if err == nil {
		if existingUsername != secret.Username || existingRevoked.Valid {
			return LoginFinishResult{}, ErrAuthentication
		}
		var existingSigningAlgorithm, existingAgreementAlgorithm string
		var existingSigningKey, existingAgreementKey []byte
		var signingRevoked, agreementRevoked sql.NullString
		if keyErr := tx.QueryRowContext(ctx, `
			SELECT signing.algorithm,signing.public_key_spki,signing.revoked_at,
			       agreement.algorithm,agreement.public_key_spki,agreement.revoked_at
			FROM device_keys signing
			JOIN device_keys agreement ON agreement.device_id=signing.device_id AND agreement.purpose='key_agreement'
			WHERE signing.device_id=? AND signing.purpose='signing'`, deviceID).Scan(
			&existingSigningAlgorithm, &existingSigningKey, &signingRevoked,
			&existingAgreementAlgorithm, &existingAgreementKey, &agreementRevoked,
		); keyErr != nil || signingRevoked.Valid || agreementRevoked.Valid ||
			existingSigningAlgorithm != signingAlgorithm || existingAgreementAlgorithm != agreementAlgorithm ||
			!hmac.Equal(existingSigningKey, signingKey) || !hmac.Equal(existingAgreementKey, agreementKey) {
			return LoginFinishResult{}, ErrAuthentication
		}
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return LoginFinishResult{}, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		invitationID := "opaque:" + attemptID
		tokenDigest := sha256.Sum256([]byte("fedmes-opaque-synthetic-invitation\n" + attemptID))
		timestamp := now.Format(time.RFC3339Nano)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO provisioning_invitations(id,username,token_digest,created_at,expires_at,redeemed_at,redeemed_by_device_id)
			VALUES(?,?,?,?,?,?,?)`, invitationID, secret.Username, tokenDigest[:], timestamp, now.Add(time.Minute).Format(time.RFC3339Nano), timestamp, deviceID); err != nil {
			return LoginFinishResult{}, err
		}
		signingFingerprint := sha256.Sum256(signingKey)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO provisioning_devices(
				id,username,invitation_id,key_algorithm,public_key_spki,public_key_fingerprint,bound_at,
				security_state,approved_at
			) VALUES(?,?,?,?,?,?,?,?,NULL)`, deviceID, secret.Username, invitationID, signingAlgorithm,
			signingKey, signingFingerprint[:], timestamp, "AUTHENTICATED_NO_KEYS"); err != nil {
			return LoginFinishResult{}, err
		}
		agreementFingerprint := sha256.Sum256(agreementKey)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO device_keys(device_id,purpose,algorithm,public_key_spki,fingerprint,created_at)
			VALUES(?,?,?,?,?,?),(?,?,?,?,?,?)`,
			deviceID, "signing", signingAlgorithm, signingKey, signingFingerprint[:], timestamp,
			deviceID, "key_agreement", agreementAlgorithm, agreementKey, agreementFingerprint[:], timestamp); err != nil {
			return LoginFinishResult{}, err
		}
		requestDigest := sha256.Sum256(bytes.Join([][]byte{[]byte(secret.Username), signingKey, agreementKey}, []byte{0}))
		provisioningRequestID = uuid.NewString()
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO device_provisioning_requests(
				id,username,target_device_id,request_digest,protocol_version,requested_at,expires_at,
				display_name,platform,network_hint
			) VALUES(?,?,?,?,?,?,?,?,?,?)`, provisioningRequestID, secret.Username, deviceID, requestDigest[:], ProtocolVersion,
			timestamp, now.Add(24*time.Hour).Format(time.RFC3339Nano), displayName, platform, "opaque-login"); err != nil {
			return LoginFinishResult{}, err
		}
	} else {
		_ = tx.QueryRowContext(ctx, `SELECT id FROM device_provisioning_requests WHERE target_device_id=? AND completed_at IS NULL AND rejected_at IS NULL ORDER BY requested_at DESC LIMIT 1`, deviceID).Scan(&provisioningRequestID)
	}
	sessionToken := make([]byte, 32)
	if _, err := rand.Read(sessionToken); err != nil {
		return LoginFinishResult{}, err
	}
	defer zero(sessionToken)
	tokenDigest := sha256.Sum256(sessionToken)
	sessionID := uuid.NewString()
	sessionExpires := now.Add(sessionTTL)
	timestamp := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO provisioning_sessions(
			id,device_id,token_digest,issued_at,expires_at,protocol_version,opaque_authenticated_at,authentication_method
		) VALUES(?,?,?,?,?,?,?,?)`, sessionID, deviceID, tokenDigest[:], timestamp,
		sessionExpires.Format(time.RFC3339Nano), ProtocolVersion, timestamp, "opaque"); err != nil {
		return LoginFinishResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE account_security_state SET state='AUTHENTICATED_NO_KEYS',protocol_version=?,updated_at=?
		WHERE username=? AND state<>'READY'`, ProtocolVersion, timestamp, secret.Username); err != nil {
		return LoginFinishResult{}, err
	}
	protectedToken, err := m.protectSessionToken(attemptID, sessionToken)
	if err != nil {
		return LoginFinishResult{}, err
	}
	serverProof := hmacSHA256(secret.SessionSecret, []byte("fedmes-opaque-server-proof-v1\n"+attemptID+"\n"+deviceID+"\n"+sessionID))
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO opaque_login_results(attempt_id,username,device_id,session_id,protected_session_token,server_session_proof,created_at)
		VALUES(?,?,?,?,?,?,?)`, attemptID, secret.Username, deviceID, sessionID, protectedToken, serverProof, timestamp); err != nil {
		return LoginFinishResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE opaque_login_attempts SET completed_at=? WHERE id=?`, timestamp, attemptID); err != nil {
		return LoginFinishResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO security_audit_events(event_id,username,device_id,event_type,outcome,protocol_version,occurred_at,metadata)
		VALUES(?,?,?,?,?,?,?,?)`, uuid.NewString(), secret.Username, deviceID, "opaque.login", "success", ProtocolVersion, timestamp, `{}`); err != nil {
		return LoginFinishResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return LoginFinishResult{}, err
	}
	m.forgetLoginSecret(ctx, attemptID)
	return LoginFinishResult{
		Username: secret.Username, DeviceID: deviceID, SessionID: sessionID,
		SessionToken:        base64.RawURLEncoding.EncodeToString(sessionToken),
		AuthenticationState: "AUTHENTICATED_NO_KEYS", ProvisioningRequestID: provisioningRequestID, ServerProof: serverProof, ExpiresAt: sessionExpires,
	}, nil
}

func (m *Manager) GetOpaqueRecoveryPackage(ctx context.Context, username string) (RecoveryPackage, error) {
	var out RecoveryPackage
	var hash []byte
	var updated string
	err := m.db.QueryRowContext(ctx, `
		SELECT vault_revision,package_version,nonce,ciphertext,ciphertext_sha256,updated_at
		FROM opaque_recovery_packages WHERE username=?`, username).Scan(
		&out.VaultRevision, &out.PackageVersion, &out.Nonce, &out.Ciphertext, &hash, &updated,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return RecoveryPackage{}, ErrNotFound
	}
	if err != nil {
		return RecoveryPackage{}, err
	}
	if len(hash) != 32 {
		return RecoveryPackage{}, ErrInvalidRequest
	}
	copy(out.CiphertextHash[:], hash)
	out.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return out, nil
}

func (m *Manager) PutOpaqueRecoveryPackage(ctx context.Context, principal Principal, input RecoveryPackage) error {
	if input.VaultRevision <= 0 || input.PackageVersion < 1 || input.PackageVersion > 64 ||
		len(input.Nonce) < 12 || len(input.Nonce) > 24 || len(input.Ciphertext) < 48 || len(input.Ciphertext) > 1<<20 {
		return ErrInvalidRequest
	}
	computed := sha256.Sum256(input.Ciphertext)
	if !hmac.Equal(computed[:], input.CiphertextHash[:]) {
		return ErrInvalidRequest
	}
	if err := m.requireReadyDevice(ctx, principal); err != nil {
		return err
	}
	now := m.now().UTC().Format(time.RFC3339Nano)
	_, err := m.db.ExecContext(ctx, `
		INSERT INTO opaque_recovery_packages(
			username,vault_revision,package_version,nonce,ciphertext,ciphertext_sha256,
			enrolled_by_device_id,created_at,updated_at
		) VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(username) DO UPDATE SET
			vault_revision=excluded.vault_revision,package_version=excluded.package_version,
			nonce=excluded.nonce,ciphertext=excluded.ciphertext,ciphertext_sha256=excluded.ciphertext_sha256,
			enrolled_by_device_id=excluded.enrolled_by_device_id,updated_at=excluded.updated_at`,
		principal.Username, input.VaultRevision, input.PackageVersion, input.Nonce, input.Ciphertext,
		input.CiphertextHash[:], principal.DeviceID, now, now,
	)
	return err
}

func (m *Manager) requireReadyDevice(ctx context.Context, principal Principal) error {
	var state, owner string
	var revoked sql.NullString
	err := m.db.QueryRowContext(ctx, `SELECT username,security_state,revoked_at FROM provisioning_devices WHERE id=?`, principal.DeviceID).Scan(&owner, &state, &revoked)
	if err != nil || owner != principal.Username || revoked.Valid || state != "READY" {
		return ErrForbidden
	}
	return nil
}

func cloneLoginSecret(secret loginSecret) loginSecret {
	return loginSecret{
		ExpectedClientMAC: append([]byte(nil), secret.ExpectedClientMAC...),
		SessionSecret:     append([]byte(nil), secret.SessionSecret...),
		Known:             secret.Known,
		Username:          secret.Username,
		ExpiresAt:         secret.ExpiresAt,
	}
}

func (m *Manager) storeLoginSecret(id string, secret loginSecret) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireSecretsLocked(m.now().UTC())
	if previous, ok := m.loginSecrets[id]; ok {
		zero(previous.ExpectedClientMAC)
		zero(previous.SessionSecret)
	}
	m.loginSecrets[id] = cloneLoginSecret(secret)
}

// loadLoginSecret deliberately leaves the encrypted continuation in SQLite
// until authentication fails, expires, or the transaction containing the
// login result commits. This makes KE3 idempotently retryable after transient
// database errors or a process crash after the client has received KE2.
func (m *Manager) loadLoginSecret(ctx context.Context, id string) (loginSecret, bool) {
	now := m.now().UTC()
	m.mu.Lock()
	m.expireSecretsLocked(now)
	if secret, ok := m.loginSecrets[id]; ok {
		copy := cloneLoginSecret(secret)
		m.mu.Unlock()
		return copy, true
	}
	m.mu.Unlock()

	var protected []byte
	var expires string
	err := m.db.QueryRowContext(ctx, `SELECT protected_state,expires_at FROM opaque_login_continuations WHERE attempt_id=?`, id).Scan(&protected, &expires)
	if err != nil {
		return loginSecret{}, false
	}
	defer zero(protected)
	expiresAt, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || !now.Before(expiresAt) {
		m.forgetLoginSecret(ctx, id)
		return loginSecret{}, false
	}
	secret, err := m.unprotectLoginContinuation(id, protected)
	if err != nil {
		return loginSecret{}, false
	}
	m.storeLoginSecret(id, secret)
	return secret, true
}

func (m *Manager) forgetLoginSecret(ctx context.Context, id string) {
	m.mu.Lock()
	if secret, ok := m.loginSecrets[id]; ok {
		zero(secret.ExpectedClientMAC)
		zero(secret.SessionSecret)
		delete(m.loginSecrets, id)
	}
	m.mu.Unlock()
	_, _ = m.db.ExecContext(ctx, `DELETE FROM opaque_login_continuations WHERE attempt_id=?`, id)
}

func (m *Manager) expireSecretsLocked(now time.Time) {
	for id, secret := range m.loginSecrets {
		if !now.Before(secret.ExpiresAt) {
			zero(secret.ExpectedClientMAC)
			zero(secret.SessionSecret)
			delete(m.loginSecrets, id)
		}
	}
}

func (m *Manager) incrementFailure(ctx context.Context, attemptID string) {
	_, _ = m.db.ExecContext(ctx, `UPDATE opaque_login_attempts SET failure_count=MIN(failure_count+1,32) WHERE id=?`, attemptID)
}

func (m *Manager) loadLoginResult(ctx context.Context, attemptID string) (LoginFinishResult, bool, error) {
	var out LoginFinishResult
	var protected, proof []byte
	var created string
	err := m.db.QueryRowContext(ctx, `
		SELECT username,device_id,session_id,protected_session_token,server_session_proof,created_at
		FROM opaque_login_results WHERE attempt_id=?`, attemptID).Scan(
		&out.Username, &out.DeviceID, &out.SessionID, &protected, &proof, &created,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return LoginFinishResult{}, false, nil
	}
	if err != nil {
		return LoginFinishResult{}, false, err
	}
	token, err := m.unprotectSessionToken(attemptID, protected)
	if err != nil {
		return LoginFinishResult{}, false, err
	}
	defer zero(token)
	var expires string
	if err := m.db.QueryRowContext(ctx, `SELECT expires_at FROM provisioning_sessions WHERE id=? AND revoked_at IS NULL`, out.SessionID).Scan(&expires); err != nil {
		return LoginFinishResult{}, false, ErrAuthentication
	}
	out.SessionToken = base64.RawURLEncoding.EncodeToString(token)
	out.AuthenticationState = "AUTHENTICATED_NO_KEYS"
	_ = m.db.QueryRowContext(ctx, `SELECT id FROM device_provisioning_requests WHERE target_device_id=? AND completed_at IS NULL AND rejected_at IS NULL ORDER BY requested_at DESC LIMIT 1`, out.DeviceID).Scan(&out.ProvisioningRequestID)
	out.ServerProof = proof
	out.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	return out, true, nil
}

type persistedLoginContinuation struct {
	ExpectedClientMAC string `json:"client_mac"`
	SessionSecret     string `json:"session_secret"`
	Known             bool   `json:"known"`
	Username          string `json:"username"`
	ExpiresAt         string `json:"expires_at"`
}

func (m *Manager) protectLoginContinuation(attemptID string, secret loginSecret) ([]byte, error) {
	payload, err := json.Marshal(persistedLoginContinuation{
		ExpectedClientMAC: base64.RawURLEncoding.EncodeToString(secret.ExpectedClientMAC),
		SessionSecret:     base64.RawURLEncoding.EncodeToString(secret.SessionSecret),
		Known:             secret.Known, Username: secret.Username,
		ExpiresAt: secret.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, err
	}
	defer zero(payload)
	return m.protectWithAAD(payload, []byte("opaque-continuation\n"+attemptID))
}

func (m *Manager) unprotectLoginContinuation(attemptID string, protected []byte) (loginSecret, error) {
	payload, err := m.unprotectWithAAD(protected, []byte("opaque-continuation\n"+attemptID))
	if err != nil {
		return loginSecret{}, err
	}
	defer zero(payload)
	var state persistedLoginContinuation
	if err := json.Unmarshal(payload, &state); err != nil {
		return loginSecret{}, err
	}
	mac, err := base64.RawURLEncoding.Strict().DecodeString(state.ExpectedClientMAC)
	if err != nil {
		return loginSecret{}, err
	}
	session, err := base64.RawURLEncoding.Strict().DecodeString(state.SessionSecret)
	if err != nil {
		zero(mac)
		return loginSecret{}, err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, state.ExpiresAt)
	if err != nil || len(mac) == 0 || len(session) == 0 || !validUsername(state.Username) {
		zero(mac)
		zero(session)
		return loginSecret{}, ErrAuthentication
	}
	return loginSecret{ExpectedClientMAC: mac, SessionSecret: session, Known: state.Known, Username: state.Username, ExpiresAt: expiresAt}, nil
}

func (m *Manager) protectWithAAD(value, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.resultKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, aead.Seal(nil, nonce, value, aad)...), nil
}

func (m *Manager) unprotectWithAAD(protected, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.resultKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(protected) <= aead.NonceSize() {
		return nil, ErrAuthentication
	}
	return aead.Open(nil, protected[:aead.NonceSize()], protected[aead.NonceSize():], aad)
}

func (m *Manager) protectSessionToken(attemptID string, token []byte) ([]byte, error) {
	return m.protectWithAAD(token, []byte("opaque-session-token\n"+attemptID))
}

func (m *Manager) unprotectSessionToken(attemptID string, protected []byte) ([]byte, error) {
	return m.unprotectWithAAD(protected, []byte("opaque-session-token\n"+attemptID))
}

func loadOrCreateKeyMaterial(configuration *opaque.Configuration, dataDirectory string, identity []byte) (*opaque.ServerKeyMaterial, error) {
	securityDir := filepath.Join(dataDirectory, "security")
	if err := os.MkdirAll(securityDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(securityDir, keyMaterialFileName)
	if encoded, err := os.ReadFile(path); err == nil {
		material, decodeErr := configuration.DecodeServerKeyMaterial(encoded)
		zero(encoded)
		if decodeErr != nil {
			return nil, fmt.Errorf("decode OPAQUE server key material: %w", decodeErr)
		}
		if !bytes.Equal(material.Identity, identity) {
			material.Flush()
			return nil, errors.New("OPAQUE server identity changed; restore the original key material or explicitly migrate identities")
		}
		return material, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	privateKey, publicKey := configuration.KeyGen()
	material := &opaque.ServerKeyMaterial{
		Identity: append([]byte(nil), identity...), PrivateKey: privateKey,
		PublicKeyBytes: publicKey.Encode(), OPRFGlobalSeed: configuration.GenerateOPRFSeed(),
	}
	encoded := material.Encode()
	defer zero(encoded)
	if err := writePrivateAtomic(path, encoded); err != nil {
		material.Flush()
		return nil, err
	}
	return material, nil
}

func writePrivateAtomic(path string, value []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".opaque-key-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(value); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return os.Chmod(path, 0o600)
}

func validUsername(value string) bool {
	switch value {
	case "grisha", "papa", "mama", "yura", "vasya":
		return true
	default:
		return false
	}
}
func validSigningAlgorithm(value string) bool {
	return value == "ed25519" || value == "ecdsa-p256-sha256"
}
func validAgreementAlgorithm(value string) bool {
	return value == "x25519" || value == "rsa-oaep-sha256" || value == "ecdh-p256"
}
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
func hmacSHA256(key, message []byte) []byte {
	value := hmac.New(sha256.New, key)
	_, _ = value.Write(message)
	return value.Sum(nil)
}
func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

var _ = cryptocore.OpaqueSuite
