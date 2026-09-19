package accountsecurity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) GetAccountState(ctx context.Context, principal Principal) (AccountState, error) {
	var state AccountState
	var recoveryConfigured, opaqueEnrolled int
	var revoked sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT security.username, device.id, device.security_state,
		       security.protocol_version, security.crypto_version,
		       security.vault_revision, security.recovery_configured,
		       security.opaque_enrolled, device.revoked_at
		FROM account_security_state security
		JOIN provisioning_devices device ON device.username = security.username
		WHERE security.username = ? AND device.id = ?
	`, principal.Username, principal.DeviceID).Scan(
		&state.Username,
		&state.DeviceID,
		&state.State,
		&state.ProtocolVersion,
		&state.CryptoVersion,
		&state.VaultRevision,
		&recoveryConfigured,
		&opaqueEnrolled,
		&revoked,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AccountState{}, ErrNotFound
	}
	if err != nil {
		return AccountState{}, fmt.Errorf("load account security state: %w", err)
	}
	if revoked.Valid {
		state.State = StateRevoked
	}
	state.RecoveryConfigured = recoveryConfigured == 1
	state.OpaqueEnrolled = opaqueEnrolled == 1
	return state, nil
}

func (s *Store) GetLatestVault(ctx context.Context, principal Principal) (VaultEnvelope, error) {
	var envelope VaultEnvelope
	var createdAt, updatedAt string
	var hash []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT revision, vault_version, crypto_version, aad_version,
		       nonce, ciphertext, ciphertext_sha256, created_at, updated_at
		FROM encrypted_key_vaults
		WHERE username = ?
		ORDER BY revision DESC
		LIMIT 1
	`, principal.Username).Scan(
		&envelope.Revision,
		&envelope.VaultVersion,
		&envelope.CryptoVersion,
		&envelope.AADVersion,
		&envelope.Nonce,
		&envelope.Ciphertext,
		&hash,
		&createdAt,
		&updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return VaultEnvelope{}, ErrNotFound
	}
	if err != nil {
		return VaultEnvelope{}, fmt.Errorf("load encrypted key vault: %w", err)
	}
	if len(hash) != sha256.Size {
		return VaultEnvelope{}, fmt.Errorf("load encrypted key vault: invalid ciphertext hash")
	}
	copy(envelope.CiphertextHash[:], hash)
	computed := sha256.Sum256(envelope.Ciphertext)
	if !hmac.Equal(computed[:], envelope.CiphertextHash[:]) {
		return VaultEnvelope{}, fmt.Errorf("load encrypted key vault: ciphertext hash mismatch")
	}
	var parseErr error
	if envelope.CreatedAt, parseErr = time.Parse(time.RFC3339Nano, createdAt); parseErr != nil {
		return VaultEnvelope{}, fmt.Errorf("parse vault created_at: %w", parseErr)
	}
	if envelope.UpdatedAt, parseErr = time.Parse(time.RFC3339Nano, updatedAt); parseErr != nil {
		return VaultEnvelope{}, fmt.Errorf("parse vault updated_at: %w", parseErr)
	}
	return envelope, nil
}

func (s *Store) PutVault(ctx context.Context, principal Principal, input VaultWrite, now time.Time) (VaultEnvelope, bool, error) {
	if input.ExpectedPreviousRevision < 0 || input.VaultVersion < 1 || input.VaultVersion > 64 ||
		input.CryptoVersion < 1 || input.CryptoVersion > 64 || input.AADVersion < 1 || input.AADVersion > 64 ||
		len(input.Nonce) < 12 || len(input.Nonce) > 24 || len(input.Ciphertext) < 16 || len(input.Ciphertext) > 16<<20 {
		return VaultEnvelope{}, false, ErrConflict
	}
	computed := sha256.Sum256(input.Ciphertext)
	if isZero(input.AccessVerifier[:]) || !hmac.Equal(computed[:], input.CiphertextHash[:]) {
		return VaultEnvelope{}, false, ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return VaultEnvelope{}, false, err
	}
	defer tx.Rollback()

	if replay, found, err := loadReplayTx(ctx, tx, principal, "vault.put", input.RequestID, input.RequestDigest, now); err != nil {
		return VaultEnvelope{}, false, err
	} else if found {
		var envelope VaultEnvelope
		if err := json.Unmarshal(replay.Body, &envelope); err != nil {
			return VaultEnvelope{}, false, fmt.Errorf("decode replayed vault response: %w", err)
		}
		loaded, loadErr := loadVaultRevisionTx(ctx, tx, principal.Username, envelope.Revision)
		if loadErr != nil {
			return VaultEnvelope{}, false, loadErr
		}
		return loaded, true, tx.Commit()
	}

	if err := requireReadyDeviceTx(ctx, tx, principal); err != nil {
		return VaultEnvelope{}, false, err
	}
	var currentRevision int64
	if err := tx.QueryRowContext(ctx, `
		SELECT vault_revision FROM account_security_state WHERE username = ?
	`, principal.Username).Scan(&currentRevision); err != nil {
		return VaultEnvelope{}, false, fmt.Errorf("load current vault revision: %w", err)
	}
	if currentRevision != input.ExpectedPreviousRevision {
		return VaultEnvelope{}, false, ErrConflict
	}
	nextRevision := currentRevision + 1
	timestamp := now.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO encrypted_key_vaults(
			username, revision, vault_version, crypto_version, aad_version,
			nonce, ciphertext, ciphertext_sha256, access_verifier, created_at, updated_at
		) VALUES(?,?,?,?,?,?,?,?,?,?,?)
	`, principal.Username, nextRevision, input.VaultVersion, input.CryptoVersion, input.AADVersion,
		input.Nonce, input.Ciphertext, input.CiphertextHash[:], input.AccessVerifier[:], timestamp, timestamp); err != nil {
		return VaultEnvelope{}, false, fmt.Errorf("insert encrypted key vault: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE account_security_state
		SET vault_revision = ?, protocol_version = MAX(protocol_version, 3),
		    crypto_version = MAX(crypto_version, ?), updated_at = ?, last_ready_device_id = ?
		WHERE username = ?
	`, nextRevision, input.CryptoVersion, timestamp, principal.DeviceID, principal.Username); err != nil {
		return VaultEnvelope{}, false, fmt.Errorf("update account security state: %w", err)
	}
	envelope := VaultEnvelope{
		Revision: nextRevision, VaultVersion: input.VaultVersion, CryptoVersion: input.CryptoVersion,
		AADVersion: input.AADVersion, Nonce: append([]byte(nil), input.Nonce...),
		Ciphertext: append([]byte(nil), input.Ciphertext...), CiphertextHash: input.CiphertextHash,
		CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}
	body, err := json.Marshal(struct {
		Revision      int64     `json:"revision"`
		VaultVersion  int       `json:"vault_version"`
		CryptoVersion int       `json:"crypto_version"`
		AADVersion    int       `json:"aad_version"`
		CreatedAt     time.Time `json:"created_at"`
		UpdatedAt     time.Time `json:"updated_at"`
	}{nextRevision, input.VaultVersion, input.CryptoVersion, input.AADVersion, now.UTC(), now.UTC()})
	if err != nil {
		return VaultEnvelope{}, false, err
	}
	if err := saveReplayTx(ctx, tx, principal, "vault.put", input.RequestID, input.RequestDigest, 201, body, now); err != nil {
		return VaultEnvelope{}, false, err
	}
	if err := auditTx(ctx, tx, principal, "vault.updated", "success", 3, now, map[string]any{"revision": nextRevision}); err != nil {
		return VaultEnvelope{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return VaultEnvelope{}, false, err
	}
	return envelope, false, nil
}

func loadVaultRevisionTx(ctx context.Context, tx *sql.Tx, username string, revision int64) (VaultEnvelope, error) {
	var envelope VaultEnvelope
	var createdAt, updatedAt string
	var hash []byte
	err := tx.QueryRowContext(ctx, `
		SELECT revision, vault_version, crypto_version, aad_version,
		       nonce, ciphertext, ciphertext_sha256, created_at, updated_at
		FROM encrypted_key_vaults WHERE username = ? AND revision = ?
	`, username, revision).Scan(
		&envelope.Revision, &envelope.VaultVersion, &envelope.CryptoVersion, &envelope.AADVersion,
		&envelope.Nonce, &envelope.Ciphertext, &hash, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return VaultEnvelope{}, ErrNotFound
	}
	if err != nil {
		return VaultEnvelope{}, err
	}
	if len(hash) != sha256.Size {
		return VaultEnvelope{}, ErrConflict
	}
	copy(envelope.CiphertextHash[:], hash)
	envelope.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return VaultEnvelope{}, err
	}
	envelope.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return VaultEnvelope{}, err
	}
	return envelope, nil
}

func (s *Store) PutRecoveryPackage(ctx context.Context, principal Principal, input RecoveryWrite, now time.Time) (RecoveryPackage, bool, error) {
	if input.ID == "" || input.VaultRevision <= 0 || input.PackageVersion < 1 || input.PackageVersion > 64 ||
		input.CryptoVersion < 1 || input.CryptoVersion > 64 || input.AADVersion < 1 || input.AADVersion > 64 ||
		len(input.KDFName) < 3 || len(input.KDFName) > 64 || len(input.KDFParameters) < 2 || len(input.KDFParameters) > 4096 ||
		len(input.Salt) < 16 || len(input.Salt) > 64 || len(input.Nonce) < 12 || len(input.Nonce) > 24 ||
		len(input.Ciphertext) < 16 || len(input.Ciphertext) > 1<<20 {
		return RecoveryPackage{}, false, ErrConflict
	}
	computed := sha256.Sum256(input.Ciphertext)
	if !hmac.Equal(computed[:], input.CiphertextHash[:]) {
		return RecoveryPackage{}, false, ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RecoveryPackage{}, false, err
	}
	defer tx.Rollback()
	if replay, found, err := loadReplayTx(ctx, tx, principal, "recovery.put", input.RequestID, input.RequestDigest, now); err != nil {
		return RecoveryPackage{}, false, err
	} else if found {
		var metadata struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(replay.Body, &metadata); err != nil {
			return RecoveryPackage{}, false, err
		}
		pkg, err := loadRecoveryPackageTx(ctx, tx, principal.Username, metadata.ID)
		if err != nil {
			return RecoveryPackage{}, false, err
		}
		return pkg, true, tx.Commit()
	}
	if err := requireReadyDeviceTx(ctx, tx, principal); err != nil {
		return RecoveryPackage{}, false, err
	}
	var vaultRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT vault_revision FROM account_security_state WHERE username = ?`, principal.Username).Scan(&vaultRevision); err != nil {
		return RecoveryPackage{}, false, err
	}
	if vaultRevision != input.VaultRevision {
		return RecoveryPackage{}, false, ErrConflict
	}
	timestamp := now.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
		UPDATE recovery_packages SET revoked_at = ? WHERE username = ? AND revoked_at IS NULL
	`, timestamp, principal.Username); err != nil {
		return RecoveryPackage{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO recovery_packages(
			id, username, vault_revision, package_version, crypto_version, aad_version,
			kdf_name, kdf_parameters, salt, nonce, ciphertext, created_at, ciphertext_sha256
		) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
	`, input.ID, principal.Username, input.VaultRevision, input.PackageVersion, input.CryptoVersion,
		input.AADVersion, input.KDFName, input.KDFParameters, input.Salt, input.Nonce,
		input.Ciphertext, timestamp, input.CiphertextHash[:]); err != nil {
		return RecoveryPackage{}, false, fmt.Errorf("insert recovery package: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE account_security_state SET recovery_configured = 1, updated_at = ? WHERE username = ?
	`, timestamp, principal.Username); err != nil {
		return RecoveryPackage{}, false, err
	}
	body, _ := json.Marshal(map[string]any{"id": input.ID})
	if err := saveReplayTx(ctx, tx, principal, "recovery.put", input.RequestID, input.RequestDigest, 201, body, now); err != nil {
		return RecoveryPackage{}, false, err
	}
	if err := auditTx(ctx, tx, principal, "recovery.configured", "success", 3, now, map[string]any{"vault_revision": input.VaultRevision}); err != nil {
		return RecoveryPackage{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return RecoveryPackage{}, false, err
	}
	return RecoveryPackage{
		ID: input.ID, VaultRevision: input.VaultRevision, PackageVersion: input.PackageVersion,
		CryptoVersion: input.CryptoVersion, AADVersion: input.AADVersion, KDFName: input.KDFName,
		KDFParameters: input.KDFParameters, Salt: append([]byte(nil), input.Salt...),
		Nonce: append([]byte(nil), input.Nonce...), Ciphertext: append([]byte(nil), input.Ciphertext...),
		CiphertextHash: input.CiphertextHash, CreatedAt: now.UTC(),
	}, false, nil
}

func (s *Store) GetActiveRecoveryPackage(ctx context.Context, principal Principal) (RecoveryPackage, error) {
	return loadRecoveryPackage(ctx, s.db, principal.Username)
}

func loadRecoveryPackage(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, username string) (RecoveryPackage, error) {
	var pkg RecoveryPackage
	var createdAt string
	var hash []byte
	err := queryer.QueryRowContext(ctx, `
		SELECT id, vault_revision, package_version, crypto_version, aad_version,
		       kdf_name, kdf_parameters, salt, nonce, ciphertext,
		       COALESCE(ciphertext_sha256, zeroblob(32)), created_at
		FROM recovery_packages
		WHERE username = ? AND revoked_at IS NULL
		ORDER BY created_at DESC LIMIT 1
	`, username).Scan(
		&pkg.ID, &pkg.VaultRevision, &pkg.PackageVersion, &pkg.CryptoVersion, &pkg.AADVersion,
		&pkg.KDFName, &pkg.KDFParameters, &pkg.Salt, &pkg.Nonce, &pkg.Ciphertext, &hash, &createdAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return RecoveryPackage{}, ErrNotFound
	}
	if err != nil {
		return RecoveryPackage{}, err
	}
	computed := sha256.Sum256(pkg.Ciphertext)
	if len(hash) == sha256.Size && !isZero(hash) && !hmac.Equal(hash, computed[:]) {
		return RecoveryPackage{}, ErrConflict
	}
	pkg.CiphertextHash = computed
	pkg.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return RecoveryPackage{}, err
	}
	return pkg, nil
}

func loadRecoveryPackageTx(ctx context.Context, tx *sql.Tx, username, id string) (RecoveryPackage, error) {
	var pkg RecoveryPackage
	var createdAt string
	var hash []byte
	err := tx.QueryRowContext(ctx, `
		SELECT id, vault_revision, package_version, crypto_version, aad_version,
		       kdf_name, kdf_parameters, salt, nonce, ciphertext,
		       COALESCE(ciphertext_sha256, zeroblob(32)), created_at
		FROM recovery_packages WHERE username = ? AND id = ?
	`, username, id).Scan(
		&pkg.ID, &pkg.VaultRevision, &pkg.PackageVersion, &pkg.CryptoVersion, &pkg.AADVersion,
		&pkg.KDFName, &pkg.KDFParameters, &pkg.Salt, &pkg.Nonce, &pkg.Ciphertext, &hash, &createdAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return RecoveryPackage{}, ErrNotFound
	}
	if err != nil {
		return RecoveryPackage{}, err
	}
	pkg.CiphertextHash = sha256.Sum256(pkg.Ciphertext)
	pkg.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	return pkg, err
}

func (s *Store) ListPendingDeviceRequests(ctx context.Context, principal Principal, now time.Time) ([]DeviceProvisioningRequest, error) {
	state, err := s.GetAccountState(ctx, principal)
	if err != nil {
		return nil, err
	}
	if state.State != StateReady {
		return nil, ErrForbidden
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT request.id, request.username, request.target_device_id,
		       request.display_name, request.platform, request.network_hint,
		       request.protocol_version, request.requested_at, request.expires_at,
		       request.approved_at, request.approved_by_device_id, request.rejected_at,
		       request.completed_at,
		       signing.algorithm, signing.public_key_spki, signing.fingerprint,
		       agreement.algorithm, agreement.public_key_spki, agreement.fingerprint
		FROM device_provisioning_requests request
		JOIN device_keys signing ON signing.device_id = request.target_device_id AND signing.purpose = 'signing'
		JOIN device_keys agreement ON agreement.device_id = request.target_device_id AND agreement.purpose = 'key_agreement'
		WHERE request.username = ? AND request.approved_at IS NULL AND request.rejected_at IS NULL
		  AND request.completed_at IS NULL AND request.expires_at > ?
		ORDER BY request.requested_at
	`, principal.Username, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]DeviceProvisioningRequest, 0)
	for rows.Next() {
		request, err := scanDeviceRequest(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, request)
	}
	return result, rows.Err()
}

func (s *Store) GetDeviceRequestForTarget(ctx context.Context, principal Principal, requestID string, now time.Time) (DeviceProvisioningRequest, error) {
	request, err := loadDeviceRequest(ctx, s.db, requestID)
	if err != nil {
		return DeviceProvisioningRequest{}, err
	}
	if request.Username != principal.Username || request.TargetDeviceID != principal.DeviceID {
		return DeviceProvisioningRequest{}, ErrForbidden
	}
	if !now.Before(request.ExpiresAt) {
		return DeviceProvisioningRequest{}, ErrRequestExpired
	}
	return request, nil
}

func loadDeviceRequest(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, requestID string) (DeviceProvisioningRequest, error) {
	row := queryer.QueryRowContext(ctx, `
		SELECT request.id, request.username, request.target_device_id,
		       request.display_name, request.platform, request.network_hint,
		       request.protocol_version, request.requested_at, request.expires_at,
		       request.approved_at, request.approved_by_device_id, request.rejected_at,
		       request.completed_at,
		       signing.algorithm, signing.public_key_spki, signing.fingerprint,
		       agreement.algorithm, agreement.public_key_spki, agreement.fingerprint
		FROM device_provisioning_requests request
		JOIN device_keys signing ON signing.device_id = request.target_device_id AND signing.purpose = 'signing'
		JOIN device_keys agreement ON agreement.device_id = request.target_device_id AND agreement.purpose = 'key_agreement'
		WHERE request.id = ?
	`, requestID)
	return scanDeviceRequest(row)
}

type scanner interface{ Scan(...any) error }

func scanDeviceRequest(row scanner) (DeviceProvisioningRequest, error) {
	var request DeviceProvisioningRequest
	var requestedAt, expiresAt string
	var approvedAt, approvedBy, rejectedAt, completedAt sql.NullString
	var signingFingerprint, keyFingerprint []byte
	err := row.Scan(
		&request.ID, &request.Username, &request.TargetDeviceID,
		&request.DisplayName, &request.Platform, &request.NetworkHint,
		&request.ProtocolVersion, &requestedAt, &expiresAt,
		&approvedAt, &approvedBy, &rejectedAt, &completedAt,
		&request.SigningAlgorithm, &request.SigningPublicKey, &signingFingerprint,
		&request.KeyAlgorithm, &request.KeyPublicKey, &keyFingerprint,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceProvisioningRequest{}, ErrNotFound
	}
	if err != nil {
		return DeviceProvisioningRequest{}, err
	}
	if len(signingFingerprint) != sha256.Size || len(keyFingerprint) != sha256.Size {
		return DeviceProvisioningRequest{}, ErrConflict
	}
	copy(request.SigningFingerprint[:], signingFingerprint)
	copy(request.KeyFingerprint[:], keyFingerprint)
	request.RequestedAt, err = time.Parse(time.RFC3339Nano, requestedAt)
	if err != nil {
		return DeviceProvisioningRequest{}, err
	}
	request.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return DeviceProvisioningRequest{}, err
	}
	request.ApprovedAt, err = parseOptionalTime(approvedAt)
	if err != nil {
		return DeviceProvisioningRequest{}, err
	}
	request.RejectedAt, err = parseOptionalTime(rejectedAt)
	if err != nil {
		return DeviceProvisioningRequest{}, err
	}
	request.CompletedAt, err = parseOptionalTime(completedAt)
	if err != nil {
		return DeviceProvisioningRequest{}, err
	}
	request.ApprovedByDeviceID = approvedBy.String
	return request, nil
}

func (s *Store) ApproveDeviceRequest(ctx context.Context, approval ProvisioningApproval, now time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, found, err := loadReplayTx(ctx, tx, approval.Approver, "device.approve", approval.IdempotencyRequestID, approval.IdempotencyDigest, now); err != nil {
		return false, err
	} else if found {
		return true, tx.Commit()
	}
	if err := requireReadyDeviceTx(ctx, tx, approval.Approver); err != nil {
		return false, err
	}
	request, err := loadDeviceRequest(ctx, tx, approval.RequestID)
	if err != nil {
		return false, err
	}
	if request.Username != approval.Approver.Username || request.TargetDeviceID == approval.Approver.DeviceID {
		return false, ErrForbidden
	}
	if !now.Before(request.ExpiresAt) {
		return false, ErrRequestExpired
	}
	if request.RejectedAt != nil || request.CompletedAt != nil {
		return false, ErrAlreadyCompleted
	}
	if request.ApprovedAt != nil {
		if request.ApprovedByDeviceID == approval.Approver.DeviceID {
			return true, tx.Commit()
		}
		return false, ErrConflict
	}
	if len(approval.CertificatePayload) < 32 || len(approval.CertificatePayload) > 16<<10 ||
		len(approval.Signature) < 32 || len(approval.Signature) > 2048 ||
		len(approval.EncryptedPackage) < 48 || len(approval.EncryptedPackage) > 1<<20 ||
		len(approval.Nonce) < 12 || len(approval.Nonce) > 24 ||
		approval.CertificateVersion < 1 || approval.CertificateVersion > 64 ||
		approval.AADVersion < 1 || approval.AADVersion > 64 || approval.PackageVersion < 1 || approval.PackageVersion > 64 {
		return false, ErrConflict
	}
	timestamp := now.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO device_certificates(
			id, username, subject_device_id, issuer_device_id, certificate_version,
			certificate_payload, signature_algorithm, signature, issued_at
		) VALUES(?,?,?,?,?,?,?,?,?)
	`, approval.CertificateID, approval.Approver.Username, request.TargetDeviceID,
		approval.Approver.DeviceID, approval.CertificateVersion, approval.CertificatePayload,
		approval.SignatureAlgorithm, approval.Signature, timestamp); err != nil {
		return false, fmt.Errorf("insert device certificate: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO device_provisioning_packages(
			request_id, target_device_id, encrypted_package, nonce,
			aad_version, package_version, created_at
		) VALUES(?,?,?,?,?,?,?)
	`, request.ID, request.TargetDeviceID, approval.EncryptedPackage, approval.Nonce,
		approval.AADVersion, approval.PackageVersion, timestamp); err != nil {
		return false, fmt.Errorf("insert provisioning package: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE device_provisioning_requests
		SET approved_at = ?, approved_by_device_id = ?
		WHERE id = ? AND approved_at IS NULL AND rejected_at IS NULL AND completed_at IS NULL
	`, timestamp, approval.Approver.DeviceID, request.ID)
	if err != nil {
		return false, err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return false, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE provisioning_devices
		SET security_state = 'KEY_TRANSFER_PENDING', approved_by_device_id = ?, approved_at = ?
		WHERE id = ? AND username = ? AND revoked_at IS NULL
	`, approval.Approver.DeviceID, timestamp, request.TargetDeviceID, approval.Approver.Username); err != nil {
		return false, err
	}
	body := []byte(`{"status":"approved"}`)
	if err := saveReplayTx(ctx, tx, approval.Approver, "device.approve", approval.IdempotencyRequestID, approval.IdempotencyDigest, 201, body, now); err != nil {
		return false, err
	}
	if err := auditTx(ctx, tx, approval.Approver, "device.approved", "success", 3, now, map[string]any{"target_device_id": request.TargetDeviceID}); err != nil {
		return false, err
	}
	return false, tx.Commit()
}

func (s *Store) RejectDeviceRequest(ctx context.Context, principal Principal, requestID string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := requireReadyDeviceTx(ctx, tx, principal); err != nil {
		return err
	}
	request, err := loadDeviceRequest(ctx, tx, requestID)
	if err != nil {
		return err
	}
	if request.Username != principal.Username || request.TargetDeviceID == principal.DeviceID {
		return ErrForbidden
	}
	if request.ApprovedAt != nil || request.CompletedAt != nil {
		return ErrConflict
	}
	timestamp := now.UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `
		UPDATE device_provisioning_requests SET rejected_at = ?
		WHERE id = ? AND rejected_at IS NULL AND approved_at IS NULL AND completed_at IS NULL
	`, timestamp, requestID)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE provisioning_devices SET security_state = 'REVOKED', revoked_at = ?
		WHERE id = ? AND username = ? AND revoked_at IS NULL
	`, timestamp, request.TargetDeviceID, principal.Username); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE provisioning_sessions SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL
	`, timestamp, request.TargetDeviceID); err != nil {
		return err
	}
	if err := auditTx(ctx, tx, principal, "device.rejected", "success", 3, now, map[string]any{"target_device_id": request.TargetDeviceID}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetProvisioningPackage(ctx context.Context, principal Principal, requestID string, now time.Time) (ProvisioningPackage, error) {
	request, err := s.GetDeviceRequestForTarget(ctx, principal, requestID, now)
	if err != nil {
		return ProvisioningPackage{}, err
	}
	if request.ApprovedAt == nil || request.RejectedAt != nil || request.CompletedAt != nil {
		return ProvisioningPackage{}, ErrInvalidState
	}
	var pkg ProvisioningPackage
	var createdAt string
	var consumedAt sql.NullString
	err = s.db.QueryRowContext(ctx, `
		SELECT package.request_id, package.target_device_id, package.encrypted_package,
		       package.nonce, package.aad_version, package.package_version,
		       package.created_at, package.consumed_at,
		       certificate.id, certificate.certificate_payload, certificate.signature,
		       certificate.signature_algorithm, certificate.issuer_device_id
		FROM device_provisioning_packages package
		JOIN device_certificates certificate
		  ON certificate.subject_device_id = package.target_device_id
		 AND certificate.issuer_device_id = ?
		WHERE package.request_id = ? AND package.target_device_id = ?
		ORDER BY certificate.issued_at DESC LIMIT 1
	`, request.ApprovedByDeviceID, requestID, principal.DeviceID).Scan(
		&pkg.RequestID, &pkg.TargetDeviceID, &pkg.Encrypted, &pkg.Nonce,
		&pkg.AADVersion, &pkg.PackageVersion, &createdAt, &consumedAt,
		&pkg.CertificateID, &pkg.Certificate, &pkg.CertificateSig,
		&pkg.SignatureAlgo, &pkg.IssuerDeviceID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ProvisioningPackage{}, ErrNotFound
	}
	if err != nil {
		return ProvisioningPackage{}, err
	}
	pkg.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return ProvisioningPackage{}, err
	}
	pkg.ConsumedAt, err = parseOptionalTime(consumedAt)
	return pkg, err
}

func (s *Store) CompleteProvisioning(ctx context.Context, principal Principal, requestID string, vaultRevision int64, accessVerifier [32]byte, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	request, err := loadDeviceRequest(ctx, tx, requestID)
	if err != nil {
		return err
	}
	if request.Username != principal.Username || request.TargetDeviceID != principal.DeviceID {
		return ErrForbidden
	}
	if request.ApprovedAt == nil || request.RejectedAt != nil {
		return ErrInvalidState
	}
	if request.CompletedAt != nil {
		return tx.Commit()
	}
	var currentVaultRevision int64
	var storedVerifier []byte
	if err := tx.QueryRowContext(ctx, `
		SELECT security.vault_revision, vault.access_verifier
		FROM account_security_state security
		JOIN encrypted_key_vaults vault
		  ON vault.username = security.username AND vault.revision = security.vault_revision
		WHERE security.username = ?
	`, principal.Username).Scan(&currentVaultRevision, &storedVerifier); err != nil {
		return err
	}
	defer clear(storedVerifier)
	if currentVaultRevision <= 0 || vaultRevision != currentVaultRevision || len(storedVerifier) != sha256.Size ||
		isZero(accessVerifier[:]) || !hmac.Equal(storedVerifier, accessVerifier[:]) {
		return ErrConflict
	}
	timestamp := now.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
		UPDATE device_provisioning_packages SET consumed_at = ?
		WHERE request_id = ? AND target_device_id = ? AND consumed_at IS NULL
	`, timestamp, requestID, principal.DeviceID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE device_provisioning_requests SET completed_at = ?
		WHERE id = ? AND completed_at IS NULL
	`, timestamp, requestID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE provisioning_devices SET security_state = 'READY'
		WHERE id = ? AND username = ? AND revoked_at IS NULL
	`, principal.DeviceID, principal.Username); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE account_security_state
		SET state = 'READY', last_ready_device_id = ?, updated_at = ? WHERE username = ?
	`, principal.DeviceID, timestamp, principal.Username); err != nil {
		return err
	}
	if err := auditTx(ctx, tx, principal, "device.provisioning.completed", "success", 3, now, map[string]any{"vault_revision": vaultRevision}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CompleteRecovery(ctx context.Context, principal Principal, vaultRevision int64, accessVerifier [32]byte, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentRevision int64
	var recoveryConfigured int
	var storedVerifier []byte
	if err := tx.QueryRowContext(ctx, `
		SELECT security.vault_revision, security.recovery_configured, vault.access_verifier
		FROM account_security_state security
		JOIN encrypted_key_vaults vault ON vault.username = security.username AND vault.revision = security.vault_revision
		WHERE security.username = ?
	`, principal.Username).Scan(&currentRevision, &recoveryConfigured, &storedVerifier); err != nil {
		return err
	}
	defer clear(storedVerifier)
	if currentRevision <= 0 || vaultRevision != currentRevision || recoveryConfigured != 1 ||
		len(storedVerifier) != sha256.Size || isZero(accessVerifier[:]) || !hmac.Equal(storedVerifier, accessVerifier[:]) {
		return ErrConflict
	}
	timestamp := now.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
		UPDATE provisioning_devices SET security_state = 'READY'
		WHERE id = ? AND username = ? AND revoked_at IS NULL
	`, principal.DeviceID, principal.Username); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE account_security_state
		SET state = 'READY', last_ready_device_id = ?, updated_at = ? WHERE username = ?
	`, principal.DeviceID, timestamp, principal.Username); err != nil {
		return err
	}
	if err := auditTx(ctx, tx, principal, "recovery.completed", "success", 3, now, map[string]any{"vault_revision": vaultRevision}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RevokeDevice(ctx context.Context, principal Principal, targetDeviceID string, now time.Time) error {
	if targetDeviceID == principal.DeviceID {
		return ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := requireReadyDeviceTx(ctx, tx, principal); err != nil {
		return err
	}
	var username string
	var revoked sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT username, revoked_at FROM provisioning_devices WHERE id = ?`, targetDeviceID).Scan(&username, &revoked); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if username != principal.Username {
		return ErrForbidden
	}
	if revoked.Valid {
		return tx.Commit()
	}
	timestamp := now.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
		UPDATE provisioning_devices SET revoked_at = ?, security_state = 'REVOKED' WHERE id = ?
	`, timestamp, targetDeviceID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE provisioning_sessions SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL`, timestamp, targetDeviceID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE device_keys SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL`, timestamp, targetDeviceID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE device_certificates SET revoked_at = ? WHERE subject_device_id = ? AND revoked_at IS NULL`, timestamp, targetDeviceID); err != nil {
		return err
	}
	if err := auditTx(ctx, tx, principal, "device.revoked", "success", 3, now, map[string]any{"target_device_id": targetDeviceID}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListMigrations(ctx context.Context, principal Principal) ([]MigrationStatus, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, migration_kind, source_version, target_version, state,
		       last_sequence, processed_count, verified_count, COALESCE(failure_code,''),
		       updated_at, completed_at
		FROM crypto_migrations WHERE username = ? ORDER BY created_at
	`, principal.Username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]MigrationStatus, 0)
	for rows.Next() {
		var item MigrationStatus
		var updatedAt string
		var completedAt sql.NullString
		if err := rows.Scan(&item.ID, &item.Kind, &item.SourceVersion, &item.TargetVersion,
			&item.State, &item.LastSequence, &item.ProcessedCount, &item.VerifiedCount,
			&item.FailureCode, &updatedAt, &completedAt); err != nil {
			return nil, err
		}
		item.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
		if err != nil {
			return nil, err
		}
		item.CompletedAt, err = parseOptionalTime(completedAt)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func requireReadyDeviceTx(ctx context.Context, tx *sql.Tx, principal Principal) error {
	var username, state string
	var revoked sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT username, security_state, revoked_at FROM provisioning_devices WHERE id = ?
	`, principal.DeviceID).Scan(&username, &state, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if username != principal.Username || revoked.Valid || state != StateReady {
		return ErrForbidden
	}
	return nil
}

type replayRecord struct {
	Status int
	Body   []byte
}

func loadReplayTx(ctx context.Context, tx *sql.Tx, principal Principal, operation, requestID string, digest [32]byte, now time.Time) (replayRecord, bool, error) {
	if requestID == "" {
		return replayRecord{}, false, ErrConflict
	}
	var storedDigest, body []byte
	var status int
	var expiresAt string
	err := tx.QueryRowContext(ctx, `
		SELECT request_digest, response_status, response_body, expires_at
		FROM security_request_replays
		WHERE username = ? AND device_id = ? AND operation = ? AND request_id = ?
	`, principal.Username, principal.DeviceID, operation, requestID).Scan(&storedDigest, &status, &body, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return replayRecord{}, false, nil
	}
	if err != nil {
		return replayRecord{}, false, err
	}
	if !hmac.Equal(storedDigest, digest[:]) {
		return replayRecord{}, false, ErrRequestReplayed
	}
	expires, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil || !now.Before(expires) {
		return replayRecord{}, false, ErrRequestExpired
	}
	return replayRecord{Status: status, Body: body}, true, nil
}

func saveReplayTx(ctx context.Context, tx *sql.Tx, principal Principal, operation, requestID string, digest [32]byte, status int, body []byte, now time.Time) error {
	if requestID == "" || len(body) < 2 || len(body) > 1<<20 {
		return ErrConflict
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO security_request_replays(
			request_id, username, device_id, operation, request_digest,
			response_status, response_body, created_at, expires_at
		) VALUES(?,?,?,?,?,?,?,?,?)
	`, requestID, principal.Username, principal.DeviceID, operation, digest[:], status, body,
		now.UTC().Format(time.RFC3339Nano), now.Add(24*time.Hour).UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("save security request replay: %w", err)
	}
	_, _ = tx.ExecContext(ctx, `DELETE FROM security_request_replays WHERE expires_at <= ?`, now.UTC().Format(time.RFC3339Nano))
	return nil
}

func auditTx(ctx context.Context, tx *sql.Tx, principal Principal, eventType, outcome string, protocolVersion int, now time.Time, metadata map[string]any) error {
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO security_audit_events(
			event_id, username, device_id, event_type, outcome,
			protocol_version, occurred_at, metadata
		) VALUES(lower(hex(randomblob(16))),?,?,?,?,?,?,?)
	`, principal.Username, principal.DeviceID, eventType, outcome, protocolVersion,
		now.UTC().Format(time.RFC3339Nano), string(encoded))
	return err
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

func isZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}
