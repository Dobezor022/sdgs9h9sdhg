package accountsecurity_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"fedmes/server/internal/accountsecurity"
	"fedmes/server/internal/database"
)

func TestVaultAndRecoveryWorkflowIsTransactionalAndIdempotent(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "fedmes.sqlite3"))
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	defer db.Close()

	principal := accountsecurity.Principal{
		Username:  "grisha",
		DeviceID:  "11111111-1111-4111-8111-111111111111",
		SessionID: "22222222-2222-4222-8222-222222222222",
	}
	seedReadySecurityDevice(t, db, principal)
	store := accountsecurity.NewStore(db.SQL())
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	ciphertext := bytes.Repeat([]byte{0x41}, 96)
	ciphertextHash := sha256.Sum256(ciphertext)
	requestDigest := sha256.Sum256([]byte("vault request"))
	input := accountsecurity.VaultWrite{
		ExpectedPreviousRevision: 0,
		VaultVersion:             1,
		CryptoVersion:            2,
		AADVersion:               1,
		Nonce:                    bytes.Repeat([]byte{0x01}, 12),
		Ciphertext:               ciphertext,
		CiphertextHash:           ciphertextHash,
		AccessVerifier:           sha256.Sum256([]byte("vault access verifier")),
		RequestID:                "33333333-3333-4333-8333-333333333333",
		RequestDigest:            requestDigest,
	}
	created, replayed, err := store.PutVault(ctx, principal, input, now)
	if err != nil || replayed || created.Revision != 1 {
		t.Fatalf("PutVault() = revision %d replayed %v error %v", created.Revision, replayed, err)
	}
	replayedVault, replayed, err := store.PutVault(ctx, principal, input, now.Add(time.Minute))
	if err != nil || !replayed || replayedVault.Revision != 1 {
		t.Fatalf("PutVault(replay) = revision %d replayed %v error %v", replayedVault.Revision, replayed, err)
	}

	recoveryCiphertext := bytes.Repeat([]byte{0x52}, 64)
	recoveryHash := sha256.Sum256(recoveryCiphertext)
	recoveryDigest := sha256.Sum256([]byte("recovery request"))
	recovery, recoveryReplayed, err := store.PutRecoveryPackage(ctx, principal, accountsecurity.RecoveryWrite{
		ID:             "44444444-4444-4444-8444-444444444444",
		VaultRevision:  1,
		PackageVersion: 1,
		CryptoVersion:  2,
		AADVersion:     1,
		KDFName:        "PBKDF2-HMAC-SHA256",
		KDFParameters:  `{"iterations":310000,"key_bits":256}`,
		Salt:           bytes.Repeat([]byte{0x02}, 32),
		Nonce:          bytes.Repeat([]byte{0x03}, 12),
		Ciphertext:     recoveryCiphertext,
		CiphertextHash: recoveryHash,
		RequestID:      "55555555-5555-4555-8555-555555555555",
		RequestDigest:  recoveryDigest,
	}, now.Add(2*time.Minute))
	if err != nil || recoveryReplayed || recovery.VaultRevision != 1 {
		t.Fatalf("PutRecoveryPackage() = %#v replayed %v error %v", recovery, recoveryReplayed, err)
	}

	state, err := store.GetAccountState(ctx, principal)
	if err != nil {
		t.Fatalf("GetAccountState() error = %v", err)
	}
	if state.VaultRevision != 1 || !state.RecoveryConfigured || state.CryptoVersion != 2 {
		t.Fatalf("security state = %#v", state)
	}

	if _, err := db.SQL().Exec(`UPDATE provisioning_devices SET security_state = ? WHERE id = ?`,
		accountsecurity.StateAuthenticatedNoKeys, principal.DeviceID); err != nil {
		t.Fatalf("stage device for recovery: %v", err)
	}
	wrongVerifier := sha256.Sum256([]byte("wrong verifier"))
	if err := store.CompleteRecovery(ctx, principal, 1, wrongVerifier, now.Add(3*time.Minute)); err == nil {
		t.Fatal("CompleteRecovery() with wrong access verifier succeeded")
	}
	state, err = store.GetAccountState(ctx, principal)
	if err != nil {
		t.Fatalf("GetAccountState(after wrong verifier) error = %v", err)
	}
	if state.State != accountsecurity.StateAuthenticatedNoKeys {
		t.Fatalf("wrong verifier changed state to %q", state.State)
	}
	if err := store.CompleteRecovery(ctx, principal, 1, input.AccessVerifier, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("CompleteRecovery() error = %v", err)
	}
	state, err = store.GetAccountState(ctx, principal)
	if err != nil {
		t.Fatalf("GetAccountState(after recovery) error = %v", err)
	}
	if state.State != accountsecurity.StateReady {
		t.Fatalf("recovery did not make device ready: %#v", state)
	}
}

func seedReadySecurityDevice(t *testing.T, db *database.Store, principal accountsecurity.Principal) {
	t.Helper()
	created := "2026-07-21T11:00:00Z"
	invitationID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	tokenDigest := bytes.Repeat([]byte{0x11}, 32)
	publicKey := bytes.Repeat([]byte{0x22}, 64)
	fingerprint := bytes.Repeat([]byte{0x33}, 32)
	sessionDigest := bytes.Repeat([]byte{0x44}, 32)
	tx, err := db.SQL().Begin()
	if err != nil {
		t.Fatalf("begin seed transaction: %v", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`
		INSERT INTO provisioning_invitations(id,username,token_digest,created_at,expires_at,redeemed_at,redeemed_by_device_id)
		VALUES(?,?,?,?,?,?,?)
	`, invitationID, principal.Username, tokenDigest, created, "2026-07-22T11:00:00Z", created, principal.DeviceID); err != nil {
		t.Fatalf("insert invitation: %v", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO provisioning_devices(
			id,username,invitation_id,key_algorithm,public_key_spki,public_key_fingerprint,
			bound_at,display_name,platform,last_seen_at,security_state
		) VALUES(?,?,?,?,?,?,?,?,?,?,?)
	`, principal.DeviceID, principal.Username, invitationID, "ecdsa-p256-sha256", publicKey,
		fingerprint, created, "Test device", "android", created, accountsecurity.StateReady); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO provisioning_sessions(id,device_id,token_digest,issued_at,expires_at,protocol_version)
		VALUES(?,?,?,?,?,?)
	`, principal.SessionID, principal.DeviceID, sessionDigest, created, "2026-07-22T11:00:00Z", 3); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit seed transaction: %v", err)
	}
}
