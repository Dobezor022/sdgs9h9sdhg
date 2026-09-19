package database

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"fedmes/server/internal/provisioning"
)

type repositoryTestClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *repositoryTestClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *repositoryTestClock) advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}

func openProvisioningTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fedmes.sqlite3")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path
}

func newDatabaseProvisioningService(t *testing.T, repository provisioning.InvitationRepository, clock provisioning.Clock) *provisioning.Service {
	t.Helper()
	service, err := provisioning.NewService(repository, clock, provisioning.CryptoEntropy{}, provisioning.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func databaseTestDeviceKey(t *testing.T) provisioning.DevicePublicKeyInput {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	return provisioning.DevicePublicKeyInput{Algorithm: provisioning.DeviceKeyEd25519, SubjectPublicKeyInfo: spki}
}

func databaseTestEncryptionKey(t *testing.T) provisioning.MessageEncryptionKeyInput {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("Generate RSA key error = %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Marshal RSA public key error = %v", err)
	}
	return provisioning.MessageEncryptionKeyInput{
		Algorithm:            provisioning.MessageEncryptionAlgorithmRSAOAEP256,
		SubjectPublicKeyInfo: spki,
	}
}

func databaseTestSigningKey(t *testing.T) (ed25519.PrivateKey, provisioning.DevicePublicKeyInput) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	return privateKey, provisioning.DevicePublicKeyInput{
		Algorithm:            provisioning.DeviceKeyEd25519,
		SubjectPublicKeyInfo: spki,
	}
}

func TestSQLiteRedemptionIsAtomicAndOneUseUnderConcurrency(t *testing.T) {
	store, _ := openProvisioningTestStore(t)
	clock := &repositoryTestClock{now: time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)}
	service := newDatabaseProvisioningService(t, store, clock)
	issued, err := service.IssueInvitation(context.Background(), "grisha", 10*time.Minute)
	if err != nil {
		t.Fatalf("IssueInvitation() error = %v", err)
	}
	request := provisioning.RedeemRequest{Username: "grisha", Token: issued.Token, DeviceKey: databaseTestDeviceKey(t), EncryptionKey: databaseTestEncryptionKey(t)}

	const attempts = 32
	start := make(chan struct{})
	results := make(chan error, attempts)
	var waitGroup sync.WaitGroup
	for index := 0; index < attempts; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			_, err := service.RedeemInvitation(context.Background(), request)
			results <- err
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)

	successCount := 0
	usedCount := 0
	for err := range results {
		switch {
		case err == nil:
			successCount++
		case errors.Is(err, provisioning.ErrInvitationUsed):
			usedCount++
		default:
			t.Fatalf("unexpected redemption error = %v", err)
		}
	}
	if successCount != 1 || usedCount != attempts-1 {
		t.Fatalf("successes = %d, used = %d; want 1 and %d", successCount, usedCount, attempts-1)
	}

	for table, expected := range map[string]int{
		"provisioning_devices":  1,
		"provisioning_sessions": 1,
	} {
		var count int
		if err := store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != expected {
			t.Fatalf("%s count = %d, want %d", table, count, expected)
		}
	}
}

func TestSQLiteWrongUserAndMalformedKeyDoNotConsumeInvitation(t *testing.T) {
	store, _ := openProvisioningTestStore(t)
	clock := &repositoryTestClock{now: time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)}
	service := newDatabaseProvisioningService(t, store, clock)
	issued, err := service.IssueInvitation(context.Background(), "grisha", 10*time.Minute)
	if err != nil {
		t.Fatalf("IssueInvitation() error = %v", err)
	}
	validKey := databaseTestDeviceKey(t)
	if _, err := service.RedeemInvitation(context.Background(), provisioning.RedeemRequest{
		Username: "papa", Token: issued.Token, DeviceKey: validKey,

		EncryptionKey: databaseTestEncryptionKey(t),
	}); !errors.Is(err, provisioning.ErrInvitationUser) {
		t.Fatalf("wrong-user error = %v, want invitation_user_mismatch", err)
	}
	if _, err := service.RedeemInvitation(context.Background(), provisioning.RedeemRequest{
		Username:  "grisha",
		Token:     issued.Token,
		DeviceKey: provisioning.DevicePublicKeyInput{Algorithm: provisioning.DeviceKeyEd25519, SubjectPublicKeyInfo: []byte("invalid")},

		EncryptionKey: databaseTestEncryptionKey(t),
	}); !errors.Is(err, provisioning.ErrInvalidDeviceKey) {
		t.Fatalf("malformed-key error = %v, want invalid_device_public_key", err)
	}
	if _, err := service.RedeemInvitation(context.Background(), provisioning.RedeemRequest{
		Username: "grisha", Token: issued.Token, DeviceKey: validKey,

		EncryptionKey: databaseTestEncryptionKey(t),
	}); err != nil {
		t.Fatalf("valid redemption after rejected attempts = %v", err)
	}
}

func TestSQLiteExpiredInvitationIsNotConsumed(t *testing.T) {
	store, _ := openProvisioningTestStore(t)
	clock := &repositoryTestClock{now: time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)}
	service := newDatabaseProvisioningService(t, store, clock)
	issued, err := service.IssueInvitation(context.Background(), "mama", time.Minute)
	if err != nil {
		t.Fatalf("IssueInvitation() error = %v", err)
	}
	clock.advance(time.Minute)
	if _, err := service.RedeemInvitation(context.Background(), provisioning.RedeemRequest{
		Username: "mama", Token: issued.Token, DeviceKey: databaseTestDeviceKey(t),

		EncryptionKey: databaseTestEncryptionKey(t),
	}); !errors.Is(err, provisioning.ErrInvitationExpired) {
		t.Fatalf("expired redemption error = %v, want invitation_expired", err)
	}
	var redeemedAt any
	if err := store.db.QueryRow("SELECT redeemed_at FROM provisioning_invitations").Scan(&redeemedAt); err != nil {
		t.Fatalf("read redeemed_at: %v", err)
	}
	if redeemedAt != nil {
		t.Fatalf("expired invitation redeemed_at = %v, want NULL", redeemedAt)
	}
}

func TestSQLiteInvitationPersistsAcrossReopenAndSessionStoresDigestOnly(t *testing.T) {
	store, path := openProvisioningTestStore(t)
	clock := &repositoryTestClock{now: time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)}
	service := newDatabaseProvisioningService(t, store, clock)
	issued, err := service.IssueInvitation(context.Background(), "vasya", 10*time.Minute)
	if err != nil {
		t.Fatalf("IssueInvitation() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	defer reopened.Close()
	service = newDatabaseProvisioningService(t, reopened, clock)
	result, err := service.RedeemInvitation(context.Background(), provisioning.RedeemRequest{
		Username: "vasya", Token: issued.Token, DeviceKey: databaseTestDeviceKey(t),

		EncryptionKey: databaseTestEncryptionKey(t),
	})
	if err != nil {
		t.Fatalf("RedeemInvitation() after reopen error = %v", err)
	}
	if duration := result.Session.ExpiresAt.Sub(result.Session.IssuedAt); duration != 15*time.Minute {
		t.Fatalf("session TTL = %s, want 15m", duration)
	}
	rawToken, err := base64.RawURLEncoding.Strict().DecodeString(result.Session.Token.Reveal())
	if err != nil {
		t.Fatalf("decode session token: %v", err)
	}
	defer clear(rawToken)
	expectedDigest := sha256.Sum256(rawToken)
	var storedDigest []byte
	if err := reopened.db.QueryRow("SELECT token_digest FROM provisioning_sessions WHERE id = ?", string(result.Session.ID)).Scan(&storedDigest); err != nil {
		t.Fatalf("read session digest: %v", err)
	}
	if !bytes.Equal(storedDigest, expectedDigest[:]) {
		t.Fatal("stored session digest differs from SHA-256 token digest")
	}
	var rawTokenMatches int
	if err := reopened.db.QueryRow("SELECT COUNT(*) FROM provisioning_sessions WHERE token_digest = ?", []byte(result.Session.Token.Reveal())).Scan(&rawTokenMatches); err != nil {
		t.Fatalf("check raw token storage: %v", err)
	}
	if rawTokenMatches != 0 {
		t.Fatal("raw session token was persisted")
	}
}

func TestSQLiteChallengePersistsAndRefreshIsAtomic(t *testing.T) {
	store, path := openProvisioningTestStore(t)
	clock := &repositoryTestClock{now: time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)}
	service := newDatabaseProvisioningService(t, store, clock)
	privateKey, publicKey := databaseTestSigningKey(t)
	issued, err := service.IssueInvitation(context.Background(), "yura", 10*time.Minute)
	if err != nil {
		t.Fatalf("IssueInvitation() error = %v", err)
	}
	provisioned, err := service.RedeemInvitation(context.Background(), provisioning.RedeemRequest{
		Username: "yura", Token: issued.Token, DeviceKey: publicKey,

		EncryptionKey: databaseTestEncryptionKey(t),
	})
	if err != nil {
		t.Fatalf("RedeemInvitation() error = %v", err)
	}
	challenge, err := service.IssueSessionChallenge(context.Background(), provisioning.SessionChallengeRequest{
		Username: "yura", DeviceKey: publicKey, Audience: "chat.example", Purpose: provisioning.ChallengePurposeSessionRefresh,
	})
	if err != nil {
		t.Fatalf("IssueSessionChallenge() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	reopened, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	defer reopened.Close()
	service = newDatabaseProvisioningService(t, reopened, clock)
	payload, err := provisioning.DeviceAuthenticationPayload(
		challenge.Audience,
		provisioning.UserYura,
		provisioned.Device.ID,
		challenge.ID,
		challenge.Purpose,
		challenge.Nonce.Reveal(),
	)
	if err != nil {
		t.Fatalf("DeviceAuthenticationPayload() error = %v", err)
	}
	signature := ed25519.Sign(privateKey, payload)
	clear(payload)
	request := provisioning.SessionRefreshRequest{
		Username:    "yura",
		DeviceID:    provisioned.Device.ID,
		ChallengeID: challenge.ID,
		Nonce:       challenge.Nonce,
		Audience:    challenge.Audience,
		Purpose:     challenge.Purpose,
		Signature:   signature,
	}
	const attempts = 16
	start := make(chan struct{})
	results := make(chan error, attempts)
	var waitGroup sync.WaitGroup
	for index := 0; index < attempts; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			_, err := service.RefreshSession(context.Background(), request)
			results <- err
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)
	successes := 0
	used := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, provisioning.ErrChallengeUsed):
			used++
		default:
			t.Fatalf("unexpected refresh error = %v", err)
		}
	}
	if successes != 1 || used != attempts-1 {
		t.Fatalf("successes/used = %d/%d, want 1/%d", successes, used, attempts-1)
	}
	var consumedCount int
	if err := reopened.db.QueryRow(
		"SELECT COUNT(*) FROM provisioning_challenges WHERE id = ? AND consumed_at IS NOT NULL",
		string(challenge.ID),
	).Scan(&consumedCount); err != nil {
		t.Fatalf("count consumed challenge: %v", err)
	}
	if consumedCount != 1 {
		t.Fatalf("consumed challenge count = %d, want 1", consumedCount)
	}
	var sessionCount int
	if err := reopened.db.QueryRow(
		"SELECT COUNT(*) FROM provisioning_sessions WHERE device_id = ?",
		string(provisioned.Device.ID),
	).Scan(&sessionCount); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessionCount != 2 {
		t.Fatalf("session count = %d, want initial + refreshed", sessionCount)
	}
}

func TestSQLiteNewQRPreservesOldAccessAndDoesNotGrantOldHistory(t *testing.T) {
	store, _ := openProvisioningTestStore(t)
	clock := &repositoryTestClock{now: time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)}
	service := newDatabaseProvisioningService(t, store, clock)

	firstInvitation, err := service.IssueInvitation(context.Background(), "grisha", 10*time.Minute)
	if err != nil {
		t.Fatalf("IssueInvitation(first) error = %v", err)
	}
	firstLogin, err := service.RedeemInvitation(context.Background(), provisioning.RedeemRequest{
		Username:      "grisha",
		Token:         firstInvitation.Token,
		DeviceKey:     databaseTestDeviceKey(t),
		EncryptionKey: databaseTestEncryptionKey(t),
	})
	if err != nil {
		t.Fatalf("RedeemInvitation(first) error = %v", err)
	}

	createdAt := formatTime(clock.Now())
	if _, err := store.db.Exec(`
		INSERT INTO messages(id, chat_id, sender_username, sender_device_id, ciphertext, nonce, aad, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)
	`, "security-message", "favorites:grisha", "grisha", string(firstLogin.Device.ID), make([]byte, 16), make([]byte, 12), "security-test", createdAt); err != nil {
		t.Fatalf("insert message: %v", err)
	}
	originalEnvelope := bytes.Repeat([]byte{0x5a}, 384)
	if _, err := store.db.Exec(`
		INSERT INTO message_envelopes(message_id, device_id, algorithm, ciphertext)
		VALUES(?, ?, ?, ?)
	`, "security-message", string(firstLogin.Device.ID), provisioning.MessageEncryptionAlgorithmRSAOAEP256, originalEnvelope); err != nil {
		t.Fatalf("insert envelope: %v", err)
	}

	clock.advance(time.Second)
	secondInvitation, err := service.IssueInvitation(context.Background(), "grisha", 10*time.Minute)
	if err != nil {
		t.Fatalf("IssueInvitation(second) error = %v", err)
	}
	secondLogin, err := service.RedeemInvitation(context.Background(), provisioning.RedeemRequest{
		Username:      "grisha",
		Token:         secondInvitation.Token,
		DeviceKey:     databaseTestDeviceKey(t),
		EncryptionKey: databaseTestEncryptionKey(t),
	})
	if err != nil {
		t.Fatalf("RedeemInvitation(second) error = %v", err)
	}
	if secondLogin.Device.ID == firstLogin.Device.ID {
		t.Fatal("different identity key unexpectedly reused old device ID")
	}

	var oldDeviceRevoked, oldSessionRevoked, newSessionRevoked any
	if err := store.db.QueryRow(`SELECT revoked_at FROM provisioning_devices WHERE id = ?`, string(firstLogin.Device.ID)).Scan(&oldDeviceRevoked); err != nil {
		t.Fatalf("read old device revocation: %v", err)
	}
	if err := store.db.QueryRow(`SELECT revoked_at FROM provisioning_sessions WHERE id = ?`, string(firstLogin.Session.ID)).Scan(&oldSessionRevoked); err != nil {
		t.Fatalf("read old session revocation: %v", err)
	}
	if err := store.db.QueryRow(`SELECT revoked_at FROM provisioning_sessions WHERE id = ?`, string(secondLogin.Session.ID)).Scan(&newSessionRevoked); err != nil {
		t.Fatalf("read new session revocation: %v", err)
	}
	if oldDeviceRevoked != nil || oldSessionRevoked != nil || newSessionRevoked != nil {
		t.Fatalf("unexpected revocation state old-device=%v old-session=%v new-session=%v", oldDeviceRevoked, oldSessionRevoked, newSessionRevoked)
	}

	var inheritedEnvelopeCount int
	if err := store.db.QueryRow(`
		SELECT COUNT(*) FROM message_envelopes WHERE message_id = ? AND device_id = ?
	`, "security-message", string(secondLogin.Device.ID)).Scan(&inheritedEnvelopeCount); err != nil {
		t.Fatalf("count inherited envelope: %v", err)
	}
	if inheritedEnvelopeCount != 0 {
		t.Fatalf("new device received %d old-history envelopes without key approval, want 0", inheritedEnvelopeCount)
	}

	var oldKeyCount, newKeyCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM device_encryption_keys WHERE device_id = ?`, string(firstLogin.Device.ID)).Scan(&oldKeyCount); err != nil {
		t.Fatalf("count old key binding: %v", err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM device_encryption_keys WHERE device_id = ?`, string(secondLogin.Device.ID)).Scan(&newKeyCount); err != nil {
		t.Fatalf("count new key binding: %v", err)
	}
	if oldKeyCount != 1 || newKeyCount != 1 {
		t.Fatalf("key bindings old=%d new=%d, want 1/1", oldKeyCount, newKeyCount)
	}
}

func TestSQLiteNewestInvitationInvalidatesOlderUnredeemedQR(t *testing.T) {
	store, _ := openProvisioningTestStore(t)
	clock := &repositoryTestClock{now: time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)}
	service := newDatabaseProvisioningService(t, store, clock)
	first, err := service.IssueInvitation(context.Background(), "papa", 10*time.Minute)
	if err != nil {
		t.Fatalf("IssueInvitation(first) error = %v", err)
	}
	second, err := service.IssueInvitation(context.Background(), "papa", 10*time.Minute)
	if err != nil {
		t.Fatalf("IssueInvitation(second) error = %v", err)
	}
	identity := databaseTestDeviceKey(t)
	encryption := databaseTestEncryptionKey(t)
	if _, err := service.RedeemInvitation(context.Background(), provisioning.RedeemRequest{
		Username:      "papa",
		Token:         first.Token,
		DeviceKey:     identity,
		EncryptionKey: encryption,
	}); !errors.Is(err, provisioning.ErrInvitationNotFound) {
		t.Fatalf("older QR error = %v, want invitation_not_found", err)
	}
	if _, err := service.RedeemInvitation(context.Background(), provisioning.RedeemRequest{
		Username:      "papa",
		Token:         second.Token,
		DeviceKey:     identity,
		EncryptionKey: encryption,
	}); err != nil {
		t.Fatalf("newest QR redemption error = %v", err)
	}
}
