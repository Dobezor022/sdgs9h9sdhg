package messaging_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"fedmes/server/internal/database"
	"fedmes/server/internal/messaging"
)

func TestApproveDeviceLinkKeepsApprovingPhoneActiveAndCompletesOnce(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "fedmes.sqlite3"))
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	defer db.Close()

	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	phoneID := "11111111-1111-4111-8111-111111111111"
	phoneInvitationID := "22222222-2222-4222-8222-222222222222"
	phoneKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(phone) error = %v", err)
	}
	phoneSPKI, err := x509.MarshalPKIXPublicKey(&phoneKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey(phone) error = %v", err)
	}
	phoneFingerprint := sha256.Sum256(phoneSPKI)
	invitationDigest := sha256.Sum256([]byte("phone invitation"))

	tx, err := db.SQL().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx() error = %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO provisioning_invitations(id,username,token_digest,created_at,expires_at,redeemed_at,redeemed_by_device_id)
        VALUES(?,?,?,?,?,?,?)`, phoneInvitationID, "grisha", invitationDigest[:], now.Add(-time.Hour).Format(time.RFC3339Nano),
		now.Add(time.Hour).Format(time.RFC3339Nano), now.Add(-time.Hour).Format(time.RFC3339Nano), phoneID); err != nil {
		t.Fatalf("insert phone invitation: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO provisioning_devices(id,username,invitation_id,key_algorithm,public_key_spki,public_key_fingerprint,bound_at,display_name,platform,last_seen_at)
        VALUES(?,?,?,?,?,?,?,?,?,?)`, phoneID, "grisha", phoneInvitationID, "ecdsa-p256-sha256", phoneSPKI,
		phoneFingerprint[:], now.Add(-time.Hour).Format(time.RFC3339Nano), "Телефон", "android", now.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert phone device: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit phone device: %v", err)
	}

	desktopIdentity, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(desktop) error = %v", err)
	}
	desktopIdentitySPKI, err := x509.MarshalPKIXPublicKey(&desktopIdentity.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey(desktop) error = %v", err)
	}
	desktopIdentityFingerprint := sha256.Sum256(desktopIdentitySPKI)
	desktopEncryption, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(desktop) error = %v", err)
	}
	desktopEncryptionSPKI, err := x509.MarshalPKIXPublicKey(&desktopEncryption.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey(encryption) error = %v", err)
	}
	desktopEncryptionFingerprint := sha256.Sum256(desktopEncryptionSPKI)
	secretDigest := sha256.Sum256([]byte("link secret"))

	store := messaging.NewStore(db.SQL())
	linkID := "33333333-3333-4333-8333-333333333333"
	if err := store.CreateDeviceLink(ctx, messaging.DeviceLinkRecord{
		ID:                      linkID,
		SecretDigest:            secretDigest,
		IdentityAlgorithm:       "ecdsa-p256-sha256",
		IdentityPublicKeySPKI:   desktopIdentitySPKI,
		IdentityFingerprint:     desktopIdentityFingerprint,
		EncryptionAlgorithm:     "rsa-oaep-sha256",
		EncryptionPublicKeySPKI: desktopEncryptionSPKI,
		EncryptionFingerprint:   desktopEncryptionFingerprint,
		DisplayName:             "Desktop · STUDIO-PC",
		Platform:                "windows",
		CreatedAt:               now,
		ExpiresAt:               now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("CreateDeviceLink() error = %v", err)
	}

	sessionDigest := sha256.Sum256([]byte("desktop session"))
	encryptedToken := []byte("encrypted-token-placeholder")
	linked, err := store.ApproveDeviceLink(ctx, messaging.DeviceLinkApproval{
		LinkID:                linkID,
		SecretDigest:          secretDigest,
		Approver:              messaging.Principal{Username: "grisha", DeviceID: phoneID},
		InvitationID:          "44444444-4444-4444-8444-444444444444",
		DeviceID:              "55555555-5555-4555-8555-555555555555",
		SessionID:             "66666666-6666-4666-8666-666666666666",
		SessionTokenDigest:    sessionDigest,
		EncryptedSessionToken: encryptedToken,
		SessionExpiresAt:      now.Add(15 * time.Minute),
		ResultExpiresAt:       now.Add(10 * time.Minute),
		ApprovedAt:            now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("ApproveDeviceLink() error = %v", err)
	}
	if linked.DisplayName != "Desktop · STUDIO-PC" || linked.Platform != "windows" {
		t.Fatalf("linked device = %#v", linked)
	}

	devices, err := store.ListAccountDevices(ctx, messaging.Principal{Username: "grisha", DeviceID: phoneID})
	if err != nil {
		t.Fatalf("ListAccountDevices() error = %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("active devices = %d, want 2", len(devices))
	}
	if !devices[0].Current || devices[0].ID != phoneID {
		t.Fatalf("current device = %#v, want phone", devices[0])
	}

	if err := store.CompleteDeviceLink(ctx, linkID, secretDigest, now.Add(2*time.Second)); err != nil {
		t.Fatalf("CompleteDeviceLink() error = %v", err)
	}
	completed, err := store.LoadDeviceLink(ctx, linkID, secretDigest)
	if err != nil {
		t.Fatalf("LoadDeviceLink() error = %v", err)
	}
	if state := messaging.DeviceLinkState(completed, now.Add(3*time.Second)); state != "consumed" {
		t.Fatalf("DeviceLinkState() = %q, want consumed", state)
	}
	if len(completed.EncryptedSessionToken) != 0 {
		t.Fatal("encrypted session token was not cleared after completion")
	}

	if err := store.RevokeCurrentDevice(ctx, messaging.Principal{
		Username: "grisha", DeviceID: linked.ID, SessionID: "66666666-6666-4666-8666-666666666666",
	}, now.Add(4*time.Second)); err != nil {
		t.Fatalf("RevokeCurrentDevice() error = %v", err)
	}

	relinkDigest := sha256.Sum256([]byte("second link secret"))
	relinkID := "77777777-7777-4777-8777-777777777777"
	if err := store.CreateDeviceLink(ctx, messaging.DeviceLinkRecord{
		ID:                      relinkID,
		SecretDigest:            relinkDigest,
		IdentityAlgorithm:       "ecdsa-p256-sha256",
		IdentityPublicKeySPKI:   desktopIdentitySPKI,
		IdentityFingerprint:     desktopIdentityFingerprint,
		EncryptionAlgorithm:     "rsa-oaep-sha256",
		EncryptionPublicKeySPKI: desktopEncryptionSPKI,
		EncryptionFingerprint:   desktopEncryptionFingerprint,
		DisplayName:             "Desktop · STUDIO-PC",
		Platform:                "windows",
		CreatedAt:               now.Add(5 * time.Second),
		ExpiresAt:               now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("CreateDeviceLink(relink) error = %v", err)
	}
	relinked, err := store.ApproveDeviceLink(ctx, messaging.DeviceLinkApproval{
		LinkID:                relinkID,
		SecretDigest:          relinkDigest,
		Approver:              messaging.Principal{Username: "grisha", DeviceID: phoneID},
		InvitationID:          "88888888-8888-4888-8888-888888888888",
		DeviceID:              "99999999-9999-4999-8999-999999999999",
		SessionID:             "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		SessionTokenDigest:    sha256.Sum256([]byte("second desktop session")),
		EncryptedSessionToken: []byte("second-encrypted-token"),
		SessionExpiresAt:      now.Add(20 * time.Minute),
		ResultExpiresAt:       now.Add(10 * time.Minute),
		ApprovedAt:            now.Add(6 * time.Second),
	})
	if err != nil {
		t.Fatalf("ApproveDeviceLink(relink) error = %v", err)
	}
	if relinked.ID != linked.ID {
		t.Fatalf("relinked device id = %s, want existing %s", relinked.ID, linked.ID)
	}

	if err := store.ExpireApprovedDeviceLinks(ctx, now.Add(11*time.Minute)); err != nil {
		t.Fatalf("ExpireApprovedDeviceLinks() error = %v", err)
	}
	abandoned, err := store.LoadDeviceLink(ctx, relinkID, relinkDigest)
	if err != nil {
		t.Fatalf("LoadDeviceLink(abandoned) error = %v", err)
	}
	if state := messaging.DeviceLinkState(abandoned, now.Add(11*time.Minute)); state != "consumed" {
		t.Fatalf("abandoned link state = %q, want consumed", state)
	}
	if len(abandoned.EncryptedSessionToken) != 0 {
		t.Fatal("abandoned encrypted session token was not cleared")
	}
	devices, err = store.ListAccountDevices(ctx, messaging.Principal{Username: "grisha", DeviceID: phoneID})
	if err != nil {
		t.Fatalf("ListAccountDevices(after cleanup) error = %v", err)
	}
	if len(devices) != 1 || devices[0].ID != phoneID {
		t.Fatalf("active devices after abandoned cleanup = %#v, want only phone", devices)
	}
}
