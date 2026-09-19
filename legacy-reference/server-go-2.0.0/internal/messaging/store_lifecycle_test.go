package messaging_test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"fedmes/server/internal/database"
	"fedmes/server/internal/messaging"
)

func TestDeferredEnvelopeAndDeleteScopes(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "fedmes.sqlite3"))
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	defer db.Close()

	seedMessagingDevice(t, db.SQL(), "grisha", "11111111-1111-4111-8111-111111111111", 1)
	seedMessagingDevice(t, db.SQL(), "papa", "22222222-2222-4222-8222-222222222222", 2)
	store := messaging.NewStore(db.SQL())
	now := time.Now().UTC()
	messageID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	grisha := messaging.Principal{Username: "grisha", DeviceID: "11111111-1111-4111-8111-111111111111"}
	_, err = store.CreateMessage(ctx, messaging.NewMessage{
		ID:         messageID,
		ChatID:     "dm:grisha:papa",
		Sender:     grisha,
		Ciphertext: bytes.Repeat([]byte{0x31}, 32),
		Nonce:      bytes.Repeat([]byte{0x32}, 12),
		AAD:        messaging.CanonicalMessageAAD("dm:grisha:papa", "grisha", grisha.DeviceID, messageID),
		Envelopes: []messaging.DecodedEnvelope{{
			DeviceID: grisha.DeviceID, Algorithm: "rsa-oaep-sha256", Ciphertext: bytes.Repeat([]byte{0x33}, 256),
		}},
	}, now)
	if err != nil {
		t.Fatalf("CreateMessage() error = %v", err)
	}

	papaChats, err := store.ListChats(ctx, "papa")
	if err != nil {
		t.Fatalf("ListChats(papa) error = %v", err)
	}
	if unread := unreadForChat(papaChats, "dm:grisha:papa"); unread != 1 {
		t.Fatalf("papa unread before receipt = %d, want 1", unread)
	}
	grishaChats, err := store.ListChats(ctx, "grisha")
	if err != nil {
		t.Fatalf("ListChats(grisha) error = %v", err)
	}
	if unread := unreadForChat(grishaChats, "dm:grisha:papa"); unread != 0 {
		t.Fatalf("grisha unread for own message = %d, want 0", unread)
	}

	papaPage, err := store.ListMessages(ctx, "dm:grisha:papa", "papa", "22222222-2222-4222-8222-222222222222", 0, 0, 100)
	if err != nil || len(papaPage.Messages) != 1 || papaPage.Messages[0].Envelope != nil {
		t.Fatalf("message before envelope = %#v, error = %v", papaPage.Messages, err)
	}
	if err := store.AddMessageEnvelopes(ctx, "dm:grisha:papa", messageID, grisha, []messaging.DecodedEnvelope{{
		DeviceID: "22222222-2222-4222-8222-222222222222", Algorithm: "rsa-oaep-sha256", Ciphertext: bytes.Repeat([]byte{0x44}, 256),
	}}); err != nil {
		t.Fatalf("AddMessageEnvelopes() error = %v", err)
	}
	papaPage, err = store.ListMessages(ctx, "dm:grisha:papa", "papa", "22222222-2222-4222-8222-222222222222", 0, 0, 100)
	if err != nil || papaPage.Messages[0].Envelope == nil {
		t.Fatalf("message after envelope = %#v, error = %v", papaPage.Messages, err)
	}
	if err := store.MarkReceipts(
		ctx, "dm:grisha:papa", "papa", []string{messageID}, []string{messageID}, now,
	); err != nil {
		t.Fatalf("MarkReceipts() error = %v", err)
	}
	papaChats, err = store.ListChats(ctx, "papa")
	if err != nil {
		t.Fatalf("ListChats(papa after read) error = %v", err)
	}
	if unread := unreadForChat(papaChats, "dm:grisha:papa"); unread != 0 {
		t.Fatalf("papa unread after receipt = %d, want 0", unread)
	}

	if err := store.DeleteMessage(ctx, "dm:grisha:papa", messageID, "papa", "me", now); err != nil {
		t.Fatalf("DeleteMessage(me) error = %v", err)
	}
	papaPage, _ = store.ListMessages(ctx, "dm:grisha:papa", "papa", "22222222-2222-4222-8222-222222222222", 0, 0, 100)
	grishaPage, _ := store.ListMessages(ctx, "dm:grisha:papa", "grisha", grisha.DeviceID, 0, 0, 100)
	if len(papaPage.Messages) != 0 || len(grishaPage.Messages) != 1 {
		t.Fatalf("local delete visibility: papa=%d grisha=%d", len(papaPage.Messages), len(grishaPage.Messages))
	}
	repairPage, err := store.ListOwnedMessagesForEnvelopeRepair(ctx, "dm:grisha:papa", "grisha", grisha.DeviceID, 0, 100)
	if err != nil || len(repairPage.Messages) != 1 {
		t.Fatalf("repair page after peer local delete = %d, error = %v", len(repairPage.Messages), err)
	}

	if err := store.DeleteMessage(ctx, "dm:grisha:papa", messageID, "papa", "everyone", now); err != nil {
		t.Fatalf("DeleteMessage(everyone) error = %v", err)
	}
	grishaPage, _ = store.ListMessages(ctx, "dm:grisha:papa", "grisha", grisha.DeviceID, 0, 0, 100)
	if len(grishaPage.Messages) != 0 {
		t.Fatalf("hard deleted message still visible: %d", len(grishaPage.Messages))
	}
}

func TestMessagePaginationReturnsNewestPageAndOlderPages(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "fedmes.sqlite3"))
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	defer db.Close()
	deviceID := "33333333-3333-4333-8333-333333333333"
	seedMessagingDevice(t, db.SQL(), "grisha", deviceID, 3)
	store := messaging.NewStore(db.SQL())
	principal := messaging.Principal{Username: "grisha", DeviceID: deviceID}
	for index := 0; index < 205; index++ {
		messageID := fmt.Sprintf("%08x-0000-4000-8000-%012x", index+1, index+1)
		_, err := store.CreateMessage(ctx, messaging.NewMessage{
			ID: messageID, ChatID: "favorites:grisha", Sender: principal,
			Ciphertext: bytes.Repeat([]byte{byte(index)}, 32), Nonce: bytes.Repeat([]byte{0x10}, 12),
			AAD:       messaging.CanonicalMessageAAD("favorites:grisha", "grisha", deviceID, messageID),
			Envelopes: []messaging.DecodedEnvelope{{DeviceID: deviceID, Algorithm: "rsa-oaep-sha256", Ciphertext: bytes.Repeat([]byte{0x20}, 256)}},
		}, time.Now().UTC())
		if err != nil {
			t.Fatalf("CreateMessage(%d) error = %v", index, err)
		}
	}
	latest, err := store.ListMessages(ctx, "favorites:grisha", "grisha", deviceID, 0, 0, 100)
	if err != nil || len(latest.Messages) != 100 || !latest.HasMoreBefore {
		t.Fatalf("latest page len=%d more=%v err=%v", len(latest.Messages), latest.HasMoreBefore, err)
	}
	older, err := store.ListMessages(ctx, "favorites:grisha", "grisha", deviceID, 0, latest.Messages[0].Sequence, 100)
	if err != nil || len(older.Messages) != 100 || !older.HasMoreBefore {
		t.Fatalf("older page len=%d more=%v err=%v", len(older.Messages), older.HasMoreBefore, err)
	}
	oldest, err := store.ListMessages(ctx, "favorites:grisha", "grisha", deviceID, 0, older.Messages[0].Sequence, 100)
	if err != nil || len(oldest.Messages) != 5 || oldest.HasMoreBefore {
		t.Fatalf("oldest page len=%d more=%v err=%v", len(oldest.Messages), oldest.HasMoreBefore, err)
	}
}

func seedMessagingDevice(t *testing.T, db *sql.DB, username, deviceID string, seed byte) {
	t.Helper()
	invitationID := fmt.Sprintf("%08x-1111-4111-8111-%012x", seed, seed)
	created := "2030-01-01T00:00:00Z"
	expires := "2030-01-02T00:00:00Z"
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin seed transaction: %v", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`
		INSERT INTO provisioning_invitations(id,username,token_digest,created_at,expires_at)
		VALUES(?,?,?,?,?)`, invitationID, username, bytes.Repeat([]byte{seed}, 32), created, expires,
	); err != nil {
		t.Fatalf("insert invitation: %v", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO provisioning_devices(
			id,username,invitation_id,key_algorithm,public_key_spki,public_key_fingerprint,bound_at
		) VALUES(?,?,?,?,?,?,?)`,
		deviceID, username, invitationID, "ecdsa-p256-sha256",
		bytes.Repeat([]byte{seed}, 64), bytes.Repeat([]byte{seed + 10}, 32), created,
	); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	if _, err := tx.Exec(`
		UPDATE provisioning_invitations
		SET redeemed_at=?,redeemed_by_device_id=? WHERE id=?`, created, deviceID, invitationID,
	); err != nil {
		t.Fatalf("redeem invitation: %v", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO device_encryption_keys(device_id,algorithm,public_key_spki,fingerprint,registered_at)
		VALUES(?,?,?,?,?)`,
		deviceID, "rsa-oaep-sha256", bytes.Repeat([]byte{seed + 20}, 256),
		bytes.Repeat([]byte{seed + 30}, 32), created,
	); err != nil {
		t.Fatalf("insert encryption key: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit seed transaction: %v", err)
	}
}

func unreadForChat(chats []messaging.Chat, chatID string) int {
	for _, chat := range chats {
		if chat.ID == chatID {
			return chat.UnreadCount
		}
	}
	return -1
}
