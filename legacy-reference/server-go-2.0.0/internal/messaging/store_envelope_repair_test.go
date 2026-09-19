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

func TestEnvelopeRepairPaginationIncludesReceivedMessages(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "fedmes.sqlite3"))
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertMessagingTestDevice(t, db.SQL(), "grisha-device", "grisha", 1, now)
	insertMessagingTestDevice(t, db.SQL(), "papa-device", "papa", 2, now)

	for index := 0; index < 205; index++ {
		messageID := fmt.Sprintf("repair-message-%03d", index)
		if _, err := db.SQL().ExecContext(ctx, `
			INSERT INTO messages(id,chat_id,sender_username,sender_device_id,ciphertext,nonce,aad,created_at)
			VALUES(?,?,?,?,?,?,?,?)`,
			messageID, "family", "papa", "papa-device", bytes.Repeat([]byte{byte(index + 1)}, 16),
			bytes.Repeat([]byte{byte(index + 3)}, 12), "repair-test", now); err != nil {
			t.Fatalf("insert message %d: %v", index, err)
		}
		if _, err := db.SQL().ExecContext(ctx, `
			INSERT INTO message_envelopes(message_id,device_id,algorithm,ciphertext)
			VALUES(?,?,?,?)`, messageID, "grisha-device", "rsa-oaep-sha256", bytes.Repeat([]byte{byte(index + 7)}, 256)); err != nil {
			t.Fatalf("insert envelope %d: %v", index, err)
		}
	}

	store := messaging.NewStore(db.SQL())
	first, err := store.ListMessagesForEnvelopeRepair(ctx, "family", "grisha", "grisha-device", 0, 200)
	if err != nil {
		t.Fatalf("first page error = %v", err)
	}
	if len(first.Messages) != 200 || !first.HasMoreBefore {
		t.Fatalf("first page = %d messages, hasMore=%v; want 200,true", len(first.Messages), first.HasMoreBefore)
	}

	second, err := store.ListMessagesForEnvelopeRepair(
		ctx,
		"family",
		"grisha",
		"grisha-device",
		first.Messages[0].Sequence,
		200,
	)
	if err != nil {
		t.Fatalf("second page error = %v", err)
	}
	if len(second.Messages) != 5 || second.HasMoreBefore {
		t.Fatalf("second page = %d messages, hasMore=%v; want 5,false", len(second.Messages), second.HasMoreBefore)
	}
}

func insertMessagingTestDevice(t *testing.T, db *sql.DB, deviceID, username string, marker byte, now string) {
	t.Helper()
	ctx := context.Background()
	invitationID := "invite-" + deviceID
	if _, err := db.ExecContext(ctx, `
		INSERT INTO provisioning_invitations(id,username,token_digest,created_at,expires_at)
		VALUES(?,?,?,?,?)`, invitationID, username, bytes.Repeat([]byte{marker}, 32), now,
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert invitation %s: %v", deviceID, err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO provisioning_devices(
			id,username,invitation_id,key_algorithm,public_key_spki,public_key_fingerprint,bound_at,display_name,platform,last_seen_at
		) VALUES(?,?,?,?,?,?,?,?,?,?)`, deviceID, username, invitationID, "ecdsa-p256-sha256",
		bytes.Repeat([]byte{marker + 10}, 91), bytes.Repeat([]byte{marker + 20}, 32), now,
		"Test device", "android", now); err != nil {
		t.Fatalf("insert device %s: %v", deviceID, err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE provisioning_invitations SET redeemed_at=?,redeemed_by_device_id=? WHERE id=?`,
		now, deviceID, invitationID); err != nil {
		t.Fatalf("redeem invitation %s: %v", deviceID, err)
	}
}
