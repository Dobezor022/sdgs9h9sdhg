package messaging_test

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"fedmes/server/internal/database"
	"fedmes/server/internal/messaging"
)

func TestReadCursorIsMonotonicAndDrivesDeliveryState(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "fedmes.sqlite3"))
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	defer db.Close()

	const (
		grishaDevice = "11111111-1111-4111-8111-111111111111"
		papaDevice   = "22222222-2222-4222-8222-222222222222"
		yuraDevice   = "33333333-3333-4333-8333-333333333333"
	)
	seedMessagingDevice(t, db.SQL(), "grisha", grishaDevice, 1)
	seedMessagingDevice(t, db.SQL(), "papa", papaDevice, 2)
	seedMessagingDevice(t, db.SQL(), "yura", yuraDevice, 3)

	store := messaging.NewStore(db.SQL())
	now := time.Date(2030, time.January, 1, 12, 0, 0, 0, time.UTC)
	grisha := messaging.Principal{Username: "grisha", DeviceID: grishaDevice}
	directChat := "dm:grisha:papa"

	first := createCursorTestMessage(t, ctx, store, grisha, directChat,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1", []string{grishaDevice, papaDevice}, now)
	second := createCursorTestMessage(t, ctx, store, grisha, directChat,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2", []string{grishaDevice, papaDevice}, now.Add(time.Second))

	accepted, err := store.MarkReadCursor(ctx, directChat, "papa", second.Sequence, now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("MarkReadCursor(second) error = %v", err)
	}
	if accepted != second.Sequence {
		t.Fatalf("accepted cursor = %d, want %d", accepted, second.Sequence)
	}
	if _, err := store.MarkReadCursor(ctx, directChat, "papa", first.Sequence, now.Add(3*time.Second)); err != nil {
		t.Fatalf("MarkReadCursor(first) error = %v", err)
	}

	var stored int64
	if err := db.SQL().QueryRowContext(ctx,
		`SELECT max_read_sequence FROM chat_read_cursors WHERE chat_id=? AND username=?`,
		directChat, "papa",
	).Scan(&stored); err != nil {
		t.Fatalf("query read cursor: %v", err)
	}
	if stored != second.Sequence {
		t.Fatalf("stored cursor regressed to %d, want %d", stored, second.Sequence)
	}

	page, err := store.ListMessages(ctx, directChat, "grisha", grishaDevice, 0, 0, 100)
	if err != nil {
		t.Fatalf("ListMessages() error = %v", err)
	}
	if len(page.Messages) != 2 {
		t.Fatalf("message count = %d, want 2", len(page.Messages))
	}
	for _, message := range page.Messages {
		if message.ReadCount != 1 || message.DeliveredCount != 1 {
			t.Fatalf("message %s read=%d delivered=%d, want 1/1", message.ID, message.ReadCount, message.DeliveredCount)
		}
	}

	papaChats, err := store.ListChats(ctx, "papa")
	if err != nil {
		t.Fatalf("ListChats(papa) error = %v", err)
	}
	if unread := unreadForChat(papaChats, directChat); unread != 0 {
		t.Fatalf("papa unread = %d, want 0", unread)
	}
}

func TestFamilyMessageIsReadWhenAnyOtherMemberAdvancesCursor(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "fedmes.sqlite3"))
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	defer db.Close()

	const (
		grishaDevice = "44444444-4444-4444-8444-444444444444"
		yuraDevice   = "55555555-5555-4555-8555-555555555555"
	)
	seedMessagingDevice(t, db.SQL(), "grisha", grishaDevice, 4)
	seedMessagingDevice(t, db.SQL(), "yura", yuraDevice, 5)

	store := messaging.NewStore(db.SQL())
	now := time.Date(2030, time.February, 1, 12, 0, 0, 0, time.UTC)
	grisha := messaging.Principal{Username: "grisha", DeviceID: grishaDevice}
	message := createCursorTestMessage(t, ctx, store, grisha, "family",
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", []string{grishaDevice, yuraDevice}, now)

	if _, err := store.MarkReadCursor(ctx, "family", "grisha", message.Sequence, now.Add(time.Second)); err != nil {
		t.Fatalf("sender cursor update error = %v", err)
	}
	before, err := store.ListMessages(ctx, "family", "grisha", grishaDevice, 0, 0, 100)
	if err != nil || len(before.Messages) != 1 {
		t.Fatalf("ListMessages(before) len=%d error=%v", len(before.Messages), err)
	}
	if before.Messages[0].ReadCount != 0 {
		t.Fatalf("sender's own cursor counted as reader: %d", before.Messages[0].ReadCount)
	}

	if _, err := store.MarkReadCursor(ctx, "family", "yura", message.Sequence, now.Add(2*time.Second)); err != nil {
		t.Fatalf("reader cursor update error = %v", err)
	}
	after, err := store.ListMessages(ctx, "family", "grisha", grishaDevice, 0, 0, 100)
	if err != nil || len(after.Messages) != 1 {
		t.Fatalf("ListMessages(after) len=%d error=%v", len(after.Messages), err)
	}
	if after.Messages[0].ReadCount != 1 {
		t.Fatalf("family read count = %d, want 1 after any other member read", after.Messages[0].ReadCount)
	}
}

func createCursorTestMessage(
	t *testing.T,
	ctx context.Context,
	store *messaging.Store,
	sender messaging.Principal,
	chatID string,
	messageID string,
	deviceIDs []string,
	now time.Time,
) messaging.Message {
	t.Helper()
	envelopes := make([]messaging.DecodedEnvelope, 0, len(deviceIDs))
	for index, deviceID := range deviceIDs {
		envelopes = append(envelopes, messaging.DecodedEnvelope{
			DeviceID:   deviceID,
			Algorithm:  "rsa-oaep-sha256",
			Ciphertext: bytes.Repeat([]byte{byte(0x60 + index)}, 256),
		})
	}
	created, err := store.CreateMessage(ctx, messaging.NewMessage{
		ID:         messageID,
		ChatID:     chatID,
		Sender:     sender,
		Ciphertext: bytes.Repeat([]byte{0x41}, 32),
		Nonce:      bytes.Repeat([]byte{0x42}, 12),
		AAD:        messaging.CanonicalMessageAAD(chatID, sender.Username, sender.DeviceID, messageID),
		Envelopes:  envelopes,
	}, now)
	if err != nil {
		t.Fatalf("CreateMessage(%s) error = %v", messageID, err)
	}
	return created
}
