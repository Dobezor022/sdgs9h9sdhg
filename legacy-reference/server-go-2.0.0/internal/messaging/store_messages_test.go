package messaging_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"fedmes/server/internal/database"
	"fedmes/server/internal/messaging"
)

func TestListMessagesReturnsEmptyJSONListInsteadOfNull(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "fedmes.sqlite3"))
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	defer db.Close()

	store := messaging.NewStore(db.SQL())
	page, err := store.ListMessages(ctx, "family", "grisha", "missing-device", 0, 0, 200)
	if err != nil {
		t.Fatalf("ListMessages() error = %v", err)
	}
	messages := page.Messages
	if messages == nil {
		t.Fatal("ListMessages() returned nil; JSON would encode messages as null")
	}
	if len(messages) != 0 {
		t.Fatalf("ListMessages() returned %d messages, want 0", len(messages))
	}

	body, err := json.Marshal(map[string]any{"version": 1, "messages": messages})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	const want = `{"messages":[],"version":1}`
	if string(body) != want {
		t.Fatalf("JSON = %s, want %s", body, want)
	}
}
