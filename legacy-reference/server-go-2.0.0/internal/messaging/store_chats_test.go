package messaging_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"fedmes/server/internal/database"
	"fedmes/server/internal/messaging"
)

func TestListChatsReturnsFixedFamilyTopologyWithoutDeadlock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "fedmes.sqlite3"))
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	defer db.Close()

	store := messaging.NewStore(db.SQL())
	for _, username := range []string{"grisha", "papa", "mama", "yura", "vasya"} {
		chats, err := store.ListChats(ctx, username)
		if err != nil {
			t.Fatalf("ListChats(%q) error = %v", username, err)
		}
		if len(chats) != 6 {
			t.Fatalf("ListChats(%q) returned %d chats, want 6", username, len(chats))
		}

		kinds := map[string]int{}
		for _, chat := range chats {
			kinds[chat.Kind]++
			if len(chat.Members) == 0 {
				t.Fatalf("chat %q has no members", chat.ID)
			}
			foundCurrentUser := false
			for _, member := range chat.Members {
				if member == username {
					foundCurrentUser = true
					break
				}
			}
			if !foundCurrentUser {
				t.Fatalf("chat %q does not include %q", chat.ID, username)
			}
		}
		if kinds["favorites"] != 1 || kinds["family"] != 1 || kinds["direct"] != 4 {
			t.Fatalf("ListChats(%q) kinds = %#v, want 1 favorites, 1 family, 4 direct", username, kinds)
		}
	}
}
