package database

import (
	"context"
	"path/filepath"
	"testing"
)

func TestOpenMigratesDatabaseIdempotently(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "fedmes.sqlite3")

	first, err := Open(context.Background(), databasePath)
	if err != nil {
		t.Fatalf("Open() first error = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close() first error = %v", err)
	}

	second, err := Open(context.Background(), databasePath)
	if err != nil {
		t.Fatalf("Open() second error = %v", err)
	}
	defer second.Close()

	var users int
	if err := second.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM family_users").Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if users != 5 {
		t.Fatalf("users = %d, want 5", users)
	}

	var chats, memberships int
	if err := second.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM chats").Scan(&chats); err != nil {
		t.Fatalf("count chats: %v", err)
	}
	if err := second.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM chat_members").Scan(&memberships); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if chats != 16 {
		t.Fatalf("chats = %d, want 16", chats)
	}
	if memberships != 30 {
		t.Fatalf("memberships = %d, want 30", memberships)
	}

	securityTables := []string{
		"account_security_state",
		"device_keys",
		"device_provisioning_requests",
		"encrypted_key_vaults",
		"recovery_packages",
		"security_request_replays",
		"server_backup_snapshots",
	}
	for _, table := range securityTables {
		var count int
		if err := second.db.QueryRowContext(context.Background(),
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&count); err != nil {
			t.Fatalf("check security table %s: %v", table, err)
		}
		if count != 1 {
			t.Fatalf("security table %s is missing", table)
		}
	}
}
