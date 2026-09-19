package database

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestMigration0013And0014FreshDatabase(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "fresh.sqlite3"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	assertMigrationVersion(t, store.db, 14)
	assertTablesExist(t, store.db,
		"opaque_registration_attempts",
		"opaque_login_attempts",
		"opaque_login_continuations",
		"opaque_login_results",
		"opaque_recovery_packages",
		"ratchet_device_bundles",
		"ratchet_one_time_keys",
		"ratchet_sessions",
		"ratchet_message_envelopes",
		"megolm_group_sessions",
		"megolm_key_packages",
		"crypto_migration_records",
		"crypto_message_replacements",
		"crypto_media_replacements",
		"room_rotation_events",
		"room_device_sequence_state",
		"message_sequence_reservations",
		"blind_routes",
		"blind_objects",
	)
	assertColumnsExist(t, store.db, "messages",
		"encryption_algorithm",
		"ciphertext_sha256",
		"legacy_retired_at",
		"crypto_sequence",
	)
	assertColumnsExist(t, store.db, "media_objects",
		"encryption_algorithm",
		"ciphertext_sha256",
		"legacy_retired_at",
	)
	assertColumnsExist(t, store.db, "account_security_state",
		"minimum_crypto_version",
		"legacy_fmk_removed_at",
	)
	assertNoSingleColumnUniqueIndex(t, store.db, "opaque_login_results", "device_id")
	assertSQLiteHealthy(t, store.db)
}

func TestMigration0013And0014Upgrades0012WithoutDeletingExistingTopology(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "upgrade.sqlite3")
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}

	if _, err := db.ExecContext(ctx, `
		CREATE TABLE schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		) STRICT;
	`); err != nil {
		db.Close()
		t.Fatalf("create migration table: %v", err)
	}
	applyEmbeddedMigrationsThrough(t, ctx, db, 12)

	var usersBefore, chatsBefore int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM family_users").Scan(&usersBefore); err != nil {
		db.Close()
		t.Fatalf("count users before migration: %v", err)
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM chats").Scan(&chatsBefore); err != nil {
		db.Close()
		t.Fatalf("count chats before migration: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close pre-0013 database: %v", err)
	}

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open() upgrade error = %v", err)
	}
	defer store.Close()

	assertMigrationVersion(t, store.db, 14)
	var usersAfter, chatsAfter int
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM family_users").Scan(&usersAfter); err != nil {
		t.Fatalf("count users after migration: %v", err)
	}
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM chats").Scan(&chatsAfter); err != nil {
		t.Fatalf("count chats after migration: %v", err)
	}
	if usersAfter != usersBefore {
		t.Fatalf("family_users changed: before=%d after=%d", usersBefore, usersAfter)
	}
	if chatsAfter != chatsBefore {
		t.Fatalf("chats changed: before=%d after=%d", chatsBefore, chatsAfter)
	}
	assertSQLiteHealthy(t, store.db)
}

func applyEmbeddedMigrationsThrough(t *testing.T, ctx context.Context, db *sql.DB, maximum int64) {
	t.Helper()
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version, err := migrationVersion(entry.Name())
		if err != nil {
			t.Fatalf("migrationVersion(%q): %v", entry.Name(), err)
		}
		if version > maximum {
			continue
		}
		script, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			t.Fatalf("read migration %s: %v", entry.Name(), err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin migration %s: %v", entry.Name(), err)
		}
		if _, err := tx.ExecContext(ctx, string(script)); err != nil {
			_ = tx.Rollback()
			t.Fatalf("execute migration %s: %v", entry.Name(), err)
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
			version, time.Now().UTC().Format(time.RFC3339Nano),
		); err != nil {
			_ = tx.Rollback()
			t.Fatalf("record migration %s: %v", entry.Name(), err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit migration %s: %v", entry.Name(), err)
		}
	}
}

func assertMigrationVersion(t *testing.T, db *sql.DB, want int64) {
	t.Helper()
	var got int64
	if err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&got); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	if got != want {
		t.Fatalf("schema version = %d, want %d", got, want)
	}
}

func assertTablesExist(t *testing.T, db *sql.DB, tables ...string) {
	t.Helper()
	for _, table := range tables {
		var count int
		if err := db.QueryRow(
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&count); err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if count != 1 {
			t.Fatalf("table %s is missing", table)
		}
	}
}

func assertColumnsExist(t *testing.T, db *sql.DB, table string, columns ...string) {
	t.Helper()
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%q)", table))
	if err != nil {
		t.Fatalf("table_info(%s): %v", table, err)
	}
	defer rows.Close()

	found := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatalf("scan table_info(%s): %v", table, err)
		}
		found[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate table_info(%s): %v", table, err)
	}
	for _, column := range columns {
		if !found[column] {
			t.Fatalf("column %s.%s is missing", table, column)
		}
	}
}

func assertNoSingleColumnUniqueIndex(t *testing.T, db *sql.DB, table, column string) {
	t.Helper()
	rows, err := db.Query(fmt.Sprintf("PRAGMA index_list(%q)", table))
	if err != nil {
		t.Fatalf("index_list(%s): %v", table, err)
	}
	defer rows.Close()
	type indexInfo struct {
		name   string
		unique int
	}
	var indexes []indexInfo
	for rows.Next() {
		var seq, unique, partial int
		var name, origin string
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			t.Fatalf("scan index_list(%s): %v", table, err)
		}
		indexes = append(indexes, indexInfo{name: name, unique: unique})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate index_list(%s): %v", table, err)
	}
	for _, index := range indexes {
		if index.unique != 1 {
			continue
		}
		infoRows, err := db.Query(fmt.Sprintf("PRAGMA index_info(%q)", index.name))
		if err != nil {
			t.Fatalf("index_info(%s): %v", index.name, err)
		}
		var names []string
		for infoRows.Next() {
			var seqNo, cid int
			var name string
			if err := infoRows.Scan(&seqNo, &cid, &name); err != nil {
				infoRows.Close()
				t.Fatalf("scan index_info(%s): %v", index.name, err)
			}
			names = append(names, name)
		}
		if err := infoRows.Close(); err != nil {
			t.Fatalf("close index_info(%s): %v", index.name, err)
		}
		if len(names) == 1 && names[0] == column {
			t.Fatalf("%s.%s unexpectedly has a single-column UNIQUE index %s", table, column, index.name)
		}
	}
}

func assertSQLiteHealthy(t *testing.T, db *sql.DB) {
	t.Helper()
	var integrity string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil {
		t.Fatalf("integrity_check: %v", err)
	}
	if integrity != "ok" {
		t.Fatalf("integrity_check = %q", integrity)
	}

	rows, err := db.Query("PRAGMA foreign_key_check")
	if err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("foreign_key_check reported a violation")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
}
