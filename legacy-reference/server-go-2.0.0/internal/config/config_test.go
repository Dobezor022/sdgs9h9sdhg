package config

import (
	"path/filepath"
	"testing"
)

func TestLoadUsesSafeDefaults(t *testing.T) {
	t.Setenv("FEDMES_ADDR", "")
	t.Setenv("FEDMES_DATA_DIR", t.TempDir())
	t.Setenv("FEDMES_SHUTDOWN_TIMEOUT", "")
	t.Setenv("FEDMES_PUBLIC_URL", "https://fedmes.test")

	actual, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if actual.Address != "127.0.0.1:8008" {
		t.Fatalf("Address = %q", actual.Address)
	}
	if filepath.Base(actual.DatabasePath) != "fedmes.sqlite3" {
		t.Fatalf("DatabasePath = %q", actual.DatabasePath)
	}
}

func TestLoadRejectsImplicitAllInterfaces(t *testing.T) {
	t.Setenv("FEDMES_ADDR", ":8008")
	t.Setenv("FEDMES_DATA_DIR", t.TempDir())
	t.Setenv("FEDMES_PUBLIC_URL", "https://fedmes.test")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}

func TestLoadRequiresPublicURL(t *testing.T) {
	t.Setenv("FEDMES_ADDR", "127.0.0.1:8008")
	t.Setenv("FEDMES_DATA_DIR", t.TempDir())
	t.Setenv("FEDMES_PUBLIC_URL", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}
