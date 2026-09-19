package config

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadOrCreateRegistrationResultKeyPersistsExactlyThirtyTwoBytes(t *testing.T) {
	directory := t.TempDir()
	first, err := LoadOrCreateRegistrationResultKey(directory)
	if err != nil {
		t.Fatalf("LoadOrCreateRegistrationResultKey() first error = %v", err)
	}
	defer clear(first)
	if len(first) != registrationResultKeyBytes {
		t.Fatalf("first key length = %d, want %d", len(first), registrationResultKeyBytes)
	}
	second, err := LoadOrCreateRegistrationResultKey(directory)
	if err != nil {
		t.Fatalf("LoadOrCreateRegistrationResultKey() second error = %v", err)
	}
	defer clear(second)
	if !bytes.Equal(first, second) {
		t.Fatal("reloaded registration result key differs")
	}
	path := filepath.Join(directory, "registration-result.key")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("key permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestLoadOrCreateRegistrationResultKeyRejectsInvalidLength(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "registration-result.key")
	if err := os.WriteFile(path, make([]byte, registrationResultKeyBytes-1), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := LoadOrCreateRegistrationResultKey(directory); err == nil {
		t.Fatal("invalid key length was accepted")
	}
}
