package config

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const registrationResultKeyBytes = 32

// LoadOrCreateRegistrationResultKey returns the persistent server-side key used
// only to encrypt replayable QR-registration results. It never encrypts user
// messages, media, Account Root Keys, Recovery Keys, or key vaults.
func LoadOrCreateRegistrationResultKey(dataDirectory string) ([]byte, error) {
	if dataDirectory == "" {
		return nil, errors.New("data directory is required")
	}
	path := filepath.Join(dataDirectory, "registration-result.key")
	key, err := readRegistrationResultKey(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key = make([]byte, registrationResultKeyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		clear(key)
		return nil, fmt.Errorf("generate registration result key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		clear(key)
		return readRegistrationResultKey(path)
	}
	if err != nil {
		clear(key)
		return nil, fmt.Errorf("create registration result key: %w", err)
	}
	writeErr := func() error {
		defer file.Close()
		if _, err := file.Write(key); err != nil {
			return err
		}
		return file.Sync()
	}()
	if writeErr != nil {
		clear(key)
		_ = os.Remove(path)
		return nil, fmt.Errorf("write registration result key: %w", writeErr)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		clear(key)
		return nil, fmt.Errorf("restrict registration result key permissions: %w", err)
	}
	return key, nil
}

func readRegistrationResultKey(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	key := make([]byte, registrationResultKeyBytes)
	if _, err := io.ReadFull(file, key); err != nil {
		clear(key)
		return nil, fmt.Errorf("read registration result key: %w", err)
	}
	extra := make([]byte, 1)
	count, err := file.Read(extra)
	clear(extra)
	if err != nil && !errors.Is(err, io.EOF) {
		clear(key)
		return nil, fmt.Errorf("inspect registration result key: %w", err)
	}
	if count != 0 {
		clear(key)
		return nil, errors.New("registration result key has an invalid length")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		clear(key)
		return nil, fmt.Errorf("restrict registration result key permissions: %w", err)
	}
	return key, nil
}
