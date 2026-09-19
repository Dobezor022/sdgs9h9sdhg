package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultAddress         = "127.0.0.1:8008"
	defaultShutdownTimeout = 10 * time.Second
)

type Config struct {
	PublicURL       string
	Address         string
	DataDirectory   string
	DatabasePath    string
	MediaDirectory  string
	ShutdownTimeout time.Duration
}

func Load() (Config, error) {
	dataDirectory := strings.TrimSpace(os.Getenv("FEDMES_DATA_DIR"))
	if dataDirectory == "" {
		dataDirectory = "data"
	}

	absoluteDataDirectory, err := filepath.Abs(dataDirectory)
	if err != nil {
		return Config{}, fmt.Errorf("resolve data directory: %w", err)
	}

	address := strings.TrimSpace(os.Getenv("FEDMES_ADDR"))
	if address == "" {
		address = defaultAddress
	}
	if err := validateAddress(address); err != nil {
		return Config{}, err
	}

	publicURL := strings.TrimSpace(os.Getenv("FEDMES_PUBLIC_URL"))
	if publicURL == "" {
		return Config{}, errors.New("FEDMES_PUBLIC_URL is required in production")
	}
	parsedPublicURL, parseErr := url.Parse(publicURL)
	if parseErr != nil || parsedPublicURL.Scheme != "https" || parsedPublicURL.Host == "" || parsedPublicURL.User != nil ||
		(parsedPublicURL.Path != "" && parsedPublicURL.Path != "/") || parsedPublicURL.RawQuery != "" || parsedPublicURL.Fragment != "" {
		return Config{}, errors.New("FEDMES_PUBLIC_URL must be an HTTPS origin without credentials, path, query, or fragment")
	}
	publicURL = strings.TrimSuffix(parsedPublicURL.String(), "/")

	shutdownTimeout := defaultShutdownTimeout
	if value := strings.TrimSpace(os.Getenv("FEDMES_SHUTDOWN_TIMEOUT")); value != "" {
		shutdownTimeout, err = time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("parse FEDMES_SHUTDOWN_TIMEOUT: %w", err)
		}
		if shutdownTimeout <= 0 || shutdownTimeout > time.Minute {
			return Config{}, errors.New("FEDMES_SHUTDOWN_TIMEOUT must be greater than zero and at most one minute")
		}
	}

	return Config{
		PublicURL:       publicURL,
		Address:         address,
		DataDirectory:   absoluteDataDirectory,
		DatabasePath:    filepath.Join(absoluteDataDirectory, "fedmes.sqlite3"),
		MediaDirectory:  filepath.Join(absoluteDataDirectory, "media"),
		ShutdownTimeout: shutdownTimeout,
	}, nil
}

func validateAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("parse FEDMES_ADDR: %w", err)
	}
	if strings.TrimSpace(port) == "" {
		return errors.New("FEDMES_ADDR must include a port")
	}
	if strings.TrimSpace(host) == "" {
		return errors.New("FEDMES_ADDR must use an explicit host; use 0.0.0.0 only intentionally")
	}
	return nil
}
