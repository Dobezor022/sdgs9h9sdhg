package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fedmes/server/internal/database"
	"fedmes/server/internal/provisioning"

	qrcode "github.com/skip2/go-qrcode"
)

const provisioningQRSize = 512

type provisioningQRPayload struct {
	Version   int    `json:"version"`
	Type      string `json:"type"`
	ServerURL string `json:"server_url"`
	Username  string `json:"username"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

func runInvite(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("invite", flag.ContinueOnError)
	flags.SetOutput(stderr)
	username := flags.String("user", "", "fixed family username")
	serverURLValue := flags.String("server-url", "", "public HTTPS server base URL")
	outputPath := flags.String("out", "", "output QR PNG path")
	ttl := flags.Duration("ttl", 10*time.Minute, "one-time invitation lifetime")
	dataDirectory := flags.String("data-dir", "data", "server data directory")
	allowHTTP := flags.Bool("allow-http", false, "allow HTTP for loopback or private LAN development")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("invite does not accept positional arguments")
	}
	parsedUsername, err := provisioning.ParseUsername(*username)
	if err != nil {
		return errors.New("--user must be one of grisha, papa, mama, yura, vasya")
	}
	serverURL, err := validateProvisioningServerURL(*serverURLValue, *allowHTTP)
	if err != nil {
		return err
	}
	if strings.ToLower(filepath.Ext(*outputPath)) != ".png" {
		return errors.New("--out must name a PNG file")
	}
	absoluteOutputPath, err := filepath.Abs(*outputPath)
	if err != nil {
		return fmt.Errorf("resolve --out: %w", err)
	}
	absoluteDataDirectory, err := filepath.Abs(strings.TrimSpace(*dataDirectory))
	if err != nil {
		return fmt.Errorf("resolve --data-dir: %w", err)
	}
	if err := os.MkdirAll(absoluteDataDirectory, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absoluteOutputPath), 0o700); err != nil {
		return fmt.Errorf("create QR output directory: %w", err)
	}
	if _, err := os.Lstat(absoluteOutputPath); err == nil {
		return errors.New("--out already exists; choose a new path")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect --out: %w", err)
	}

	store, err := database.Open(ctx, filepath.Join(absoluteDataDirectory, "fedmes.sqlite3"))
	if err != nil {
		return err
	}
	defer store.Close()
	service, err := provisioning.NewService(store, provisioning.SystemClock{}, provisioning.CryptoEntropy{}, provisioning.DefaultConfig())
	if err != nil {
		return err
	}
	invitation, err := service.IssueInvitation(ctx, string(parsedUsername), *ttl)
	if err != nil {
		return err
	}
	payload, err := marshalProvisioningQR(provisioningQRPayload{
		Version:   1,
		Type:      "fedmes.provisioning",
		ServerURL: serverURL,
		Username:  string(parsedUsername),
		Token:     invitation.Token.Reveal(),
		ExpiresAt: invitation.ExpiresAt.Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("encode QR payload: %w", err)
	}
	defer clear(payload)
	png, err := qrcode.Encode(string(payload), qrcode.Medium, provisioningQRSize)
	if err != nil {
		return errors.New("encode QR image")
	}
	defer clear(png)
	if err := writePrivateFileAtomically(absoluteOutputPath, png); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "invitation created username=%s qr=%s expires_at=%s\n", parsedUsername, absoluteOutputPath, invitation.ExpiresAt.Format(time.RFC3339))
	return err
}

func validateProvisioningServerURL(value string, allowHTTP bool) (string, error) {
	trimmed := strings.TrimSpace(value)
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" {
		return "", errors.New("--server-url must be an absolute server URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("--server-url must not contain credentials, a path, query, or fragment")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	switch parsed.Scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return "", errors.New("--server-url must use HTTPS; use --allow-http only for local development")
		}
		if !isDevelopmentHost(parsed.Hostname()) {
			return "", errors.New("--allow-http accepts only loopback or private LAN hosts")
		}
	default:
		return "", errors.New("--server-url must use HTTPS")
	}
	port := parsed.Port()
	if strings.HasSuffix(parsed.Host, ":") {
		return "", errors.New("--server-url contains an empty port")
	}
	if port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", errors.New("--server-url contains an invalid port")
		}
	}
	hostname := strings.ToLower(parsed.Hostname())
	if port != "" {
		parsed.Host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		parsed.Host = "[" + hostname + "]"
	} else {
		parsed.Host = hostname
	}
	parsed.Path = ""
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func marshalProvisioningQR(payload provisioningQRPayload) ([]byte, error) {
	return json.Marshal(payload)
}

func isDevelopmentHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

func writePrivateFileAtomically(path string, contents []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".fedmes-qr-*.png")
	if err != nil {
		return fmt.Errorf("create temporary QR file: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict QR file permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		return fmt.Errorf("write QR file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("flush QR file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close QR file: %w", err)
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if _, statErr := os.Lstat(path); statErr == nil {
			return errors.New("QR output already exists; it was not overwritten")
		}
		return fmt.Errorf("publish QR file: %w", err)
	}
	if err := os.Remove(temporaryPath); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("remove temporary QR link: %w", err)
	}
	committed = true
	return nil
}
