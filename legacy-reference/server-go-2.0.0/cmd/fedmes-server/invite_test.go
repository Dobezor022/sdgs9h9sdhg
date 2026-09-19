package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestValidateProvisioningServerURL(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		allowHTTP bool
		want      string
		wantError bool
	}{
		{name: "HTTPS", value: "https://chat.example/", want: "https://chat.example"},
		{name: "canonical case", value: "HTTPS://CHAT.EXAMPLE:8443/", want: "https://chat.example:8443"},
		{name: "HTTP localhost", value: "http://localhost:8008/", allowHTTP: true, want: "http://localhost:8008"},
		{name: "HTTP emulator host", value: "http://10.0.2.2:8008", allowHTTP: true, want: "http://10.0.2.2:8008"},
		{name: "HTTP private IPv4", value: "http://192.168.1.10:8008", allowHTTP: true, want: "http://192.168.1.10:8008"},
		{name: "HTTP ULA IPv6", value: "http://[fd00::1]:8008", allowHTTP: true, want: "http://[fd00::1]:8008"},
		{name: "HTTP flag required", value: "http://127.0.0.1:8008", wantError: true},
		{name: "public HTTP rejected", value: "http://203.0.113.10:8008", allowHTTP: true, wantError: true},
		{name: "LAN hostname rejected", value: "http://devbox:8008", allowHTTP: true, wantError: true},
		{name: "credentials rejected", value: "https://user:password@chat.example", wantError: true},
		{name: "path rejected", value: "https://chat.example/api", wantError: true},
		{name: "query rejected", value: "https://chat.example/?debug=true", wantError: true},
		{name: "fragment rejected", value: "https://chat.example/#value", wantError: true},
		{name: "empty port rejected", value: "https://chat.example:", wantError: true},
		{name: "zero port rejected", value: "https://chat.example:0", wantError: true},
		{name: "large port rejected", value: "https://chat.example:65536", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := validateProvisioningServerURL(test.value, test.allowHTTP)
			if test.wantError {
				if err == nil {
					t.Fatalf("validateProvisioningServerURL() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateProvisioningServerURL() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("validateProvisioningServerURL() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestProvisioningQRContractUsesExactPublicFields(t *testing.T) {
	expiresAt := time.Date(2026, 7, 11, 12, 10, 0, 0, time.UTC).Format(time.RFC3339)
	encoded, err := marshalProvisioningQR(provisioningQRPayload{
		Version:   1,
		Type:      "fedmes.provisioning",
		ServerURL: "https://chat.example",
		Username:  "grisha",
		Token:     "secret-value",
		ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatalf("marshalProvisioningQR() error = %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	for _, field := range []string{"version", "type", "server_url", "username", "token", "expires_at"} {
		if _, exists := fields[field]; !exists {
			t.Fatalf("QR payload missing %q: %s", field, encoded)
		}
	}
	if len(fields) != 6 {
		t.Fatalf("QR payload fields = %v, want exactly six contract fields", fields)
	}
}

func TestRunInviteWritesPrivatePNGWithoutPrintingSecret(t *testing.T) {
	root := t.TempDir()
	outputPath := filepath.Join(root, "qr", "grisha.png")
	dataDirectory := filepath.Join(root, "data")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := runInvite(context.Background(), []string{
		"--user", "grisha",
		"--server-url", "https://chat.example",
		"--out", outputPath,
		"--ttl", "10m",
		"--data-dir", dataDirectory,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runInvite() error = %v, stderr = %s", err, stderr.String())
	}
	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if len(contents) < 8 || !bytes.Equal(contents[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
		t.Fatal("QR output is not a PNG")
	}
	output := stdout.String()
	for _, forbidden := range []string{"https://chat.example", "fedmes.provisioning", `"token"`, "server_url"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("stdout contains QR secret payload material %q: %s", forbidden, output)
		}
	}
	if !strings.Contains(output, "username=grisha") || !strings.Contains(output, "qr="+outputPath) || !strings.Contains(output, "expires_at=") {
		t.Fatalf("stdout = %q, want redacted creation summary", output)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(outputPath)
		if err != nil {
			t.Fatalf("Stat() error = %v", err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("QR permissions = %o, want no group/other access", info.Mode().Perm())
		}
	}
}

func TestRunInviteRefusesToOverwriteExistingOutput(t *testing.T) {
	root := t.TempDir()
	outputPath := filepath.Join(root, "grisha.png")
	original := []byte("existing-private-file")
	if err := os.WriteFile(outputPath, original, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	var stdout bytes.Buffer
	err := runInvite(context.Background(), []string{
		"--user", "grisha",
		"--server-url", "https://chat.example",
		"--out", outputPath,
		"--data-dir", filepath.Join(root, "data"),
	}, &stdout, &bytes.Buffer{})
	if err == nil {
		t.Fatal("runInvite() succeeded over an existing output file")
	}
	contents, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatalf("ReadFile() error = %v", readErr)
	}
	if !bytes.Equal(contents, original) {
		t.Fatalf("existing output was modified: %q", contents)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty on failure", stdout.String())
	}
	if _, statErr := os.Stat(filepath.Join(root, "data", "fedmes.sqlite3")); !os.IsNotExist(statErr) {
		t.Fatalf("database should not be created when output exists; stat error = %v", statErr)
	}
}
