package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	version          = "2.0.0"
	ticketTTL        = 3 * time.Minute
	maximumJSONBytes = 16 << 10
)

var (
	sha256Pattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	fileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)
)

type release struct {
	VersionName          string `json:"version_name"`
	VersionCode          int64  `json:"version_code"`
	MinimumSupportedCode int64  `json:"minimum_supported_code"`
	FileName             string `json:"file_name"`
	SHA256               string `json:"sha256"`
	SizeBytes            int64  `json:"size_bytes"`
	Notes                string `json:"notes"`
	PublishedAt          string `json:"published_at"`
}

type manifest struct {
	Schema   int                `json:"schema"`
	Releases map[string]release `json:"releases"`
}

type manifestStore struct {
	path    string
	mu      sync.Mutex
	modTime time.Time
	size    int64
	value   manifest
}

type ticketClaims struct {
	Version     int    `json:"v"`
	Platform    string `json:"p"`
	VersionCode int64  `json:"c"`
	SHA256      string `json:"s"`
	Username    string `json:"u"`
	DeviceID    string `json:"d"`
	ExpiresAt   int64  `json:"e"`
	Nonce       string `json:"n"`
}

type downloadRequest struct {
	Version int    `json:"version"`
	Ticket  string `json:"ticket"`
}

type ticketManager struct {
	key  []byte
	mu   sync.Mutex
	used map[string]time.Time
	now  func() time.Time
}

func main() {
	address := flag.String("addr", "127.0.0.1:8010", "адрес HTTP сервиса")
	manifestPath := flag.String("manifest", "/var/lib/fedmes/updates/releases.json", "путь к releases.json")
	filesDirectory := flag.String("files-dir", "/var/lib/fedmes/updates/files", "каталог артефактов")
	ticketKeyPath := flag.String("ticket-key", "/etc/fedmes/update-ticket.key", "ключ HMAC для трёхминутных билетов")
	showVersion := flag.Bool("version", false, "показать версию")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	key, err := readTicketKey(*ticketKeyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "update ticket key:", err)
		os.Exit(1)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	store := &manifestStore{path: strings.TrimSpace(*manifestPath)}
	tickets := &ticketManager{key: key, used: make(map[string]time.Time), now: time.Now}
	defer zero(key)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": version, "protocol": 2})
	})
	mux.HandleFunc("GET /api/v1/updates/check", func(w http.ResponseWriter, r *http.Request) {
		username, deviceID, ok := authenticatedIdentity(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "update_auth_required")
			return
		}
		platform := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("platform")))
		currentName := strings.TrimSpace(r.URL.Query().Get("version_name"))
		currentCodeText := strings.TrimSpace(r.URL.Query().Get("version_code"))
		if !supportedPlatform(platform) || len(currentName) > 64 || len(currentCodeText) > 20 {
			writeError(w, http.StatusBadRequest, "invalid_update_request")
			return
		}
		currentCode, err := strconv.ParseInt(currentCodeText, 10, 64)
		if err != nil || currentCode < 0 || currentCode > 1_000_000_000 {
			writeError(w, http.StatusBadRequest, "invalid_update_request")
			return
		}
		value, err := store.load()
		if err != nil {
			logger.Error("update manifest unavailable", "cause", err.Error())
			writeError(w, http.StatusServiceUnavailable, "update_manifest_unavailable")
			return
		}
		latest, ok := value.Releases[platform]
		if !ok {
			writeError(w, http.StatusServiceUnavailable, "release_not_configured")
			return
		}
		available := currentCode < latest.VersionCode
		latestResponse := map[string]any{
			"version_name":           latest.VersionName,
			"version_code":           latest.VersionCode,
			"minimum_supported_code": latest.MinimumSupportedCode,
			"sha256":                 latest.SHA256,
			"size_bytes":             latest.SizeBytes,
			"notes":                  latest.Notes,
			"published_at":           latest.PublishedAt,
		}
		if available {
			ticket, err := tickets.issue(platform, latest, username, deviceID)
			if err != nil {
				logger.Error("update ticket generation failed", "cause", err.Error())
				writeError(w, http.StatusInternalServerError, "update_ticket_failed")
				return
			}
			latestResponse["download_method"] = "POST"
			latestResponse["download_path"] = "/api/v1/updates/download"
			latestResponse["download_ticket"] = ticket
			latestResponse["ticket_expires_in_seconds"] = int(ticketTTL / time.Second)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"version":          2,
			"platform":         platform,
			"current_version":  currentName,
			"current_code":     currentCode,
			"update_available": available,
			"required":         currentCode < latest.MinimumSupportedCode,
			"latest":           latestResponse,
		})
	})
	mux.HandleFunc("POST /api/v1/updates/download", func(w http.ResponseWriter, r *http.Request) {
		username, deviceID, ok := authenticatedIdentity(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "update_auth_required")
			return
		}
		var request downloadRequest
		if err := decodeLimitedJSON(r.Body, &request); err != nil || request.Version != 1 || len(request.Ticket) > 4096 {
			writeError(w, http.StatusBadRequest, "invalid_download_request")
			return
		}
		claims, err := tickets.consume(request.Ticket, username, deviceID)
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, errTicketExpired) || errors.Is(err, errTicketUsed) {
				status = http.StatusGone
			}
			writeError(w, status, "download_ticket_invalid")
			return
		}
		value, err := store.load()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "update_manifest_unavailable")
			return
		}
		item, ok := value.Releases[claims.Platform]
		if !ok || item.VersionCode != claims.VersionCode || !hmac.Equal([]byte(item.SHA256), []byte(claims.SHA256)) {
			writeError(w, http.StatusGone, "release_changed")
			return
		}
		path, err := safeArtifactPath(*filesDirectory, item.FileName)
		if err != nil {
			logger.Error("invalid artifact path", "cause", err.Error())
			writeError(w, http.StatusServiceUnavailable, "artifact_unavailable")
			return
		}
		file, err := os.Open(path)
		if err != nil {
			logger.Error("artifact unavailable", "cause", err.Error(), "platform", claims.Platform)
			writeError(w, http.StatusServiceUnavailable, "artifact_unavailable")
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() != item.SizeBytes {
			writeError(w, http.StatusServiceUnavailable, "artifact_metadata_mismatch")
			return
		}
		contentType := "application/octet-stream"
		if strings.HasPrefix(claims.Platform, "android-") {
			contentType = "application/vnd.android.package-archive"
		} else if detected := mime.TypeByExtension(filepath.Ext(item.FileName)); detected != "" {
			contentType = detected
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Length", strconv.FormatInt(item.SizeBytes, 10))
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, item.FileName))
		w.Header().Set("X-FedMes-SHA256", item.SHA256)
		w.Header().Set("X-FedMes-Size", strconv.FormatInt(item.SizeBytes, 10))
		w.Header().Set("X-FedMes-Version", item.VersionName)
		w.Header().Set("Cache-Control", "private, no-store, max-age=0")
		w.WriteHeader(http.StatusOK)
		if _, err := io.Copy(w, file); err != nil {
			logger.Warn("artifact stream interrupted", "cause", err.Error(), "platform", claims.Platform, "user", username)
		}
	})

	server := &http.Server{
		Addr:              *address,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      45 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	logger.Info("update server listening", "address", *address, "manifest", *manifestPath, "version", version, "protocol", 2)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("update server stopped", "cause", err.Error())
		os.Exit(1)
	}
}

var (
	errTicketExpired = errors.New("ticket expired")
	errTicketUsed    = errors.New("ticket used")
)

func (m *ticketManager) issue(platform string, item release, username, deviceID string) (string, error) {
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", err
	}
	claims := ticketClaims{
		Version:     1,
		Platform:    platform,
		VersionCode: item.VersionCode,
		SHA256:      item.SHA256,
		Username:    username,
		DeviceID:    deviceID,
		ExpiresAt:   m.now().UTC().Add(ticketTTL).Unix(),
		Nonce:       base64.RawURLEncoding.EncodeToString(nonceBytes),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, m.key)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (m *ticketManager) consume(ticket, username, deviceID string) (ticketClaims, error) {
	parts := strings.Split(ticket, ".")
	if len(parts) != 2 || len(parts[0]) == 0 || len(parts[1]) == 0 {
		return ticketClaims{}, errors.New("malformed ticket")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ticketClaims{}, err
	}
	mac := hmac.New(sha256.New, m.key)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return ticketClaims{}, errors.New("invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ticketClaims{}, err
	}
	var claims ticketClaims
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil {
		return ticketClaims{}, err
	}
	now := m.now().UTC()
	if claims.Version != 1 || !supportedPlatform(claims.Platform) || claims.VersionCode <= 0 ||
		!sha256Pattern.MatchString(claims.SHA256) || claims.Username != username || claims.DeviceID != deviceID ||
		len(claims.Nonce) < 16 || len(claims.Nonce) > 64 {
		return ticketClaims{}, errors.New("invalid claims")
	}
	if claims.ExpiresAt < now.Unix() || claims.ExpiresAt > now.Add(ticketTTL+15*time.Second).Unix() {
		return ticketClaims{}, errTicketExpired
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for nonce, expiry := range m.used {
		if !expiry.After(now) {
			delete(m.used, nonce)
		}
	}
	if _, exists := m.used[claims.Nonce]; exists {
		return ticketClaims{}, errTicketUsed
	}
	m.used[claims.Nonce] = time.Unix(claims.ExpiresAt, 0).UTC()
	return claims, nil
}

func authenticatedIdentity(r *http.Request) (string, string, bool) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	username := strings.TrimSpace(r.Header.Get("X-FedMes-Authenticated-User"))
	deviceID := strings.TrimSpace(r.Header.Get("X-FedMes-Authenticated-Device"))
	if !strings.HasPrefix(authorization, "Bearer ") || len(strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))) < 16 ||
		username == "" || deviceID == "" || len(username) > 64 || len(deviceID) > 128 {
		return "", "", false
	}
	return username, deviceID, true
}

func readTicketKey(path string) ([]byte, error) {
	data, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(data))
	decoded, err := hex.DecodeString(text)
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("ticket key must be 64 hexadecimal characters")
	}
	return decoded, nil
}

func safeArtifactPath(directory, name string) (string, error) {
	if !fileNamePattern.MatchString(name) || filepath.Base(name) != name {
		return "", errors.New("invalid artifact name")
	}
	root, err := filepath.Abs(directory)
	if err != nil {
		return "", err
	}
	candidate, err := filepath.Abs(filepath.Join(root, name))
	if err != nil {
		return "", err
	}
	if filepath.Dir(candidate) != root {
		return "", errors.New("artifact escaped root")
	}
	return candidate, nil
}

func decodeLimitedJSON(body io.ReadCloser, destination any) error {
	defer body.Close()
	limited := io.LimitReader(body, maximumJSONBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil || len(data) == 0 || len(data) > maximumJSONBytes {
		return errors.New("invalid body")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func (s *manifestStore) load() (manifest, error) {
	info, err := os.Stat(s.path)
	if err != nil {
		return manifest{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.modTime.IsZero() && info.ModTime().Equal(s.modTime) && info.Size() == s.size {
		return s.value, nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return manifest{}, err
	}
	if len(data) == 0 || len(data) > 256<<10 {
		return manifest{}, errors.New("invalid manifest size")
	}
	var value manifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return manifest{}, err
	}
	if err := validateManifest(value); err != nil {
		return manifest{}, err
	}
	s.modTime, s.size, s.value = info.ModTime(), info.Size(), value
	return value, nil
}

func validateManifest(value manifest) error {
	if value.Schema != 2 || len(value.Releases) == 0 || len(value.Releases) > 8 {
		return errors.New("unsupported manifest schema")
	}
	for platform, item := range value.Releases {
		if !supportedPlatform(platform) {
			return fmt.Errorf("unsupported platform %q", platform)
		}
		if strings.TrimSpace(item.VersionName) == "" || item.VersionCode <= 0 || item.MinimumSupportedCode <= 0 || item.MinimumSupportedCode > item.VersionCode {
			return fmt.Errorf("invalid release %q", platform)
		}
		if !fileNamePattern.MatchString(item.FileName) || filepath.Base(item.FileName) != item.FileName {
			return fmt.Errorf("invalid file name for %q", platform)
		}
		if !sha256Pattern.MatchString(strings.ToLower(strings.TrimSpace(item.SHA256))) || item.SizeBytes <= 0 || item.SizeBytes > 2<<30 {
			return fmt.Errorf("invalid artifact metadata for %q", platform)
		}
		if _, err := time.Parse(time.RFC3339, item.PublishedAt); err != nil {
			return err
		}
		if len(item.Notes) > 4000 {
			return errors.New("release notes too long")
		}
	}
	return nil
}

func supportedPlatform(value string) bool {
	return value == "android-normal" || value == "android-huawei" || value == "windows-x64"
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store, max-age=0")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"version": 2, "error": map[string]string{"code": code}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
