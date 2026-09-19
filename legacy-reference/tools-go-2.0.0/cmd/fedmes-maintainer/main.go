package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	version     = "2.0.0"
	versionCode = int64(20000)
)

type config struct {
	dataDir          string
	manifestPath     string
	updateURL        string
	applyCommand     string
	interval         time.Duration
	updateInterval   time.Duration
	once             bool
	autoServerUpdate bool
}

type releaseManifest struct {
	Schema   int                    `json:"schema"`
	Releases map[string]clientBuild `json:"releases"`
}

type clientBuild struct {
	FileName  string `json:"file_name"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type serverUpdate struct {
	Version     string `json:"version"`
	VersionCode int64  `json:"version_code"`
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	PublishedAt string `json:"published_at"`
}

type maintainer struct {
	cfg             config
	httpClient      *http.Client
	fedmesUID       int
	fedmesGID       int
	lastUpdateCheck time.Time
	lastAppliedCode int64
}

func main() {
	cfg := config{}
	flag.StringVar(&cfg.dataDir, "data-dir", "/var/lib/fedmes", "FedMes data directory")
	flag.StringVar(&cfg.manifestPath, "manifest", "/var/lib/fedmes/updates/releases.json", "client release manifest")
	flag.StringVar(&cfg.updateURL, "server-update-url", "", "server update manifest URL (required when auto-server-update=true)")
	flag.StringVar(&cfg.applyCommand, "apply-command", "/opt/fedmes/bin/fedmes-apply-update", "verified update apply command")
	flag.DurationVar(&cfg.interval, "interval", time.Minute, "repair interval")
	flag.DurationVar(&cfg.updateInterval, "update-interval", 30*time.Minute, "server update check interval")
	flag.BoolVar(&cfg.once, "once", false, "run one repair cycle and exit")
	flag.BoolVar(&cfg.autoServerUpdate, "auto-server-update", true, "download and apply newer server bundles")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Printf("FedMes Maintainer %s (%d)\n", version, versionCode)
		return
	}
	if cfg.interval < 10*time.Second {
		log.Fatal("interval must be at least 10 seconds")
	}
	if cfg.updateInterval < time.Minute {
		log.Fatal("update interval must be at least one minute")
	}
	if cfg.autoServerUpdate && strings.TrimSpace(cfg.updateURL) == "" {
		log.Fatal("server-update-url is required when auto-server-update=true")
	}

	uid, gid := lookupUser("fedmes")
	m := &maintainer{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Minute,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}
				if len(via) > 0 && !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
					return errors.New("cross-host update redirect rejected")
				}
				return nil
			},
		},
		fedmesUID: uid,
		fedmesGID: gid,
	}

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
		if err := m.runCycle(ctx); err != nil {
			log.Printf("cycle completed with errors: %v", err)
		}
		cancel()
		if cfg.once {
			return
		}
		time.Sleep(cfg.interval)
	}
}

func (m *maintainer) runCycle(ctx context.Context) error {
	var failures []error
	steps := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"permissions", m.repairPermissions},
		{"temporary files", m.cleanTemporaryFiles},
		{"release manifest", m.validateClientManifest},
		{"nginx", m.repairNginx},
		{"fedmes service", func(ctx context.Context) error {
			return m.ensureService(ctx, "fedmes.service", "http://127.0.0.1:8008/health/live")
		}},
		{"update service", func(ctx context.Context) error {
			return m.ensureService(ctx, "fedmes-update.service", "http://127.0.0.1:8010/health")
		}},
	}
	for _, step := range steps {
		if err := step.fn(ctx); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", step.name, err))
			log.Printf("repair %s failed: %v", step.name, err)
		}
	}
	if m.cfg.autoServerUpdate && time.Since(m.lastUpdateCheck) >= m.cfg.updateInterval {
		m.lastUpdateCheck = time.Now()
		if err := m.checkServerUpdate(ctx); err != nil {
			failures = append(failures, fmt.Errorf("server update: %w", err))
			log.Printf("server update check failed: %v", err)
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	log.Printf("FedMes %s maintenance cycle OK", version)
	return nil
}

func (m *maintainer) repairPermissions(context.Context) error {
	updatesDir := filepath.Join(m.cfg.dataDir, "updates")
	filesDir := filepath.Join(updatesDir, "files")
	maintenanceDir := filepath.Join(m.cfg.dataDir, "maintenance")
	serverUpdatesDir := filepath.Join(m.cfg.dataDir, "server-updates")
	serverFilesDir := filepath.Join(serverUpdatesDir, "files")
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{
		{m.cfg.dataDir, 0o700},
		{updatesDir, 0o700},
		{filesDir, 0o700},
		{maintenanceDir, 0o700},
		{serverUpdatesDir, 0o755},
		{serverFilesDir, 0o755},
	} {
		if err := os.MkdirAll(item.path, item.mode); err != nil {
			return err
		}
		if err := os.Chmod(item.path, item.mode); err != nil {
			return err
		}
		_ = os.Chown(item.path, m.fedmesUID, m.fedmesGID)
	}
	entries, err := os.ReadDir(filesDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(filesDir, entry.Name())
		if err := os.Chmod(path, 0o600); err != nil {
			return err
		}
		_ = os.Chown(path, m.fedmesUID, m.fedmesGID)
	}
	serverEntries, err := os.ReadDir(serverFilesDir)
	if err != nil {
		return err
	}
	for _, entry := range serverEntries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(serverFilesDir, entry.Name())
		if err := os.Chmod(path, 0o644); err != nil {
			return err
		}
		_ = os.Chown(path, m.fedmesUID, m.fedmesGID)
	}
	if _, err := exec.LookPath("setfacl"); err == nil {
		_ = exec.Command("setfacl", "-x", "u:www-data", updatesDir).Run()
		_ = exec.Command("setfacl", "-x", "u:www-data", filesDir).Run()
		_ = exec.Command("setfacl", "-k", filesDir).Run()
		commands := [][]string{
			{"-m", "u:www-data:--x", m.cfg.dataDir},
			{"-m", "u:www-data:rx", serverUpdatesDir},
			{"-m", "u:www-data:rx", serverFilesDir},
			{"-m", "d:u:www-data:r-x", serverFilesDir},
		}
		for _, args := range commands {
			if output, err := exec.Command("setfacl", args...).CombinedOutput(); err != nil {
				return fmt.Errorf("setfacl %v: %w: %s", args, err, strings.TrimSpace(string(output)))
			}
		}
	}
	return nil
}

func (m *maintainer) cleanTemporaryFiles(context.Context) error {
	cutoff := time.Now().Add(-2 * time.Hour)
	roots := []string{
		filepath.Join(m.cfg.dataDir, "updates", "files"),
		filepath.Join(m.cfg.dataDir, "maintenance"),
		filepath.Join(m.cfg.dataDir, "media"),
	}
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := strings.ToLower(entry.Name())
			if !strings.HasSuffix(name, ".part") && !strings.HasSuffix(name, ".tmp") && !strings.HasPrefix(name, "upload-") {
				continue
			}
			info, err := entry.Info()
			if err == nil && info.ModTime().Before(cutoff) {
				_ = os.Remove(filepath.Join(root, entry.Name()))
			}
		}
	}
	return nil
}

func (m *maintainer) validateClientManifest(context.Context) error {
	bytes, err := os.ReadFile(m.cfg.manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var manifest releaseManifest
	if err := json.Unmarshal(bytes, &manifest); err != nil {
		return err
	}
	if manifest.Schema != 2 {
		return fmt.Errorf("unsupported client manifest schema %d", manifest.Schema)
	}
	for platform, release := range manifest.Releases {
		if release.SHA256 == strings.Repeat("0", 64) {
			continue
		}
		if release.SizeBytes < 1 || !validSHA(release.SHA256) {
			return fmt.Errorf("invalid %s release metadata", platform)
		}
		name := filepath.Base(release.FileName)
		if name == "." || name == "/" || name == "" || name != release.FileName {
			return fmt.Errorf("invalid %s file name", platform)
		}
		path := filepath.Join(m.cfg.dataDir, "updates", "files", name)
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("%s file: %w", platform, err)
		}
		if info.Size() != release.SizeBytes {
			return fmt.Errorf("%s size mismatch: manifest=%d file=%d", platform, release.SizeBytes, info.Size())
		}
		actual, hashErr := fileSHA256(path)
		if hashErr != nil {
			return fmt.Errorf("%s SHA-256: %w", platform, hashErr)
		}
		if !strings.EqualFold(actual, release.SHA256) {
			return fmt.Errorf("%s SHA-256 mismatch", platform)
		}
	}
	return nil
}

func (m *maintainer) repairNginx(ctx context.Context) error {
	if output, err := exec.CommandContext(ctx, "nginx", "-t").CombinedOutput(); err != nil {
		backup := "/etc/fedmes/nginx-fedmes.conf"
		bytes, readErr := os.ReadFile(backup)
		if readErr != nil {
			return fmt.Errorf("configuration invalid and backup unavailable: %w: %s", err, strings.TrimSpace(string(output)))
		}
		if writeErr := os.WriteFile("/etc/nginx/sites-available/fedmes", bytes, 0o644); writeErr != nil {
			return fmt.Errorf("restore nginx configuration: %w", writeErr)
		}
		_ = os.Remove("/etc/nginx/sites-enabled/fedmes")
		if linkErr := os.Symlink("/etc/nginx/sites-available/fedmes", "/etc/nginx/sites-enabled/fedmes"); linkErr != nil {
			return fmt.Errorf("restore nginx symlink: %w", linkErr)
		}
		if retryOutput, retryErr := exec.CommandContext(ctx, "nginx", "-t").CombinedOutput(); retryErr != nil {
			return fmt.Errorf("configuration remains invalid after restore: %w: %s", retryErr, strings.TrimSpace(string(retryOutput)))
		}
		log.Printf("restored FedMes nginx configuration from %s", backup)
	}
	if err := m.ensureService(ctx, "nginx.service", ""); err != nil {
		return err
	}
	if output, err := exec.CommandContext(ctx, "systemctl", "reload", "nginx.service").CombinedOutput(); err != nil {
		return fmt.Errorf("reload nginx: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (m *maintainer) ensureService(ctx context.Context, service, healthURL string) error {
	if err := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", service).Run(); err != nil {
		log.Printf("%s is inactive; restarting", service)
		if output, restartErr := exec.CommandContext(ctx, "systemctl", "restart", service).CombinedOutput(); restartErr != nil {
			return fmt.Errorf("restart: %w: %s", restartErr, strings.TrimSpace(string(output)))
		}
	}
	if healthURL == "" {
		return nil
	}
	if err := m.health(ctx, healthURL); err == nil {
		return nil
	}
	log.Printf("%s health failed; restarting", service)
	if output, err := exec.CommandContext(ctx, "systemctl", "restart", service).CombinedOutput(); err != nil {
		return fmt.Errorf("health restart: %w: %s", err, strings.TrimSpace(string(output)))
	}
	for attempt := 0; attempt < 10; attempt++ {
		time.Sleep(time.Second)
		if err := m.health(ctx, healthURL); err == nil {
			return nil
		}
	}
	return errors.New("health endpoint did not recover")
}

func (m *maintainer) health(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (m *maintainer) checkServerUpdate(ctx context.Context) error {
	url := m.cfg.updateURL
	separator := "?"
	if strings.Contains(url, "?") {
		separator = "&"
	}
	url += separator + "fedmes_current=" + strconv.FormatInt(versionCode, 10) + "&nonce=" + strconv.FormatInt(time.Now().UnixNano(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache, no-store")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("manifest HTTP %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, 256*1024)
	var release serverUpdate
	if err := json.NewDecoder(limited).Decode(&release); err != nil {
		return err
	}
	if release.VersionCode <= versionCode || release.VersionCode <= m.lastAppliedCode {
		return nil
	}
	if release.SizeBytes < 1 || !validSHA(release.SHA256) || !sameHTTPSOrigin(m.cfg.updateURL, release.DownloadURL) {
		return errors.New("server update manifest is invalid")
	}
	maintenanceDir := filepath.Join(m.cfg.dataDir, "maintenance")
	if err := os.MkdirAll(maintenanceDir, 0o700); err != nil {
		return err
	}
	target := filepath.Join(maintenanceDir, fmt.Sprintf("FedMes-server-%d-%s.tar.gz", release.VersionCode, strings.ToLower(release.SHA256[:12])))
	if err := m.downloadVerified(ctx, release, target); err != nil {
		return err
	}
	m.lastAppliedCode = release.VersionCode
	log.Printf("applying FedMes server update %s (%d)", release.Version, release.VersionCode)
	cmd := exec.CommandContext(ctx, m.cfg.applyCommand, target, strconv.FormatInt(release.VersionCode, 10))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("apply update: %w", err)
	}
	return nil
}

func sameHTTPSOrigin(manifestURL, downloadURL string) bool {
	manifest, err := url.Parse(manifestURL)
	if err != nil || !strings.EqualFold(manifest.Scheme, "https") || manifest.Hostname() == "" {
		return false
	}
	download, err := url.Parse(downloadURL)
	if err != nil || !strings.EqualFold(download.Scheme, "https") || download.Hostname() == "" || download.User != nil {
		return false
	}
	return strings.EqualFold(manifest.Hostname(), download.Hostname()) && effectivePort(manifest) == effectivePort(download)
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return ""
}

func (m *maintainer) downloadVerified(ctx context.Context, release serverUpdate, target string) error {
	url := release.DownloadURL
	separator := "?"
	if strings.Contains(url, "?") {
		separator = "&"
	}
	url += separator + "fedmes_sha=" + release.SHA256[:16]
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache, no-store")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bundle HTTP %d", resp.StatusCode)
	}
	temporary := target + ".part"
	_ = os.Remove(temporary)
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	written, copyErr := io.CopyBuffer(io.MultiWriter(file, hasher), resp.Body, make([]byte, 256*1024))
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(temporary)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(temporary)
		return closeErr
	}
	if written != release.SizeBytes {
		_ = os.Remove(temporary)
		return fmt.Errorf("bundle size mismatch: expected %d, received %d", release.SizeBytes, written)
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(actual, release.SHA256) {
		_ = os.Remove(temporary)
		return errors.New("bundle SHA-256 mismatch")
	}
	_ = os.Remove(target)
	if err := os.Rename(temporary, target); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.CopyBuffer(hasher, file, make([]byte, 256*1024)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func validSHA(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func lookupUser(name string) (int, int) {
	entry, err := user.Lookup(name)
	if err != nil {
		return -1, -1
	}
	uid, _ := strconv.Atoi(entry.Uid)
	gid, _ := strconv.Atoi(entry.Gid)
	return uid, gid
}
