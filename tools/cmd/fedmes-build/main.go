package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const version = "3.0.0"

type options struct {
	root      string
	skipTests bool
}

type buildMetadata struct {
	Target   string `json:"target"`
	BuiltAt  string `json:"built_at_utc"`
	Builder  string `json:"builder"`
	HostOS   string `json:"host_os"`
	HostArch string `json:"host_arch"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("fedmes-build", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", "", "корень проекта")
	skipTests := flags.Bool("skip-tests", false, "не запускать тесты")
	showVersion := flags.Bool("version", false, "показать версию")
	if err := flags.Parse(args); err != nil {
		return usageError()
	}
	if *showVersion {
		fmt.Println(version)
		return nil
	}

	target := ""
	if flags.NArg() > 0 {
		target = strings.ToLower(strings.TrimSpace(flags.Arg(0)))
	} else {
		selected, err := selectTarget()
		if err != nil {
			return err
		}
		target = selected
	}
	if flags.NArg() > 1 {
		return usageError()
	}

	resolvedRoot, err := resolveProjectRoot(*root)
	if err != nil {
		return err
	}
	cfg := options{root: resolvedRoot, skipTests: *skipTests}

	fmt.Printf("FedMes Builder %s\n", version)
	fmt.Printf("Проект: %s\n", cfg.root)
	fmt.Printf("Цель:   %s\n\n", target)

	switch target {
	case "android", "normal":
		return buildAndroid(cfg, false)
	case "huawei", "harmonyos", "harmonous2.0":
		return buildAndroid(cfg, true)
	case "windowsclient":
		return buildWindowsClient(cfg)
	case "windowsxhttp", "windowshttp":
		return buildWindowsHTTP(cfg)
	case "linuxhttps":
		return buildLinuxHTTPS(cfg)
	case "all":
		return buildAll(cfg)
	default:
		return usageError()
	}
}

func usageError() error {
	return errors.New("использование: fedmes-build [--root ПУТЬ] [--skip-tests] android|huawei|windowsclient|linuxhttps|all")
}

func selectTarget() (string, error) {
	fmt.Println("Выберите сборку:")
	fmt.Println("  1 — Android Normal")
	fmt.Println("  2 — Huawei / HarmonyOS 2.0+")
	fmt.Println("  3 — Windows клиент")
	fmt.Println("  4 — Linux HTTPS комплект (Rust server source)")
	fmt.Println("  5 — Всё")
	fmt.Print("Номер: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	switch strings.TrimSpace(line) {
	case "1":
		return "android", nil
	case "2":
		return "huawei", nil
	case "3":
		return "windowsclient", nil
	case "4":
		return "linuxhttps", nil
	case "5":
		return "all", nil
	default:
		return "", errors.New("неверный номер сборки")
	}
}

func resolveProjectRoot(explicit string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		absolute, err := filepath.Abs(explicit)
		if err != nil {
			return "", err
		}
		if isProjectRoot(absolute) {
			return absolute, nil
		}
		return "", fmt.Errorf("в каталоге %s не найден проект FedMes", absolute)
	}

	candidates := []string{}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(executable))
	}
	if current, err := os.Getwd(); err == nil {
		candidates = append(candidates, current)
	}
	for _, start := range candidates {
		current := start
		for {
			if isProjectRoot(current) {
				return current, nil
			}
			parent := filepath.Dir(current)
			if parent == current {
				break
			}
			current = parent
		}
	}
	return "", errors.New("не удалось найти корень проекта; укажите --root")
}

func isProjectRoot(path string) bool {
	required := []string{
		filepath.Join(path, "server", "Cargo.toml"),
		filepath.Join(path, "android", "settings.gradle.kts"),
		filepath.Join(path, "desktop", "FedMes.Desktop.slnx"),
		filepath.Join(path, "tools", "go.mod"),
	}
	for _, item := range required {
		if info, err := os.Stat(item); err != nil || info.IsDir() {
			return false
		}
	}
	return true
}

func buildAll(cfg options) error {
	steps := []struct {
		name string
		run  func(options) error
	}{
		{"Android Normal", func(o options) error { return buildAndroid(o, false) }},
		{"Huawei", func(o options) error { return buildAndroid(o, true) }},
		{"Windows клиент", buildWindowsClient},
		{"Linux HTTPS комплект", buildLinuxHTTPS},
	}
	for _, step := range steps {
		fmt.Printf("\n========== %s ==========\n", step.name)
		if err := step.run(cfg); err != nil {
			return fmt.Errorf("%s: %w", step.name, err)
		}
	}
	fmt.Printf("\nВсе сборки готовы: %s\n", filepath.Join(cfg.root, "Build"))
	return nil
}

func buildAndroid(cfg options, huawei bool) error {
	if err := buildAndroidCryptoCore(cfg); err != nil {
		return fmt.Errorf("shared Android crypto core: %w", err)
	}
	androidRoot := filepath.Join(cfg.root, "android")
	wrapper := filepath.Join(androidRoot, "gradlew")
	if runtime.GOOS == "windows" {
		wrapper = filepath.Join(androidRoot, "gradlew.bat")
	} else if err := os.Chmod(wrapper, 0o755); err != nil {
		return fmt.Errorf("сделать gradlew исполняемым: %w", err)
	}

	for _, name := range []string{"FEDMES_ANDROID_KEYSTORE", "FEDMES_ANDROID_KEYSTORE_PASSWORD", "FEDMES_ANDROID_KEY_ALIAS", "FEDMES_ANDROID_KEY_PASSWORD"} {
		if strings.TrimSpace(os.Getenv(name)) == "" {
			return fmt.Errorf("для release APK не задана переменная %s", name)
		}
	}
	if !fileExists(os.Getenv("FEDMES_ANDROID_KEYSTORE")) {
		return errors.New("release keystore не найден; проверьте FEDMES_ANDROID_KEYSTORE")
	}

	flavor := "normal"
	task := ":app:assembleNormalRelease"
	source := filepath.Join(androidRoot, "app", "build", "outputs", "apk", "normal", "release", "app-normal-release.apk")
	outputDir := filepath.Join(cfg.root, "Build", "android", "normal")
	outputName := "FedMes-normal.apk"
	if huawei {
		flavor = "huawei"
		task = ":app:assembleHuaweiRelease"
		source = filepath.Join(androidRoot, "app", "build", "outputs", "apk", "huawei", "release", "app-huawei-release.apk")
		outputDir = filepath.Join(cfg.root, "Build", "android", "huawei", "harmonous2.0")
		outputName = "FedMes-huawei.apk"
	}

	if _, err := exec.LookPath("java"); err != nil {
		return errors.New("Java 21 не найдена в PATH")
	}
	if err := ensureAndroidLocalProperties(androidRoot); err != nil {
		return err
	}
	args := []string{"--console=plain", "--stacktrace"}
	if !cfg.skipTests {
		// AGP 9.2 does not guarantee the old per-variant unit-test task name,
		// therefore unit tests use the stable aggregate lifecycle task. Lint
		// remains scoped to the release variant being assembled so a Normal
		// build does not compile or lint Huawei Debug and vice versa.
		lintTask := ":app:lintNormalRelease"
		if huawei {
			lintTask = ":app:lintHuaweiRelease"
		}
		args = append(args, ":app:test", lintTask)
	}
	args = append(args, task)
	if err := runCommand(androidRoot, nil, wrapper, args...); err != nil {
		return err
	}
	if err := resetOutputDirectory(outputDir); err != nil {
		return err
	}
	destination := filepath.Join(outputDir, outputName)
	if err := copyFile(source, destination, 0o644); err != nil {
		return fmt.Errorf("копирование APK %s: %w", flavor, err)
	}
	if err := writeChecksum(destination); err != nil {
		return err
	}
	if err := writeMetadata(outputDir, "android-"+flavor); err != nil {
		return err
	}
	fmt.Println("Готово:", destination)
	return nil
}

func ensureAndroidLocalProperties(androidRoot string) error {
	localProperties := filepath.Join(androidRoot, "local.properties")

	// Java .properties treats ':' as a key/value separator even when forward
	// slashes are used. Always rewrite a discovered SDK path to canonical form
	// (for example C\:/Android/Sdk) instead of accepting an existing but lint-
	// invalid value such as C:/Android/Sdk.
	if content, err := os.ReadFile(localProperties); err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(strings.TrimSuffix(line, "\r")), "=")
			if !ok || key != "sdk.dir" {
				continue
			}
			decoded := strings.ReplaceAll(value, `\\`, `\`)
			decoded = strings.ReplaceAll(decoded, `\:`, `:`)
			if info, statErr := os.Stat(decoded); statErr == nil && info.IsDir() {
				return writeAndroidLocalProperties(localProperties, decoded)
			}
		}
	}

	candidates := []string{
		strings.TrimSpace(os.Getenv("ANDROID_SDK_ROOT")),
		strings.TrimSpace(os.Getenv("ANDROID_HOME")),
	}
	if runtime.GOOS == "windows" {
		candidates = append(candidates, `C:\Android\Sdk`, `C:\Android\SDK`, `C:\Android\sdk`)
		if localAppData := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); localAppData != "" {
			candidates = append(candidates, filepath.Join(localAppData, "Android", "Sdk"))
		}
	} else {
		if home, err := os.UserHomeDir(); err == nil {
			candidates = append(candidates, filepath.Join(home, "Android", "Sdk"))
		}
		candidates = append(candidates, "/opt/android-sdk", "/usr/lib/android-sdk")
	}

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			absolute, absErr := filepath.Abs(candidate)
			if absErr != nil {
				return fmt.Errorf("получить абсолютный путь Android SDK: %w", absErr)
			}
			return writeAndroidLocalProperties(localProperties, absolute)
		}
	}
	return errors.New("Android SDK не найден; задайте ANDROID_SDK_ROOT")
}

func writeAndroidLocalProperties(path string, sdk string) error {
	canonical := filepath.Clean(strings.TrimSpace(sdk))
	encoded := strings.ReplaceAll(canonical, `\`, `/`)
	encoded = strings.ReplaceAll(encoded, `:`, `\:`)
	return os.WriteFile(path, []byte("sdk.dir="+encoded+"\n"), 0o644)
}

func testCryptoCore(cfg options) error {
	root := filepath.Join(cfg.root, "crypto-core")
	if _, err := exec.LookPath("go"); err != nil {
		return errors.New("Go 1.25+ не найден в PATH")
	}
	// A release source archive must be buildable even when go.sum was not
	// created on the packaging host. Resolve and verify the pinned module graph
	// before tests. GOFLAGS is overridden deliberately so a global
	// -mod=readonly setting cannot cause a misleading missing-go.sum failure.
	moduleEnv := []string{"GOFLAGS=-mod=mod"}
	const mobileVersion = "v0.0.0-20260520154334-0e4426e1883d"
	const gobindTool = "golang.org/x/mobile/cmd/gobind"
	const patchedKSF = "./third_party/ksf"
	if !fileExists(filepath.Join(root, "third_party", "ksf", "go.mod")) {
		return errors.New("локальный Android 32-bit patch github.com/bytemare/ksf не найден")
	}
	if err := runCommand(root, moduleEnv, "go", "mod", "edit", "-replace=github.com/bytemare/ksf="+patchedKSF); err != nil {
		return fmt.Errorf("подключение локального Android 32-bit patch github.com/bytemare/ksf: %w", err)
	}
	if err := runCommand(root, moduleEnv, "go", "mod", "edit", "-require=golang.org/x/mobile@"+mobileVersion); err != nil {
		return fmt.Errorf("фиксация golang.org/x/mobile: %w", err)
	}
	if err := runCommand(root, moduleEnv, "go", "mod", "edit", "-tool="+gobindTool); err != nil {
		return fmt.Errorf("регистрация gobind как module tool: %w", err)
	}
	if err := runCommand(root, moduleEnv, "go", "mod", "tidy"); err != nil {
		return fmt.Errorf("подготовка зависимостей crypto-core: %w", err)
	}
	if cfg.skipTests {
		return nil
	}
	readonlyEnv := []string{"GOFLAGS=-mod=readonly"}
	if err := runCommand(root, readonlyEnv, "go", "test", "./..."); err != nil {
		return err
	}
	return runCommand(root, readonlyEnv, "go", "vet", "./...")
}

func buildWindowsCryptoWorker(cfg options) error {
	if err := testCryptoCore(cfg); err != nil {
		return err
	}
	root := filepath.Join(cfg.root, "crypto-core")
	output := filepath.Join(root, "build", "windows", "fedmes-crypto-worker.exe")
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return err
	}
	env := []string{"CGO_ENABLED=0", "GOOS=windows", "GOARCH=amd64"}
	if err := runCommand(root, env, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", output, "./cmd/fedmes-crypto-worker"); err != nil {
		return err
	}
	return writeChecksum(output)
}

const gomobileVersion = "v0.0.0-20260520154334-0e4426e1883d"

func buildAndroidCryptoCore(cfg options) error {
	if err := testCryptoCore(cfg); err != nil {
		return err
	}
	root := filepath.Join(cfg.root, "crypto-core")
	gomobile, err := ensureHostGomobile(root)
	if err != nil {
		return err
	}
	hostEnv := []string{
		"CGO_ENABLED=0",
		"GOOS=" + runtime.GOOS,
		"GOARCH=" + runtime.GOARCH,
	}
	if err := runCommand(root, hostEnv, gomobile, "init"); err != nil {
		// The executable may have been replaced or corrupted after validation.
		// Reinstall once with the explicit host target and retry.
		if reinstallErr := installHostGomobile(root, gomobile); reinstallErr != nil {
			return errors.Join(err, reinstallErr)
		}
		if retryErr := runCommand(root, hostEnv, gomobile, "init"); retryErr != nil {
			return retryErr
		}
	}
	output := filepath.Join(root, "build", "android", "fedmescrypto.aar")
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return err
	}
	if err := runCommand(root, hostEnv, gomobile, "bind", "-target=android", "-androidapi=26", "-trimpath", "-o", output, "./mobile"); err != nil {
		return err
	}
	return writeChecksum(output)
}

func ensureHostGomobile(root string) (string, error) {
	goPath, err := goEnvValue(root, "GOPATH", []string{
		"CGO_ENABLED=0",
		"GOOS=" + runtime.GOOS,
		"GOARCH=" + runtime.GOARCH,
	})
	if err != nil {
		return "", err
	}
	firstGoPath := strings.Split(goPath, string(os.PathListSeparator))[0]
	if strings.TrimSpace(firstGoPath) == "" {
		return "", errors.New("go env GOPATH вернул пустой путь")
	}
	gomobile := filepath.Join(firstGoPath, "bin", "gomobile")
	if runtime.GOOS == "windows" {
		gomobile += ".exe"
	}
	if err := validateHostGoExecutable(root, gomobile); err == nil {
		return gomobile, nil
	}
	if err := installHostGomobile(root, gomobile); err != nil {
		return "", err
	}
	if err := validateHostGoExecutable(root, gomobile); err != nil {
		return "", fmt.Errorf("проверка установленного gomobile: %w", err)
	}
	return gomobile, nil
}

func installHostGomobile(root, destination string) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("удалить несовместимый gomobile %s: %w", destination, err)
	}
	env := []string{
		"CGO_ENABLED=0",
		"GOOS=" + runtime.GOOS,
		"GOARCH=" + runtime.GOARCH,
		"GOBIN=" + filepath.Dir(destination),
		"GOFLAGS=-mod=mod",
	}
	if err := runCommand(root, env, "go", "install", "golang.org/x/mobile/cmd/gomobile@"+gomobileVersion); err != nil {
		return fmt.Errorf("установка gomobile для %s/%s: %w", runtime.GOOS, runtime.GOARCH, err)
	}
	return nil
}

func validateHostGoExecutable(_ string, path string) error {
	if !fileExists(path) {
		return os.ErrNotExist
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return fmt.Errorf("прочитать Go build info %s: %w", path, err)
	}
	goos, goarch := goBinaryTarget(info)
	if goos == "" || goarch == "" {
		return fmt.Errorf("в Go build info %s отсутствуют GOOS/GOARCH", path)
	}
	expected := runtime.GOOS + "/" + runtime.GOARCH
	actual := goos + "/" + goarch
	if actual != expected {
		return fmt.Errorf("gomobile имеет неверную платформу: ожидалась %s, получено %s", expected, actual)
	}
	return nil
}

func goBinaryTarget(info *buildinfo.BuildInfo) (goos, goarch string) {
	if info == nil {
		return "", ""
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "GOOS":
			goos = setting.Value
		case "GOARCH":
			goarch = setting.Value
		}
	}
	return goos, goarch
}

func goEnvValue(root, key string, environment []string) (string, error) {
	command := exec.Command("go", "env", key)
	command.Dir = root
	command.Env = mergeEnvironment(os.Environ(), environment)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("go env %s: %w: %s", key, err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func buildWindowsClient(cfg options) error {
	if err := buildWindowsCryptoWorker(cfg); err != nil {
		return fmt.Errorf("shared Windows crypto core: %w", err)
	}
	if _, err := exec.LookPath("dotnet"); err != nil {
		return errors.New(".NET SDK 10 не найден в PATH")
	}
	solution := filepath.Join(cfg.root, "desktop", "FedMes.Desktop.slnx")
	project := filepath.Join(cfg.root, "desktop", "FedMes.Desktop", "FedMes.Desktop.csproj")
	outputDir := filepath.Join(cfg.root, "Build", "windowsclient")
	if err := resetOutputDirectory(outputDir); err != nil {
		return err
	}

	common := []string{}
	if runtime.GOOS != "windows" {
		common = append(common, "-p:EnableWindowsTargeting=true")
	}
	if err := runCommand(cfg.root, nil, "dotnet", append([]string{"restore", solution}, common...)...); err != nil {
		return err
	}
	if err := runCommand(cfg.root, nil, "dotnet", append([]string{"build", solution, "--configuration", "Release", "--no-restore"}, common...)...); err != nil {
		return err
	}
	if !cfg.skipTests {
		testArgs := []string{"test", "--solution", solution, "--configuration", "Release", "--no-restore", "--no-build", "--verbosity", "normal"}
		if err := runCommand(cfg.root, nil, "dotnet", append(testArgs, common...)...); err != nil {
			return err
		}
	}
	publishArgs := []string{
		"publish", project,
		"--configuration", "Release",
		"--runtime", "win-x64",
		"--self-contained", "true",
		"--no-restore",
		"--output", outputDir,
		"-p:PublishSingleFile=true",
		"-p:PublishTrimmed=false",
		"-p:DebugType=embedded",
	}
	publishArgs = append(publishArgs, common...)
	if err := runCommand(cfg.root, nil, "dotnet", publishArgs...); err != nil {
		return err
	}
	executable := filepath.Join(outputDir, "FedMes.Desktop.exe")
	if !fileExists(executable) {
		return fmt.Errorf("не создан файл %s", executable)
	}
	if err := writeChecksum(executable); err != nil {
		return err
	}
	if err := writeMetadata(outputDir, "windowsclient"); err != nil {
		return err
	}
	fmt.Println("Готово:", executable)
	return nil
}

func buildWindowsHTTP(cfg options) error {
	return errors.New("FedMes 3.0.0 не выпускает Go/Windows server; production backend — Rust на Ubuntu. Используйте цель linuxhttps")
}

func buildLinuxHTTPS(cfg options) error {
	outputDir := filepath.Join(cfg.root, "Build", "linuxhttps")
	if err := resetOutputDirectory(outputDir); err != nil {
		return err
	}
	serverSourceOutput := filepath.Join(outputDir, "server-source.tar.gz")
	if err := createServerSourceArchive(cfg.root, serverSourceOutput); err != nil {
		return err
	}

	for _, item := range []struct {
		source, name string
		mode         os.FileMode
	}{
		{filepath.Join(cfg.root, "deploy", "linux-server.env.example"), "server.env.example", 0o644},
		{filepath.Join(cfg.root, "deploy", "releases.json"), "releases.json", 0o640},
		{filepath.Join(cfg.root, "deploy", "releases-required-template.json"), "releases-required-template.json", 0o640},
		{filepath.Join(cfg.root, "deploy", "publish-release.sh"), "publish-release.sh", 0o755},
		{filepath.Join(cfg.root, "deploy", "publish-required-update.sh"), "publish-required-update.sh", 0o755},
		{filepath.Join(cfg.root, "deploy", "clean-install-3.0.0.sh"), "clean-install-3.0.0.sh", 0o755},
		{filepath.Join(cfg.root, "deploy", "cleanup-old-fedmes-releases.sh"), "cleanup-old-fedmes-releases.sh", 0o755},
		{filepath.Join(cfg.root, "deploy", "wipe-fedmes-data.sh"), "wipe-fedmes-data.sh", 0o755},
		{filepath.Join(cfg.root, "deploy", "build-rust-server-3.0-on-ubuntu.sh"), "build-rust-server-3.0-on-ubuntu.sh", 0o755},
		{filepath.Join(cfg.root, "deploy", "backup-fedmes-encrypted.sh"), "backup-fedmes-encrypted.sh", 0o755},
		{filepath.Join(cfg.root, "deploy", "verify-fedmes-backup.sh"), "verify-fedmes-backup.sh", 0o755},
		{filepath.Join(cfg.root, "deploy", "restore-fedmes-encrypted.sh"), "restore-fedmes-encrypted.sh", 0o755},
		{filepath.Join(cfg.root, "docs", "CLEAN-INSTALL-3.0.0-UBUNTU-RU.md"), "CLEAN-INSTALL-3.0.0-UBUNTU-RU.md", 0o644},
		{filepath.Join(cfg.root, "deploy", "VERSION.txt"), "VERSION.txt", 0o644},
		{filepath.Join(cfg.root, "deploy", "README-FIRST-RU.txt"), "README-FIRST-RU.txt", 0o644},
		{filepath.Join(cfg.root, "deploy", "CHANGELOG-3.0.0-RU.md"), "CHANGELOG-3.0.0-RU.md", 0o644},
		{filepath.Join(cfg.root, "deploy", "VALIDATION-3.0.0-30000-RU.txt"), "VALIDATION-3.0.0-30000-RU.txt", 0o644},
		{filepath.Join(cfg.root, "deploy", "SECURITY-ARCHITECTURE-2.0-RU.md"), "SECURITY-ARCHITECTURE-2.0-RU.md", 0o644},
	} {
		if err := copyFile(item.source, filepath.Join(outputDir, item.name), item.mode); err != nil {
			return err
		}
	}
	if err := writeChecksum(serverSourceOutput); err != nil {
		return err
	}
	if err := writeMetadata(outputDir, "linuxhttps-rust"); err != nil {
		return err
	}
	fmt.Println("Готов Rust production bundle:", outputDir)
	fmt.Println("Сборка и cargo test выполняются на Ubuntu ДО переключения systemd.")
	return nil
}

func buildServer(cfg options, goos, goarch, output string) error {
	return errors.New("legacy Go server build disabled in FedMes 3.0.0; production backend is Rust")
}

func createServerSourceArchive(projectRoot, destination string) error {
	temporary := destination + ".tmp"
	_ = os.Remove(temporary)
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	ok := false
	defer func() {
		_ = tarWriter.Close()
		_ = gzipWriter.Close()
		_ = file.Close()
		if !ok {
			_ = os.Remove(temporary)
		}
	}()

	sourceRoot := filepath.Join(projectRoot, "server")
	if !fileExists(filepath.Join(sourceRoot, "Cargo.toml")) {
		return errors.New("missing server/Cargo.toml")
	}
	err = filepath.WalkDir(sourceRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		base := entry.Name()
		if entry.IsDir() && (base == ".git" || base == "target" || base == "data" || base == "artifacts") {
			return filepath.SkipDir
		}
		if !entry.IsDir() && (strings.HasSuffix(base, ".sqlite3") || strings.HasSuffix(base, ".db")) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(filepath.Join("server", relative))
		header.ModTime = time.Unix(0, 0).UTC()
		header.AccessTime = time.Time{}
		header.ChangeTime = time.Time{}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tarWriter, input)
		closeErr := input.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err != nil {
		return err
	}
	if err := tarWriter.Close(); err != nil {
		return err
	}
	if err := gzipWriter.Close(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	_ = os.Remove(destination)
	if err := os.Rename(temporary, destination); err != nil {
		return err
	}
	ok = true
	return nil
}

func runCommand(directory string, environment []string, name string, args ...string) error {
	fmt.Printf("> %s %s\n", name, strings.Join(args, " "))
	command := exec.Command(name, args...)
	command.Dir = directory
	command.Env = mergeEnvironment(os.Environ(), environment)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Stdin = os.Stdin
	if err := command.Run(); err != nil {
		return fmt.Errorf("команда %s завершилась с ошибкой: %w", name, err)
	}
	return nil
}

func mergeEnvironment(base, overrides []string) []string {
	values := make(map[string]string, len(base)+len(overrides))
	order := make([]string, 0, len(base)+len(overrides))
	normalize := func(key string) string {
		if runtime.GOOS == "windows" {
			return strings.ToUpper(key)
		}
		return key
	}
	apply := func(entry string) {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			return
		}
		normalized := normalize(key)
		if _, exists := values[normalized]; !exists {
			order = append(order, normalized)
		}
		values[normalized] = key + "=" + value
	}
	for _, entry := range base {
		apply(entry)
	}
	for _, entry := range overrides {
		apply(entry)
	}
	merged := make([]string, 0, len(order))
	for _, key := range order {
		merged = append(merged, values[key])
	}
	return merged
}

func resetOutputDirectory(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("очистить %s: %w", path, err)
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("создать %s: %w", path, err)
	}
	return nil
}

func copyFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	temporary := destination + ".tmp"
	output, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = output.Close()
		if !ok {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temporary, mode); err != nil {
		return err
	}
	if err := os.Rename(temporary, destination); err != nil {
		return err
	}
	ok = true
	return nil
}

func writeChecksum(path string) error {
	input, err := os.Open(path)
	if err != nil {
		return err
	}
	defer input.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, input); err != nil {
		return err
	}
	content := hex.EncodeToString(hash.Sum(nil)) + "  " + filepath.Base(path) + "\n"
	return os.WriteFile(path+".sha256", []byte(content), 0o644)
}

func writeMetadata(directory, target string) error {
	metadata := buildMetadata{
		Target:   target,
		BuiltAt:  time.Now().UTC().Format(time.RFC3339),
		Builder:  "fedmes-build/" + version,
		HostOS:   runtime.GOOS,
		HostArch: runtime.GOARCH,
	}
	encoded, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return os.WriteFile(filepath.Join(directory, "build.json"), encoded, 0o644)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
