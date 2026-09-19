package main

import (
	"bufio"
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

const version = "2.0.0"

var fixedUsers = []string{"grisha", "papa", "mama", "yura", "vasya"}

type config struct {
	serverURL string
	dataDir   string
	outputDir string
	ttl       string
	users     []string
	allowHTTP bool
	replace   bool
	serverExe string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("fedmes-qr", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	serverURL := flags.String("server-url", "", "публичный адрес сервера")
	dataDir := flags.String("data-dir", "", "каталог данных сервера")
	outputDir := flags.String("out-dir", "", "каталог QR PNG")
	ttl := flags.String("ttl", "15m", "срок действия QR")
	usersValue := flags.String("users", "all", "all или список через запятую")
	allowHTTP := flags.Bool("allow-http", false, "разрешить HTTP для локальной сети")
	replace := flags.Bool("replace", false, "удалить старые PNG с теми же именами")
	serverExe := flags.String("server-exe", "", "путь к fedmes-server")
	showVersion := flags.Bool("version", false, "показать версию")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return usageError()
	}
	if *showVersion {
		fmt.Println(version)
		return nil
	}

	cfg := config{
		serverURL: strings.TrimSpace(*serverURL),
		dataDir:   strings.TrimSpace(*dataDir),
		outputDir: strings.TrimSpace(*outputDir),
		ttl:       strings.TrimSpace(*ttl),
		allowHTTP: *allowHTTP,
		replace:   *replace,
		serverExe: strings.TrimSpace(*serverExe),
	}
	users, err := parseUsers(*usersValue)
	if err != nil {
		return err
	}
	cfg.users = users

	if cfg.serverURL == "" {
		if err := fillInteractively(&cfg); err != nil {
			return err
		}
	}
	if cfg.dataDir == "" {
		cfg.dataDir = defaultDataDirectory()
	}
	if cfg.outputDir == "" {
		cfg.outputDir = filepath.Join(currentDirectory(), "FedMes-QR-"+time.Now().Format("20060102-150405"))
	}
	if cfg.ttl == "" {
		cfg.ttl = "15m"
	}

	executable, err := resolveServerExecutable(cfg.serverExe)
	if err != nil {
		return err
	}
	absoluteData, err := filepath.Abs(cfg.dataDir)
	if err != nil {
		return err
	}
	absoluteOutput, err := filepath.Abs(cfg.outputDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(absoluteData, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(absoluteOutput, 0o700); err != nil {
		return err
	}

	fmt.Printf("FedMes QR %s\n", version)
	fmt.Printf("Сервер:   %s\n", cfg.serverURL)
	fmt.Printf("Данные:   %s\n", absoluteData)
	fmt.Printf("QR:       %s\n", absoluteOutput)
	fmt.Printf("Пользователи: %s\n\n", strings.Join(cfg.users, ", "))

	for _, user := range cfg.users {
		output := filepath.Join(absoluteOutput, "fedmes-invite-"+user+".png")
		if cfg.replace {
			if err := os.Remove(output); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("удалить старый QR %s: %w", output, err)
			}
		}
		arguments := []string{
			"invite",
			"--user", user,
			"--server-url", cfg.serverURL,
			"--out", output,
			"--ttl", cfg.ttl,
			"--data-dir", absoluteData,
		}
		if cfg.allowHTTP {
			arguments = append(arguments, "--allow-http")
		}
		command := exec.Command(executable, arguments...)
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		command.Stdin = os.Stdin
		if err := command.Run(); err != nil {
			return fmt.Errorf("QR для %s не создан: %w", user, err)
		}
	}
	fmt.Println("\nQR-коды готовы:", absoluteOutput)
	fmt.Println("Не публикуйте QR-коды на сайте и удалите их после подключения устройств.")
	return nil
}

func fillInteractively(cfg *config) error {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("FedMes QR — создание одноразовых кодов подключения")
	fmt.Print("Адрес сервера, например https://chat.example.ru: ")
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	cfg.serverURL = strings.TrimSpace(line)
	if cfg.serverURL == "" {
		return errors.New("адрес сервера обязателен")
	}

	fmt.Printf("Каталог данных [%s]: ", defaultDataDirectory())
	line, _ = reader.ReadString('\n')
	if value := strings.TrimSpace(line); value != "" {
		cfg.dataDir = value
	}
	fmt.Printf("Каталог для QR [%s]: ", filepath.Join(currentDirectory(), "FedMes-QR-"+time.Now().Format("20060102-150405")))
	line, _ = reader.ReadString('\n')
	if value := strings.TrimSpace(line); value != "" {
		cfg.outputDir = value
	}
	fmt.Printf("Срок действия [%s]: ", cfg.ttl)
	line, _ = reader.ReadString('\n')
	if value := strings.TrimSpace(line); value != "" {
		cfg.ttl = value
	}
	fmt.Print("Разрешить HTTP для локальной сети? [y/N]: ")
	line, _ = reader.ReadString('\n')
	cfg.allowHTTP = isYes(line)
	return nil
}

func parseUsers(value string) ([]string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" || normalized == "all" {
		return append([]string(nil), fixedUsers...), nil
	}
	allowed := map[string]bool{}
	for _, user := range fixedUsers {
		allowed[user] = true
	}
	seen := map[string]bool{}
	result := []string{}
	for _, item := range strings.Split(normalized, ",") {
		user := strings.TrimSpace(item)
		if !allowed[user] {
			return nil, fmt.Errorf("неизвестный пользователь %q", user)
		}
		if !seen[user] {
			seen[user] = true
			result = append(result, user)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("не выбраны пользователи")
	}
	return result, nil
}

func resolveServerExecutable(requested string) (string, error) {
	if requested != "" {
		absolute, err := filepath.Abs(requested)
		if err != nil {
			return "", err
		}
		if fileExists(absolute) {
			return absolute, nil
		}
		return "", fmt.Errorf("fedmes-server не найден: %s", absolute)
	}

	name := "fedmes-server"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	candidates := []string{}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(executable), name))
	}
	candidates = append(candidates,
		filepath.Join(currentDirectory(), name),
		filepath.Join(currentDirectory(), "Build", "windowshttp", "fedmes-server.exe"),
		filepath.Join(currentDirectory(), "Build", "linuxhttps", "fedmes-server"),
	)
	if found, err := exec.LookPath(name); err == nil {
		candidates = append(candidates, found)
	}
	for _, candidate := range candidates {
		if fileExists(candidate) {
			absolute, _ := filepath.Abs(candidate)
			return absolute, nil
		}
	}
	return "", errors.New("fedmes-server не найден рядом с QR-программой; укажите --server-exe")
}

func defaultDataDirectory() string {
	if runtime.GOOS == "linux" {
		if info, err := os.Stat("/var/lib/fedmes"); err == nil && info.IsDir() {
			return "/var/lib/fedmes"
		}
	}
	return filepath.Join(currentDirectory(), "data")
}

func currentDirectory() string {
	directory, err := os.Getwd()
	if err != nil {
		return "."
	}
	return directory
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func isYes(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "y", "yes", "д", "да":
		return true
	default:
		return false
	}
}

func usageError() error {
	return errors.New("использование: fedmes-qr [--server-url URL] [--data-dir ПУТЬ] [--out-dir ПУТЬ] [--ttl 15m] [--users all] [--allow-http] [--replace]")
}
