package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"fedmes/server/internal/config"
	"fedmes/server/internal/database"
	"fedmes/server/internal/httpserver"
	"fedmes/server/internal/messaging"
	"fedmes/server/internal/opaqueauth"
	"fedmes/server/internal/provisioning"
)

const version = "2.0.0"

func main() {
	loggerOutput := io.Writer(io.Discard)
	if os.Getenv("FEDMES_DEV_LOGS") == "1" {
		loggerOutput = os.Stderr
	}
	logger := slog.New(slog.NewJSONHandler(loggerOutput, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := execute(os.Args[1:], logger, os.Stdout, os.Stderr); err != nil {
		if os.Getenv("FEDMES_DEV_LOGS") == "1" {
			_, _ = fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}

func execute(args []string, logger *slog.Logger, stdout io.Writer, stderr io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "invite":
			return runInvite(context.Background(), args[1:], stdout, stderr)
		case "smoke-refresh":
			return runSmokeRefresh(context.Background(), args[1:], stdout, stderr)
		case "serve":
			if len(args) != 1 {
				return errors.New("serve does not accept positional arguments")
			}
		case "version", "--version":
			if len(args) != 1 {
				return errors.New("version does not accept positional arguments")
			}
			_, err := fmt.Fprintln(stdout, version)
			return err
		default:
			return fmt.Errorf("unknown command %q; expected serve, invite, smoke-refresh, or version", args[0])
		}
	}
	return runServer(logger)
}

func runServer(logger *slog.Logger) error {
	configuration, err := config.Load()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(configuration.DataDirectory, 0o700); err != nil {
		return err
	}

	rootContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := database.Open(rootContext, configuration.DatabasePath)
	if err != nil {
		return err
	}
	defer store.Close()
	registrationResultKey, err := config.LoadOrCreateRegistrationResultKey(configuration.DataDirectory)
	if err != nil {
		return err
	}
	defer clear(registrationResultKey)
	provisioningConfig := provisioning.DefaultConfig()
	provisioningConfig.RegistrationResultKey = registrationResultKey
	provisioningService, err := provisioning.NewService(store, provisioning.SystemClock{}, provisioning.CryptoEntropy{}, provisioningConfig)
	if err != nil {
		return err
	}

	messagingStore := messaging.NewStore(store.SQL())
	opaqueManager, err := opaqueauth.Open(store.SQL(), configuration.DataDirectory, configuration.PublicURL, registrationResultKey)
	if err != nil {
		return err
	}
	defer opaqueManager.Close()
	mediaDirectory := configuration.MediaDirectory
	if err := os.MkdirAll(mediaDirectory, 0o700); err != nil {
		return err
	}
	server := httpserver.New(configuration.Address, store, provisioningService, messagingStore, opaqueManager, mediaDirectory, logger).HTTP()
	serveErrors := make(chan error, 1)
	go func() {
		logger.Info("server listening", "address", configuration.Address, "data_directory", configuration.DataDirectory, "database", configuration.DatabasePath)
		serveErrors <- server.ListenAndServe()
	}()

	select {
	case <-rootContext.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), configuration.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return err
		}
		if err := <-serveErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		logger.Info("server stopped gracefully")
		return nil
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
