package httpserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"fedmes/server/internal/messaging"
	"fedmes/server/internal/opaqueauth"
	"fedmes/server/internal/provisioning"
)

type ReadinessChecker interface {
	Ping(ctx context.Context) error
}

type Server struct {
	httpServer *http.Server
}

func New(address string, readiness ReadinessChecker, provisioningService *provisioning.Service, messagingStore *messaging.Store, opaqueManager *opaqueauth.Manager, mediaDirectory string, logger *slog.Logger) *Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	redeemHandler := newProvisioningHandler(provisioningService, logger)
	redeemLimiter := newIPRateLimiter(10, time.Minute, 4096, time.Now)
	mux.Handle("POST /api/v1/provisioning/redeem", redeemLimiter.middleware(redeemHandler))
	authenticationLimiter := newIPRateLimiter(20, time.Minute, 4096, time.Now)
	mux.Handle(
		"POST /api/v1/auth/challenge",
		authenticationLimiter.middleware(newDeviceAuthenticationHandler(
			provisioningService,
			logger,
			authenticationChallengeMode,
		)),
	)
	mux.Handle(
		"POST /api/v1/auth/session",
		authenticationLimiter.middleware(newDeviceAuthenticationHandler(
			provisioningService,
			logger,
			authenticationSessionMode,
		)),
	)
	registerMessagingRoutes(mux, messagingStore, mediaDirectory, logger)
	registerDeviceLinkRoutes(mux, messagingStore, logger)
	registerAccountSecurityRoutes(mux, messagingStore, logger)
	registerOpaqueAuthRoutes(mux, opaqueManager, messagingStore, logger)
	registerRatchetRoutes(mux, messagingStore, logger)
	registerCryptoMigrationRoutes(mux, messagingStore, mediaDirectory, logger)
	registerBlindObjectRoutes(mux, messagingStore)
	registerBlindStreamRoutes(mux, messagingStore)
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		if err := readiness.Ping(r.Context()); err != nil {
			logger.Error("readiness check failed", "error_code", "database_unavailable")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})

	httpServer := &http.Server{
		Addr:              address,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	if messagingStore != nil {
		cleanupContext, cancelCleanup := context.WithCancel(context.Background())
		httpServer.RegisterOnShutdown(cancelCleanup)
		go expireAbandonedDeviceLinks(cleanupContext, messagingStore, logger)
	}
	return &Server{httpServer: httpServer}
}

func expireAbandonedDeviceLinks(ctx context.Context, store *messaging.Store, logger *slog.Logger) {
	cleanup := func() {
		cleanupContext, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := store.ExpireApprovedDeviceLinks(cleanupContext, time.Now().UTC()); err != nil && ctx.Err() == nil && logger != nil {
			logger.Error("expire abandoned device links failed", "error_code", "device_link_cleanup_failed", "cause", err.Error())
		}
	}
	cleanup()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanup()
		}
	}
}

func (s *Server) HTTP() *http.Server {
	return s.httpServer
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
