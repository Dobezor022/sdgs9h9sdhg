package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"fedmes/server/internal/accountsecurity"
	"fedmes/server/internal/messaging"
	"fedmes/server/internal/opaqueauth"
)

const maximumOpaqueRequestBytes = int64(1 << 20)

type opaqueAuthHTTP struct {
	manager        *opaqueauth.Manager
	messagingStore *messaging.Store
	logger         *slog.Logger
	now            func() time.Time
}

type opaqueRegistrationStartRequest struct {
	Version   int    `json:"version"`
	RequestID string `json:"request_id"`
	Username  string `json:"username"`
	Message   string `json:"message"`
}

type opaqueRegistrationFinishRequest struct {
	Version   int    `json:"version"`
	AttemptID string `json:"attempt_id"`
	Message   string `json:"message"`
}

type opaqueLoginStartRequest struct {
	Version                   int    `json:"version"`
	RequestID                 string `json:"request_id"`
	Username                  string `json:"username"`
	Message                   string `json:"message"`
	DeviceID                  string `json:"device_id"`
	DisplayName               string `json:"display_name"`
	Platform                  string `json:"platform"`
	SigningAlgorithm          string `json:"signing_algorithm"`
	SigningPublicKeySPKI      string `json:"signing_public_key_spki"`
	KeyAgreementAlgorithm     string `json:"key_agreement_algorithm"`
	KeyAgreementPublicKeySPKI string `json:"key_agreement_public_key_spki"`
}

type opaqueLoginFinishRequest struct {
	Version   int    `json:"version"`
	AttemptID string `json:"attempt_id"`
	Message   string `json:"message"`
}

type opaqueRecoveryWriteRequest struct {
	Version          int    `json:"version"`
	VaultRevision    int64  `json:"vault_revision"`
	PackageVersion   int    `json:"package_version"`
	Nonce            string `json:"nonce"`
	Ciphertext       string `json:"ciphertext"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
}

func registerOpaqueAuthRoutes(mux *http.ServeMux, manager *opaqueauth.Manager, messagingStore *messaging.Store, logger *slog.Logger) {
	if manager == nil || messagingStore == nil {
		return
	}
	h := &opaqueAuthHTTP{manager: manager, messagingStore: messagingStore, logger: logger, now: time.Now}
	publicLimiter := newIPRateLimiter(10, time.Minute, 8192, time.Now)
	protectedLimiter := newIPRateLimiter(30, time.Minute, 8192, time.Now)

	mux.Handle("POST /api/v3/auth/opaque/login/start", publicLimiter.middleware(http.HandlerFunc(h.loginStart)))
	mux.Handle("POST /api/v3/auth/opaque/login/finish", publicLimiter.middleware(http.HandlerFunc(h.loginFinish)))
	mux.Handle("POST /api/v3/auth/opaque/registration/start", protectedLimiter.middleware(h.authReady(http.HandlerFunc(h.registrationStart("enroll")))))
	mux.Handle("POST /api/v3/auth/opaque/registration/finish", protectedLimiter.middleware(h.authReady(http.HandlerFunc(h.registrationFinish))))
	mux.Handle("POST /api/v3/auth/opaque/password-change/start", protectedLimiter.middleware(h.authReady(http.HandlerFunc(h.registrationStart("password_change")))))
	mux.Handle("POST /api/v3/auth/opaque/password-change/finish", protectedLimiter.middleware(h.authReady(http.HandlerFunc(h.registrationFinish))))
	mux.Handle("GET /api/v3/security/opaque-recovery-package", protectedLimiter.middleware(h.authAny(http.HandlerFunc(h.getRecoveryPackage))))
	mux.Handle("PUT /api/v3/security/opaque-recovery-package", protectedLimiter.middleware(h.authReady(http.HandlerFunc(h.putRecoveryPackage))))
}

func (h *opaqueAuthHTTP) authAny(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(header, "Bearer ") || len(header) <= 7 {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		principal, err := h.messagingStore.Authenticate(r.Context(), strings.TrimSpace(header[7:]), h.now().UTC())
		if err != nil || principal.SecurityState == accountsecurity.StateRevoked {
			writeAPIError(w, http.StatusUnauthorized, "session_invalid")
			return
		}
		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *opaqueAuthHTTP) authReady(next http.Handler) http.Handler {
	return h.authAny(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestPrincipal(r).SecurityState != accountsecurity.StateReady {
			writeAPIError(w, http.StatusForbidden, "security_recovery_required")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func (h *opaqueAuthHTTP) registrationStart(operation string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request opaqueRegistrationStartRequest
		raw, ok := decodeOpaqueJSON(w, r, &request)
		if !ok {
			return
		}
		message, ok := decodeOpaqueBase64(request.Message, 16, 65536)
		if !ok || request.Version != opaqueauth.ProtocolVersion {
			writeAPIError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		defer clear(message)
		principal := requestPrincipal(r)
		result, err := h.manager.RegistrationStart(r.Context(), opaqueauth.Principal{
			Username: principal.Username, DeviceID: principal.DeviceID, SessionID: principal.SessionID,
		}, opaqueauth.RegistrationStartInput{
			Username: request.Username, Operation: operation, RegistrationRequest: message,
			RequestID: request.RequestID, RequestDigest: sha256.Sum256(raw),
		})
		if err != nil {
			h.writeError(w, err, false)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"version": opaqueauth.ProtocolVersion, "attempt_id": result.AttemptID,
			"message": base64.RawURLEncoding.EncodeToString(result.Response), "suite": result.Suite,
			"expires_at": result.ExpiresAt.Format(time.RFC3339Nano), "replayed": result.Replayed,
		})
	}
}

func (h *opaqueAuthHTTP) registrationFinish(w http.ResponseWriter, r *http.Request) {
	var request opaqueRegistrationFinishRequest
	_, ok := decodeOpaqueJSON(w, r, &request)
	if !ok {
		return
	}
	message, ok := decodeOpaqueBase64(request.Message, 32, 65536)
	if !ok || request.Version != opaqueauth.ProtocolVersion {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	defer clear(message)
	principal := requestPrincipal(r)
	err := h.manager.RegistrationFinish(r.Context(), opaqueauth.Principal{
		Username: principal.Username, DeviceID: principal.DeviceID, SessionID: principal.SessionID,
	}, opaqueauth.RegistrationFinishInput{AttemptID: request.AttemptID, RegistrationRecord: message})
	if err != nil {
		h.writeError(w, err, false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": opaqueauth.ProtocolVersion, "status": "ok"})
}

func (h *opaqueAuthHTTP) loginStart(w http.ResponseWriter, r *http.Request) {
	var request opaqueLoginStartRequest
	raw, ok := decodeOpaqueJSON(w, r, &request)
	if !ok {
		return
	}
	ke1, ok1 := decodeOpaqueBase64(request.Message, 16, 65536)
	signingKey, ok2 := decodeOpaqueBase64(request.SigningPublicKeySPKI, 32, 2048)
	agreementKey, ok3 := decodeOpaqueBase64(request.KeyAgreementPublicKeySPKI, 32, 2048)
	if !ok1 || !ok2 || !ok3 || request.Version != opaqueauth.ProtocolVersion {
		clear(ke1)
		clear(signingKey)
		clear(agreementKey)
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	defer clear(ke1)
	defer clear(signingKey)
	defer clear(agreementKey)
	result, err := h.manager.LoginStart(r.Context(), opaqueauth.LoginStartInput{
		Username: request.Username, KE1: ke1, ProposedDeviceID: request.DeviceID,
		DisplayName: request.DisplayName, Platform: request.Platform,
		SigningAlgorithm: request.SigningAlgorithm, SigningPublicKeySPKI: signingKey,
		AgreementAlgorithm: request.KeyAgreementAlgorithm, AgreementPublicKeySPKI: agreementKey,
		RequestID: request.RequestID, RequestDigest: sha256.Sum256(raw),
	})
	if err != nil {
		// Keep the externally visible response identical for malformed/unknown credentials.
		h.writeError(w, err, true)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": opaqueauth.ProtocolVersion, "attempt_id": result.AttemptID,
		"message": base64.RawURLEncoding.EncodeToString(result.KE2), "suite": result.Suite,
		"server_identity": h.manager.ServerIdentity(),
		"expires_at":      result.ExpiresAt.Format(time.RFC3339Nano), "replayed": result.Replayed,
	})
}

func (h *opaqueAuthHTTP) loginFinish(w http.ResponseWriter, r *http.Request) {
	var request opaqueLoginFinishRequest
	_, ok := decodeOpaqueJSON(w, r, &request)
	if !ok {
		return
	}
	ke3, ok := decodeOpaqueBase64(request.Message, 16, 65536)
	if !ok || request.Version != opaqueauth.ProtocolVersion {
		writeAPIError(w, http.StatusUnauthorized, "authentication_failed")
		return
	}
	defer clear(ke3)
	result, err := h.manager.LoginFinish(r.Context(), request.AttemptID, ke3)
	if err != nil {
		h.writeError(w, err, true)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": opaqueauth.ProtocolVersion, "username": result.Username,
		"device_id": result.DeviceID, "session_id": result.SessionID,
		"session_token": result.SessionToken, "authentication_state": result.AuthenticationState,
		"provisioning_request_id": result.ProvisioningRequestID,
		"server_proof":            base64.RawURLEncoding.EncodeToString(result.ServerProof),
		"expires_at":              result.ExpiresAt.Format(time.RFC3339Nano), "replayed": result.Replayed,
	})
}

func (h *opaqueAuthHTTP) getRecoveryPackage(w http.ResponseWriter, r *http.Request) {
	principal := requestPrincipal(r)
	pkg, err := h.manager.GetOpaqueRecoveryPackage(r.Context(), principal.Username)
	if err != nil {
		h.writeError(w, err, false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": opaqueauth.ProtocolVersion, "vault_revision": pkg.VaultRevision,
		"package_version": pkg.PackageVersion, "nonce": base64.RawURLEncoding.EncodeToString(pkg.Nonce),
		"ciphertext":        base64.RawURLEncoding.EncodeToString(pkg.Ciphertext),
		"ciphertext_sha256": hex.EncodeToString(pkg.CiphertextHash[:]),
		"updated_at":        pkg.UpdatedAt.Format(time.RFC3339Nano),
	})
}

func (h *opaqueAuthHTTP) putRecoveryPackage(w http.ResponseWriter, r *http.Request) {
	var request opaqueRecoveryWriteRequest
	_, ok := decodeOpaqueJSON(w, r, &request)
	if !ok {
		return
	}
	nonce, ok1 := decodeOpaqueBase64(request.Nonce, 12, 24)
	ciphertext, ok2 := decodeOpaqueBase64(request.Ciphertext, 48, 1<<20)
	hashBytes, err := hex.DecodeString(request.CiphertextSHA256)
	if !ok1 || !ok2 || err != nil || len(hashBytes) != sha256.Size || request.Version != opaqueauth.ProtocolVersion {
		clear(nonce)
		clear(ciphertext)
		clear(hashBytes)
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	defer clear(nonce)
	defer clear(ciphertext)
	defer clear(hashBytes)
	var digest [sha256.Size]byte
	copy(digest[:], hashBytes)
	principal := requestPrincipal(r)
	err = h.manager.PutOpaqueRecoveryPackage(r.Context(), opaqueauth.Principal{
		Username: principal.Username, DeviceID: principal.DeviceID, SessionID: principal.SessionID,
	}, opaqueauth.RecoveryPackage{
		VaultRevision: request.VaultRevision, PackageVersion: request.PackageVersion,
		Nonce: nonce, Ciphertext: ciphertext, CiphertextHash: digest,
	})
	if err != nil {
		h.writeError(w, err, false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": opaqueauth.ProtocolVersion, "status": "ok"})
}

func decodeOpaqueJSON(w http.ResponseWriter, r *http.Request, target any) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maximumOpaqueRequestBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil || len(raw) == 0 {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return nil, false
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		clear(raw)
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return nil, false
	}
	return raw, true
}

func decodeOpaqueBase64(value string, minimum, maximum int) ([]byte, bool) {
	if value == "" || len(value) > ((maximum+2)/3)*4+8 {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) < minimum || len(decoded) > maximum {
		clear(decoded)
		return nil, false
	}
	return decoded, true
}

func (h *opaqueAuthHTTP) writeError(w http.ResponseWriter, err error, obscure bool) {
	if obscure {
		// Do not disclose whether a username exists or a password was wrong.
		time.Sleep(50 * time.Millisecond)
		writeAPIError(w, http.StatusUnauthorized, "authentication_failed")
		return
	}
	switch {
	case errors.Is(err, opaqueauth.ErrInvalidRequest):
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, opaqueauth.ErrForbidden):
		writeAPIError(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, opaqueauth.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, opaqueauth.ErrExpired):
		writeAPIError(w, http.StatusGone, "attempt_expired")
	case errors.Is(err, opaqueauth.ErrReplayed):
		writeAPIError(w, http.StatusConflict, "replay_conflict")
	case errors.Is(err, opaqueauth.ErrServerStateMissing):
		writeAPIError(w, http.StatusConflict, "restart_authentication")
	default:
		if h.logger != nil {
			h.logger.Error("opaque operation failed", "error_code", "opaque_operation_failed", "cause", err.Error())
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
	}
}
