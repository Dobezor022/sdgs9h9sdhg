package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"fedmes/server/internal/accountsecurity"
	"fedmes/server/internal/cryptomigration"
	"fedmes/server/internal/messaging"
)

type cryptoMigrationHTTP struct {
	manager        *cryptomigration.Manager
	messagingStore *messaging.Store
	logger         *slog.Logger
	now            func() time.Time
}
type startMigrationRequest struct {
	Version int    `json:"version"`
	Kind    string `json:"migration_kind"`
}
type messageMigrationUploadRequest struct {
	Version              int    `json:"version"`
	MessageID            string `json:"message_id"`
	SourceHash           string `json:"source_ciphertext_sha256"`
	TargetCiphertext     string `json:"target_ciphertext"`
	TargetNonce          string `json:"target_nonce"`
	TargetAAD            string `json:"target_aad"`
	TargetCryptoVersion  int    `json:"target_crypto_version"`
	TargetRoomKeyVersion int64  `json:"target_room_key_version"`
	TargetAADVersion     int    `json:"target_aad_version"`
	TargetAlgorithm      string `json:"target_encryption_algorithm"`
	TargetHash           string `json:"target_ciphertext_sha256"`
	Signature            string `json:"signature"`
}
type verifyMigrationRequest struct {
	Version   int    `json:"version"`
	Signature string `json:"signature"`
}
type completeMigrationRequest struct {
	Version int `json:"version"`
}
type retireFMKRequest struct {
	Version       int    `json:"version"`
	VaultRevision int64  `json:"vault_revision"`
	Signature     string `json:"signature"`
}

func registerCryptoMigrationRoutes(mux *http.ServeMux, store *messaging.Store, mediaDir string, logger *slog.Logger) {
	if store == nil || store.DB == nil {
		return
	}
	manager, err := cryptomigration.NewManager(store.DB, mediaDir)
	if err != nil {
		if logger != nil {
			logger.Error("crypto migration initialization failed", "cause", err.Error())
		}
		return
	}
	h := &cryptoMigrationHTTP{manager: manager, messagingStore: store, logger: logger, now: time.Now}
	limiter := newIPRateLimiter(120, time.Minute, 8192, time.Now)
	protected := func(fn http.HandlerFunc) http.Handler { return limiter.middleware(h.auth(fn)) }
	mux.Handle("POST /api/v3/security/migrations", protected(h.start))
	mux.Handle("GET /api/v3/security/migrations/{migrationID}", protected(h.get))
	mux.Handle("GET /api/v3/security/migrations/{migrationID}/messages", protected(h.listMessages))
	mux.Handle("PUT /api/v3/security/migrations/{migrationID}/messages/{messageID}", protected(h.uploadMessage))
	mux.Handle("GET /api/v3/security/migrations/{migrationID}/messages/{messageID}/replacement", protected(h.getMessageReplacement))
	mux.Handle("POST /api/v3/security/migrations/{migrationID}/messages/{messageID}/verify", protected(h.verifyMessage))
	mux.Handle("GET /api/v3/security/migrations/{migrationID}/media", protected(h.listMedia))
	mux.Handle("PUT /api/v3/security/migrations/{migrationID}/media/{mediaID}", protected(h.stageMedia))
	mux.Handle("GET /api/v3/security/migrations/{migrationID}/media/{mediaID}/staged", protected(h.downloadStagedMedia))
	mux.Handle("POST /api/v3/security/migrations/{migrationID}/media/{mediaID}/verify", protected(h.verifyMedia))
	mux.Handle("POST /api/v3/security/migrations/{migrationID}/complete", protected(h.complete))
	mux.Handle("POST /api/v3/security/legacy-fmk/retire", protected(h.retireFMK))
	_ = manager.CleanupStaging(48 * time.Hour)
}
func (h *cryptoMigrationHTTP) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(header, "Bearer ") || len(header) <= 7 {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		p, err := h.messagingStore.Authenticate(r.Context(), strings.TrimSpace(header[7:]), h.now().UTC())
		if err != nil || p.SecurityState != accountsecurity.StateReady {
			writeAPIError(w, http.StatusForbidden, "security_recovery_required")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), principalContextKey{}, p)))
	})
}
func migrationPrincipal(r *http.Request) cryptomigration.Principal {
	p := requestPrincipal(r)
	return cryptomigration.Principal{Username: p.Username, DeviceID: p.DeviceID}
}
func (h *cryptoMigrationHTTP) start(w http.ResponseWriter, r *http.Request) {
	var req startMigrationRequest
	if !decodeMigrationJSON(w, r, &req) || req.Version != cryptomigration.ProtocolVersion {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	mig, replayed, err := h.manager.Start(r.Context(), migrationPrincipal(r), req.Kind)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": cryptomigration.ProtocolVersion, "migration": mig, "replayed": replayed})
}
func (h *cryptoMigrationHTTP) get(w http.ResponseWriter, r *http.Request) {
	mig, err := h.manager.Get(r.Context(), migrationPrincipal(r), r.PathValue("migrationID"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": cryptomigration.ProtocolVersion, "migration": mig})
}
func (h *cryptoMigrationHTTP) listMessages(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.ParseInt(defaultString(r.URL.Query().Get("after"), "0"), 10, 64)
	limit, _ := strconv.Atoi(defaultString(r.URL.Query().Get("limit"), "50"))
	items, err := h.manager.ListMessages(r.Context(), migrationPrincipal(r), r.PathValue("migrationID"), after, limit)
	if err != nil {
		h.writeError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, x := range items {
		out = append(out, map[string]any{"sequence": x.Sequence, "id": x.ID, "chat_id": x.ChatID, "sender_username": x.SenderUsername, "sender_device_id": x.SenderDeviceID, "ciphertext": base64.RawURLEncoding.EncodeToString(x.Ciphertext), "nonce": base64.RawURLEncoding.EncodeToString(x.Nonce), "aad": x.AAD, "ciphertext_sha256": hex.EncodeToString(x.CiphertextSHA256[:]), "created_at": x.CreatedAt.Format(time.RFC3339Nano)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": cryptomigration.ProtocolVersion, "messages": out})
}
func (h *cryptoMigrationHTTP) uploadMessage(w http.ResponseWriter, r *http.Request) {
	var req messageMigrationUploadRequest
	if !decodeMigrationJSON(w, r, &req) || req.Version != cryptomigration.ProtocolVersion || req.MessageID != r.PathValue("messageID") {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	source, ok1 := decodeHex32(req.SourceHash)
	target, ok2 := decodeHex32(req.TargetHash)
	cipher, ok3 := decodeRawURL(req.TargetCiphertext, 16, 1<<20)
	nonce, ok4 := decodeRawURL(req.TargetNonce, 12, 12)
	sig, ok5 := decodeRawURL(req.Signature, 32, 2048)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		clear(cipher)
		clear(nonce)
		clear(sig)
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	defer clear(cipher)
	defer clear(nonce)
	defer clear(sig)
	err := h.manager.UploadMessage(r.Context(), migrationPrincipal(r), cryptomigration.MessageReplacement{MigrationID: r.PathValue("migrationID"), MessageID: req.MessageID, SourceHash: source, TargetCiphertext: cipher, TargetNonce: nonce, TargetAAD: req.TargetAAD, TargetCryptoVersion: req.TargetCryptoVersion, TargetRoomKeyVersion: req.TargetRoomKeyVersion, TargetAADVersion: req.TargetAADVersion, TargetAlgorithm: req.TargetAlgorithm, TargetHash: target, Signature: sig})
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"version": cryptomigration.ProtocolVersion, "status": "uploaded"})
}
func (h *cryptoMigrationHTTP) getMessageReplacement(w http.ResponseWriter, r *http.Request) {
	x, err := h.manager.GetMessageReplacement(r.Context(), migrationPrincipal(r), r.PathValue("migrationID"), r.PathValue("messageID"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": cryptomigration.ProtocolVersion, "message_id": x.MessageID, "source_ciphertext_sha256": hex.EncodeToString(x.SourceHash[:]), "target_ciphertext": base64.RawURLEncoding.EncodeToString(x.TargetCiphertext), "target_nonce": base64.RawURLEncoding.EncodeToString(x.TargetNonce), "target_aad": x.TargetAAD, "target_crypto_version": x.TargetCryptoVersion, "target_room_key_version": x.TargetRoomKeyVersion, "target_aad_version": x.TargetAADVersion, "target_encryption_algorithm": x.TargetAlgorithm, "target_ciphertext_sha256": hex.EncodeToString(x.TargetHash[:]), "uploaded_by_device_id": x.UploadedByDeviceID, "uploaded_at": x.UploadedAt.Format(time.RFC3339Nano)})
}
func (h *cryptoMigrationHTTP) verifyMessage(w http.ResponseWriter, r *http.Request) {
	var req verifyMigrationRequest
	if !decodeMigrationJSON(w, r, &req) || req.Version != cryptomigration.ProtocolVersion {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	sig, ok := decodeRawURL(req.Signature, 32, 2048)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	defer clear(sig)
	if err := h.manager.VerifyMessage(r.Context(), migrationPrincipal(r), r.PathValue("migrationID"), r.PathValue("messageID"), sig); err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": cryptomigration.ProtocolVersion, "status": "retired"})
}
func (h *cryptoMigrationHTTP) listMedia(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(defaultString(r.URL.Query().Get("limit"), "50"))
	items, err := h.manager.ListMedia(r.Context(), migrationPrincipal(r), r.PathValue("migrationID"), limit)
	if err != nil {
		h.writeError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, x := range items {
		out = append(out, map[string]any{"id": x.ID, "chat_id": x.ChatID, "size_bytes": x.SizeBytes, "ciphertext_sha256": hex.EncodeToString(x.CiphertextSHA256[:]), "created_at": x.CreatedAt.Format(time.RFC3339Nano)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": cryptomigration.ProtocolVersion, "media": out})
}
func (h *cryptoMigrationHTTP) stageMedia(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-FedMes-Protocol") != "4" {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	source, ok1 := decodeHex32(r.Header.Get("X-Source-SHA256"))
	target, ok2 := decodeHex32(r.Header.Get("X-Target-SHA256"))
	version, err := strconv.Atoi(r.Header.Get("X-Target-Crypto-Version"))
	sig, ok3 := decodeRawURL(r.Header.Get("X-Device-Signature"), 32, 2048)
	size, err2 := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)
	if !ok1 || !ok2 || !ok3 || err != nil || err2 != nil {
		clear(sig)
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	defer clear(sig)
	view, err := h.manager.StageMedia(r.Context(), migrationPrincipal(r), cryptomigration.MediaStageInput{MigrationID: r.PathValue("migrationID"), MediaID: r.PathValue("mediaID"), SourceHash: source, TargetHash: target, TargetCryptoVersion: version, TargetAlgorithm: r.Header.Get("X-Target-Algorithm"), Signature: sig}, r.Body, size)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"version": cryptomigration.ProtocolVersion, "media_id": view.MediaID, "target_size_bytes": view.TargetSizeBytes, "target_ciphertext_sha256": hex.EncodeToString(view.TargetHash[:])})
}
func (h *cryptoMigrationHTTP) downloadStagedMedia(w http.ResponseWriter, r *http.Request) {
	file, view, err := h.manager.OpenStagedMedia(r.Context(), migrationPrincipal(r), r.PathValue("migrationID"), r.PathValue("mediaID"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(view.TargetSizeBytes, 10))
	w.Header().Set("X-Content-SHA256", hex.EncodeToString(view.TargetHash[:]))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, file)
}
func (h *cryptoMigrationHTTP) verifyMedia(w http.ResponseWriter, r *http.Request) {
	var req verifyMigrationRequest
	if !decodeMigrationJSON(w, r, &req) || req.Version != cryptomigration.ProtocolVersion {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	sig, ok := decodeRawURL(req.Signature, 32, 2048)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	defer clear(sig)
	if err := h.manager.VerifyMedia(r.Context(), migrationPrincipal(r), r.PathValue("migrationID"), r.PathValue("mediaID"), sig); err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": cryptomigration.ProtocolVersion, "status": "retired"})
}
func (h *cryptoMigrationHTTP) complete(w http.ResponseWriter, r *http.Request) {
	var req completeMigrationRequest
	if !decodeMigrationJSON(w, r, &req) || req.Version != cryptomigration.ProtocolVersion {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.manager.Complete(r.Context(), migrationPrincipal(r), r.PathValue("migrationID")); err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": cryptomigration.ProtocolVersion, "status": "completed"})
}
func (h *cryptoMigrationHTTP) retireFMK(w http.ResponseWriter, r *http.Request) {
	var req retireFMKRequest
	if !decodeMigrationJSON(w, r, &req) || req.Version != cryptomigration.ProtocolVersion {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	sig, ok := decodeRawURL(req.Signature, 32, 2048)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	defer clear(sig)
	if err := h.manager.RetireLegacyFMK(r.Context(), migrationPrincipal(r), req.VaultRevision, sig); err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": cryptomigration.ProtocolVersion, "minimum_crypto_version": 2, "legacy_fmk_removed": true})
}
func decodeMigrationJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 18<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return false
	}
	return true
}
func decodeHex32(value string) ([32]byte, bool) {
	var out [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		clear(decoded)
		return out, false
	}
	copy(out[:], decoded)
	clear(decoded)
	return out, true
}
func (h *cryptoMigrationHTTP) writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, cryptomigration.ErrInvalid):
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, cryptomigration.ErrForbidden):
		writeAPIError(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, cryptomigration.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, cryptomigration.ErrConflict):
		writeAPIError(w, http.StatusConflict, "migration_conflict")
	case errors.Is(err, cryptomigration.ErrIncomplete):
		writeAPIError(w, http.StatusConflict, "migration_incomplete")
	default:
		if h.logger != nil {
			h.logger.Error("crypto migration failed", "error_code", "crypto_migration_failed", "cause", err.Error())
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
	}
}
