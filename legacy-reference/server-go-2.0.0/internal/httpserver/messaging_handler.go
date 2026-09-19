package httpserver

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fedmes/server/internal/messaging"
)

const maxMessageJSON = int64(3 << 20)

type messagingHTTP struct {
	store    *messaging.Store
	mediaDir string
	logger   *slog.Logger
	now      func() time.Time
}

type messageWriteRequest struct {
	Version             int                         `json:"version"`
	ID                  string                      `json:"id"`
	Ciphertext          string                      `json:"ciphertext"`
	Nonce               string                      `json:"nonce"`
	AAD                 string                      `json:"aad"`
	CryptoVersion       int                         `json:"crypto_version"`
	RoomKeyVersion      int64                       `json:"room_key_version"`
	AADVersion          int                         `json:"aad_version"`
	CryptoSequence      int64                       `json:"crypto_sequence"`
	EncryptionAlgorithm string                      `json:"encryption_algorithm"`
	MessageType         string                      `json:"message_type"`
	SequenceRequestID   string                      `json:"sequence_request_id"`
	Envelopes           []messaging.Envelope        `json:"envelopes"`
	RatchetEnvelopes    []messaging.RatchetEnvelope `json:"ratchet_envelopes"`
}

type cryptoSequenceRequest struct {
	Version   int    `json:"version"`
	RequestID string `json:"request_id"`
	MessageID string `json:"message_id"`
}

type encryptionKeyRequest struct {
	Version       int    `json:"version"`
	Algorithm     string `json:"algorithm"`
	PublicKeySPKI string `json:"public_key_spki"`
}

type heartbeatRequest struct {
	Version   int  `json:"version"`
	ShowExact bool `json:"show_exact"`
}

type envelopeWriteRequest struct {
	Version   int                  `json:"version"`
	Envelopes []messaging.Envelope `json:"envelopes"`
}

type receiptWriteRequest struct {
	Version      int      `json:"version"`
	DeliveredIDs []string `json:"delivered_message_ids"`
	ReadIDs      []string `json:"read_message_ids"`
}

type readCursorWriteRequest struct {
	Version         int   `json:"version"`
	MaxReadSequence int64 `json:"max_read_sequence"`
}

type typingWriteRequest struct {
	Version int  `json:"version"`
	Typing  bool `json:"typing"`
}

type principalContextKey struct{}

func registerMessagingRoutes(mux *http.ServeMux, store *messaging.Store, mediaDir string, logger *slog.Logger) {
	if store == nil {
		return
	}
	h := &messagingHTTP{store: store, mediaDir: mediaDir, logger: logger, now: time.Now}
	limiter := newIPRateLimiter(600, time.Minute, 8192, time.Now)
	protected := func(handler http.HandlerFunc) http.Handler {
		return limiter.middleware(h.auth(handler))
	}
	mux.Handle("GET /api/v1/auth/validate", protected(h.validateSession))
	mux.Handle("PUT /api/v1/devices/encryption-key", protected(h.registerEncryptionKey))
	mux.Handle("GET /api/v1/chats", protected(h.listChats))
	mux.Handle("GET /api/v1/chats/{chatID}/devices", protected(h.listDevices))
	mux.Handle("POST /api/v3/chats/{chatID}/crypto-sequence", protected(h.reserveCryptoSequence))
	mux.Handle("GET /api/v1/chats/{chatID}/messages", protected(h.listMessages))
	mux.Handle("GET /api/v1/chats/{chatID}/envelope-repair", protected(h.listEnvelopeRepairMessages))
	mux.Handle("POST /api/v1/chats/{chatID}/messages", protected(h.createMessage))
	mux.Handle("PUT /api/v1/chats/{chatID}/messages/{messageID}", protected(h.updateMessage))
	mux.Handle("PUT /api/v1/chats/{chatID}/messages/{messageID}/envelopes", protected(h.addMessageEnvelopes))
	mux.Handle("DELETE /api/v1/chats/{chatID}/messages/{messageID}", protected(h.deleteMessage))
	mux.Handle("POST /api/v1/chats/{chatID}/receipts", protected(h.markReceipts))
	mux.Handle("PUT /api/v1/chats/{chatID}/read-cursor", protected(h.markReadCursor))
	mux.Handle("PUT /api/v1/chats/{chatID}/typing", protected(h.setTyping))
	mux.Handle("GET /api/v1/chats/{chatID}/typing", protected(h.listTyping))
	mux.Handle("PUT /api/v1/chats/{chatID}/pin/{messageID}", protected(h.pinMessage))
	mux.Handle("DELETE /api/v1/chats/{chatID}/pin", protected(h.unpinMessage))
	mux.Handle("PUT /api/v1/chats/{chatID}/media/{mediaID}", protected(h.uploadMedia))
	mux.Handle("GET /api/v1/chats/{chatID}/media/{mediaID}", protected(h.downloadMedia))
	mux.Handle("DELETE /api/v1/chats/{chatID}/media/{mediaID}", protected(h.deleteMedia))
	mux.Handle("POST /api/v1/presence/heartbeat", protected(h.heartbeat))
	mux.Handle("GET /api/v1/presence", protected(h.listPresence))
	mux.Handle("GET /api/v1/events", protected(h.events))
}

func (h *messagingHTTP) validateSession(w http.ResponseWriter, r *http.Request) {
	principal := requestPrincipal(r)
	if principal.Username == "" || principal.DeviceID == "" {
		writeAPIError(w, http.StatusUnauthorized, "session_invalid")
		return
	}
	w.Header().Set("X-FedMes-User", principal.Username)
	w.Header().Set("X-FedMes-Device", principal.DeviceID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *messagingHTTP) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(header, "Bearer ") || len(header) <= 7 {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		principal, err := h.store.Authenticate(r.Context(), strings.TrimSpace(header[7:]), h.now().UTC())
		if err != nil {
			writeAPIError(w, http.StatusUnauthorized, "session_invalid")
			return
		}
		if principal.SecurityState != "READY" {
			writeAPIError(w, http.StatusLocked, "keys_not_ready")
			return
		}
		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requestPrincipal(r *http.Request) messaging.Principal {
	principal, _ := r.Context().Value(principalContextKey{}).(messaging.Principal)
	return principal
}

func (h *messagingHTTP) requireMembership(w http.ResponseWriter, r *http.Request) (messaging.Principal, string, bool) {
	principal := requestPrincipal(r)
	chatID := strings.TrimSpace(r.PathValue("chatID"))
	if chatID == "" || len(chatID) > 128 {
		writeAPIError(w, http.StatusBadRequest, "invalid_chat")
		return principal, chatID, false
	}
	member, err := h.store.IsMember(r.Context(), chatID, principal.Username)
	if err != nil {
		if requestCanceled(r, err) {
			return principal, chatID, false
		}
		h.internal("membership query failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return principal, chatID, false
	}
	if !member {
		writeAPIError(w, http.StatusForbidden, "chat_forbidden")
		return principal, chatID, false
	}
	return principal, chatID, true
}

func (h *messagingHTTP) registerEncryptionKey(w http.ResponseWriter, r *http.Request) {
	principal := requestPrincipal(r)
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request encryptionKeyRequest
	if err := decoder.Decode(&request); err != nil || requireJSONEOF(decoder) != nil || request.Version != 1 || request.Algorithm != "rsa-oaep-sha256" {
		writeAPIError(w, http.StatusBadRequest, "invalid_encryption_key")
		return
	}
	publicKey, err := base64.StdEncoding.Strict().DecodeString(request.PublicKeySPKI)
	if err != nil || len(publicKey) < 256 || len(publicKey) > 1024 {
		clear(publicKey)
		writeAPIError(w, http.StatusBadRequest, "invalid_encryption_key")
		return
	}
	defer clear(publicKey)
	parsedKey, err := x509.ParsePKIXPublicKey(publicKey)
	rsaKey, ok := parsedKey.(*rsa.PublicKey)
	if err != nil || !ok || rsaKey.N.BitLen() < 2048 || rsaKey.E < 65537 {
		writeAPIError(w, http.StatusBadRequest, "invalid_encryption_key")
		return
	}
	if err := h.store.RegisterEncryptionKey(r.Context(), principal, request.Algorithm, publicKey, h.now().UTC()); err != nil {
		if requestCanceled(r, err) {
			return
		}
		h.internal("register encryption key failed", err)
		writeAPIError(w, http.StatusConflict, "encryption_key_conflict")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *messagingHTTP) listChats(w http.ResponseWriter, r *http.Request) {
	principal := requestPrincipal(r)
	chats, err := h.store.ListChats(r.Context(), principal.Username)
	if err != nil {
		if requestCanceled(r, err) {
			return
		}
		h.internal("list chats failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": 1, "chats": chats})
}

func (h *messagingHTTP) listDevices(w http.ResponseWriter, r *http.Request) {
	_, chatID, ok := h.requireMembership(w, r)
	if !ok {
		return
	}
	devices, err := h.store.ListDevices(r.Context(), chatID)
	if err != nil {
		if requestCanceled(r, err) {
			return
		}
		h.internal("list devices failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": 1, "devices": devices})
}

func (h *messagingHTTP) listMessages(w http.ResponseWriter, r *http.Request) {
	principal, chatID, ok := h.requireMembership(w, r)
	if !ok {
		return
	}
	after, err := parseBoundedInt64(r.URL.Query().Get("after"), 0, 1<<62)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_after")
		return
	}
	before, err := parseBoundedInt64(r.URL.Query().Get("before"), 0, 1<<62)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_before")
		return
	}
	if after > 0 && before > 0 {
		writeAPIError(w, http.StatusBadRequest, "invalid_message_cursor")
		return
	}
	limit64, err := parseBoundedInt64(r.URL.Query().Get("limit"), 1, 200)
	if err != nil {
		limit64 = 100
	}
	page, err := h.store.ListMessages(
		r.Context(), chatID, principal.Username, principal.DeviceID,
		after, before, int(limit64),
	)
	if err != nil {
		if requestCanceled(r, err) {
			return
		}
		h.internal("list messages failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":         1,
		"messages":        page.Messages,
		"has_more_before": page.HasMoreBefore,
	})
}

func (h *messagingHTTP) listEnvelopeRepairMessages(w http.ResponseWriter, r *http.Request) {
	principal, chatID, ok := h.requireMembership(w, r)
	if !ok {
		return
	}
	before, err := parseBoundedInt64(r.URL.Query().Get("before"), 0, 1<<62)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_before")
		return
	}
	limit64, err := parseBoundedInt64(r.URL.Query().Get("limit"), 1, 200)
	if err != nil {
		limit64 = 200
	}
	page, err := h.store.ListMessagesForEnvelopeRepair(
		r.Context(), chatID, principal.Username, principal.DeviceID, before, int(limit64),
	)
	if err != nil {
		if requestCanceled(r, err) {
			return
		}
		h.internal("list envelope repair messages failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":         1,
		"messages":        page.Messages,
		"has_more_before": page.HasMoreBefore,
	})
}

func (h *messagingHTTP) createMessage(w http.ResponseWriter, r *http.Request) {
	principal, chatID, ok := h.requireMembership(w, r)
	if !ok {
		return
	}
	input, ok := h.decodeMessageWrite(w, r, chatID, principal)
	if !ok {
		return
	}
	created, err := h.store.CreateMessage(r.Context(), input, h.now().UTC())
	clear(input.Ciphertext)
	for i := range input.Envelopes {
		clear(input.Envelopes[i].Ciphertext)
	}
	for i := range input.RatchetEnvelopes {
		clear(input.RatchetEnvelopes[i].Ciphertext)
	}
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeAPIError(w, http.StatusConflict, "message_exists")
			return
		}
		h.internal("create message failed", err)
		writeAPIError(w, http.StatusBadRequest, "message_rejected")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"version": input.CryptoVersion, "message": created})
}

func (h *messagingHTTP) updateMessage(w http.ResponseWriter, r *http.Request) {
	principal, chatID, ok := h.requireMembership(w, r)
	if !ok {
		return
	}
	input, ok := h.decodeMessageWrite(w, r, chatID, principal)
	if !ok {
		return
	}
	pathID := strings.TrimSpace(r.PathValue("messageID"))
	if pathID != input.ID {
		writeAPIError(w, http.StatusBadRequest, "message_id_mismatch")
		return
	}
	err := h.store.UpdateMessage(r.Context(), input, h.now().UTC())
	clear(input.Ciphertext)
	for i := range input.Envelopes {
		clear(input.Envelopes[i].Ciphertext)
	}
	for i := range input.RatchetEnvelopes {
		clear(input.RatchetEnvelopes[i].Ciphertext)
	}
	if err != nil {
		writeAPIError(w, http.StatusForbidden, "message_update_forbidden")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *messagingHTTP) deleteMessage(w http.ResponseWriter, r *http.Request) {
	principal, chatID, ok := h.requireMembership(w, r)
	if !ok {
		return
	}
	messageID := strings.TrimSpace(r.PathValue("messageID"))
	if !messaging.ValidateUUID(messageID) {
		writeAPIError(w, http.StatusBadRequest, "invalid_message_id")
		return
	}
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	if scope == "" {
		scope = "me"
	}
	if scope != "me" && scope != "everyone" {
		writeAPIError(w, http.StatusBadRequest, "invalid_delete_scope")
		return
	}
	if err := h.store.DeleteMessage(r.Context(), chatID, messageID, principal.Username, scope, h.now().UTC()); err != nil {
		writeAPIError(w, http.StatusNotFound, "message_not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *messagingHTTP) addMessageEnvelopes(w http.ResponseWriter, r *http.Request) {
	principal, chatID, ok := h.requireMembership(w, r)
	if !ok {
		return
	}
	messageID := strings.TrimSpace(r.PathValue("messageID"))
	if !messaging.ValidateUUID(messageID) {
		writeAPIError(w, http.StatusBadRequest, "invalid_message_id")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request envelopeWriteRequest
	if err := decoder.Decode(&request); err != nil || requireJSONEOF(decoder) != nil ||
		request.Version != 1 || len(request.Envelopes) == 0 || len(request.Envelopes) > 64 {
		writeAPIError(w, http.StatusBadRequest, "invalid_envelopes")
		return
	}
	decoded, ok := decodeEnvelopes(w, request.Envelopes)
	if !ok {
		return
	}
	defer func() {
		for i := range decoded {
			clear(decoded[i].Ciphertext)
		}
	}()
	if err := h.store.AddMessageEnvelopes(r.Context(), chatID, messageID, principal, decoded); err != nil {
		writeAPIError(w, http.StatusForbidden, "envelope_update_forbidden")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *messagingHTTP) markReceipts(w http.ResponseWriter, r *http.Request) {
	principal, chatID, ok := h.requireMembership(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request receiptWriteRequest
	if err := decoder.Decode(&request); err != nil || requireJSONEOF(decoder) != nil ||
		request.Version != 1 || len(request.DeliveredIDs) > 200 || len(request.ReadIDs) > 200 {
		writeAPIError(w, http.StatusBadRequest, "invalid_receipts")
		return
	}
	if err := h.store.MarkReceipts(
		r.Context(), chatID, principal.Username,
		request.DeliveredIDs, request.ReadIDs, h.now().UTC(),
	); err != nil {
		if requestCanceled(r, err) {
			return
		}
		h.internal("receipt update failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *messagingHTTP) markReadCursor(w http.ResponseWriter, r *http.Request) {
	principal, chatID, ok := h.requireMembership(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request readCursorWriteRequest
	if err := decoder.Decode(&request); err != nil || requireJSONEOF(decoder) != nil ||
		request.Version != 1 || request.MaxReadSequence <= 0 {
		writeAPIError(w, http.StatusBadRequest, "invalid_read_cursor")
		return
	}
	accepted, err := h.store.MarkReadCursor(
		r.Context(), chatID, principal.Username, request.MaxReadSequence, h.now().UTC(),
	)
	if err != nil {
		if requestCanceled(r, err) {
			return
		}
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "invalid") {
			writeAPIError(w, http.StatusBadRequest, "invalid_read_cursor")
			return
		}
		h.internal("read cursor update failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":           1,
		"max_read_sequence": accepted,
	})
}

func (h *messagingHTTP) setTyping(w http.ResponseWriter, r *http.Request) {
	principal, chatID, ok := h.requireMembership(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request typingWriteRequest
	if err := decoder.Decode(&request); err != nil || requireJSONEOF(decoder) != nil || request.Version != 1 {
		writeAPIError(w, http.StatusBadRequest, "invalid_typing")
		return
	}
	if err := h.store.SetTyping(r.Context(), chatID, principal.Username, request.Typing, h.now().UTC()); err != nil {
		if requestCanceled(r, err) {
			return
		}
		h.internal("typing update failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *messagingHTTP) listTyping(w http.ResponseWriter, r *http.Request) {
	principal, chatID, ok := h.requireMembership(w, r)
	if !ok {
		return
	}
	typing, err := h.store.ListTyping(r.Context(), chatID, principal.Username, h.now().UTC())
	if err != nil {
		if requestCanceled(r, err) {
			return
		}
		h.internal("typing list failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": 1, "typing": typing})
}

func (h *messagingHTTP) pinMessage(w http.ResponseWriter, r *http.Request) {
	principal, chatID, ok := h.requireMembership(w, r)
	if !ok {
		return
	}
	messageID := strings.TrimSpace(r.PathValue("messageID"))
	if !messaging.ValidateUUID(messageID) {
		writeAPIError(w, http.StatusBadRequest, "invalid_message_id")
		return
	}
	if err := h.store.PinMessage(r.Context(), chatID, messageID, principal.Username, h.now().UTC()); err != nil {
		writeAPIError(w, http.StatusNotFound, "message_not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *messagingHTTP) unpinMessage(w http.ResponseWriter, r *http.Request) {
	_, chatID, ok := h.requireMembership(w, r)
	if !ok {
		return
	}
	if err := h.store.UnpinMessage(r.Context(), chatID); err != nil {
		if requestCanceled(r, err) {
			return
		}
		h.internal("unpin failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *messagingHTTP) reserveCryptoSequence(w http.ResponseWriter, r *http.Request) {
	principal, chatID, ok := h.requireMembership(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request cryptoSequenceRequest
	if err := decoder.Decode(&request); err != nil || requireJSONEOF(decoder) != nil || request.Version != 2 || len(request.RequestID) < 16 || len(request.RequestID) > 128 || !messaging.ValidateUUID(request.MessageID) {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	sequence, replayed, err := h.store.ReserveCryptoSequence(r.Context(), chatID, principal, request.RequestID, request.MessageID, h.now().UTC())
	if err != nil {
		writeAPIError(w, http.StatusConflict, "sequence_reservation_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": 2, "message_id": request.MessageID, "crypto_sequence": sequence, "replayed": replayed})
}

func (h *messagingHTTP) decodeMessageWrite(w http.ResponseWriter, r *http.Request, chatID string, principal messaging.Principal) (messaging.NewMessage, bool) {
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		writeAPIError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return messaging.NewMessage{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxMessageJSON)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request messageWriteRequest
	if err := decoder.Decode(&request); err != nil || requireJSONEOF(decoder) != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json")
		return messaging.NewMessage{}, false
	}
	if (request.Version != 1 && request.Version != 2) || !messaging.ValidateUUID(request.ID) || len(request.AAD) == 0 || len(request.AAD) > 4096 {
		writeAPIError(w, http.StatusBadRequest, "invalid_message")
		return messaging.NewMessage{}, false
	}
	if request.Version == 1 {
		if len(request.Envelopes) == 0 || len(request.Envelopes) > 64 || len(request.RatchetEnvelopes) != 0 {
			writeAPIError(w, http.StatusBadRequest, "invalid_message")
			return messaging.NewMessage{}, false
		}
		expectedAAD := messaging.CanonicalMessageAAD(chatID, principal.Username, principal.DeviceID, request.ID)
		if request.AAD != expectedAAD {
			writeAPIError(w, http.StatusBadRequest, "aad_mismatch")
			return messaging.NewMessage{}, false
		}
		request.CryptoVersion, request.RoomKeyVersion, request.AADVersion = 1, 1, 1
		request.EncryptionAlgorithm = "fedmes-aes256gcm-rsa-oaep-v1"
		if request.MessageType == "" {
			request.MessageType = "legacy"
		}
	} else {
		if request.CryptoVersion != 2 || request.AADVersion != 2 || request.RoomKeyVersion <= 0 || request.CryptoSequence <= 0 || len(request.SequenceRequestID) < 16 || len(request.SequenceRequestID) > 128 || len(request.MessageType) == 0 || len(request.MessageType) > 64 || len(request.Envelopes) != 0 || len(request.RatchetEnvelopes) > 64 {
			writeAPIError(w, http.StatusBadRequest, "invalid_message_v2")
			return messaging.NewMessage{}, false
		}
		expectedAAD := messaging.CanonicalMessageAADV2(chatID, principal.Username, principal.DeviceID, request.ID, request.MessageType, request.CryptoSequence, request.RoomKeyVersion)
		if request.AAD != expectedAAD {
			writeAPIError(w, http.StatusBadRequest, "aad_mismatch")
			return messaging.NewMessage{}, false
		}
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(request.Ciphertext)
	if err != nil || len(ciphertext) < 16 || len(ciphertext) > 1<<20 {
		clear(ciphertext)
		writeAPIError(w, http.StatusBadRequest, "invalid_ciphertext")
		return messaging.NewMessage{}, false
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(request.Nonce)
	if err != nil || len(nonce) != 12 {
		clear(ciphertext)
		clear(nonce)
		writeAPIError(w, http.StatusBadRequest, "invalid_nonce")
		return messaging.NewMessage{}, false
	}
	decoded, ok := decodeEnvelopes(w, request.Envelopes)
	if !ok {
		clear(ciphertext)
		clear(nonce)
		return messaging.NewMessage{}, false
	}
	ratchetDecoded, ok := decodeRatchetMessageEnvelopes(w, request.RatchetEnvelopes)
	if !ok {
		clear(ciphertext)
		clear(nonce)
		for i := range decoded {
			clear(decoded[i].Ciphertext)
		}
		return messaging.NewMessage{}, false
	}
	return messaging.NewMessage{
		ID: request.ID, ChatID: chatID, Sender: principal, Ciphertext: ciphertext, Nonce: nonce, AAD: request.AAD,
		CryptoVersion: request.CryptoVersion, RoomKeyVersion: request.RoomKeyVersion, AADVersion: request.AADVersion,
		CryptoSequence: request.CryptoSequence, EncryptionAlgorithm: request.EncryptionAlgorithm, MessageType: request.MessageType,
		SequenceRequestID: request.SequenceRequestID, Envelopes: decoded, RatchetEnvelopes: ratchetDecoded,
	}, true
}

func decodeRatchetMessageEnvelopes(w http.ResponseWriter, envelopes []messaging.RatchetEnvelope) ([]messaging.DecodedRatchetEnvelope, bool) {
	seen := make(map[string]struct{}, len(envelopes))
	out := make([]messaging.DecodedRatchetEnvelope, 0, len(envelopes))
	fail := func() ([]messaging.DecodedRatchetEnvelope, bool) {
		for i := range out {
			clear(out[i].Ciphertext)
		}
		writeAPIError(w, http.StatusBadRequest, "invalid_ratchet_envelope")
		return nil, false
	}
	for _, item := range envelopes {
		if item.RecipientDeviceID == "" || len(item.SenderCurve25519Key) < 32 || len(item.SenderCurve25519Key) > 128 || len(item.SessionID) < 16 || len(item.SessionID) > 256 || (item.MessageType != 0 && item.MessageType != 1) {
			return fail()
		}
		if _, ok := seen[item.RecipientDeviceID]; ok {
			return fail()
		}
		seen[item.RecipientDeviceID] = struct{}{}
		ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(item.CiphertextBase64)
		if err != nil || len(ciphertext) < 16 || len(ciphertext) > 1<<20 {
			clear(ciphertext)
			return fail()
		}
		hashBytes, err := hex.DecodeString(item.CiphertextSHA256)
		if err != nil || len(hashBytes) != sha256.Size {
			clear(ciphertext)
			clear(hashBytes)
			return fail()
		}
		var digest [sha256.Size]byte
		copy(digest[:], hashBytes)
		clear(hashBytes)
		out = append(out, messaging.DecodedRatchetEnvelope{RecipientDeviceID: item.RecipientDeviceID, SenderCurve25519Key: item.SenderCurve25519Key, SessionID: item.SessionID, MessageType: item.MessageType, Ciphertext: ciphertext, CiphertextSHA256: digest})
	}
	return out, true
}

func decodeEnvelopes(w http.ResponseWriter, envelopes []messaging.Envelope) ([]messaging.DecodedEnvelope, bool) {
	seen := make(map[string]struct{}, len(envelopes))
	decoded := make([]messaging.DecodedEnvelope, 0, len(envelopes))
	fail := func(code string) ([]messaging.DecodedEnvelope, bool) {
		for i := range decoded {
			clear(decoded[i].Ciphertext)
		}
		writeAPIError(w, http.StatusBadRequest, code)
		return nil, false
	}
	for _, item := range envelopes {
		if item.DeviceID == "" {
			return fail("invalid_envelope")
		}
		if _, exists := seen[item.DeviceID]; exists {
			return fail("duplicate_envelope")
		}
		seen[item.DeviceID] = struct{}{}
		if item.Algorithm != "rsa-oaep-sha256" {
			return fail("invalid_envelope")
		}
		ecipher, err := base64.StdEncoding.Strict().DecodeString(item.CiphertextBase64)
		if err != nil || len(ecipher) < 256 || len(ecipher) > 1024 {
			clear(ecipher)
			return fail("invalid_envelope")
		}
		decoded = append(decoded, messaging.DecodedEnvelope{
			DeviceID: item.DeviceID, Algorithm: item.Algorithm, Ciphertext: ecipher,
		})
	}
	return decoded, true
}

func (h *messagingHTTP) heartbeat(w http.ResponseWriter, r *http.Request) {
	principal := requestPrincipal(r)
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req heartbeatRequest
	if err := decoder.Decode(&req); err != nil || requireJSONEOF(decoder) != nil || req.Version != 1 {
		writeAPIError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if err := h.store.Heartbeat(r.Context(), principal.Username, req.ShowExact, h.now().UTC()); err != nil {
		if requestCanceled(r, err) {
			return
		}
		h.internal("heartbeat failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *messagingHTTP) listPresence(w http.ResponseWriter, r *http.Request) {
	principal := requestPrincipal(r)
	presence, err := h.store.ListPresence(r.Context(), principal.Username, h.now().UTC())
	if err != nil {
		if requestCanceled(r, err) {
			return
		}
		h.internal("presence failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": 1, "presence": presence})
}

func (h *messagingHTTP) events(w http.ResponseWriter, r *http.Request) {
	principal := requestPrincipal(r)
	after, err := parseBoundedInt64(r.URL.Query().Get("after"), 0, 1<<62)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_after")
		return
	}
	seq, err := h.store.WaitForSequence(r.Context(), principal.Username, after, 25*time.Second)
	if err != nil {
		if requestCanceled(r, err) {
			return
		}
		h.internal("events failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": 1, "sequence": seq})
}

func (h *messagingHTTP) uploadMedia(w http.ResponseWriter, r *http.Request) {
	principal, chatID, ok := h.requireMembership(w, r)
	if !ok {
		return
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/octet-stream") {
		writeAPIError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	defer r.Body.Close()
	mediaID := strings.TrimSpace(r.PathValue("mediaID"))
	if !messaging.ValidateUUID(mediaID) {
		writeAPIError(w, http.StatusBadRequest, "invalid_media_id")
		return
	}
	if err := os.MkdirAll(h.mediaDir, 0o700); err != nil {
		h.internal("media mkdir failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	blobName := mediaID
	finalPath := filepath.Join(h.mediaDir, blobName)
	tmp, err := os.CreateTemp(h.mediaDir, "upload-*.tmp")
	if err != nil {
		h.internal("temp media failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	defer tmp.Close()
	hasher := sha256.New()
	written, copyErr := io.CopyBuffer(
		io.MultiWriter(tmp, hasher),
		r.Body,
		make([]byte, 256*1024),
	)
	if copyErr != nil {
		h.internal("media upload failed", copyErr)
		writeAPIError(w, http.StatusBadRequest, "upload_failed")
		return
	}
	if written < 1 {
		writeAPIError(w, http.StatusBadRequest, "empty_media")
		return
	}
	if err := tmp.Sync(); err != nil {
		h.internal("media sync failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if err := tmp.Close(); err != nil {
		h.internal("media close failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		h.internal("media chmod failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if err := os.Link(tmpPath, finalPath); err != nil {
		if errors.Is(err, os.ErrExist) {
			writeAPIError(w, http.StatusConflict, "media_exists")
			return
		}
		h.internal("media commit failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	sumBytes := hasher.Sum(nil)
	var sum [32]byte
	copy(sum[:], sumBytes)
	clear(sumBytes)
	object := messaging.MediaObject{ID: mediaID, ChatID: chatID, UploaderUsername: principal.Username, UploaderDeviceID: principal.DeviceID, BlobName: blobName, SizeBytes: written, SHA256: sum, CreatedAt: h.now().UTC()}
	if err := h.store.CreateMedia(r.Context(), object); err != nil {
		_ = os.Remove(finalPath)
		writeAPIError(w, http.StatusConflict, "media_exists")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"version": 1, "media": map[string]any{"id": mediaID, "size_bytes": written, "sha256": fmt.Sprintf("%x", sum)}})
}

func (h *messagingHTTP) downloadMedia(w http.ResponseWriter, r *http.Request) {
	_, chatID, ok := h.requireMembership(w, r)
	if !ok {
		return
	}
	mediaID := strings.TrimSpace(r.PathValue("mediaID"))
	object, err := h.store.LoadMedia(r.Context(), mediaID, chatID)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "media_not_found")
		return
	}
	path := filepath.Join(h.mediaDir, object.BlobName)
	file, err := os.Open(path)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "media_not_found")
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(object.SizeBytes, 10))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, file)
}

func (h *messagingHTTP) deleteMedia(w http.ResponseWriter, r *http.Request) {
	_, chatID, ok := h.requireMembership(w, r)
	if !ok {
		return
	}
	mediaID := strings.TrimSpace(r.PathValue("mediaID"))
	if !messaging.ValidateUUID(mediaID) {
		writeAPIError(w, http.StatusBadRequest, "invalid_media_id")
		return
	}
	object, err := h.store.DeleteMedia(r.Context(), mediaID, chatID)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "media_not_found")
		return
	}
	if err := os.Remove(filepath.Join(h.mediaDir, object.BlobName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		h.internal("media delete failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseBoundedInt64(value string, minimum, maximum int64) (int64, error) {
	if strings.TrimSpace(value) == "" {
		return minimum, nil
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < minimum || n > maximum {
		return 0, errors.New("out of range")
	}
	return n, nil
}

func requestCanceled(r *http.Request, err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if r == nil {
		return false
	}
	requestErr := r.Context().Err()
	return errors.Is(requestErr, context.Canceled) || errors.Is(requestErr, context.DeadlineExceeded)
}

func writeAPIError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"version": 1, "error": map[string]string{"code": code}})
}
func (h *messagingHTTP) internal(message string, err error) {
	if h.logger != nil {
		h.logger.Error(message, "error_code", "internal_error", "cause", err.Error())
	}
}
