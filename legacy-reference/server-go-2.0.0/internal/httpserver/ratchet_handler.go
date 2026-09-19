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
	"strconv"
	"strings"
	"time"

	"fedmes/server/internal/accountsecurity"
	"fedmes/server/internal/messaging"
	"fedmes/server/internal/ratchet"
)

const maximumRatchetRequestBytes = int64(18 << 20)

type ratchetHTTP struct {
	store          *ratchet.Store
	messagingStore *messaging.Store
	logger         *slog.Logger
	now            func() time.Time
}

type ratchetOneTimeKeyRequest struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}
type ratchetBundleRequest struct {
	Version               int                        `json:"version"`
	BundleVersion         int                        `json:"bundle_version"`
	Curve25519IdentityKey string                     `json:"curve25519_identity_key"`
	Ed25519IdentityKey    string                     `json:"ed25519_identity_key"`
	SignedPayload         string                     `json:"signed_payload"`
	Signature             string                     `json:"signature"`
	OneTimeKeys           []ratchetOneTimeKeyRequest `json:"one_time_keys"`
}
type ratchetClaimRequest struct {
	Version        int    `json:"version"`
	TargetDeviceID string `json:"target_device_id"`
}
type ratchetEnvelopeRequest struct {
	MessageID           string `json:"message_id"`
	RecipientDeviceID   string `json:"recipient_device_id"`
	SenderCurve25519Key string `json:"sender_curve25519_key"`
	SessionID           string `json:"session_id"`
	MessageType         int    `json:"message_type"`
	Ciphertext          string `json:"ciphertext"`
	CiphertextSHA256    string `json:"ciphertext_sha256"`
}
type ratchetEnvelopeBatchRequest struct {
	Version   int                      `json:"version"`
	Envelopes []ratchetEnvelopeRequest `json:"envelopes"`
}
type groupKeyPackageRequest struct {
	RecipientDeviceID   string `json:"recipient_device_id"`
	OlmSessionID        string `json:"olm_session_id"`
	MessageType         int    `json:"message_type"`
	EncryptedSessionKey string `json:"encrypted_session_key"`
}
type groupVersionReserveRequest struct {
	Version    int    `json:"version"`
	ChatID     string `json:"chat_id"`
	RotationID string `json:"rotation_id"`
}
type groupSessionRequest struct {
	Version        int                      `json:"version"`
	ChatID         string                   `json:"chat_id"`
	RoomKeyVersion int64                    `json:"room_key_version"`
	SessionID      string                   `json:"session_id"`
	RotationID     string                   `json:"rotation_id"`
	Packages       []groupKeyPackageRequest `json:"packages"`
}
type consumeGroupKeyRequest struct {
	Version        int    `json:"version"`
	ChatID         string `json:"chat_id"`
	RoomKeyVersion int64  `json:"room_key_version"`
}

func registerRatchetRoutes(mux *http.ServeMux, messagingStore *messaging.Store, logger *slog.Logger) {
	if messagingStore == nil || messagingStore.DB == nil {
		return
	}
	h := &ratchetHTTP{store: ratchet.NewStore(messagingStore.DB), messagingStore: messagingStore, logger: logger, now: time.Now}
	limiter := newIPRateLimiter(180, time.Minute, 8192, time.Now)
	protected := func(handler http.HandlerFunc) http.Handler { return limiter.middleware(h.auth(handler)) }
	mux.Handle("PUT /api/v3/crypto/ratchet/bundle", protected(h.putBundle))
	mux.Handle("POST /api/v3/crypto/ratchet/claim", protected(h.claim))
	mux.Handle("POST /api/v3/crypto/ratchet/envelopes", protected(h.putEnvelopes))
	mux.Handle("GET /api/v3/crypto/ratchet/envelopes", protected(h.listEnvelopes))
	mux.Handle("POST /api/v3/crypto/megolm/reserve", protected(h.reserveGroupVersion))
	mux.Handle("POST /api/v3/crypto/megolm/sessions", protected(h.putGroupSession))
	mux.Handle("GET /api/v3/crypto/megolm/packages", protected(h.listGroupPackages))
	mux.Handle("POST /api/v3/crypto/megolm/packages/consume", protected(h.consumeGroupPackage))
}

func (h *ratchetHTTP) auth(next http.HandlerFunc) http.Handler {
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
		ctx := context.WithValue(r.Context(), principalContextKey{}, p)
		next(w, r.WithContext(ctx))
	})
}
func ratchetPrincipal(r *http.Request) ratchet.Principal {
	p := requestPrincipal(r)
	return ratchet.Principal{Username: p.Username, DeviceID: p.DeviceID}
}

func (h *ratchetHTTP) putBundle(w http.ResponseWriter, r *http.Request) {
	var req ratchetBundleRequest
	if !decodeRatchetJSON(w, r, &req) {
		return
	}
	if req.Version != ratchet.ProtocolVersion {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	payload, ok1 := decodeRawURL(req.SignedPayload, 32, 65536)
	signature, ok2 := decodeRawURL(req.Signature, 32, 2048)
	if !ok1 || !ok2 {
		clear(payload)
		clear(signature)
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	defer clear(payload)
	defer clear(signature)
	input := ratchet.BundleWrite{BundleVersion: req.BundleVersion, Curve25519IdentityKey: req.Curve25519IdentityKey, Ed25519IdentityKey: req.Ed25519IdentityKey, SignedPayload: payload, Signature: signature, OneTimeKeys: make([]ratchet.OneTimeKey, 0, len(req.OneTimeKeys))}
	for _, raw := range req.OneTimeKeys {
		sig, ok := decodeRawURL(raw.Signature, 32, 2048)
		if !ok {
			writeAPIError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		defer clear(sig)
		input.OneTimeKeys = append(input.OneTimeKeys, ratchet.OneTimeKey{KeyID: raw.KeyID, PublicKey: raw.PublicKey, Signature: sig})
	}
	if err := h.store.PutBundle(r.Context(), ratchetPrincipal(r), input); err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": ratchet.ProtocolVersion, "status": "ok"})
}
func (h *ratchetHTTP) claim(w http.ResponseWriter, r *http.Request) {
	var req ratchetClaimRequest
	if !decodeRatchetJSON(w, r, &req) {
		return
	}
	if req.Version != ratchet.ProtocolVersion {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	key, err := h.store.ClaimOneTimeKey(r.Context(), ratchetPrincipal(r), req.TargetDeviceID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": ratchet.ProtocolVersion, "device_id": key.DeviceID, "username": key.Username, "bundle_version": key.BundleVersion, "curve25519_identity_key": key.Curve25519IdentityKey, "ed25519_identity_key": key.Ed25519IdentityKey, "signed_payload": base64.RawURLEncoding.EncodeToString(key.SignedPayload), "bundle_signature": base64.RawURLEncoding.EncodeToString(key.BundleSignature), "one_time_key": map[string]any{"key_id": key.OneTimeKey.KeyID, "public_key": key.OneTimeKey.PublicKey, "signature": base64.RawURLEncoding.EncodeToString(key.OneTimeKey.Signature)}, "claimed_at": key.ClaimedAt.Format(time.RFC3339Nano)})
}
func (h *ratchetHTTP) putEnvelopes(w http.ResponseWriter, r *http.Request) {
	var req ratchetEnvelopeBatchRequest
	if !decodeRatchetJSON(w, r, &req) {
		return
	}
	if req.Version != ratchet.ProtocolVersion {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	values := make([]ratchet.MessageEnvelope, 0, len(req.Envelopes))
	for _, raw := range req.Envelopes {
		ciphertext, ok := decodeRawURL(raw.Ciphertext, 16, 1<<20)
		hash, err := hex.DecodeString(raw.CiphertextSHA256)
		if !ok || err != nil || len(hash) != 32 {
			clear(ciphertext)
			clear(hash)
			writeAPIError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		defer clear(ciphertext)
		defer clear(hash)
		var digest [32]byte
		copy(digest[:], hash)
		values = append(values, ratchet.MessageEnvelope{MessageID: raw.MessageID, RecipientDeviceID: raw.RecipientDeviceID, SenderCurve25519Key: raw.SenderCurve25519Key, SessionID: raw.SessionID, MessageType: raw.MessageType, Ciphertext: ciphertext, CiphertextSHA256: digest})
	}
	if err := h.store.PutMessageEnvelopes(r.Context(), ratchetPrincipal(r), values); err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"version": ratchet.ProtocolVersion, "status": "ok"})
}
func (h *ratchetHTTP) listEnvelopes(w http.ResponseWriter, r *http.Request) {
	after, err := strconv.ParseInt(defaultString(r.URL.Query().Get("after_sequence"), "0"), 10, 64)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	limit, err := strconv.Atoi(defaultString(r.URL.Query().Get("limit"), "100"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	items, err := h.store.ListPendingEnvelopes(r.Context(), ratchetPrincipal(r), after, limit)
	if err != nil {
		h.writeError(w, err)
		return
	}
	response := make([]map[string]any, 0, len(items))
	for _, x := range items {
		response = append(response, map[string]any{"message_id": x.MessageID, "chat_id": x.ChatID, "recipient_device_id": x.RecipientDeviceID, "sender_device_id": x.SenderDeviceID, "sender_curve25519_key": x.SenderCurve25519Key, "session_id": x.SessionID, "message_type": x.MessageType, "ciphertext": base64.RawURLEncoding.EncodeToString(x.Ciphertext), "ciphertext_sha256": hex.EncodeToString(x.CiphertextSHA256[:]), "created_at": x.CreatedAt.Format(time.RFC3339Nano)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": ratchet.ProtocolVersion, "envelopes": response})
}
func (h *ratchetHTTP) reserveGroupVersion(w http.ResponseWriter, r *http.Request) {
	var req groupVersionReserveRequest
	if !decodeRatchetJSON(w, r, &req) {
		return
	}
	if req.Version != ratchet.ProtocolVersion {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	reservation, err := h.store.ReserveGroupVersion(r.Context(), ratchetPrincipal(r), strings.TrimSpace(req.ChatID), strings.TrimSpace(req.RotationID))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":          ratchet.ProtocolVersion,
		"chat_id":          reservation.ChatID,
		"rotation_id":      reservation.RotationID,
		"room_key_version": reservation.RoomKeyVersion,
		"expires_at":       reservation.ExpiresAt.Format(time.RFC3339Nano),
		"replayed":         reservation.Replayed,
	})
}

func (h *ratchetHTTP) putGroupSession(w http.ResponseWriter, r *http.Request) {
	var req groupSessionRequest
	if !decodeRatchetJSON(w, r, &req) {
		return
	}
	if req.Version != ratchet.ProtocolVersion {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	input := ratchet.GroupSessionWrite{ChatID: req.ChatID, RoomKeyVersion: req.RoomKeyVersion, SessionID: req.SessionID, RotationID: req.RotationID, Packages: make([]ratchet.GroupKeyPackage, 0, len(req.Packages))}
	for _, raw := range req.Packages {
		encrypted, ok := decodeRawURL(raw.EncryptedSessionKey, 16, 65536)
		if !ok {
			writeAPIError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		defer clear(encrypted)
		input.Packages = append(input.Packages, ratchet.GroupKeyPackage{RecipientDeviceID: raw.RecipientDeviceID, OlmSessionID: raw.OlmSessionID, MessageType: raw.MessageType, EncryptedSessionKey: encrypted})
	}
	if err := h.store.PutGroupSession(r.Context(), ratchetPrincipal(r), input); err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"version": ratchet.ProtocolVersion, "status": "ok"})
}
func (h *ratchetHTTP) listGroupPackages(w http.ResponseWriter, r *http.Request) {
	limit, err := strconv.Atoi(defaultString(r.URL.Query().Get("limit"), "100"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	items, err := h.store.ListPendingGroupKeys(r.Context(), ratchetPrincipal(r), limit)
	if err != nil {
		h.writeError(w, err)
		return
	}
	response := make([]map[string]any, 0, len(items))
	for _, x := range items {
		response = append(response, map[string]any{"chat_id": x.ChatID, "room_key_version": x.RoomKeyVersion, "session_id": x.SessionID, "sender_device_id": x.SenderDeviceID, "sender_curve25519_key": x.SenderCurve25519Key, "rotation_id": x.RotationID, "olm_session_id": x.OlmSessionID, "message_type": x.MessageType, "encrypted_session_key": base64.RawURLEncoding.EncodeToString(x.EncryptedSessionKey), "created_at": x.CreatedAt.Format(time.RFC3339Nano)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": ratchet.ProtocolVersion, "packages": response})
}
func (h *ratchetHTTP) consumeGroupPackage(w http.ResponseWriter, r *http.Request) {
	var req consumeGroupKeyRequest
	if !decodeRatchetJSON(w, r, &req) {
		return
	}
	if req.Version != ratchet.ProtocolVersion {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.store.ConsumeGroupKey(r.Context(), ratchetPrincipal(r), req.ChatID, req.RoomKeyVersion); err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": ratchet.ProtocolVersion, "status": "ok"})
}

func decodeRatchetJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maximumRatchetRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}
func decodeRawURL(value string, min, max int) ([]byte, bool) {
	if value == "" || len(value) > ((max+2)/3)*4+8 {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) < min || len(decoded) > max {
		clear(decoded)
		return nil, false
	}
	return decoded, true
}
func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
func (h *ratchetHTTP) writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ratchet.ErrInvalid):
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, ratchet.ErrForbidden):
		writeAPIError(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, ratchet.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, ratchet.ErrNoKey):
		writeAPIError(w, http.StatusConflict, "one_time_key_unavailable")
	case errors.Is(err, ratchet.ErrConflict):
		writeAPIError(w, http.StatusConflict, "state_conflict")
	default:
		if h.logger != nil {
			h.logger.Error("ratchet operation failed", "error_code", "ratchet_operation_failed", "cause", err.Error())
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
	}
}

var _ = sha256.Size
