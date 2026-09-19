package httpserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"fedmes/server/internal/messaging"
	"fedmes/server/internal/provisioning"

	"github.com/google/uuid"
	qrcode "github.com/skip2/go-qrcode"
)

const (
	deviceLinkRequestTTL = 2 * time.Minute
	deviceLinkResultTTL  = 10 * time.Minute
	deviceSessionTTL     = 15 * time.Minute
	maxDeviceLinkBody    = int64(24 << 10)
)

type deviceLinkHTTP struct {
	store  *messaging.Store
	logger *slog.Logger
	now    func() time.Time
}

type deviceLinkPublicKey struct {
	Algorithm     string `json:"algorithm"`
	PublicKeySPKI string `json:"public_key_spki"`
}

type createDeviceLinkRequest struct {
	Version     int                 `json:"version"`
	DisplayName string              `json:"display_name"`
	Platform    string              `json:"platform"`
	Identity    deviceLinkPublicKey `json:"identity"`
	Encryption  deviceLinkPublicKey `json:"encryption"`
}

type deviceLinkSecretRequest struct {
	Version int    `json:"version"`
	Secret  string `json:"secret"`
}

type approveDeviceLinkRequest struct {
	Version   int    `json:"version"`
	Secret    string `json:"secret"`
	Signature string `json:"signature"`
}

func registerDeviceLinkRoutes(mux *http.ServeMux, store *messaging.Store, logger *slog.Logger) {
	if store == nil {
		return
	}
	h := &deviceLinkHTTP{store: store, logger: logger, now: time.Now}
	auth := (&messagingHTTP{store: store, logger: logger, now: time.Now}).auth
	publicMutationLimiter := newIPRateLimiter(30, time.Minute, 4096, time.Now)
	publicStatusLimiter := newIPRateLimiter(180, time.Minute, 4096, time.Now)
	protectedLimiter := newIPRateLimiter(300, time.Minute, 8192, time.Now)

	mux.Handle("POST /api/v1/device-links", publicMutationLimiter.middleware(http.HandlerFunc(h.create)))
	mux.Handle("POST /api/v1/device-links/{linkID}/status", publicStatusLimiter.middleware(http.HandlerFunc(h.status)))
	mux.Handle("POST /api/v1/device-links/{linkID}/cancel", publicMutationLimiter.middleware(http.HandlerFunc(h.cancel)))
	mux.Handle("POST /api/v1/device-links/{linkID}/complete", publicMutationLimiter.middleware(http.HandlerFunc(h.complete)))
	mux.Handle("POST /api/v1/device-links/{linkID}/preview", protectedLimiter.middleware(auth(http.HandlerFunc(h.preview))))
	mux.Handle("POST /api/v1/device-links/{linkID}/approve", protectedLimiter.middleware(auth(http.HandlerFunc(h.approve))))

	mux.Handle("GET /api/v1/account/devices", protectedLimiter.middleware(auth(http.HandlerFunc(h.listDevices))))
	mux.Handle("DELETE /api/v1/account/devices/{deviceID}", protectedLimiter.middleware(auth(http.HandlerFunc(h.revokeDevice))))
	mux.Handle("POST /api/v1/account/devices/terminate-others", protectedLimiter.middleware(auth(http.HandlerFunc(h.terminateOthers))))
	mux.Handle("DELETE /api/v1/account/device", protectedLimiter.middleware(auth(http.HandlerFunc(h.revokeCurrentDevice))))
}

func (h *deviceLinkHTTP) create(w http.ResponseWriter, r *http.Request) {
	var request createDeviceLinkRequest
	if !decodeStrictJSON(w, r, maxDeviceLinkBody, &request) {
		return
	}
	request.DisplayName = strings.TrimSpace(request.DisplayName)
	request.Platform = strings.ToLower(strings.TrimSpace(request.Platform))
	if request.Version != 1 || len(request.DisplayName) < 1 || len(request.DisplayName) > 64 ||
		(request.Platform != "windows" && request.Platform != "linux" && request.Platform != "macos") {
		writeAPIError(w, http.StatusBadRequest, "invalid_device_link")
		return
	}

	identityDER, err := base64.StdEncoding.Strict().DecodeString(request.Identity.PublicKeySPKI)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_identity_key")
		return
	}
	defer clear(identityDER)
	identity, err := provisioning.ValidateDevicePublicKey(provisioning.DevicePublicKeyInput{
		Algorithm: provisioning.DeviceKeyAlgorithm(request.Identity.Algorithm), SubjectPublicKeyInfo: identityDER,
	})
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_identity_key")
		return
	}

	encryptionDER, err := base64.StdEncoding.Strict().DecodeString(request.Encryption.PublicKeySPKI)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_encryption_key")
		return
	}
	defer clear(encryptionDER)
	encryption, err := provisioning.ValidateMessageEncryptionKey(provisioning.MessageEncryptionKeyInput{
		Algorithm: request.Encryption.Algorithm, SubjectPublicKeyInfo: encryptionDER,
	})
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_encryption_key")
		return
	}

	secretRaw := make([]byte, 32)
	if _, err := rand.Read(secretRaw); err != nil {
		clear(secretRaw)
		h.internal("device link entropy failed", err)
		writeAPIError(w, http.StatusServiceUnavailable, "entropy_unavailable")
		return
	}
	secret := base64.RawURLEncoding.EncodeToString(secretRaw)
	secretDigest := sha256.Sum256(secretRaw)
	clear(secretRaw)
	created := h.now().UTC()
	linkID := uuid.NewString()
	record := messaging.DeviceLinkRecord{
		ID: linkID, SecretDigest: secretDigest,
		IdentityAlgorithm: string(identity.Algorithm()), IdentityPublicKeySPKI: identity.SubjectPublicKeyInfo(), IdentityFingerprint: identity.Fingerprint(),
		EncryptionAlgorithm: encryption.Algorithm(), EncryptionPublicKeySPKI: encryption.SubjectPublicKeyInfo(), EncryptionFingerprint: encryption.Fingerprint(),
		DisplayName: request.DisplayName, Platform: request.Platform, CreatedAt: created, ExpiresAt: created.Add(deviceLinkRequestTTL),
	}
	if err := h.store.CreateDeviceLink(r.Context(), record); err != nil {
		status := http.StatusConflict
		if !errors.Is(err, messaging.ErrDeviceLinkConflict) {
			status = http.StatusInternalServerError
			h.internal("create device link failed", err)
		}
		writeAPIError(w, status, "device_link_conflict")
		return
	}

	values := url.Values{}
	values.Set("v", "1")
	values.Set("id", linkID)
	values.Set("secret", secret)
	payload := (&url.URL{Scheme: "fedmes", Host: "link-device", RawQuery: values.Encode()}).String()
	png, err := qrcode.Encode(payload, qrcode.Medium, 512)
	if err != nil {
		h.internal("encode device link QR failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"version":       1,
		"link_id":       linkID,
		"secret":        secret,
		"qr_payload":    payload,
		"qr_png_base64": base64.StdEncoding.EncodeToString(png),
		"expires_at":    record.ExpiresAt.Format(time.RFC3339Nano),
	})
}

func (h *deviceLinkHTTP) status(w http.ResponseWriter, r *http.Request) {
	request, digest, ok := h.secretRequest(w, r)
	if !ok {
		return
	}
	_ = request
	record, err := h.store.LoadDeviceLink(r.Context(), strings.TrimSpace(r.PathValue("linkID")), digest)
	if err != nil {
		h.writeLinkError(w, err)
		return
	}
	now := h.now().UTC()
	state := messaging.DeviceLinkState(record, now)
	if state == "expired" && record.ApprovedAt != nil && record.ConsumedAt == nil {
		if err := h.store.ExpireApprovedDeviceLink(r.Context(), record, now); err != nil {
			h.internal("expire abandoned device link failed", err)
			writeAPIError(w, http.StatusInternalServerError, "internal_error")
			return
		}
	}
	response := map[string]any{"version": 1, "status": state, "expires_at": record.ExpiresAt.Format(time.RFC3339Nano)}
	if state == "approved" {
		response["username"] = record.Username
		response["device_id"] = record.LinkedDeviceID
		response["session_id"] = record.LinkedSessionID
		var authenticationState string
		if err := h.store.DB.QueryRowContext(r.Context(), `
			SELECT security_state FROM provisioning_devices WHERE id = ? AND username = ?
		`, record.LinkedDeviceID, record.Username).Scan(&authenticationState); err != nil {
			h.internal("load linked device security state failed", err)
			writeAPIError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		response["authentication_state"] = authenticationState
		response["encrypted_session_token"] = base64.StdEncoding.EncodeToString(record.EncryptedSessionToken)
		response["session_expires_at"] = record.SessionExpiresAt.Format(time.RFC3339Nano)
		response["result_expires_at"] = record.ResultExpiresAt.Format(time.RFC3339Nano)
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *deviceLinkHTTP) preview(w http.ResponseWriter, r *http.Request) {
	_, digest, ok := h.secretRequest(w, r)
	if !ok {
		return
	}
	record, err := h.store.LoadDeviceLink(r.Context(), strings.TrimSpace(r.PathValue("linkID")), digest)
	if err != nil {
		h.writeLinkError(w, err)
		return
	}
	if messaging.DeviceLinkState(record, h.now().UTC()) != "pending" {
		writeAPIError(w, http.StatusGone, "device_link_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":                1,
		"link_id":                record.ID,
		"display_name":           record.DisplayName,
		"platform":               record.Platform,
		"identity_fingerprint":   fmt.Sprintf("%x", record.IdentityFingerprint[:]),
		"encryption_fingerprint": fmt.Sprintf("%x", record.EncryptionFingerprint[:]),
		"expires_at":             record.ExpiresAt.Format(time.RFC3339Nano),
	})
}

func (h *deviceLinkHTTP) approve(w http.ResponseWriter, r *http.Request) {
	var request approveDeviceLinkRequest
	if !decodeStrictJSON(w, r, maxDeviceLinkBody, &request) {
		return
	}
	if request.Version != 1 {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	secretDigest, ok := parseLinkSecret(request.Secret)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_device_link_secret")
		return
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(request.Signature)
	if err != nil || len(signature) == 0 || len(signature) > 512 {
		clear(signature)
		writeAPIError(w, http.StatusUnauthorized, "invalid_device_signature")
		return
	}
	defer clear(signature)
	linkID := strings.TrimSpace(r.PathValue("linkID"))
	record, err := h.store.LoadDeviceLink(r.Context(), linkID, secretDigest)
	if err != nil {
		h.writeLinkError(w, err)
		return
	}

	principal := requestPrincipal(r)
	algorithm, approverPublicKey, err := h.store.LoadActiveDeviceIdentity(r.Context(), principal)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, "session_invalid")
		return
	}
	defer clear(approverPublicKey)
	canonical := canonicalDeviceLinkApproval(
		linkID, request.Secret, principal.DeviceID,
		fmt.Sprintf("%x", record.IdentityFingerprint[:]), fmt.Sprintf("%x", record.EncryptionFingerprint[:]),
	)
	if !messaging.VerifyDeviceLinkApprovalSignature(algorithm, approverPublicKey, canonical, signature) {
		clear(canonical)
		writeAPIError(w, http.StatusUnauthorized, "invalid_device_signature")
		return
	}
	clear(canonical)

	state := messaging.DeviceLinkState(record, h.now().UTC())
	if state == "approved" && record.Username == principal.Username &&
		record.ApprovedByDeviceID == principal.DeviceID && record.LinkedDeviceID != "" {
		// Approval is deliberately idempotent. If the phone's first HTTP response was lost,
		// a retry must not force the user to scan the same QR a second time.
		devices, listErr := h.store.ListAccountDevices(r.Context(), principal)
		if listErr != nil {
			h.internal("load idempotently linked device failed", listErr)
			writeAPIError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		for _, device := range devices {
			if device.ID == record.LinkedDeviceID {
				writeJSON(w, http.StatusOK, map[string]any{
					"version":               1,
					"device":                device,
					"history_sync_required": true,
				})
				return
			}
		}
		writeAPIError(w, http.StatusGone, "device_link_unavailable")
		return
	}
	if state != "pending" {
		writeAPIError(w, http.StatusGone, "device_link_unavailable")
		return
	}

	parsedEncryptionKey, err := x509.ParsePKIXPublicKey(record.EncryptionPublicKeySPKI)
	if err != nil {
		h.internal("parse linked encryption key failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	rsaKey, ok := parsedEncryptionKey.(*rsa.PublicKey)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_encryption_key")
		return
	}

	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		clear(rawToken)
		h.internal("session entropy failed", err)
		writeAPIError(w, http.StatusServiceUnavailable, "entropy_unavailable")
		return
	}
	tokenDigest := sha256.Sum256(rawToken)
	encryptedToken, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKey, rawToken, nil)
	clear(rawToken)
	if err != nil {
		h.internal("encrypt linked session token failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	defer clear(encryptedToken)

	approvedAt := h.now().UTC()
	linked, err := h.store.ApproveDeviceLink(r.Context(), messaging.DeviceLinkApproval{
		LinkID: linkID, SecretDigest: secretDigest, Approver: principal,
		InvitationID: uuid.NewString(), DeviceID: uuid.NewString(), SessionID: uuid.NewString(),
		SessionTokenDigest: tokenDigest, EncryptedSessionToken: encryptedToken,
		SessionExpiresAt: approvedAt.Add(deviceSessionTTL), ResultExpiresAt: approvedAt.Add(deviceLinkResultTTL), ApprovedAt: approvedAt,
	})
	if err != nil {
		h.writeLinkError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"version":               1,
		"device":                linked,
		"history_sync_required": true,
	})
}

func (h *deviceLinkHTTP) cancel(w http.ResponseWriter, r *http.Request) {
	_, digest, ok := h.secretRequest(w, r)
	if !ok {
		return
	}
	if err := h.store.CancelDeviceLink(r.Context(), strings.TrimSpace(r.PathValue("linkID")), digest, h.now().UTC()); err != nil {
		h.writeLinkError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *deviceLinkHTTP) complete(w http.ResponseWriter, r *http.Request) {
	_, digest, ok := h.secretRequest(w, r)
	if !ok {
		return
	}
	if err := h.store.CompleteDeviceLink(r.Context(), strings.TrimSpace(r.PathValue("linkID")), digest, h.now().UTC()); err != nil {
		h.writeLinkError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *deviceLinkHTTP) listDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := h.store.ListAccountDevices(r.Context(), requestPrincipal(r))
	if err != nil {
		h.internal("list account devices failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": 1, "devices": devices})
}

func (h *deviceLinkHTTP) revokeDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := strings.TrimSpace(r.PathValue("deviceID"))
	if _, err := uuid.Parse(deviceID); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_device_id")
		return
	}
	err := h.store.RevokeAccountDevice(r.Context(), requestPrincipal(r), deviceID, h.now().UTC())
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, messaging.ErrCurrentDevice):
		writeAPIError(w, http.StatusConflict, "current_device")
	case errors.Is(err, messaging.ErrDeviceNotFound):
		writeAPIError(w, http.StatusNotFound, "device_not_found")
	default:
		h.internal("revoke account device failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
	}
}

func (h *deviceLinkHTTP) terminateOthers(w http.ResponseWriter, r *http.Request) {
	if err := h.store.RevokeOtherAccountDevices(r.Context(), requestPrincipal(r), h.now().UTC()); err != nil {
		h.internal("terminate other devices failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *deviceLinkHTTP) revokeCurrentDevice(w http.ResponseWriter, r *http.Request) {
	if err := h.store.RevokeCurrentDevice(r.Context(), requestPrincipal(r), h.now().UTC()); err != nil {
		h.internal("revoke current device failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *deviceLinkHTTP) secretRequest(w http.ResponseWriter, r *http.Request) (deviceLinkSecretRequest, [32]byte, bool) {
	var request deviceLinkSecretRequest
	if !decodeStrictJSON(w, r, 2048, &request) {
		return request, [32]byte{}, false
	}
	if request.Version != 1 {
		writeAPIError(w, http.StatusBadRequest, "invalid_request")
		return request, [32]byte{}, false
	}
	digest, ok := parseLinkSecret(request.Secret)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_device_link_secret")
		return request, [32]byte{}, false
	}
	return request, digest, true
}

func parseLinkSecret(encoded string) ([32]byte, bool) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) != 32 {
		clear(raw)
		return [32]byte{}, false
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	return digest, true
}

func canonicalDeviceLinkApproval(linkID, secret, approverDeviceID, identityFingerprint, encryptionFingerprint string) []byte {
	return []byte(strings.Join([]string{
		"fedmes-device-link-approval-v1", linkID, secret, approverDeviceID, identityFingerprint, encryptionFingerprint,
	}, "\n"))
}

func decodeStrictJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, target any) bool {
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		writeAPIError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || requireJSONEOF(decoder) != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

func (h *deviceLinkHTTP) writeLinkError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, messaging.ErrDeviceLinkNotFound):
		writeAPIError(w, http.StatusNotFound, "device_link_not_found")
	case errors.Is(err, messaging.ErrDeviceLinkExpired):
		writeAPIError(w, http.StatusGone, "device_link_expired")
	case errors.Is(err, messaging.ErrDeviceLinkUsed):
		writeAPIError(w, http.StatusConflict, "device_link_used")
	case errors.Is(err, messaging.ErrDeviceLinkConflict):
		writeAPIError(w, http.StatusConflict, "device_link_conflict")
	default:
		h.internal("device link operation failed", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error")
	}
}

func (h *deviceLinkHTTP) internal(message string, err error) {
	if h.logger != nil {
		h.logger.Error(message, "error_code", "internal_error", "cause", err.Error())
	}
}
