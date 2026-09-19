package httpserver

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"fedmes/server/internal/provisioning"
)

const maximumProvisioningRequestBytes int64 = 8 << 10

type provisioningHandler struct {
	service *provisioning.Service
	logger  *slog.Logger
}

type redeemHTTPRequest struct {
	Version        int                     `json:"version"`
	IdempotencyKey string                  `json:"idempotency_key,omitempty"`
	Username       string                  `json:"username"`
	Token          string                  `json:"token"`
	Device         redeemHTTPDevice        `json:"device"`
	Encryption     redeemHTTPEncryptionKey `json:"encryption"`
}

type redeemHTTPDevice struct {
	Algorithm     provisioning.DeviceKeyAlgorithm `json:"algorithm"`
	PublicKeySPKI string                          `json:"public_key_spki"`
}

type redeemHTTPEncryptionKey struct {
	Algorithm     string `json:"algorithm"`
	PublicKeySPKI string `json:"public_key_spki"`
}

type redeemHTTPResponse struct {
	Version             int                              `json:"version"`
	Device              provisioning.DeviceView          `json:"device"`
	Session             redeemHTTPSession                `json:"session"`
	AuthenticationState provisioning.AuthenticationState `json:"authentication_state,omitempty"`
}

type redeemHTTPSession struct {
	ID        provisioning.SessionID `json:"id"`
	Token     string                 `json:"token"`
	IssuedAt  string                 `json:"issued_at"`
	ExpiresAt string                 `json:"expires_at"`
}

type errorEnvelope struct {
	Error protocolError `json:"error"`
}

type protocolError struct {
	Code string `json:"code"`
}

func newProvisioningHandler(service *provisioning.Service, logger *slog.Logger) http.Handler {
	return &provisioningHandler{service: service, logger: logger}
}

func (handler *provisioningHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if handler.service == nil {
		handler.logger.Error("provisioning service unavailable", "error_code", "service_unavailable")
		writeProtocolError(w, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeProtocolError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maximumProvisioningRequestBytes)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request redeemHTTPRequest
	if err := decoder.Decode(&request); err != nil {
		writeDecodeError(w, err)
		return
	}
	if err := requireJSONEOF(decoder); err != nil {
		writeDecodeError(w, err)
		return
	}
	if (request.Version != 2 && request.Version != 3) ||
		(request.Version == 3 && !validHTTPIdempotencyKey(request.IdempotencyKey)) ||
		strings.TrimSpace(request.Username) == "" || strings.TrimSpace(request.Token) == "" ||
		strings.TrimSpace(string(request.Device.Algorithm)) == "" || strings.TrimSpace(request.Device.PublicKeySPKI) == "" ||
		strings.TrimSpace(request.Encryption.Algorithm) == "" || strings.TrimSpace(request.Encryption.PublicKeySPKI) == "" {
		writeProtocolError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	token, err := provisioning.ParseInvitationToken(request.Token)
	if err != nil {
		writeProvisioningError(w, err)
		return
	}
	publicKey, err := base64.StdEncoding.Strict().DecodeString(request.Device.PublicKeySPKI)
	if err != nil || len(publicKey) == 0 || len(publicKey) > 512 {
		clear(publicKey)
		writeProtocolError(w, http.StatusBadRequest, string(provisioning.CodeInvalidDeviceKey))
		return
	}
	defer clear(publicKey)
	encryptionPublicKey, err := base64.StdEncoding.Strict().DecodeString(request.Encryption.PublicKeySPKI)
	if err != nil || len(encryptionPublicKey) < 256 || len(encryptionPublicKey) > 1024 {
		clear(encryptionPublicKey)
		writeProtocolError(w, http.StatusBadRequest, string(provisioning.CodeInvalidEncryptionKey))
		return
	}
	defer clear(encryptionPublicKey)

	result, err := handler.service.RedeemInvitation(r.Context(), provisioning.RedeemRequest{
		ProtocolVersion: request.Version,
		IdempotencyKey:  request.IdempotencyKey,
		Username:        request.Username,
		Token:           token,
		DeviceKey: provisioning.DevicePublicKeyInput{
			Algorithm:            request.Device.Algorithm,
			SubjectPublicKeyInfo: publicKey,
		},
		EncryptionKey: provisioning.MessageEncryptionKeyInput{
			Algorithm:            request.Encryption.Algorithm,
			SubjectPublicKeyInfo: encryptionPublicKey,
		},
	})
	if err != nil {
		if _, ok := provisioning.CodeOf(err); !ok {
			handler.logger.Error("provisioning redemption failed", "error_code", "internal_error")
		}
		writeProvisioningError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, redeemHTTPResponse{
		Version:             request.Version,
		Device:              result.Device,
		AuthenticationState: result.AuthenticationState,
		Session: redeemHTTPSession{
			ID:        result.Session.ID,
			Token:     result.Session.Token.Reveal(),
			IssuedAt:  result.Session.IssuedAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
			ExpiresAt: result.Session.ExpiresAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
		},
	})
}

func validHTTPIdempotencyKey(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func writeDecodeError(w http.ResponseWriter, err error) {
	var maximumBytesError *http.MaxBytesError
	if errors.As(err, &maximumBytesError) {
		writeProtocolError(w, http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	writeProtocolError(w, http.StatusBadRequest, "invalid_request")
}

func writeProvisioningError(w http.ResponseWriter, err error) {
	code, ok := provisioning.CodeOf(err)
	if !ok {
		writeProtocolError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	status := http.StatusBadRequest
	switch code {
	case provisioning.CodeInvitationNotFound, provisioning.CodeUnknownDevice, provisioning.CodeChallengeNotFound:
		status = http.StatusNotFound
	case provisioning.CodeInvitationExpired, provisioning.CodeChallengeExpired:
		status = http.StatusGone
	case provisioning.CodeInvitationUsed, provisioning.CodeInvitationUser, provisioning.CodeChallengeUsed,
		provisioning.CodeChallengeContext, provisioning.CodeConflict:
		status = http.StatusConflict
	case provisioning.CodeInvalidSignature:
		status = http.StatusUnauthorized
	case provisioning.CodeEntropyUnavailable:
		status = http.StatusServiceUnavailable
	case provisioning.CodeInvariantViolation, provisioning.CodeInvalidConfiguration, provisioning.CodeEntropyCollision:
		status = http.StatusInternalServerError
	}
	writeProtocolError(w, status, string(code))
}

func writeProtocolError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, errorEnvelope{Error: protocolError{Code: code}})
}
