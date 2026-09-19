package httpserver

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"fedmes/server/internal/provisioning"
)

const maximumAuthenticationRequestBytes int64 = 8 << 10

type deviceAuthenticationHandler struct {
	service *provisioning.Service
	logger  *slog.Logger
	mode    authenticationHandlerMode
}

type authenticationHandlerMode int

const (
	authenticationChallengeMode authenticationHandlerMode = iota
	authenticationSessionMode
)

type authenticationChallengeRequest struct {
	Version  int              `json:"version"`
	Username string           `json:"username"`
	Device   redeemHTTPDevice `json:"device"`
	Purpose  string           `json:"purpose"`
}

type authenticationChallengeResponse struct {
	Version   int                         `json:"version"`
	Challenge authenticationHTTPChallenge `json:"challenge"`
}

type authenticationHTTPChallenge struct {
	ID        provisioning.ChallengeID      `json:"id"`
	DeviceID  provisioning.DeviceID         `json:"device_id"`
	Audience  string                        `json:"audience"`
	Purpose   provisioning.ChallengePurpose `json:"purpose"`
	Nonce     string                        `json:"nonce"`
	ExpiresAt string                        `json:"expires_at"`
}

type authenticationSessionRequest struct {
	Version     int                           `json:"version"`
	Username    string                        `json:"username"`
	DeviceID    provisioning.DeviceID         `json:"device_id"`
	ChallengeID provisioning.ChallengeID      `json:"challenge_id"`
	Nonce       string                        `json:"nonce"`
	Purpose     provisioning.ChallengePurpose `json:"purpose"`
	Signature   string                        `json:"signature"`
}

func newDeviceAuthenticationHandler(
	service *provisioning.Service,
	logger *slog.Logger,
	mode authenticationHandlerMode,
) http.Handler {
	return &deviceAuthenticationHandler{service: service, logger: logger, mode: mode}
}

func (handler *deviceAuthenticationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if handler.service == nil {
		handler.logInternal("authentication service unavailable")
		writeProtocolError(w, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeProtocolError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	audience, err := normalizeRequestAudience(r.Host)
	if err != nil {
		writeProtocolError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maximumAuthenticationRequestBytes)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	switch handler.mode {
	case authenticationChallengeMode:
		handler.issueChallenge(w, r, decoder, audience)
	case authenticationSessionMode:
		handler.createSession(w, r, decoder, audience)
	default:
		handler.logInternal("invalid authentication handler mode")
		writeProtocolError(w, http.StatusInternalServerError, "internal_error")
	}
}

func (handler *deviceAuthenticationHandler) issueChallenge(
	w http.ResponseWriter,
	r *http.Request,
	decoder *json.Decoder,
	audience string,
) {
	var request authenticationChallengeRequest
	if err := decoder.Decode(&request); err != nil {
		writeDecodeError(w, err)
		return
	}
	if err := requireJSONEOF(decoder); err != nil {
		writeDecodeError(w, err)
		return
	}
	if request.Version != 1 || request.Purpose != string(provisioning.ChallengePurposeSessionRefresh) ||
		strings.TrimSpace(request.Username) == "" || request.Device.Algorithm == "" ||
		strings.TrimSpace(request.Device.PublicKeySPKI) == "" {
		writeProtocolError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	publicKey, err := base64.StdEncoding.Strict().DecodeString(request.Device.PublicKeySPKI)
	if err != nil || len(publicKey) == 0 || len(publicKey) > 512 {
		clear(publicKey)
		writeProtocolError(w, http.StatusBadRequest, string(provisioning.CodeInvalidDeviceKey))
		return
	}
	defer clear(publicKey)
	challenge, err := handler.service.IssueSessionChallenge(r.Context(), provisioning.SessionChallengeRequest{
		Username: request.Username,
		DeviceKey: provisioning.DevicePublicKeyInput{
			Algorithm:            request.Device.Algorithm,
			SubjectPublicKeyInfo: publicKey,
		},
		Audience: audience,
		Purpose:  provisioning.ChallengePurposeSessionRefresh,
	})
	if err != nil {
		handler.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, authenticationChallengeResponse{
		Version: 1,
		Challenge: authenticationHTTPChallenge{
			ID:        challenge.ID,
			DeviceID:  challenge.DeviceID,
			Audience:  challenge.Audience,
			Purpose:   challenge.Purpose,
			Nonce:     challenge.Nonce.Reveal(),
			ExpiresAt: challenge.ExpiresAt.Format(time.RFC3339Nano),
		},
	})
}

func (handler *deviceAuthenticationHandler) createSession(
	w http.ResponseWriter,
	r *http.Request,
	decoder *json.Decoder,
	audience string,
) {
	var request authenticationSessionRequest
	if err := decoder.Decode(&request); err != nil {
		writeDecodeError(w, err)
		return
	}
	if err := requireJSONEOF(decoder); err != nil {
		writeDecodeError(w, err)
		return
	}
	if request.Version != 1 || strings.TrimSpace(request.Username) == "" || request.DeviceID == "" ||
		request.ChallengeID == "" || request.Purpose != provisioning.ChallengePurposeSessionRefresh ||
		strings.TrimSpace(request.Nonce) == "" || strings.TrimSpace(request.Signature) == "" {
		writeProtocolError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	nonce, err := provisioning.ParseInvitationToken(request.Nonce)
	if err != nil {
		writeProtocolError(w, http.StatusConflict, string(provisioning.CodeChallengeContext))
		return
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(request.Signature)
	if err != nil || len(signature) == 0 || len(signature) > 512 {
		clear(signature)
		writeProtocolError(w, http.StatusUnauthorized, string(provisioning.CodeInvalidSignature))
		return
	}
	defer clear(signature)
	result, err := handler.service.RefreshSession(r.Context(), provisioning.SessionRefreshRequest{
		Username:    request.Username,
		DeviceID:    request.DeviceID,
		ChallengeID: request.ChallengeID,
		Nonce:       nonce,
		Audience:    audience,
		Purpose:     request.Purpose,
		Signature:   signature,
	})
	if err != nil {
		handler.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, redeemHTTPResponse{
		Version: 1,
		Device:  result.Device,
		Session: redeemHTTPSession{
			ID:        result.Session.ID,
			Token:     result.Session.Token.Reveal(),
			IssuedAt:  result.Session.IssuedAt.Format(time.RFC3339Nano),
			ExpiresAt: result.Session.ExpiresAt.Format(time.RFC3339Nano),
		},
	})
}

func (handler *deviceAuthenticationHandler) writeServiceError(w http.ResponseWriter, err error) {
	if _, ok := provisioning.CodeOf(err); !ok {
		handler.logInternal("device authentication failed")
	}
	writeProvisioningError(w, err)
}

func (handler *deviceAuthenticationHandler) logInternal(message string) {
	if handler.logger != nil {
		handler.logger.Error(message, "error_code", "internal_error")
	}
}

func normalizeRequestAudience(hostValue string) (string, error) {
	if hostValue == "" || hostValue != strings.TrimSpace(hostValue) || len(hostValue) > 512 ||
		strings.ContainsAny(hostValue, "\r\n/@?#") {
		return "", errors.New("invalid host")
	}
	parsed, err := url.Parse("http://" + hostValue)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("invalid host")
	}
	port := parsed.Port()
	if strings.HasSuffix(parsed.Host, ":") {
		return "", errors.New("empty port")
	}
	if port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", errors.New("invalid port")
		}
	}
	hostname := strings.ToLower(parsed.Hostname())
	if port != "" {
		return net.JoinHostPort(hostname, port), nil
	}
	if strings.Contains(hostname, ":") {
		return "[" + hostname + "]", nil
	}
	return hostname, nil
}
