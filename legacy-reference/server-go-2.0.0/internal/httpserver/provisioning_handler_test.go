package httpserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"fedmes/server/internal/provisioning"
)

type handlerTestClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *handlerTestClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *handlerTestClock) advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}

func newHandlerTestService(t *testing.T) (*provisioning.Service, *handlerTestClock) {
	t.Helper()
	clock := &handlerTestClock{now: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)}
	service, err := provisioning.NewService(provisioning.NewInMemoryRepository(), clock, provisioning.CryptoEntropy{}, provisioning.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service, clock
}

func handlerTestSPKI(t *testing.T) []byte {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	return spki
}

func handlerTestEncryptionKey(t *testing.T) provisioning.MessageEncryptionKeyInput {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("Generate RSA key error = %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Marshal RSA public key error = %v", err)
	}
	return provisioning.MessageEncryptionKeyInput{
		Algorithm:            provisioning.MessageEncryptionAlgorithmRSAOAEP256,
		SubjectPublicKeyInfo: spki,
	}
}

func redeemJSON(t *testing.T, username, token string, spki []byte) []byte {
	t.Helper()
	encryption := handlerTestEncryptionKey(t)
	value, err := json.Marshal(redeemHTTPRequest{
		Version:  2,
		Username: username,
		Token:    token,
		Device: redeemHTTPDevice{
			Algorithm:     provisioning.DeviceKeyEd25519,
			PublicKeySPKI: base64.StdEncoding.EncodeToString(spki),
		},
		Encryption: redeemHTTPEncryptionKey{
			Algorithm:     provisioning.MessageEncryptionAlgorithmRSAOAEP256,
			PublicKeySPKI: base64.StdEncoding.EncodeToString(encryption.SubjectPublicKeyInfo),
		},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return value
}

func performRedeem(handler http.Handler, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/provisioning/redeem", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func responseErrorCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var envelope errorEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error response %q: %v", recorder.Body.String(), err)
	}
	return envelope.Error.Code
}

func TestProvisioningHandlerReturnsInitialShortSession(t *testing.T) {
	service, _ := newHandlerTestService(t)
	issued, err := service.IssueInvitation(t.Context(), "grisha", 10*time.Minute)
	if err != nil {
		t.Fatalf("IssueInvitation() error = %v", err)
	}
	handler := newProvisioningHandler(service, slog.New(slog.NewTextHandler(io.Discard, nil)))
	recorder := performRedeem(handler, redeemJSON(t, "grisha", issued.Token.Reveal(), handlerTestSPKI(t)))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response redeemHTTPResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Version != 2 || response.Device.Username != provisioning.UserGrisha || response.Session.ID == "" {
		t.Fatalf("unexpected response = %+v", response)
	}
	rawSessionToken, err := base64.RawURLEncoding.Strict().DecodeString(response.Session.Token)
	if err != nil {
		t.Fatalf("decode session token: %v", err)
	}
	defer clear(rawSessionToken)
	if len(rawSessionToken) != 32 {
		t.Fatalf("session token bytes = %d, want 32", len(rawSessionToken))
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, response.Session.IssuedAt)
	if err != nil {
		t.Fatalf("parse issued_at: %v", err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, response.Session.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expires_at: %v", err)
	}
	if expiresAt.Sub(issuedAt) != 15*time.Minute {
		t.Fatalf("session TTL = %s, want 15m", expiresAt.Sub(issuedAt))
	}
}

func TestProvisioningHandlerRejectsUsedExpiredAndWrongUserInvitations(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Run("used", func(t *testing.T) {
		service, _ := newHandlerTestService(t)
		issued, _ := service.IssueInvitation(t.Context(), "grisha", 10*time.Minute)
		handler := newProvisioningHandler(service, logger)
		body := redeemJSON(t, "grisha", issued.Token.Reveal(), handlerTestSPKI(t))
		if first := performRedeem(handler, body); first.Code != http.StatusCreated {
			t.Fatalf("first status = %d", first.Code)
		}
		second := performRedeem(handler, body)
		if second.Code != http.StatusConflict || responseErrorCode(t, second) != string(provisioning.CodeInvitationUsed) {
			t.Fatalf("second status/code = %d/%s", second.Code, responseErrorCode(t, second))
		}
	})
	t.Run("expired", func(t *testing.T) {
		service, clock := newHandlerTestService(t)
		issued, _ := service.IssueInvitation(t.Context(), "mama", time.Minute)
		clock.advance(time.Minute)
		recorder := performRedeem(newProvisioningHandler(service, logger), redeemJSON(t, "mama", issued.Token.Reveal(), handlerTestSPKI(t)))
		if recorder.Code != http.StatusGone || responseErrorCode(t, recorder) != string(provisioning.CodeInvitationExpired) {
			t.Fatalf("status/code = %d/%s", recorder.Code, responseErrorCode(t, recorder))
		}
	})
	t.Run("wrong user", func(t *testing.T) {
		service, _ := newHandlerTestService(t)
		issued, _ := service.IssueInvitation(t.Context(), "yura", time.Minute)
		recorder := performRedeem(newProvisioningHandler(service, logger), redeemJSON(t, "vasya", issued.Token.Reveal(), handlerTestSPKI(t)))
		if recorder.Code != http.StatusConflict || responseErrorCode(t, recorder) != string(provisioning.CodeInvitationUser) {
			t.Fatalf("status/code = %d/%s", recorder.Code, responseErrorCode(t, recorder))
		}
	})
}

func TestProvisioningHandlerEnforcesBoundedStrictJSON(t *testing.T) {
	service, _ := newHandlerTestService(t)
	handler := newProvisioningHandler(service, slog.New(slog.NewTextHandler(io.Discard, nil)))
	tests := []struct {
		name       string
		body       []byte
		wantStatus int
		wantCode   string
	}{
		{name: "unknown field", body: []byte(`{"version":2,"username":"grisha","token":"value","device":{"algorithm":"ed25519","public_key_spki":"value"},"encryption":{"algorithm":"rsa-oaep-sha256","public_key_spki":"value"},"extra":true}`), wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "trailing JSON", body: []byte(`{"version":2} {"version":2}`), wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "too large", body: []byte(`{"version":2,"username":"grisha","token":"` + strings.Repeat("a", int(maximumProvisioningRequestBytes)+1) + `","device":{"algorithm":"ed25519","public_key_spki":"value"},"encryption":{"algorithm":"rsa-oaep-sha256","public_key_spki":"value"}}`), wantStatus: http.StatusRequestEntityTooLarge, wantCode: "request_too_large"},
		{name: "unsupported version", body: []byte(`{"version":1,"username":"grisha","token":"value","device":{"algorithm":"ed25519","public_key_spki":"value"}}`), wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := performRedeem(handler, test.body)
			if recorder.Code != test.wantStatus || responseErrorCode(t, recorder) != test.wantCode {
				t.Fatalf("status/code = %d/%s, want %d/%s", recorder.Code, responseErrorCode(t, recorder), test.wantStatus, test.wantCode)
			}
		})
	}
}

func TestProvisioningHandlerRejectsMalformedDeviceKeyWithStableError(t *testing.T) {
	service, _ := newHandlerTestService(t)
	issued, _ := service.IssueInvitation(t.Context(), "papa", time.Minute)
	body := redeemJSON(t, "papa", issued.Token.Reveal(), []byte("not-a-key"))
	recorder := performRedeem(newProvisioningHandler(service, slog.New(slog.NewTextHandler(io.Discard, nil))), body)
	if recorder.Code != http.StatusBadRequest || responseErrorCode(t, recorder) != string(provisioning.CodeInvalidDeviceKey) {
		t.Fatalf("status/code = %d/%s", recorder.Code, responseErrorCode(t, recorder))
	}
}

func TestIPRateLimiterUsesRemoteAddressAndBoundsEntries(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	limiter := newIPRateLimiter(2, time.Minute, 2, func() time.Time { return now })
	nextCalls := 0
	handler := limiter.middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalls++
		w.WriteHeader(http.StatusNoContent)
	}))
	for attempt := 0; attempt < 3; attempt++ {
		request := httptest.NewRequest(http.MethodPost, "/", nil)
		request.RemoteAddr = "192.0.2.10:1234"
		request.Header.Set("X-Forwarded-For", "198.51.100.99")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if attempt < 2 && recorder.Code != http.StatusNoContent {
			t.Fatalf("attempt %d status = %d", attempt, recorder.Code)
		}
		if attempt == 2 && (recorder.Code != http.StatusTooManyRequests || responseErrorCode(t, recorder) != "rate_limited") {
			t.Fatalf("limited status/code = %d/%s", recorder.Code, responseErrorCode(t, recorder))
		}
	}
	if nextCalls != 2 {
		t.Fatalf("next calls = %d, want 2", nextCalls)
	}
	if !limiter.allow("192.0.2.11") || !limiter.allow("192.0.2.12") {
		t.Fatal("new IPs should be admitted")
	}
	if len(limiter.entries) > 2 {
		t.Fatalf("limiter entries = %d, want at most 2", len(limiter.entries))
	}
	now = now.Add(time.Minute)
	if !limiter.allow("192.0.2.10") {
		t.Fatal("expired rate-limit window was not reset")
	}
}

func TestProvisioningHandlerV3ReplaysCommittedRegistration(t *testing.T) {
	service, _ := newHandlerTestService(t)
	issued, err := service.IssueInvitation(t.Context(), "grisha", 10*time.Minute)
	if err != nil {
		t.Fatalf("IssueInvitation() error = %v", err)
	}
	spki := handlerTestSPKI(t)
	encryption := handlerTestEncryptionKey(t)
	body, err := json.Marshal(redeemHTTPRequest{
		Version:        3,
		IdempotencyKey: "registration-handler-attempt-0001",
		Username:       "grisha",
		Token:          issued.Token.Reveal(),
		Device: redeemHTTPDevice{
			Algorithm:     provisioning.DeviceKeyEd25519,
			PublicKeySPKI: base64.StdEncoding.EncodeToString(spki),
		},
		Encryption: redeemHTTPEncryptionKey{
			Algorithm:     provisioning.MessageEncryptionAlgorithmRSAOAEP256,
			PublicKeySPKI: base64.StdEncoding.EncodeToString(encryption.SubjectPublicKeyInfo),
		},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	handler := newProvisioningHandler(service, slog.New(slog.NewTextHandler(io.Discard, nil)))
	first := performRedeem(handler, body)
	second := performRedeem(handler, body)
	if first.Code != http.StatusCreated || second.Code != http.StatusCreated {
		t.Fatalf("statuses = %d/%d, bodies = %s / %s", first.Code, second.Code, first.Body.String(), second.Body.String())
	}
	var firstResponse, secondResponse redeemHTTPResponse
	if err := json.Unmarshal(first.Body.Bytes(), &firstResponse); err != nil {
		t.Fatalf("decode first response: %v", err)
	}
	if err := json.Unmarshal(second.Body.Bytes(), &secondResponse); err != nil {
		t.Fatalf("decode second response: %v", err)
	}
	if firstResponse.Version != 3 || firstResponse.AuthenticationState != provisioning.AuthenticationStateReady {
		t.Fatalf("unexpected v3 response = %+v", firstResponse)
	}
	if firstResponse.Device.ID != secondResponse.Device.ID || firstResponse.Session.ID != secondResponse.Session.ID || firstResponse.Session.Token != secondResponse.Session.Token {
		t.Fatalf("replayed response differs: first=%+v second=%+v", firstResponse, secondResponse)
	}
}
