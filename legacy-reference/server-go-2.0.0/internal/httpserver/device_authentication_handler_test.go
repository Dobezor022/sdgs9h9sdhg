package httpserver

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fedmes/server/internal/provisioning"
)

func authenticationTestIdentity(t *testing.T) (*ecdsa.PrivateKey, provisioning.DevicePublicKeyInput) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	return privateKey, provisioning.DevicePublicKeyInput{
		Algorithm:            provisioning.DeviceKeyECDSAP256,
		SubjectPublicKeyInfo: spki,
	}
}

func performAuthenticationRequest(
	handler http.Handler,
	host string,
	body []byte,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://"+host+"/", bytes.NewReader(body))
	request.Host = host
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestDeviceAuthenticationHandlersRefreshSessionAndRejectReplay(t *testing.T) {
	service, _ := newHandlerTestService(t)
	privateKey, publicKey := authenticationTestIdentity(t)
	issued, err := service.IssueInvitation(t.Context(), "grisha", 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueInvitation() error = %v", err)
	}
	provisioned, err := service.RedeemInvitation(t.Context(), provisioning.RedeemRequest{
		Username: "grisha", Token: issued.Token, DeviceKey: publicKey,

		EncryptionKey: handlerTestEncryptionKey(t),
	})
	if err != nil {
		t.Fatalf("RedeemInvitation() error = %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	challengeHandler := newDeviceAuthenticationHandler(service, logger, authenticationChallengeMode)
	challengeBody, err := json.Marshal(authenticationChallengeRequest{
		Version:  1,
		Username: "grisha",
		Device: redeemHTTPDevice{
			Algorithm:     publicKey.Algorithm,
			PublicKeySPKI: base64.StdEncoding.EncodeToString(publicKey.SubjectPublicKeyInfo),
		},
		Purpose: string(provisioning.ChallengePurposeSessionRefresh),
	})
	if err != nil {
		t.Fatalf("Marshal(challenge) error = %v", err)
	}
	challengeRecorder := performAuthenticationRequest(challengeHandler, "chat.example:8443", challengeBody)
	if challengeRecorder.Code != http.StatusCreated {
		t.Fatalf("challenge status/body = %d/%s", challengeRecorder.Code, challengeRecorder.Body.String())
	}
	var challengeResponse authenticationChallengeResponse
	if err := json.Unmarshal(challengeRecorder.Body.Bytes(), &challengeResponse); err != nil {
		t.Fatalf("decode challenge response: %v", err)
	}
	challenge := challengeResponse.Challenge
	if challenge.DeviceID != provisioned.Device.ID || challenge.Audience != "chat.example:8443" || challenge.Purpose != provisioning.ChallengePurposeSessionRefresh {
		t.Fatalf("unexpected challenge = %+v", challenge)
	}
	payload, err := provisioning.DeviceAuthenticationPayload(
		challenge.Audience,
		provisioning.UserGrisha,
		challenge.DeviceID,
		challenge.ID,
		challenge.Purpose,
		challenge.Nonce,
	)
	if err != nil {
		t.Fatalf("DeviceAuthenticationPayload() error = %v", err)
	}
	digest := sha256.Sum256(payload)
	clear(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatalf("SignASN1() error = %v", err)
	}
	sessionBody, err := json.Marshal(authenticationSessionRequest{
		Version:     1,
		Username:    "grisha",
		DeviceID:    challenge.DeviceID,
		ChallengeID: challenge.ID,
		Nonce:       challenge.Nonce,
		Purpose:     challenge.Purpose,
		Signature:   base64.StdEncoding.EncodeToString(signature),
	})
	clear(signature)
	if err != nil {
		t.Fatalf("Marshal(session) error = %v", err)
	}
	sessionHandler := newDeviceAuthenticationHandler(service, logger, authenticationSessionMode)
	sessionRecorder := performAuthenticationRequest(sessionHandler, "chat.example:8443", sessionBody)
	if sessionRecorder.Code != http.StatusCreated {
		t.Fatalf("session status/body = %d/%s", sessionRecorder.Code, sessionRecorder.Body.String())
	}
	var sessionResponse redeemHTTPResponse
	if err := json.Unmarshal(sessionRecorder.Body.Bytes(), &sessionResponse); err != nil {
		t.Fatalf("decode session response: %v", err)
	}
	if sessionResponse.Device.ID != provisioned.Device.ID || sessionResponse.Session.ID == "" || sessionResponse.Session.Token == "" {
		t.Fatalf("unexpected session response = %+v", sessionResponse)
	}
	replay := performAuthenticationRequest(sessionHandler, "chat.example:8443", sessionBody)
	if replay.Code != http.StatusConflict || responseErrorCode(t, replay) != string(provisioning.CodeChallengeUsed) {
		t.Fatalf("replay status/code = %d/%s", replay.Code, responseErrorCode(t, replay))
	}
}

func TestDeviceAuthenticationHandlerRejectsWrongAudienceAndStrictJSON(t *testing.T) {
	service, _ := newHandlerTestService(t)
	privateKey, publicKey := authenticationTestIdentity(t)
	issued, _ := service.IssueInvitation(t.Context(), "papa", 5*time.Minute)
	_, err := service.RedeemInvitation(t.Context(), provisioning.RedeemRequest{
		Username: "papa", Token: issued.Token, DeviceKey: publicKey,

		EncryptionKey: handlerTestEncryptionKey(t),
	})
	if err != nil {
		t.Fatalf("RedeemInvitation() error = %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	challengeHandler := newDeviceAuthenticationHandler(service, logger, authenticationChallengeMode)
	challengeBody := []byte(`{"version":1,"username":"papa","device":{"algorithm":"ecdsa-p256-sha256","public_key_spki":"` + base64.StdEncoding.EncodeToString(publicKey.SubjectPublicKeyInfo) + `"},"purpose":"session.refresh"}`)
	challengeRecorder := performAuthenticationRequest(challengeHandler, "chat.example", challengeBody)
	if challengeRecorder.Code != http.StatusCreated {
		t.Fatalf("challenge status/body = %d/%s", challengeRecorder.Code, challengeRecorder.Body.String())
	}
	var challengeResponse authenticationChallengeResponse
	if err := json.Unmarshal(challengeRecorder.Body.Bytes(), &challengeResponse); err != nil {
		t.Fatalf("decode challenge response: %v", err)
	}
	challenge := challengeResponse.Challenge
	payload, _ := provisioning.DeviceAuthenticationPayload(
		challenge.Audience, provisioning.UserPapa, challenge.DeviceID, challenge.ID, challenge.Purpose, challenge.Nonce,
	)
	digest := sha256.Sum256(payload)
	clear(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatalf("SignASN1() error = %v", err)
	}
	sessionBody, _ := json.Marshal(authenticationSessionRequest{
		Version: 1, Username: "papa", DeviceID: challenge.DeviceID, ChallengeID: challenge.ID,
		Nonce: challenge.Nonce, Purpose: challenge.Purpose, Signature: base64.StdEncoding.EncodeToString(signature),
	})
	clear(signature)
	sessionHandler := newDeviceAuthenticationHandler(service, logger, authenticationSessionMode)
	wrongAudience := performAuthenticationRequest(sessionHandler, "attacker.example", sessionBody)
	if wrongAudience.Code != http.StatusConflict || responseErrorCode(t, wrongAudience) != string(provisioning.CodeChallengeContext) {
		t.Fatalf("wrong audience status/code = %d/%s", wrongAudience.Code, responseErrorCode(t, wrongAudience))
	}

	unknownField := performAuthenticationRequest(
		challengeHandler,
		"chat.example",
		[]byte(`{"version":1,"username":"papa","device":{},"purpose":"session.refresh","extra":true}`),
	)
	if unknownField.Code != http.StatusBadRequest || responseErrorCode(t, unknownField) != "invalid_request" {
		t.Fatalf("unknown field status/code = %d/%s", unknownField.Code, responseErrorCode(t, unknownField))
	}
	oversized := performAuthenticationRequest(
		challengeHandler,
		"chat.example",
		[]byte(`{"version":1,"username":"`+strings.Repeat("a", int(maximumAuthenticationRequestBytes)+1)+`"}`),
	)
	if oversized.Code != http.StatusRequestEntityTooLarge || responseErrorCode(t, oversized) != "request_too_large" {
		t.Fatalf("oversized status/code = %d/%s", oversized.Code, responseErrorCode(t, oversized))
	}
}

func TestNormalizeRequestAudience(t *testing.T) {
	tests := []struct {
		input string
		want  string
		err   bool
	}{
		{input: "CHAT.EXAMPLE", want: "chat.example"},
		{input: "CHAT.EXAMPLE:8443", want: "chat.example:8443"},
		{input: "[FD00::1]:8008", want: "[fd00::1]:8008"},
		{input: "chat.example:0", err: true},
		{input: "chat.example:", err: true},
		{input: "user@chat.example", err: true},
		{input: "chat.example/path", err: true},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := normalizeRequestAudience(test.input)
			if test.err {
				if err == nil {
					t.Fatalf("normalizeRequestAudience() = %q, want error", got)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("normalizeRequestAudience() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}
