package provisioning

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"sync"
	"testing"
	"time"
)

func p256DeviceIdentity(t *testing.T) (*ecdsa.PrivateKey, DevicePublicKeyInput) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	return privateKey, DevicePublicKeyInput{
		Algorithm:            DeviceKeyECDSAP256,
		SubjectPublicKeyInfo: encoded,
	}
}

func provisionP256Device(
	t *testing.T,
	service *Service,
	username string,
) (*ecdsa.PrivateKey, DevicePublicKeyInput, RedeemResult) {
	t.Helper()
	privateKey, publicKey := p256DeviceIdentity(t)
	issued, err := service.IssueInvitation(context.Background(), username, 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueInvitation() error = %v", err)
	}
	result, err := service.RedeemInvitation(context.Background(), RedeemRequest{
		Username:  username,
		Token:     issued.Token,
		DeviceKey: publicKey,

		EncryptionKey: validMessageEncryptionInput(t),
	})
	if err != nil {
		t.Fatalf("RedeemInvitation() error = %v", err)
	}
	return privateKey, publicKey, result
}

func signedRefreshRequest(
	t *testing.T,
	privateKey *ecdsa.PrivateKey,
	username string,
	challenge IssuedChallenge,
) SessionRefreshRequest {
	t.Helper()
	payload, err := DeviceAuthenticationPayload(
		challenge.Audience,
		Username(username),
		challenge.DeviceID,
		challenge.ID,
		challenge.Purpose,
		challenge.Nonce.Reveal(),
	)
	if err != nil {
		t.Fatalf("DeviceAuthenticationPayload() error = %v", err)
	}
	defer clear(payload)
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatalf("SignASN1() error = %v", err)
	}
	return SessionRefreshRequest{
		Username:    username,
		DeviceID:    challenge.DeviceID,
		ChallengeID: challenge.ID,
		Nonce:       challenge.Nonce,
		Audience:    challenge.Audience,
		Purpose:     challenge.Purpose,
		Signature:   signature,
	}
}

func TestDeviceAuthenticationPayloadIsExactAndUnambiguous(t *testing.T) {
	payload, err := DeviceAuthenticationPayload(
		"chat.example:8443",
		UserGrisha,
		DeviceID("11111111-1111-4111-8111-111111111111"),
		ChallengeID("22222222-2222-4222-8222-222222222222"),
		ChallengePurposeSessionRefresh,
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	)
	if err != nil {
		t.Fatalf("DeviceAuthenticationPayload() error = %v", err)
	}
	want := "fedmes-device-auth-v1\nchat.example:8443\ngrisha\n11111111-1111-4111-8111-111111111111\n22222222-2222-4222-8222-222222222222\nsession.refresh\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if string(payload) != want {
		t.Fatalf("payload = %q, want %q", payload, want)
	}
	if _, err := DeviceAuthenticationPayload("chat.example\nattacker", UserGrisha, "device", "challenge", ChallengePurposeSessionRefresh, "nonce"); !errors.Is(err, ErrChallengeContext) {
		t.Fatalf("newline context error = %v, want %v", err, ErrChallengeContext)
	}
}

func TestSessionChallengeRefreshesRegisteredDevice(t *testing.T) {
	service, repository, _ := newTestService(t)
	privateKey, publicKey, provisioned := provisionP256Device(t, service, "grisha")
	challenge, err := service.IssueSessionChallenge(context.Background(), SessionChallengeRequest{
		Username:  "grisha",
		DeviceKey: publicKey,
		Audience:  "chat.example",
		Purpose:   ChallengePurposeSessionRefresh,
	})
	if err != nil {
		t.Fatalf("IssueSessionChallenge() error = %v", err)
	}
	if challenge.DeviceID != provisioned.Device.ID {
		t.Fatalf("challenge device = %s, want %s", challenge.DeviceID, provisioned.Device.ID)
	}
	request := signedRefreshRequest(t, privateKey, "grisha", challenge)
	refreshed, err := service.RefreshSession(context.Background(), request)
	if err != nil {
		t.Fatalf("RefreshSession() error = %v", err)
	}
	if refreshed.Device.ID != provisioned.Device.ID || refreshed.Session.ID == "" || refreshed.Session.Token.Reveal() == "" {
		t.Fatalf("unexpected refresh result = %+v", refreshed)
	}
	if len(repository.sessionsByID) != 2 {
		t.Fatalf("stored sessions = %d, want initial + refreshed", len(repository.sessionsByID))
	}
	if _, err := service.RefreshSession(context.Background(), request); !errors.Is(err, ErrChallengeUsed) {
		t.Fatalf("replay error = %v, want %v", err, ErrChallengeUsed)
	}
}

func TestSessionChallengeRejectsUnknownKeyExpiryAndTampering(t *testing.T) {
	service, _, clock := newTestService(t)
	privateKey, publicKey, _ := provisionP256Device(t, service, "mama")
	_, unknownKey := p256DeviceIdentity(t)
	if _, err := service.IssueSessionChallenge(context.Background(), SessionChallengeRequest{
		Username: "mama", DeviceKey: unknownKey, Audience: "chat.example", Purpose: ChallengePurposeSessionRefresh,
	}); !errors.Is(err, ErrUnknownDevice) {
		t.Fatalf("unknown key error = %v, want %v", err, ErrUnknownDevice)
	}

	challenge, err := service.IssueSessionChallenge(context.Background(), SessionChallengeRequest{
		Username: "mama", DeviceKey: publicKey, Audience: "chat.example", Purpose: ChallengePurposeSessionRefresh,
	})
	if err != nil {
		t.Fatalf("IssueSessionChallenge() error = %v", err)
	}
	request := signedRefreshRequest(t, privateKey, "mama", challenge)
	tampered := request
	tampered.Audience = "attacker.example"
	if _, err := service.RefreshSession(context.Background(), tampered); !errors.Is(err, ErrChallengeContext) {
		t.Fatalf("tampered audience error = %v, want %v", err, ErrChallengeContext)
	}
	tampered = request
	tampered.Signature = append([]byte(nil), request.Signature...)
	tampered.Signature[len(tampered.Signature)-1] ^= 0x01
	if _, err := service.RefreshSession(context.Background(), tampered); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered signature error = %v, want %v", err, ErrInvalidSignature)
	}
	clock.Advance(10 * time.Second)
	if _, err := service.RefreshSession(context.Background(), request); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("expired challenge error = %v, want %v", err, ErrChallengeExpired)
	}
}

func TestConcurrentSessionRefreshSucceedsExactlyOnce(t *testing.T) {
	service, _, _ := newTestService(t)
	privateKey, publicKey, _ := provisionP256Device(t, service, "papa")
	challenge, err := service.IssueSessionChallenge(context.Background(), SessionChallengeRequest{
		Username: "papa", DeviceKey: publicKey, Audience: "chat.example", Purpose: ChallengePurposeSessionRefresh,
	})
	if err != nil {
		t.Fatalf("IssueSessionChallenge() error = %v", err)
	}
	request := signedRefreshRequest(t, privateKey, "papa", challenge)
	const attempts = 32
	start := make(chan struct{})
	results := make(chan error, attempts)
	var waitGroup sync.WaitGroup
	waitGroup.Add(attempts)
	for index := 0; index < attempts; index++ {
		go func() {
			defer waitGroup.Done()
			<-start
			_, err := service.RefreshSession(context.Background(), request)
			results <- err
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)
	successes := 0
	used := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrChallengeUsed):
			used++
		default:
			t.Fatalf("unexpected refresh error = %v", err)
		}
	}
	if successes != 1 || used != attempts-1 {
		t.Fatalf("successes/used = %d/%d, want 1/%d", successes, used, attempts-1)
	}
}
