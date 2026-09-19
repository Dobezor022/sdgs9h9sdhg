package provisioning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixedClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *fixedClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *fixedClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}

func newTestService(t *testing.T) (*Service, *InMemoryRepository, *fixedClock) {
	t.Helper()
	repository := NewInMemoryRepository()
	clock := &fixedClock{now: time.Date(2026, time.July, 10, 12, 0, 0, 0, time.UTC)}
	service, err := NewService(repository, clock, CryptoEntropy{}, DefaultConfig())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service, repository, clock
}

func validEd25519Input(t *testing.T) DevicePublicKeyInput {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	return DevicePublicKeyInput{
		Algorithm:            DeviceKeyEd25519,
		SubjectPublicKeyInfo: encoded,
	}
}

func validMessageEncryptionInput(t *testing.T) MessageEncryptionKeyInput {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("Generate RSA key error = %v", err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Marshal RSA public key error = %v", err)
	}
	return MessageEncryptionKeyInput{
		Algorithm:            MessageEncryptionAlgorithmRSAOAEP256,
		SubjectPublicKeyInfo: encoded,
	}
}

func issueForGrisha(t *testing.T, service *Service, ttl time.Duration) IssuedInvitation {
	t.Helper()
	issued, err := service.IssueInvitation(context.Background(), string(UserGrisha), ttl)
	if err != nil {
		t.Fatalf("IssueInvitation() error = %v", err)
	}
	return issued
}

func TestInvitationTokenContainsAtLeastThirtyTwoRandomBytes(t *testing.T) {
	service, _, _ := newTestService(t)
	issued := issueForGrisha(t, service, 5*time.Minute)
	raw, err := base64.RawURLEncoding.Strict().DecodeString(issued.Token.Reveal())
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	defer clear(raw)
	if len(raw) < MinimumTokenBytes {
		t.Fatalf("decoded token length = %d, want at least %d", len(raw), MinimumTokenBytes)
	}
}

func TestConcurrentRedemptionSucceedsExactlyOnce(t *testing.T) {
	service, repository, _ := newTestService(t)
	issued := issueForGrisha(t, service, 5*time.Minute)
	request := RedeemRequest{
		Username:  string(UserGrisha),
		Token:     issued.Token,
		DeviceKey: validEd25519Input(t),

		EncryptionKey: validMessageEncryptionInput(t),
	}

	const attempts = 64
	start := make(chan struct{})
	results := make(chan error, attempts)
	var waitGroup sync.WaitGroup
	waitGroup.Add(attempts)
	for index := 0; index < attempts; index++ {
		go func() {
			defer waitGroup.Done()
			<-start
			_, err := service.RedeemInvitation(context.Background(), request)
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
		case errors.Is(err, ErrInvitationUsed):
			used++
		default:
			t.Fatalf("unexpected redemption error = %v", err)
		}
	}
	if successes != 1 || used != attempts-1 {
		t.Fatalf("successes = %d, used = %d; want 1 and %d", successes, used, attempts-1)
	}
	snapshot := repository.Snapshot()
	if len(snapshot.Invitations) != 1 || len(snapshot.Devices) != 1 {
		t.Fatalf("snapshot counts = invitations:%d devices:%d, want 1 and 1", len(snapshot.Invitations), len(snapshot.Devices))
	}
}

func TestExpiredInvitationIsRejected(t *testing.T) {
	service, repository, clock := newTestService(t)
	issued := issueForGrisha(t, service, time.Minute)
	clock.Advance(time.Minute)

	_, err := service.RedeemInvitation(context.Background(), RedeemRequest{
		Username:  string(UserGrisha),
		Token:     issued.Token,
		DeviceKey: validEd25519Input(t),

		EncryptionKey: validMessageEncryptionInput(t),
	})
	if !errors.Is(err, ErrInvitationExpired) {
		t.Fatalf("RedeemInvitation() error = %v, want %v", err, ErrInvitationExpired)
	}
	if devices := repository.Snapshot().Devices; len(devices) != 0 {
		t.Fatalf("stored devices = %d, want 0", len(devices))
	}
}

func TestWrongUserDoesNotConsumeInvitation(t *testing.T) {
	service, _, _ := newTestService(t)
	issued := issueForGrisha(t, service, 5*time.Minute)
	key := validEd25519Input(t)

	_, err := service.RedeemInvitation(context.Background(), RedeemRequest{
		Username:  string(UserPapa),
		Token:     issued.Token,
		DeviceKey: key,

		EncryptionKey: validMessageEncryptionInput(t),
	})
	if !errors.Is(err, ErrInvitationUser) {
		t.Fatalf("wrong-user error = %v, want %v", err, ErrInvitationUser)
	}
	if _, err := service.RedeemInvitation(context.Background(), RedeemRequest{
		Username:  string(UserGrisha),
		Token:     issued.Token,
		DeviceKey: key,

		EncryptionKey: validMessageEncryptionInput(t),
	}); err != nil {
		t.Fatalf("valid redemption after wrong user error = %v", err)
	}
}

func TestUsedInvitationIsRejected(t *testing.T) {
	service, _, _ := newTestService(t)
	issued := issueForGrisha(t, service, 5*time.Minute)
	request := RedeemRequest{
		Username:  string(UserGrisha),
		Token:     issued.Token,
		DeviceKey: validEd25519Input(t),

		EncryptionKey: validMessageEncryptionInput(t),
	}
	if _, err := service.RedeemInvitation(context.Background(), request); err != nil {
		t.Fatalf("first redemption error = %v", err)
	}
	if _, err := service.RedeemInvitation(context.Background(), request); !errors.Is(err, ErrInvitationUsed) {
		t.Fatalf("second redemption error = %v, want %v", err, ErrInvitationUsed)
	}
}

func TestNewestInvitationInvalidatesOlderQRAndSameDeviceIsRebound(t *testing.T) {
	service, repository, _ := newTestService(t)
	first := issueForGrisha(t, service, 5*time.Minute)
	second := issueForGrisha(t, service, 5*time.Minute)
	identity := validEd25519Input(t)
	encryption := validMessageEncryptionInput(t)

	if _, err := service.RedeemInvitation(context.Background(), RedeemRequest{
		Username:      string(UserGrisha),
		Token:         first.Token,
		DeviceKey:     identity,
		EncryptionKey: encryption,
	}); !errors.Is(err, ErrInvitationNotFound) {
		t.Fatalf("older QR error = %v, want %v", err, ErrInvitationNotFound)
	}
	firstLogin, err := service.RedeemInvitation(context.Background(), RedeemRequest{
		Username:      string(UserGrisha),
		Token:         second.Token,
		DeviceKey:     identity,
		EncryptionKey: encryption,
	})
	if err != nil {
		t.Fatalf("newest QR redemption error = %v", err)
	}

	third := issueForGrisha(t, service, 5*time.Minute)
	secondLogin, err := service.RedeemInvitation(context.Background(), RedeemRequest{
		Username:      string(UserGrisha),
		Token:         third.Token,
		DeviceKey:     identity,
		EncryptionKey: encryption,
	})
	if err != nil {
		t.Fatalf("replacement QR redemption error = %v", err)
	}
	if secondLogin.Device.ID != firstLogin.Device.ID {
		t.Fatalf("replacement device ID = %s, want reused %s", secondLogin.Device.ID, firstLogin.Device.ID)
	}
	snapshot := repository.Snapshot()
	if len(snapshot.Devices) != 1 || snapshot.Devices[0].RevokedAt != nil {
		t.Fatalf("replacement device state = %+v", snapshot.Devices)
	}
}

func TestMalformedDeviceKeyDoesNotConsumeInvitation(t *testing.T) {
	service, _, _ := newTestService(t)
	issued := issueForGrisha(t, service, 5*time.Minute)

	_, err := service.RedeemInvitation(context.Background(), RedeemRequest{
		Username: string(UserGrisha),
		Token:    issued.Token,
		DeviceKey: DevicePublicKeyInput{
			Algorithm:            DeviceKeyEd25519,
			SubjectPublicKeyInfo: []byte("not-a-public-key"),
		},

		EncryptionKey: validMessageEncryptionInput(t),
	})
	if !errors.Is(err, ErrInvalidDeviceKey) {
		t.Fatalf("malformed-key error = %v, want %v", err, ErrInvalidDeviceKey)
	}
	if _, err := service.RedeemInvitation(context.Background(), RedeemRequest{
		Username:  string(UserGrisha),
		Token:     issued.Token,
		DeviceKey: validEd25519Input(t),

		EncryptionKey: validMessageEncryptionInput(t),
	}); err != nil {
		t.Fatalf("valid redemption after malformed key error = %v", err)
	}
}

func TestRepositoryPersistsDigestOnlyAndRecordsAreRedacted(t *testing.T) {
	service, repository, _ := newTestService(t)
	issued := issueForGrisha(t, service, 5*time.Minute)
	encodedToken := issued.Token.Reveal()
	rawToken, err := base64.RawURLEncoding.Strict().DecodeString(encodedToken)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	defer clear(rawToken)
	expectedDigest := TokenDigest(sha256.Sum256(rawToken))

	repository.mu.RLock()
	if len(repository.invitationsByDigest) != 1 {
		repository.mu.RUnlock()
		t.Fatalf("stored invitation count = %d, want 1", len(repository.invitationsByDigest))
	}
	stored, exists := repository.invitationsByDigest[expectedDigest]
	repository.mu.RUnlock()
	if !exists {
		t.Fatal("repository did not index invitation by SHA-256 token digest")
	}
	if stored.TokenDigest != expectedDigest {
		t.Fatal("stored digest differs from expected SHA-256 digest")
	}

	snapshotJSON, err := json.Marshal(repository.Snapshot())
	if err != nil {
		t.Fatalf("Marshal(snapshot) error = %v", err)
	}
	issuedJSON, err := json.Marshal(issued)
	if err != nil {
		t.Fatalf("Marshal(issued) error = %v", err)
	}
	for label, value := range map[string][]byte{
		"snapshot JSON": snapshotJSON,
		"issued JSON":   issuedJSON,
		"record string": []byte(stored.String()),
	} {
		if bytes.Contains(value, []byte(encodedToken)) {
			t.Fatalf("%s contains raw invitation token", label)
		}
	}
	if !strings.Contains(string(issuedJSON), "[REDACTED]") {
		t.Fatalf("issued JSON = %s, want redaction marker", issuedJSON)
	}
}

func TestUnknownUserAndInvalidConfigurationHaveStableCodes(t *testing.T) {
	service, _, _ := newTestService(t)
	_, err := service.IssueInvitation(context.Background(), "Grisha", time.Minute)
	if !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("IssueInvitation() error = %v, want %v", err, ErrUnknownUser)
	}
	if code, ok := CodeOf(err); !ok || code != CodeUnknownUser {
		t.Fatalf("CodeOf(error) = %q, %t; want %q, true", code, ok, CodeUnknownUser)
	}

	config := DefaultConfig()
	config.TokenBytes = MinimumTokenBytes - 1
	_, err = NewService(NewInMemoryRepository(), &fixedClock{now: time.Now()}, CryptoEntropy{}, config)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("NewService() error = %v, want %v", err, ErrInvalidConfiguration)
	}
}

func TestMalformedEncryptionKeyDoesNotConsumeInvitation(t *testing.T) {
	service, _, _ := newTestService(t)
	issued := issueForGrisha(t, service, 5*time.Minute)
	identity := validEd25519Input(t)

	_, err := service.RedeemInvitation(context.Background(), RedeemRequest{
		Username:  string(UserGrisha),
		Token:     issued.Token,
		DeviceKey: identity,
		EncryptionKey: MessageEncryptionKeyInput{
			Algorithm:            MessageEncryptionAlgorithmRSAOAEP256,
			SubjectPublicKeyInfo: []byte("not-a-public-key"),
		},
	})
	if !errors.Is(err, ErrInvalidEncryptionKey) {
		t.Fatalf("malformed encryption key error = %v, want %v", err, ErrInvalidEncryptionKey)
	}
	if _, err := service.RedeemInvitation(context.Background(), RedeemRequest{
		Username:      string(UserGrisha),
		Token:         issued.Token,
		DeviceKey:     identity,
		EncryptionKey: validMessageEncryptionInput(t),
	}); err != nil {
		t.Fatalf("valid redemption after malformed encryption key = %v", err)
	}
}

func TestRegistrationIdempotencyReturnsCommittedResult(t *testing.T) {
	service, repository, _ := newTestService(t)
	issued := issueForGrisha(t, service, 5*time.Minute)
	request := RedeemRequest{
		ProtocolVersion: 3,
		IdempotencyKey:  "registration-attempt-00000001",
		Username:        string(UserGrisha),
		Token:           issued.Token,
		DeviceKey:       validEd25519Input(t),
		EncryptionKey:   validMessageEncryptionInput(t),
	}

	first, err := service.RedeemInvitation(context.Background(), request)
	if err != nil {
		t.Fatalf("first redemption error = %v", err)
	}
	second, err := service.RedeemInvitation(context.Background(), request)
	if err != nil {
		t.Fatalf("idempotent replay error = %v", err)
	}
	if second.Device.ID != first.Device.ID || second.Session.ID != first.Session.ID {
		t.Fatalf("replayed IDs = device:%s session:%s, want device:%s session:%s", second.Device.ID, second.Session.ID, first.Device.ID, first.Session.ID)
	}
	if second.Session.Token.Reveal() != first.Session.Token.Reveal() {
		t.Fatal("idempotent replay returned a different session token")
	}
	if second.AuthenticationState != AuthenticationStateReady {
		t.Fatalf("authentication state = %q, want %q", second.AuthenticationState, AuthenticationStateReady)
	}
	snapshot := repository.Snapshot()
	if len(snapshot.Devices) != 1 {
		t.Fatalf("device count = %d, want 1", len(snapshot.Devices))
	}
}

func TestConcurrentIdempotentRegistrationCreatesOneDeviceAndOneSession(t *testing.T) {
	service, repository, _ := newTestService(t)
	issued := issueForGrisha(t, service, 5*time.Minute)
	request := RedeemRequest{
		ProtocolVersion: 3,
		IdempotencyKey:  "registration-attempt-concurrent-01",
		Username:        string(UserGrisha),
		Token:           issued.Token,
		DeviceKey:       validEd25519Input(t),
		EncryptionKey:   validMessageEncryptionInput(t),
	}

	const attempts = 32
	start := make(chan struct{})
	results := make(chan RedeemResult, attempts)
	errorsChannel := make(chan error, attempts)
	var waitGroup sync.WaitGroup
	waitGroup.Add(attempts)
	for index := 0; index < attempts; index++ {
		go func() {
			defer waitGroup.Done()
			<-start
			result, err := service.RedeemInvitation(context.Background(), request)
			results <- result
			errorsChannel <- err
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)
	close(errorsChannel)

	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("concurrent idempotent registration error = %v", err)
		}
	}
	var expected RedeemResult
	for result := range results {
		if expected.Device.ID == "" {
			expected = result
			continue
		}
		if result.Device.ID != expected.Device.ID || result.Session.ID != expected.Session.ID || result.Session.Token.Reveal() != expected.Session.Token.Reveal() {
			t.Fatalf("concurrent replay returned different result: got device:%s session:%s, want device:%s session:%s", result.Device.ID, result.Session.ID, expected.Device.ID, expected.Session.ID)
		}
	}
	snapshot := repository.Snapshot()
	if len(snapshot.Devices) != 1 {
		t.Fatalf("device count = %d, want 1", len(snapshot.Devices))
	}
	repository.mu.RLock()
	sessionCount := len(repository.sessionsByID)
	attemptCount := len(repository.registrationAttempts)
	repository.mu.RUnlock()
	if sessionCount != 1 || attemptCount != 1 {
		t.Fatalf("session count = %d, attempt count = %d; want 1 and 1", sessionCount, attemptCount)
	}
}

func TestRegistrationIdempotencyRejectsChangedRequest(t *testing.T) {
	service, _, _ := newTestService(t)
	issued := issueForGrisha(t, service, 5*time.Minute)
	request := RedeemRequest{
		ProtocolVersion: 3,
		IdempotencyKey:  "registration-attempt-00000002",
		Username:        string(UserGrisha),
		Token:           issued.Token,
		DeviceKey:       validEd25519Input(t),
		EncryptionKey:   validMessageEncryptionInput(t),
	}
	if _, err := service.RedeemInvitation(context.Background(), request); err != nil {
		t.Fatalf("first redemption error = %v", err)
	}
	request.EncryptionKey = validMessageEncryptionInput(t)
	if _, err := service.RedeemInvitation(context.Background(), request); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed request error = %v, want %v", err, ErrConflict)
	}
}
