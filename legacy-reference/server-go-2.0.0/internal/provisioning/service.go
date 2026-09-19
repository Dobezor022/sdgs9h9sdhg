package provisioning

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	defaultTokenBytes         = 32
	defaultSessionTokenBytes  = 32
	defaultSessionTTL         = 15 * time.Minute
	defaultChallengeTTL       = 10 * time.Second
	defaultMaximumTTL         = 15 * time.Minute
	defaultGenerationAttempts = 4
	identifierBytes           = 16
	maximumConfigurableTTL    = 24 * time.Hour
)

type Config struct {
	RegistrationResultKey []byte
	TokenBytes            int
	SessionTokenBytes     int
	SessionTTL            time.Duration
	ChallengeTTL          time.Duration
	MaximumTTL            time.Duration
	GenerationAttempts    int
}

func DefaultConfig() Config {
	return Config{
		TokenBytes:         defaultTokenBytes,
		SessionTokenBytes:  defaultSessionTokenBytes,
		SessionTTL:         defaultSessionTTL,
		ChallengeTTL:       defaultChallengeTTL,
		MaximumTTL:         defaultMaximumTTL,
		GenerationAttempts: defaultGenerationAttempts,
	}
}

type Service struct {
	repository          InvitationRepository
	registrationResults *registrationResultProtector
	clock               Clock
	entropy             EntropySource
	config              Config
}

func NewService(repository InvitationRepository, clock Clock, entropy EntropySource, config Config) (*Service, error) {
	if repository == nil {
		return nil, newError(CodeInvalidConfiguration, "repository")
	}
	if clock == nil {
		return nil, newError(CodeInvalidConfiguration, "clock")
	}
	if entropy == nil {
		return nil, newError(CodeInvalidConfiguration, "entropy")
	}
	if config.TokenBytes < MinimumTokenBytes || config.TokenBytes > MaximumTokenBytes {
		return nil, newError(CodeInvalidConfiguration, "token_bytes")
	}
	if config.SessionTokenBytes < MinimumTokenBytes || config.SessionTokenBytes > MaximumTokenBytes {
		return nil, newError(CodeInvalidConfiguration, "session_token_bytes")
	}
	if config.SessionTTL <= 0 || config.SessionTTL > time.Hour {
		return nil, newError(CodeInvalidConfiguration, "session_ttl")
	}
	if config.ChallengeTTL <= 0 || config.ChallengeTTL > 10*time.Second {
		return nil, newError(CodeInvalidConfiguration, "challenge_ttl")
	}
	if config.MaximumTTL <= 0 || config.MaximumTTL > maximumConfigurableTTL {
		return nil, newError(CodeInvalidConfiguration, "maximum_ttl")
	}
	if config.GenerationAttempts <= 0 || config.GenerationAttempts > 32 {
		return nil, newError(CodeInvalidConfiguration, "generation_attempts")
	}
	registrationKey := append([]byte(nil), config.RegistrationResultKey...)
	if len(registrationKey) == 0 {
		registrationKey = make([]byte, registrationResultKeyBytes)
		if _, err := io.ReadFull(entropy, registrationKey); err != nil {
			clear(registrationKey)
			return nil, wrapError(CodeEntropyUnavailable, "registration_result_key", err)
		}
	}
	registrationResults, err := newRegistrationResultProtector(registrationKey, entropy)
	clear(registrationKey)
	if err != nil {
		return nil, err
	}
	return &Service{
		repository:          repository,
		registrationResults: registrationResults,
		clock:               clock,
		entropy:             entropy,
		config:              config,
	}, nil
}

type SessionChallengeRequest struct {
	Username  string
	DeviceKey DevicePublicKeyInput
	Audience  string
	Purpose   ChallengePurpose
}

type SessionRefreshRequest struct {
	Username    string
	DeviceID    DeviceID
	ChallengeID ChallengeID
	Nonce       SecretToken
	Audience    string
	Purpose     ChallengePurpose
	Signature   []byte
}

func (service *Service) IssueSessionChallenge(
	ctx context.Context,
	request SessionChallengeRequest,
) (IssuedChallenge, error) {
	if err := ctx.Err(); err != nil {
		return IssuedChallenge{}, err
	}
	username, err := ParseUsername(request.Username)
	if err != nil {
		return IssuedChallenge{}, err
	}
	deviceKey, err := ValidateDevicePublicKey(request.DeviceKey)
	if err != nil {
		return IssuedChallenge{}, err
	}
	if request.Purpose != ChallengePurposeSessionRefresh || !validAuthenticationContextValue(request.Audience, 512) {
		return IssuedChallenge{}, newError(CodeChallengeContext, "challenge")
	}
	device, err := service.repository.FindActiveDeviceByFingerprint(ctx, username, deviceKey.Fingerprint())
	if err != nil {
		return IssuedChallenge{}, err
	}
	createdAt := service.clock.Now().UTC()
	for attempt := 0; attempt < service.config.GenerationAttempts; attempt++ {
		challengeID, err := service.newUUID()
		if err != nil {
			return IssuedChallenge{}, err
		}
		rawNonce := make([]byte, MinimumTokenBytes)
		if _, err := io.ReadFull(service.entropy, rawNonce); err != nil {
			clear(rawNonce)
			return IssuedChallenge{}, wrapError(CodeEntropyUnavailable, "challenge_nonce", err)
		}
		encodedNonce := base64.RawURLEncoding.EncodeToString(rawNonce)
		nonceDigest := digestRawToken(rawNonce)
		clear(rawNonce)
		record := ChallengeRecord{
			ID:          ChallengeID(challengeID),
			DeviceID:    device.ID,
			NonceDigest: nonceDigest,
			Audience:    request.Audience,
			Purpose:     request.Purpose,
			CreatedAt:   createdAt,
			ExpiresAt:   createdAt.Add(service.config.ChallengeTTL),
		}
		if err := service.repository.CreateChallenge(ctx, record); err != nil {
			if errors.Is(err, ErrConflict) {
				continue
			}
			return IssuedChallenge{}, err
		}
		return IssuedChallenge{
			ID:        record.ID,
			DeviceID:  device.ID,
			Audience:  record.Audience,
			Purpose:   record.Purpose,
			Nonce:     SecretToken{encoded: encodedNonce},
			ExpiresAt: record.ExpiresAt,
		}, nil
	}
	return IssuedChallenge{}, newError(CodeEntropyCollision, "challenge")
}

func (service *Service) RefreshSession(
	ctx context.Context,
	request SessionRefreshRequest,
) (SessionRefreshResult, error) {
	if err := ctx.Err(); err != nil {
		return SessionRefreshResult{}, err
	}
	username, err := ParseUsername(request.Username)
	if err != nil {
		return SessionRefreshResult{}, err
	}
	if request.DeviceID == "" || request.ChallengeID == "" ||
		request.Purpose != ChallengePurposeSessionRefresh ||
		!validAuthenticationContextValue(request.Audience, 512) || len(request.Signature) == 0 || len(request.Signature) > 512 {
		return SessionRefreshResult{}, newError(CodeChallengeContext, "challenge")
	}
	nonceDigest, err := request.Nonce.digest()
	if err != nil {
		return SessionRefreshResult{}, newError(CodeChallengeContext, "nonce")
	}
	challenge, device, err := service.repository.LoadChallenge(ctx, request.ChallengeID)
	if err != nil {
		return SessionRefreshResult{}, err
	}
	now := service.clock.Now().UTC()
	if challenge.ConsumedAt != nil {
		return SessionRefreshResult{}, newError(CodeChallengeUsed, "challenge_id")
	}
	if !now.Before(challenge.ExpiresAt) {
		return SessionRefreshResult{}, newError(CodeChallengeExpired, "challenge_id")
	}
	if device.ID != request.DeviceID || device.Username != username || challenge.DeviceID != device.ID ||
		challenge.NonceDigest != nonceDigest || challenge.Audience != request.Audience || challenge.Purpose != request.Purpose {
		return SessionRefreshResult{}, newError(CodeChallengeContext, "challenge")
	}
	payload, err := DeviceAuthenticationPayload(
		request.Audience,
		username,
		device.ID,
		challenge.ID,
		challenge.Purpose,
		request.Nonce.Reveal(),
	)
	if err != nil {
		return SessionRefreshResult{}, err
	}
	defer clear(payload)
	if !verifyDeviceSignature(device.PublicKey, payload, request.Signature) {
		return SessionRefreshResult{}, newError(CodeInvalidSignature, "signature")
	}

	sessionIDValue, err := service.newUUID()
	if err != nil {
		return SessionRefreshResult{}, err
	}
	rawSessionToken := make([]byte, service.config.SessionTokenBytes)
	if _, err := io.ReadFull(service.entropy, rawSessionToken); err != nil {
		clear(rawSessionToken)
		return SessionRefreshResult{}, wrapError(CodeEntropyUnavailable, "session_token", err)
	}
	encodedSessionToken := base64.RawURLEncoding.EncodeToString(rawSessionToken)
	sessionTokenDigest := digestRawToken(rawSessionToken)
	clear(rawSessionToken)
	sessionID := SessionID(sessionIDValue)
	sessionExpiresAt := now.Add(service.config.SessionTTL)
	storedDevice, err := service.repository.ConsumeChallengeAndCreateSession(ctx, RefreshSessionCommand{
		ChallengeID:        challenge.ID,
		DeviceID:           device.ID,
		Username:           username,
		NonceDigest:        nonceDigest,
		Audience:           request.Audience,
		Purpose:            request.Purpose,
		ConsumedAt:         now,
		SessionID:          sessionID,
		SessionTokenDigest: sessionTokenDigest,
		SessionExpiresAt:   sessionExpiresAt,
	})
	if err != nil {
		return SessionRefreshResult{}, err
	}
	return SessionRefreshResult{
		Device: storedDevice.Redacted(),
		Session: IssuedSession{
			SessionView: SessionView{ID: sessionID, IssuedAt: now, ExpiresAt: sessionExpiresAt},
			Token:       SessionToken{encoded: encodedSessionToken},
		},
	}, nil
}

func DeviceAuthenticationPayload(
	audience string,
	username Username,
	deviceID DeviceID,
	challengeID ChallengeID,
	purpose ChallengePurpose,
	nonce string,
) ([]byte, error) {
	values := []string{audience, string(username), string(deviceID), string(challengeID), string(purpose), nonce}
	for _, value := range values {
		if !validAuthenticationContextValue(value, 1024) {
			return nil, newError(CodeChallengeContext, "challenge")
		}
	}
	return []byte(strings.Join([]string{
		"fedmes-device-auth-v1",
		audience,
		string(username),
		string(deviceID),
		string(challengeID),
		string(purpose),
		nonce,
	}, "\n")), nil
}

func validAuthenticationContextValue(value string, maximumLength int) bool {
	return value != "" && len(value) <= maximumLength && !strings.ContainsAny(value, "\r\n")
}

func verifyDeviceSignature(key DevicePublicKey, payload, signature []byte) bool {
	parsed, err := x509.ParsePKIXPublicKey(key.SubjectPublicKeyInfo())
	if err != nil {
		return false
	}
	switch publicKey := parsed.(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(payload)
		return key.Algorithm() == DeviceKeyECDSAP256 && ecdsa.VerifyASN1(publicKey, digest[:], signature)
	case ed25519.PublicKey:
		return key.Algorithm() == DeviceKeyEd25519 && ed25519.Verify(publicKey, payload, signature)
	default:
		return false
	}
}

func (service *Service) IssueInvitation(ctx context.Context, usernameValue string, ttl time.Duration) (IssuedInvitation, error) {
	if err := ctx.Err(); err != nil {
		return IssuedInvitation{}, err
	}
	username, err := ParseUsername(usernameValue)
	if err != nil {
		return IssuedInvitation{}, err
	}
	if ttl <= 0 || ttl > service.config.MaximumTTL {
		return IssuedInvitation{}, newError(CodeInvalidTTL, "ttl")
	}

	createdAt := service.clock.Now().UTC()
	expiresAt := createdAt.Add(ttl)
	for attempt := 0; attempt < service.config.GenerationAttempts; attempt++ {
		invitationID, err := service.newUUID()
		if err != nil {
			return IssuedInvitation{}, err
		}
		rawToken := make([]byte, service.config.TokenBytes)
		if _, err := io.ReadFull(service.entropy, rawToken); err != nil {
			clear(rawToken)
			return IssuedInvitation{}, wrapError(CodeEntropyUnavailable, "token", err)
		}
		encodedToken := base64.RawURLEncoding.EncodeToString(rawToken)
		tokenDigest := digestRawToken(rawToken)
		clear(rawToken)

		record := InvitationRecord{
			ID:          InvitationID(invitationID),
			Username:    username,
			TokenDigest: tokenDigest,
			CreatedAt:   createdAt,
			ExpiresAt:   expiresAt,
		}
		if err := service.repository.CreateInvitation(ctx, record); err != nil {
			if errors.Is(err, ErrConflict) {
				continue
			}
			return IssuedInvitation{}, err
		}
		return IssuedInvitation{
			ID:        record.ID,
			Username:  username,
			Token:     SecretToken{encoded: encodedToken},
			CreatedAt: createdAt,
			ExpiresAt: expiresAt,
		}, nil
	}
	return IssuedInvitation{}, newError(CodeEntropyCollision, "invitation")
}

type RedeemRequest struct {
	ProtocolVersion int
	IdempotencyKey  string
	Username        string
	Token           SecretToken
	DeviceKey       DevicePublicKeyInput
	EncryptionKey   MessageEncryptionKeyInput
}

func (request RedeemRequest) String() string {
	return "RedeemRequest{username=" + request.Username + ", token=[REDACTED], device_key=[REDACTED], encryption_key=[REDACTED]}"
}

func (service *Service) RedeemInvitation(ctx context.Context, request RedeemRequest) (RedeemResult, error) {
	if err := ctx.Err(); err != nil {
		return RedeemResult{}, err
	}
	protocolVersion := request.ProtocolVersion
	if protocolVersion == 0 {
		protocolVersion = 2
	}
	if protocolVersion < 2 || protocolVersion > 3 {
		return RedeemResult{}, newError(CodeChallengeContext, "protocol_version")
	}
	idempotencyKey := request.IdempotencyKey
	if idempotencyKey == "" {
		var err error
		idempotencyKey, err = generateIdempotencyKey(service.entropy)
		if err != nil {
			return RedeemResult{}, err
		}
	}
	if !validIdempotencyKey(idempotencyKey) {
		return RedeemResult{}, newError(CodeChallengeContext, "idempotency_key")
	}
	username, err := ParseUsername(request.Username)
	if err != nil {
		return RedeemResult{}, err
	}
	tokenDigest, err := request.Token.digest()
	if err != nil {
		return RedeemResult{}, err
	}
	deviceKey, err := ValidateDevicePublicKey(request.DeviceKey)
	if err != nil {
		return RedeemResult{}, err
	}
	encryptionKey, err := ValidateMessageEncryptionKey(request.EncryptionKey)
	if err != nil {
		return RedeemResult{}, err
	}
	requestDigest := registrationRequestDigest(protocolVersion, username, tokenDigest, deviceKey, encryptionKey)
	deviceID, err := service.newUUID()
	if err != nil {
		return RedeemResult{}, err
	}
	sessionID, err := service.newUUID()
	if err != nil {
		return RedeemResult{}, err
	}
	rawSessionToken := make([]byte, service.config.SessionTokenBytes)
	if _, err := io.ReadFull(service.entropy, rawSessionToken); err != nil {
		clear(rawSessionToken)
		return RedeemResult{}, wrapError(CodeEntropyUnavailable, "session_token", err)
	}
	encodedSessionToken := base64.RawURLEncoding.EncodeToString(rawSessionToken)
	sessionTokenDigest := digestRawToken(rawSessionToken)
	clear(rawSessionToken)
	protectedSessionToken, err := service.registrationResults.protect(idempotencyKey, requestDigest, encodedSessionToken)
	if err != nil {
		return RedeemResult{}, err
	}
	defer clear(protectedSessionToken)
	redeemedAt := service.clock.Now().UTC()
	sessionExpiresAt := redeemedAt.Add(service.config.SessionTTL)

	record, err := service.repository.RedeemInvitation(ctx, RedeemCommand{
		ProtocolVersion:       protocolVersion,
		IdempotencyKey:        idempotencyKey,
		RequestDigest:         requestDigest,
		ProtectedSessionToken: protectedSessionToken,
		TokenDigest:           tokenDigest,
		Username:              username,
		DeviceID:              DeviceID(deviceID),
		DeviceKey:             deviceKey,
		EncryptionKey:         encryptionKey,
		RedeemedAt:            redeemedAt,
		SessionID:             SessionID(sessionID),
		SessionTokenDigest:    sessionTokenDigest,
		SessionExpiresAt:      sessionExpiresAt,
	})
	if err != nil {
		return RedeemResult{}, err
	}
	defer clear(record.ProtectedSessionToken)
	resolvedToken, err := service.registrationResults.unprotect(
		idempotencyKey,
		requestDigest,
		record.ProtectedSessionToken,
	)
	if err != nil {
		return RedeemResult{}, err
	}
	return RedeemResult{
		Invitation: record.Invitation,
		Device:     record.Device,
		Session: IssuedSession{
			SessionView: record.Session,
			Token:       SessionToken{encoded: resolvedToken},
		},
		AuthenticationState: record.AuthenticationState,
	}, nil
}

func (service *Service) newUUID() (string, error) {
	value := make([]byte, identifierBytes)
	if _, err := io.ReadFull(service.entropy, value); err != nil {
		clear(value)
		return "", wrapError(CodeEntropyUnavailable, "identifier", err)
	}
	defer clear(value)
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func digestRawToken(raw []byte) TokenDigest {
	return TokenDigest(sha256Sum(raw))
}

// Kept behind a small function so hashing policy can be versioned without
// exposing token material to repositories.
func sha256Sum(value []byte) [32]byte {
	return sha256.Sum256(value)
}
