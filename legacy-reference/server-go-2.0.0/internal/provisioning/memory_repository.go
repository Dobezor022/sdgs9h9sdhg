package provisioning

import (
	"context"
	"crypto/hmac"
	"sort"
	"sync"
)

// InMemoryRepository provides the same atomic boundary expected from a future
// database adapter. It is intended for unit tests and local composition, not
// durable production storage.
type InMemoryRepository struct {
	mu                   sync.RWMutex
	invitationsByDigest  map[TokenDigest]InvitationRecord
	invitationIDs        map[InvitationID]struct{}
	devicesByID          map[DeviceID]DeviceRecord
	deviceFingerprints   map[[32]byte]DeviceID
	encryptionKeysByID   map[DeviceID]MessageEncryptionKey
	deviceStates         map[DeviceID]AuthenticationState
	sessionsByID         map[SessionID]SessionRecord
	sessionsByDigest     map[TokenDigest]SessionID
	challengesByID       map[ChallengeID]ChallengeRecord
	challengesByDigest   map[TokenDigest]ChallengeID
	registrationAttempts map[string]memoryRegistrationAttempt
}

type memoryRegistrationAttempt struct {
	requestDigest         TokenDigest
	invitationID          InvitationID
	username              Username
	deviceID              DeviceID
	sessionID             SessionID
	protectedSessionToken []byte
	protocolVersion       int
	authenticationState   AuthenticationState
}

func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{
		invitationsByDigest:  make(map[TokenDigest]InvitationRecord),
		invitationIDs:        make(map[InvitationID]struct{}),
		devicesByID:          make(map[DeviceID]DeviceRecord),
		deviceFingerprints:   make(map[[32]byte]DeviceID),
		encryptionKeysByID:   make(map[DeviceID]MessageEncryptionKey),
		deviceStates:         make(map[DeviceID]AuthenticationState),
		sessionsByID:         make(map[SessionID]SessionRecord),
		sessionsByDigest:     make(map[TokenDigest]SessionID),
		challengesByID:       make(map[ChallengeID]ChallengeRecord),
		challengesByDigest:   make(map[TokenDigest]ChallengeID),
		registrationAttempts: make(map[string]memoryRegistrationAttempt),
	}
}

func (repository *InMemoryRepository) FindActiveDeviceByFingerprint(
	ctx context.Context,
	username Username,
	fingerprint [32]byte,
) (DeviceRecord, error) {
	if err := ctx.Err(); err != nil {
		return DeviceRecord{}, err
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	deviceID, exists := repository.deviceFingerprints[fingerprint]
	if !exists {
		return DeviceRecord{}, newError(CodeUnknownDevice, "device_key")
	}
	device, exists := repository.devicesByID[deviceID]
	if !exists || device.Username != username || device.RevokedAt != nil {
		return DeviceRecord{}, newError(CodeUnknownDevice, "device_key")
	}
	return device.clone(), nil
}

func (repository *InMemoryRepository) CreateChallenge(ctx context.Context, challenge ChallengeRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if challenge.ID == "" || challenge.DeviceID == "" || challenge.Audience == "" ||
		challenge.Purpose != ChallengePurposeSessionRefresh || challenge.CreatedAt.IsZero() ||
		!challenge.ExpiresAt.After(challenge.CreatedAt) || challenge.ConsumedAt != nil {
		return newError(CodeInvariantViolation, "challenge")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	device, exists := repository.devicesByID[challenge.DeviceID]
	if !exists || device.RevokedAt != nil {
		return newError(CodeUnknownDevice, "device_id")
	}
	if _, exists := repository.challengesByID[challenge.ID]; exists {
		return newError(CodeConflict, "challenge_id")
	}
	if _, exists := repository.challengesByDigest[challenge.NonceDigest]; exists {
		return newError(CodeConflict, "challenge_nonce")
	}
	repository.challengesByID[challenge.ID] = challenge.clone()
	repository.challengesByDigest[challenge.NonceDigest] = challenge.ID
	return nil
}

func (repository *InMemoryRepository) LoadChallenge(
	ctx context.Context,
	challengeID ChallengeID,
) (ChallengeRecord, DeviceRecord, error) {
	if err := ctx.Err(); err != nil {
		return ChallengeRecord{}, DeviceRecord{}, err
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	challenge, exists := repository.challengesByID[challengeID]
	if !exists {
		return ChallengeRecord{}, DeviceRecord{}, newError(CodeChallengeNotFound, "challenge_id")
	}
	device, exists := repository.devicesByID[challenge.DeviceID]
	if !exists || device.RevokedAt != nil {
		return ChallengeRecord{}, DeviceRecord{}, newError(CodeUnknownDevice, "device_id")
	}
	return challenge.clone(), device.clone(), nil
}

func (repository *InMemoryRepository) ConsumeChallengeAndCreateSession(
	ctx context.Context,
	command RefreshSessionCommand,
) (DeviceRecord, error) {
	if err := ctx.Err(); err != nil {
		return DeviceRecord{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	challenge, exists := repository.challengesByID[command.ChallengeID]
	if !exists {
		return DeviceRecord{}, newError(CodeChallengeNotFound, "challenge_id")
	}
	device, exists := repository.devicesByID[challenge.DeviceID]
	if !exists || device.RevokedAt != nil || device.ID != command.DeviceID || device.Username != command.Username {
		return DeviceRecord{}, newError(CodeUnknownDevice, "device_id")
	}
	if challenge.ConsumedAt != nil {
		return DeviceRecord{}, newError(CodeChallengeUsed, "challenge_id")
	}
	if !command.ConsumedAt.Before(challenge.ExpiresAt) {
		return DeviceRecord{}, newError(CodeChallengeExpired, "challenge_id")
	}
	if challenge.NonceDigest != command.NonceDigest || challenge.Audience != command.Audience || challenge.Purpose != command.Purpose {
		return DeviceRecord{}, newError(CodeChallengeContext, "challenge")
	}
	if command.SessionID == "" || !command.SessionExpiresAt.After(command.ConsumedAt) {
		return DeviceRecord{}, newError(CodeInvariantViolation, "session")
	}
	if _, exists := repository.sessionsByID[command.SessionID]; exists {
		return DeviceRecord{}, newError(CodeConflict, "session_id")
	}
	if _, exists := repository.sessionsByDigest[command.SessionTokenDigest]; exists {
		return DeviceRecord{}, newError(CodeConflict, "session_token")
	}
	consumedAt := command.ConsumedAt
	challenge.ConsumedAt = &consumedAt
	repository.challengesByID[challenge.ID] = challenge
	repository.sessionsByID[command.SessionID] = SessionRecord{
		ID:          command.SessionID,
		DeviceID:    device.ID,
		TokenDigest: command.SessionTokenDigest,
		IssuedAt:    command.ConsumedAt,
		ExpiresAt:   command.SessionExpiresAt,
	}
	repository.sessionsByDigest[command.SessionTokenDigest] = command.SessionID
	return device.clone(), nil
}

func (repository *InMemoryRepository) CreateInvitation(ctx context.Context, invitation InvitationRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if invitation.ID == "" || !isFixedUser(invitation.Username) || invitation.CreatedAt.IsZero() || !invitation.ExpiresAt.After(invitation.CreatedAt) || invitation.RedeemedAt != nil || invitation.RedeemedByDeviceID != "" {
		return newError(CodeInvariantViolation, "invitation")
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, exists := repository.invitationsByDigest[invitation.TokenDigest]; exists {
		return newError(CodeConflict, "token_digest")
	}
	if _, exists := repository.invitationIDs[invitation.ID]; exists {
		return newError(CodeConflict, "invitation_id")
	}

	// The newest unredeemed invitation replaces every older QR for the same
	// username. Redeemed records remain available for audit.
	for digest, existing := range repository.invitationsByDigest {
		if existing.Username == invitation.Username && existing.RedeemedAt == nil {
			delete(repository.invitationsByDigest, digest)
			delete(repository.invitationIDs, existing.ID)
		}
	}
	repository.invitationsByDigest[invitation.TokenDigest] = invitation.clone()
	repository.invitationIDs[invitation.ID] = struct{}{}
	return nil
}

func (repository *InMemoryRepository) RedeemInvitation(ctx context.Context, command RedeemCommand) (RedemptionRecord, error) {
	if err := ctx.Err(); err != nil {
		return RedemptionRecord{}, err
	}
	if command.ProtocolVersion < 2 || command.ProtocolVersion > 3 || !validIdempotencyKey(command.IdempotencyKey) ||
		!isFixedUser(command.Username) || command.DeviceID == "" || command.RedeemedAt.IsZero() ||
		len(command.DeviceKey.canonicalDER) == 0 || len(command.EncryptionKey.canonicalDER) == 0 ||
		command.SessionID == "" || !command.SessionExpiresAt.After(command.RedeemedAt) ||
		len(command.ProtectedSessionToken) < 61 || len(command.ProtectedSessionToken) > 512 {
		return RedemptionRecord{}, newError(CodeInvariantViolation, "redemption")
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return RedemptionRecord{}, err
	}

	if attempt, exists := repository.registrationAttempts[command.IdempotencyKey]; exists {
		if !hmac.Equal(attempt.requestDigest[:], command.RequestDigest[:]) ||
			attempt.username != command.Username || attempt.protocolVersion != command.ProtocolVersion {
			return RedemptionRecord{}, newError(CodeConflict, "idempotency_key")
		}
		invitation, exists := repository.invitationByID(attempt.invitationID)
		if !exists {
			return RedemptionRecord{}, newError(CodeInvariantViolation, "invitation")
		}
		device, exists := repository.devicesByID[attempt.deviceID]
		if !exists {
			return RedemptionRecord{}, newError(CodeInvariantViolation, "device")
		}
		session, exists := repository.sessionsByID[attempt.sessionID]
		if !exists {
			return RedemptionRecord{}, newError(CodeInvariantViolation, "session")
		}
		return RedemptionRecord{
			Invitation:            invitation.Redacted(),
			Device:                device.Redacted(),
			Session:               SessionView{ID: session.ID, IssuedAt: session.IssuedAt, ExpiresAt: session.ExpiresAt},
			AuthenticationState:   attempt.authenticationState,
			ProtectedSessionToken: append([]byte(nil), attempt.protectedSessionToken...),
		}, nil
	}

	invitation, exists := repository.invitationsByDigest[command.TokenDigest]
	if !exists {
		return RedemptionRecord{}, newError(CodeInvitationNotFound, "token")
	}
	if invitation.Username != command.Username {
		return RedemptionRecord{}, newError(CodeInvitationUser, "username")
	}
	if invitation.RedeemedAt != nil {
		return RedemptionRecord{}, newError(CodeInvitationUsed, "token")
	}
	if !command.RedeemedAt.Before(invitation.ExpiresAt) {
		return RedemptionRecord{}, newError(CodeInvitationExpired, "token")
	}
	if _, exists := repository.sessionsByID[command.SessionID]; exists {
		return RedemptionRecord{}, newError(CodeConflict, "session_id")
	}
	if _, exists := repository.sessionsByDigest[command.SessionTokenDigest]; exists {
		return RedemptionRecord{}, newError(CodeConflict, "session_token")
	}

	actualDeviceID := command.DeviceID
	identityFingerprint := command.DeviceKey.Fingerprint()
	if existingID, exists := repository.deviceFingerprints[identityFingerprint]; exists {
		existing := repository.devicesByID[existingID]
		if existing.Username != command.Username || existing.RevokedAt != nil {
			return RedemptionRecord{}, newError(CodeConflict, "device_key")
		}
		if existingEncryption, exists := repository.encryptionKeysByID[existingID]; exists {
			existingEncryptionFingerprint := existingEncryption.Fingerprint()
			commandEncryptionFingerprint := command.EncryptionKey.Fingerprint()
			if !hmac.Equal(existingEncryptionFingerprint[:], commandEncryptionFingerprint[:]) {
				return RedemptionRecord{}, newError(CodeConflict, "encryption_key")
			}
		}
		actualDeviceID = existingID
	} else if _, exists := repository.devicesByID[command.DeviceID]; exists {
		return RedemptionRecord{}, newError(CodeConflict, "device_id")
	}

	device, exists := repository.devicesByID[actualDeviceID]
	authenticationState := repository.deviceStates[actualDeviceID]
	if !exists {
		authenticationState = AuthenticationStateReady
		if command.ProtocolVersion >= 3 {
			for existingID, existingDevice := range repository.devicesByID {
				if existingDevice.Username == command.Username && existingDevice.RevokedAt == nil &&
					repository.deviceStates[existingID] == AuthenticationStateReady {
					authenticationState = AuthenticationStateAuthenticatedNoKeys
					break
				}
			}
		}
		device = DeviceRecord{
			ID:                  actualDeviceID,
			Username:            command.Username,
			PublicKey:           command.DeviceKey.clone(),
			BoundByInvitationID: invitation.ID,
			BoundAt:             command.RedeemedAt,
		}
		repository.devicesByID[device.ID] = device
		repository.deviceFingerprints[device.PublicKey.Fingerprint()] = device.ID
		repository.deviceStates[device.ID] = authenticationState
	}
	repository.encryptionKeysByID[device.ID] = command.EncryptionKey.clone()

	redeemedAt := command.RedeemedAt
	invitation.RedeemedAt = &redeemedAt
	invitation.RedeemedByDeviceID = device.ID
	repository.invitationsByDigest[command.TokenDigest] = invitation
	repository.sessionsByID[command.SessionID] = SessionRecord{
		ID:          command.SessionID,
		DeviceID:    device.ID,
		TokenDigest: command.SessionTokenDigest,
		IssuedAt:    command.RedeemedAt,
		ExpiresAt:   command.SessionExpiresAt,
	}
	repository.sessionsByDigest[command.SessionTokenDigest] = command.SessionID
	repository.registrationAttempts[command.IdempotencyKey] = memoryRegistrationAttempt{
		requestDigest:         command.RequestDigest,
		invitationID:          invitation.ID,
		username:              command.Username,
		deviceID:              device.ID,
		sessionID:             command.SessionID,
		protectedSessionToken: append([]byte(nil), command.ProtectedSessionToken...),
		protocolVersion:       command.ProtocolVersion,
		authenticationState:   authenticationState,
	}

	return RedemptionRecord{
		Invitation:            invitation.Redacted(),
		Device:                device.Redacted(),
		Session:               SessionView{ID: command.SessionID, IssuedAt: command.RedeemedAt, ExpiresAt: command.SessionExpiresAt},
		AuthenticationState:   authenticationState,
		ProtectedSessionToken: append([]byte(nil), command.ProtectedSessionToken...),
	}, nil
}

func (repository *InMemoryRepository) invitationByID(id InvitationID) (InvitationRecord, bool) {
	for _, invitation := range repository.invitationsByDigest {
		if invitation.ID == id {
			return invitation, true
		}
	}
	return InvitationRecord{}, false
}

// Snapshot exposes only redacted diagnostic records. Token digests and public
// key bytes are intentionally omitted.
func (repository *InMemoryRepository) Snapshot() RepositorySnapshot {
	repository.mu.RLock()
	defer repository.mu.RUnlock()

	snapshot := RepositorySnapshot{
		Invitations: make([]InvitationView, 0, len(repository.invitationsByDigest)),
		Devices:     make([]DeviceView, 0, len(repository.devicesByID)),
	}
	for _, invitation := range repository.invitationsByDigest {
		snapshot.Invitations = append(snapshot.Invitations, invitation.Redacted())
	}
	for _, device := range repository.devicesByID {
		snapshot.Devices = append(snapshot.Devices, device.Redacted())
	}
	sort.Slice(snapshot.Invitations, func(left, right int) bool {
		return snapshot.Invitations[left].ID < snapshot.Invitations[right].ID
	})
	sort.Slice(snapshot.Devices, func(left, right int) bool {
		return snapshot.Devices[left].ID < snapshot.Devices[right].ID
	})
	return snapshot
}
