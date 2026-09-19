package provisioning

import (
	"context"
	"time"
)

type RedeemCommand struct {
	ProtocolVersion       int
	IdempotencyKey        string
	RequestDigest         TokenDigest
	ProtectedSessionToken []byte
	TokenDigest           TokenDigest
	Username              Username
	DeviceID              DeviceID
	DeviceKey             DevicePublicKey
	EncryptionKey         MessageEncryptionKey
	RedeemedAt            time.Time
	SessionID             SessionID
	SessionTokenDigest    TokenDigest
	SessionExpiresAt      time.Time
}

type RefreshSessionCommand struct {
	ChallengeID        ChallengeID
	DeviceID           DeviceID
	Username           Username
	NonceDigest        TokenDigest
	Audience           string
	Purpose            ChallengePurpose
	ConsumedAt         time.Time
	SessionID          SessionID
	SessionTokenDigest TokenDigest
	SessionExpiresAt   time.Time
}

// InvitationRepository is deliberately transaction-oriented. A durable
// implementation must mark the invitation redeemed and insert the bound
// device and initial session in one transaction.
type InvitationRepository interface {
	CreateInvitation(ctx context.Context, invitation InvitationRecord) error
	RedeemInvitation(ctx context.Context, command RedeemCommand) (RedemptionRecord, error)
	FindActiveDeviceByFingerprint(ctx context.Context, username Username, fingerprint [32]byte) (DeviceRecord, error)
	CreateChallenge(ctx context.Context, challenge ChallengeRecord) error
	LoadChallenge(ctx context.Context, challengeID ChallengeID) (ChallengeRecord, DeviceRecord, error)
	ConsumeChallengeAndCreateSession(ctx context.Context, command RefreshSessionCommand) (DeviceRecord, error)
}

type RepositorySnapshot struct {
	Invitations []InvitationView `json:"invitations"`
	Devices     []DeviceView     `json:"devices"`
}
