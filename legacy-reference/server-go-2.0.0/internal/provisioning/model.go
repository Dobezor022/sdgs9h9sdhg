package provisioning

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const (
	MinimumTokenBytes = 32
	MaximumTokenBytes = 64
)

type InvitationID string
type DeviceID string
type SessionID string
type ChallengeID string
type ChallengePurpose string
type AuthenticationState string

const ChallengePurposeSessionRefresh ChallengePurpose = "session.refresh"

const (
	AuthenticationStateUnregistered        AuthenticationState = "UNREGISTERED"
	AuthenticationStateRegistrationPending AuthenticationState = "REGISTRATION_PENDING"
	AuthenticationStateAuthenticatedNoKeys AuthenticationState = "AUTHENTICATED_NO_KEYS"
	AuthenticationStateKeyTransferPending  AuthenticationState = "KEY_TRANSFER_PENDING"
	AuthenticationStateKeysRestored        AuthenticationState = "KEYS_RESTORED"
	AuthenticationStateReady               AuthenticationState = "READY"
	AuthenticationStateRevoked             AuthenticationState = "REVOKED"
	AuthenticationStateRecoveryRequired    AuthenticationState = "RECOVERY_REQUIRED"
)

// TokenDigest is the only invitation proof representation repositories may
// persist. Its formatting and JSON forms are redacted by default.
type TokenDigest [sha256.Size]byte

func (TokenDigest) String() string   { return "[REDACTED]" }
func (TokenDigest) GoString() string { return "provisioning.TokenDigest([REDACTED])" }
func (TokenDigest) MarshalJSON() ([]byte, error) {
	return json.Marshal("[REDACTED]")
}

// Bytes returns a defensive copy for database adapters.
func (digest TokenDigest) Bytes() []byte {
	result := make([]byte, len(digest))
	copy(result, digest[:])
	return result
}

// SecretToken is the one-time invitation proof returned to an authorized
// issuer. String, GoString, and JSON output are always redacted. Reveal should
// be called only at the QR or protocol boundary and its result must not be
// logged or persisted.
type SecretToken struct {
	encoded string
}

// SessionToken is returned exactly once after successful device provisioning.
// Only its SHA-256 digest is persisted by repositories.
type SessionToken struct {
	encoded string
}

func (SessionToken) String() string   { return "[REDACTED]" }
func (SessionToken) GoString() string { return "provisioning.SessionToken([REDACTED])" }
func (SessionToken) MarshalJSON() ([]byte, error) {
	return json.Marshal("[REDACTED]")
}

func (token SessionToken) Reveal() string {
	return token.encoded
}

func (SecretToken) String() string   { return "[REDACTED]" }
func (SecretToken) GoString() string { return "provisioning.SecretToken([REDACTED])" }
func (SecretToken) MarshalJSON() ([]byte, error) {
	return json.Marshal("[REDACTED]")
}

func (token SecretToken) Reveal() string {
	return token.encoded
}

// ParseInvitationToken accepts only canonical unpadded base64url containing
// between 32 and 64 random bytes. It does not establish that a token exists.
func ParseInvitationToken(encoded string) (SecretToken, error) {
	minimumEncodedLength := base64.RawURLEncoding.EncodedLen(MinimumTokenBytes)
	maximumEncodedLength := base64.RawURLEncoding.EncodedLen(MaximumTokenBytes)
	if len(encoded) < minimumEncodedLength || len(encoded) > maximumEncodedLength {
		return SecretToken{}, newError(CodeInvalidToken, "token")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return SecretToken{}, newError(CodeInvalidToken, "token")
	}
	defer clear(raw)
	if len(raw) < MinimumTokenBytes || len(raw) > MaximumTokenBytes {
		return SecretToken{}, newError(CodeInvalidToken, "token")
	}
	if base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return SecretToken{}, newError(CodeInvalidToken, "token")
	}
	return SecretToken{encoded: encoded}, nil
}

func (token SecretToken) digest() (TokenDigest, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token.encoded)
	if err != nil || len(raw) < MinimumTokenBytes || len(raw) > MaximumTokenBytes {
		clear(raw)
		return TokenDigest{}, newError(CodeInvalidToken, "token")
	}
	defer clear(raw)
	return sha256.Sum256(raw), nil
}

type InvitationRecord struct {
	ID                 InvitationID
	Username           Username
	TokenDigest        TokenDigest
	CreatedAt          time.Time
	ExpiresAt          time.Time
	RedeemedAt         *time.Time
	RedeemedByDeviceID DeviceID
}

func (record InvitationRecord) String() string {
	return fmt.Sprintf(
		"InvitationRecord{id=%s, username=%s, created_at=%s, expires_at=%s, redeemed=%t}",
		record.ID,
		record.Username,
		record.CreatedAt.Format(time.RFC3339),
		record.ExpiresAt.Format(time.RFC3339),
		record.RedeemedAt != nil,
	)
}

func (record InvitationRecord) clone() InvitationRecord {
	cloned := record
	if record.RedeemedAt != nil {
		value := *record.RedeemedAt
		cloned.RedeemedAt = &value
	}
	return cloned
}

func (record InvitationRecord) Redacted() InvitationView {
	view := InvitationView{
		ID:                 record.ID,
		Username:           record.Username,
		CreatedAt:          record.CreatedAt,
		ExpiresAt:          record.ExpiresAt,
		RedeemedByDeviceID: record.RedeemedByDeviceID,
	}
	if record.RedeemedAt != nil {
		value := *record.RedeemedAt
		view.RedeemedAt = &value
	}
	return view
}

type InvitationView struct {
	ID                 InvitationID `json:"id"`
	Username           Username     `json:"username"`
	CreatedAt          time.Time    `json:"created_at"`
	ExpiresAt          time.Time    `json:"expires_at"`
	RedeemedAt         *time.Time   `json:"redeemed_at,omitempty"`
	RedeemedByDeviceID DeviceID     `json:"redeemed_by_device_id,omitempty"`
}

type IssuedInvitation struct {
	ID        InvitationID `json:"id"`
	Username  Username     `json:"username"`
	Token     SecretToken  `json:"token"`
	CreatedAt time.Time    `json:"created_at"`
	ExpiresAt time.Time    `json:"expires_at"`
}

func (invitation IssuedInvitation) String() string {
	return fmt.Sprintf(
		"IssuedInvitation{id=%s, username=%s, token=[REDACTED], expires_at=%s}",
		invitation.ID,
		invitation.Username,
		invitation.ExpiresAt.Format(time.RFC3339),
	)
}

type DeviceRecord struct {
	ID                  DeviceID
	Username            Username
	PublicKey           DevicePublicKey
	BoundByInvitationID InvitationID
	BoundAt             time.Time
	RevokedAt           *time.Time
}

func (record DeviceRecord) clone() DeviceRecord {
	cloned := record
	cloned.PublicKey = record.PublicKey.clone()
	if record.RevokedAt != nil {
		value := *record.RevokedAt
		cloned.RevokedAt = &value
	}
	return cloned
}

func (record DeviceRecord) Redacted() DeviceView {
	view := DeviceView{
		ID:                  record.ID,
		Username:            record.Username,
		KeyAlgorithm:        record.PublicKey.Algorithm(),
		KeyFingerprint:      record.PublicKey.FingerprintHex(),
		BoundByInvitationID: record.BoundByInvitationID,
		BoundAt:             record.BoundAt,
	}
	if record.RevokedAt != nil {
		value := *record.RevokedAt
		view.RevokedAt = &value
	}
	return view
}

type DeviceView struct {
	ID                  DeviceID           `json:"id"`
	Username            Username           `json:"username"`
	KeyAlgorithm        DeviceKeyAlgorithm `json:"key_algorithm"`
	KeyFingerprint      string             `json:"key_fingerprint"`
	BoundByInvitationID InvitationID       `json:"bound_by_invitation_id"`
	BoundAt             time.Time          `json:"bound_at"`
	RevokedAt           *time.Time         `json:"revoked_at,omitempty"`
}

type RedemptionRecord struct {
	Invitation            InvitationView
	Device                DeviceView
	Session               SessionView
	AuthenticationState   AuthenticationState
	ProtectedSessionToken []byte
}

type SessionRecord struct {
	ID          SessionID
	DeviceID    DeviceID
	TokenDigest TokenDigest
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

type SessionView struct {
	ID        SessionID `json:"id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type IssuedSession struct {
	SessionView
	Token SessionToken `json:"token"`
}

func (session IssuedSession) String() string {
	return fmt.Sprintf(
		"IssuedSession{id=%s, token=[REDACTED], expires_at=%s}",
		session.ID,
		session.ExpiresAt.Format(time.RFC3339),
	)
}

type RedeemResult struct {
	Invitation          InvitationView      `json:"invitation"`
	Device              DeviceView          `json:"device"`
	Session             IssuedSession       `json:"session"`
	AuthenticationState AuthenticationState `json:"authentication_state"`
}

type ChallengeRecord struct {
	ID          ChallengeID
	DeviceID    DeviceID
	NonceDigest TokenDigest
	Audience    string
	Purpose     ChallengePurpose
	CreatedAt   time.Time
	ExpiresAt   time.Time
	ConsumedAt  *time.Time
}

func (record ChallengeRecord) clone() ChallengeRecord {
	cloned := record
	if record.ConsumedAt != nil {
		value := *record.ConsumedAt
		cloned.ConsumedAt = &value
	}
	return cloned
}

type IssuedChallenge struct {
	ID        ChallengeID      `json:"id"`
	DeviceID  DeviceID         `json:"device_id"`
	Audience  string           `json:"audience"`
	Purpose   ChallengePurpose `json:"purpose"`
	Nonce     SecretToken      `json:"nonce"`
	ExpiresAt time.Time        `json:"expires_at"`
}

func (challenge IssuedChallenge) String() string {
	return fmt.Sprintf(
		"IssuedChallenge{id=%s, device_id=%s, audience=%s, purpose=%s, nonce=[REDACTED], expires_at=%s}",
		challenge.ID,
		challenge.DeviceID,
		challenge.Audience,
		challenge.Purpose,
		challenge.ExpiresAt.Format(time.RFC3339),
	)
}

type SessionRefreshResult struct {
	Device  DeviceView    `json:"device"`
	Session IssuedSession `json:"session"`
}

func fingerprintHex(fingerprint [sha256.Size]byte) string {
	return hex.EncodeToString(fingerprint[:])
}
