package ratchet

import "time"

const ProtocolVersion = 4

type Principal struct {
	Username string
	DeviceID string
}

type OneTimeKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Signature []byte `json:"-"`
}

type BundleWrite struct {
	BundleVersion         int
	Curve25519IdentityKey string
	Ed25519IdentityKey    string
	SignedPayload         []byte
	Signature             []byte
	OneTimeKeys           []OneTimeKey
}

type ClaimedKey struct {
	DeviceID              string     `json:"device_id"`
	Username              string     `json:"username"`
	BundleVersion         int        `json:"bundle_version"`
	Curve25519IdentityKey string     `json:"curve25519_identity_key"`
	Ed25519IdentityKey    string     `json:"ed25519_identity_key"`
	SignedPayload         []byte     `json:"-"`
	BundleSignature       []byte     `json:"-"`
	OneTimeKey            OneTimeKey `json:"one_time_key"`
	ClaimedAt             time.Time  `json:"claimed_at"`
}

type MessageEnvelope struct {
	MessageID           string
	RecipientDeviceID   string
	SenderCurve25519Key string
	SessionID           string
	MessageType         int
	Ciphertext          []byte
	CiphertextSHA256    [32]byte
}

type PendingEnvelope struct {
	MessageEnvelope
	ChatID         string
	SenderDeviceID string
	CreatedAt      time.Time
}

type GroupVersionReservation struct {
	RotationID     string    `json:"rotation_id"`
	ChatID         string    `json:"chat_id"`
	RoomKeyVersion int64     `json:"room_key_version"`
	ExpiresAt      time.Time `json:"expires_at"`
	Replayed       bool      `json:"replayed"`
}

type GroupSessionWrite struct {
	ChatID         string
	RoomKeyVersion int64
	SessionID      string
	RotationID     string
	Packages       []GroupKeyPackage
}

type GroupKeyPackage struct {
	RecipientDeviceID   string
	OlmSessionID        string
	MessageType         int
	EncryptedSessionKey []byte
}

type PendingGroupKeyPackage struct {
	ChatID              string    `json:"chat_id"`
	RoomKeyVersion      int64     `json:"room_key_version"`
	SessionID           string    `json:"session_id"`
	SenderDeviceID      string    `json:"sender_device_id"`
	SenderCurve25519Key string    `json:"sender_curve25519_key"`
	RotationID          string    `json:"rotation_id"`
	OlmSessionID        string    `json:"olm_session_id"`
	MessageType         int       `json:"message_type"`
	EncryptedSessionKey []byte    `json:"-"`
	CreatedAt           time.Time `json:"created_at"`
}
