package opaqueauth

import "time"

const (
	ProtocolVersion = 4
	Suite           = "OPAQUE-Ristretto255-SHA512-Argon2id-RFC9807"
)

type Principal struct {
	Username  string
	DeviceID  string
	SessionID string
}

type RegistrationStartInput struct {
	Username            string
	Operation           string
	RegistrationRequest []byte
	RequestID           string
	RequestDigest       [32]byte
}

type RegistrationStartResult struct {
	AttemptID string    `json:"attempt_id"`
	Response  []byte    `json:"-"`
	Suite     string    `json:"suite"`
	ExpiresAt time.Time `json:"expires_at"`
	Replayed  bool      `json:"replayed"`
}

type RegistrationFinishInput struct {
	AttemptID          string
	RegistrationRecord []byte
}

type LoginStartInput struct {
	Username               string
	KE1                    []byte
	ProposedDeviceID       string
	DisplayName            string
	Platform               string
	SigningAlgorithm       string
	SigningPublicKeySPKI   []byte
	AgreementAlgorithm     string
	AgreementPublicKeySPKI []byte
	RequestID              string
	RequestDigest          [32]byte
}

type LoginStartResult struct {
	AttemptID string    `json:"attempt_id"`
	KE2       []byte    `json:"-"`
	Suite     string    `json:"suite"`
	ExpiresAt time.Time `json:"expires_at"`
	Replayed  bool      `json:"replayed"`
}

type LoginFinishResult struct {
	Username              string    `json:"username"`
	DeviceID              string    `json:"device_id"`
	SessionID             string    `json:"session_id"`
	SessionToken          string    `json:"session_token"`
	AuthenticationState   string    `json:"authentication_state"`
	ProvisioningRequestID string    `json:"provisioning_request_id"`
	ServerProof           []byte    `json:"-"`
	ExpiresAt             time.Time `json:"expires_at"`
	Replayed              bool      `json:"replayed"`
}

type RecoveryPackage struct {
	VaultRevision  int64
	PackageVersion int
	Nonce          []byte
	Ciphertext     []byte
	CiphertextHash [32]byte
	UpdatedAt      time.Time
}
