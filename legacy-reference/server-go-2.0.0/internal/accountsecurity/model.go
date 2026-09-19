package accountsecurity

import "time"

const (
	StateUnregistered        = "UNREGISTERED"
	StateRegistrationPending = "REGISTRATION_PENDING"
	StateAuthenticatedNoKeys = "AUTHENTICATED_NO_KEYS"
	StateKeyTransferPending  = "KEY_TRANSFER_PENDING"
	StateKeysRestored        = "KEYS_RESTORED"
	StateReady               = "READY"
	StateRevoked             = "REVOKED"
	StateRecoveryRequired    = "RECOVERY_REQUIRED"
)

type Principal struct {
	Username  string
	DeviceID  string
	SessionID string
}

type AccountState struct {
	Username           string `json:"username"`
	DeviceID           string `json:"device_id"`
	State              string `json:"state"`
	ProtocolVersion    int    `json:"protocol_version"`
	CryptoVersion      int    `json:"crypto_version"`
	VaultRevision      int64  `json:"vault_revision"`
	RecoveryConfigured bool   `json:"recovery_configured"`
	OpaqueEnrolled     bool   `json:"opaque_enrolled"`
}

type VaultEnvelope struct {
	Revision       int64     `json:"revision"`
	VaultVersion   int       `json:"vault_version"`
	CryptoVersion  int       `json:"crypto_version"`
	AADVersion     int       `json:"aad_version"`
	Nonce          []byte    `json:"-"`
	Ciphertext     []byte    `json:"-"`
	CiphertextHash [32]byte  `json:"-"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type VaultWrite struct {
	ExpectedPreviousRevision int64
	VaultVersion             int
	CryptoVersion            int
	AADVersion               int
	Nonce                    []byte
	Ciphertext               []byte
	CiphertextHash           [32]byte
	AccessVerifier           [32]byte
	RequestID                string
	RequestDigest            [32]byte
}

type RecoveryPackage struct {
	ID             string    `json:"id"`
	VaultRevision  int64     `json:"vault_revision"`
	PackageVersion int       `json:"package_version"`
	CryptoVersion  int       `json:"crypto_version"`
	AADVersion     int       `json:"aad_version"`
	KDFName        string    `json:"kdf_name"`
	KDFParameters  string    `json:"kdf_parameters"`
	Salt           []byte    `json:"-"`
	Nonce          []byte    `json:"-"`
	Ciphertext     []byte    `json:"-"`
	CiphertextHash [32]byte  `json:"-"`
	CreatedAt      time.Time `json:"created_at"`
}

type RecoveryWrite struct {
	ID             string
	VaultRevision  int64
	PackageVersion int
	CryptoVersion  int
	AADVersion     int
	KDFName        string
	KDFParameters  string
	Salt           []byte
	Nonce          []byte
	Ciphertext     []byte
	CiphertextHash [32]byte
	RequestID      string
	RequestDigest  [32]byte
}

type DeviceProvisioningRequest struct {
	ID                 string     `json:"id"`
	Username           string     `json:"username"`
	TargetDeviceID     string     `json:"target_device_id"`
	DisplayName        string     `json:"display_name"`
	Platform           string     `json:"platform"`
	NetworkHint        string     `json:"network_hint"`
	ProtocolVersion    int        `json:"protocol_version"`
	RequestedAt        time.Time  `json:"requested_at"`
	ExpiresAt          time.Time  `json:"expires_at"`
	ApprovedAt         *time.Time `json:"approved_at,omitempty"`
	ApprovedByDeviceID string     `json:"approved_by_device_id,omitempty"`
	RejectedAt         *time.Time `json:"rejected_at,omitempty"`
	CompletedAt        *time.Time `json:"completed_at,omitempty"`
	SigningAlgorithm   string     `json:"signing_algorithm"`
	SigningPublicKey   []byte     `json:"-"`
	SigningFingerprint [32]byte   `json:"-"`
	KeyAlgorithm       string     `json:"key_agreement_algorithm"`
	KeyPublicKey       []byte     `json:"-"`
	KeyFingerprint     [32]byte   `json:"-"`
}

type ProvisioningApproval struct {
	RequestID            string
	Approver             Principal
	CertificateID        string
	CertificateVersion   int
	CertificatePayload   []byte
	SignatureAlgorithm   string
	Signature            []byte
	EncryptedPackage     []byte
	Nonce                []byte
	AADVersion           int
	PackageVersion       int
	CanonicalRequest     []byte
	RequestSignature     []byte
	IdempotencyRequestID string
	IdempotencyDigest    [32]byte
}

type ProvisioningPackage struct {
	RequestID      string     `json:"request_id"`
	TargetDeviceID string     `json:"target_device_id"`
	Encrypted      []byte     `json:"-"`
	Nonce          []byte     `json:"-"`
	AADVersion     int        `json:"aad_version"`
	PackageVersion int        `json:"package_version"`
	CreatedAt      time.Time  `json:"created_at"`
	ConsumedAt     *time.Time `json:"consumed_at,omitempty"`
	CertificateID  string     `json:"certificate_id"`
	Certificate    []byte     `json:"-"`
	CertificateSig []byte     `json:"-"`
	SignatureAlgo  string     `json:"signature_algorithm"`
	IssuerDeviceID string     `json:"issuer_device_id"`
}

type MigrationStatus struct {
	ID             string     `json:"id"`
	Kind           string     `json:"kind"`
	SourceVersion  int        `json:"source_version"`
	TargetVersion  int        `json:"target_version"`
	State          string     `json:"state"`
	LastSequence   int64      `json:"last_sequence"`
	ProcessedCount int64      `json:"processed_count"`
	VerifiedCount  int64      `json:"verified_count"`
	FailureCode    string     `json:"failure_code,omitempty"`
	UpdatedAt      time.Time  `json:"updated_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}
