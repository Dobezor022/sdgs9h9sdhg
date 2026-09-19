package cryptomigration

import "time"

const ProtocolVersion = 4

type Principal struct{ Username, DeviceID string }

type Migration struct {
	ID             string     `json:"id"`
	Username       string     `json:"username"`
	Kind           string     `json:"migration_kind"`
	SourceVersion  int        `json:"source_version"`
	TargetVersion  int        `json:"target_version"`
	State          string     `json:"state"`
	LastSequence   int64      `json:"last_sequence"`
	ProcessedCount int64      `json:"processed_count"`
	VerifiedCount  int64      `json:"verified_count"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}
type LegacyMessage struct {
	Sequence                                   int64 `json:"sequence"`
	ID, ChatID, SenderUsername, SenderDeviceID string
	Ciphertext, Nonce                          []byte
	AAD                                        string
	CiphertextSHA256                           [32]byte
	CreatedAt                                  time.Time
}
type MessageReplacement struct {
	MigrationID, MessageID        string
	SourceHash                    [32]byte
	TargetCiphertext, TargetNonce []byte
	TargetAAD                     string
	TargetCryptoVersion           int
	TargetRoomKeyVersion          int64
	TargetAADVersion              int
	TargetAlgorithm               string
	TargetHash                    [32]byte
	Signature                     []byte
}
type MessageReplacementView struct {
	MessageReplacement
	UploadedByDeviceID string
	UploadedAt         time.Time
}
type LegacyMedia struct {
	ID, ChatID       string
	SizeBytes        int64
	CiphertextSHA256 [32]byte
	CreatedAt        time.Time
}
type MediaStageInput struct {
	MigrationID, MediaID   string
	SourceHash, TargetHash [32]byte
	TargetCryptoVersion    int
	TargetAlgorithm        string
	Signature              []byte
}
type MediaReplacementView struct {
	MigrationID, MediaID, StagedBlobName string
	SourceHash, TargetHash               [32]byte
	TargetSizeBytes                      int64
	TargetCryptoVersion                  int
	TargetAlgorithm, UploadedByDeviceID  string
	UploadedAt                           time.Time
}
