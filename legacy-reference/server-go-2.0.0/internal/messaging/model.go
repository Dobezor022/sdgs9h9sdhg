package messaging

import "time"

type Principal struct {
	Username      string `json:"username"`
	DeviceID      string `json:"device_id"`
	SessionID     string `json:"session_id"`
	SecurityState string `json:"security_state"`
}

type Chat struct {
	ID              string     `json:"id"`
	Kind            string     `json:"kind"`
	Title           string     `json:"title"`
	Members         []string   `json:"members"`
	LastSequence    int64      `json:"last_sequence"`
	LastMessageAt   *time.Time `json:"last_message_at,omitempty"`
	PinnedMessageID string     `json:"pinned_message_id,omitempty"`
	UnreadCount     int        `json:"unread_count"`
}

type Device struct {
	ID                      string `json:"id"`
	Username                string `json:"username"`
	IdentityAlgorithm       string `json:"identity_algorithm"`
	IdentityPublicKeySPKI   string `json:"identity_public_key_spki"`
	EncryptionAlgorithm     string `json:"encryption_algorithm,omitempty"`
	EncryptionPublicKeySPKI string `json:"encryption_public_key_spki,omitempty"`
	RatchetBundleVersion    int    `json:"ratchet_bundle_version"`
}

type RatchetEnvelope struct {
	RecipientDeviceID   string `json:"recipient_device_id"`
	SenderCurve25519Key string `json:"sender_curve25519_key"`
	SessionID           string `json:"session_id"`
	MessageType         int    `json:"message_type"`
	CiphertextBase64    string `json:"ciphertext"`
	CiphertextSHA256    string `json:"ciphertext_sha256"`
}

type Envelope struct {
	DeviceID         string `json:"device_id"`
	Algorithm        string `json:"algorithm"`
	CiphertextBase64 string `json:"ciphertext"`
}

type Message struct {
	Sequence            int64            `json:"sequence"`
	ID                  string           `json:"id"`
	ChatID              string           `json:"chat_id"`
	SenderUsername      string           `json:"sender_username"`
	SenderDeviceID      string           `json:"sender_device_id"`
	CiphertextBase64    string           `json:"ciphertext"`
	NonceBase64         string           `json:"nonce"`
	AAD                 string           `json:"aad"`
	CryptoVersion       int              `json:"crypto_version"`
	RoomKeyVersion      int64            `json:"room_key_version"`
	AADVersion          int              `json:"aad_version"`
	CryptoSequence      int64            `json:"crypto_sequence"`
	EncryptionAlgorithm string           `json:"encryption_algorithm"`
	MessageType         string           `json:"message_type"`
	RatchetEnvelope     *RatchetEnvelope `json:"ratchet_envelope,omitempty"`
	CreatedAt           time.Time        `json:"created_at"`
	EditedAt            *time.Time       `json:"edited_at,omitempty"`
	Envelope            *Envelope        `json:"envelope,omitempty"`
	EnvelopeDeviceIDs   []string         `json:"envelope_device_ids"`
	RecipientCount      int              `json:"recipient_count"`
	DeliveredCount      int              `json:"delivered_count"`
	ReadCount           int              `json:"read_count"`
}

type MessagePage struct {
	Messages      []Message
	HasMoreBefore bool
}

type NewMessage struct {
	ID                  string
	ChatID              string
	Sender              Principal
	Ciphertext          []byte
	Nonce               []byte
	AAD                 string
	CryptoVersion       int
	RoomKeyVersion      int64
	AADVersion          int
	CryptoSequence      int64
	EncryptionAlgorithm string
	MessageType         string
	SequenceRequestID   string
	Envelopes           []DecodedEnvelope
	RatchetEnvelopes    []DecodedRatchetEnvelope
}

type DecodedRatchetEnvelope struct {
	RecipientDeviceID   string
	SenderCurve25519Key string
	SessionID           string
	MessageType         int
	Ciphertext          []byte
	CiphertextSHA256    [32]byte
}

type DecodedEnvelope struct {
	DeviceID   string
	Algorithm  string
	Ciphertext []byte
}

type Presence struct {
	Username         string     `json:"username"`
	Online           bool       `json:"online"`
	LastSeen         *time.Time `json:"last_seen_at,omitempty"`
	ShowExact        bool       `json:"show_exact"`
	LastSeenCategory string     `json:"last_seen_category"`
}

type TypingUser struct {
	Username string `json:"username"`
}

type MediaObject struct {
	ID               string
	ChatID           string
	UploaderUsername string
	UploaderDeviceID string
	BlobName         string
	SizeBytes        int64
	SHA256           [32]byte
	CreatedAt        time.Time
}
