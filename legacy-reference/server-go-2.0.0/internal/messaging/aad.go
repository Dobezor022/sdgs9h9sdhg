package messaging

import (
	"fmt"
	"strings"
)

const (
	MessageProtocolVersion   = "fedmes-message-v1"
	MessageProtocolVersionV2 = "fedmes-message-v2"
)

func CanonicalMessageAAD(chatID, username, deviceID, messageID string) string {
	return strings.Join([]string{MessageProtocolVersion, chatID, username, deviceID, messageID}, "\n")
}

// CanonicalMessageAADV2 binds every security-critical routing and key-version
// field to the ciphertext. cryptoSequence is reserved atomically before
// encryption, so retries never reuse a nonce/sequence pair.
func CanonicalMessageAADV2(chatID, username, deviceID, messageID, messageType string, cryptoSequence int64, roomKeyVersion int64) string {
	return strings.Join([]string{
		MessageProtocolVersionV2,
		chatID,
		messageID,
		username,
		deviceID,
		messageType,
		fmt.Sprintf("%d", cryptoSequence),
		fmt.Sprintf("%d", roomKeyVersion),
		"aad-v2",
	}, "\n")
}
