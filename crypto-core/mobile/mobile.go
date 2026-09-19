// Package mobile exposes a gomobile-compatible API used by both Android flavours.
package mobile

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"fedmes/crypto/core"
)

var opaqueClients = core.NewOpaqueClientRegistry()

func Version() string { return "2.0.1-20001" }

func OpaqueRegistrationStart(password string) (string, error) {
	secret := []byte(password)
	defer zero(secret)
	result, err := opaqueClients.RegistrationStart(secret)
	return marshal(result, err)
}

func OpaqueRegistrationFinish(handle, response, username, serverIdentity string) (string, error) {
	return marshal(opaqueClients.RegistrationFinish(handle, response, []byte(username), []byte(serverIdentity)))
}

func OpaqueLoginStart(password string) (string, error) {
	secret := []byte(password)
	defer zero(secret)
	result, err := opaqueClients.LoginStart(secret)
	return marshal(result, err)
}

func OpaqueLoginFinish(handle, response, username, serverIdentity string) (string, error) {
	return marshal(opaqueClients.LoginFinish(handle, response, []byte(username), []byte(serverIdentity)))
}

func OpaqueCancel(handle string) { opaqueClients.Cancel(handle) }

func OlmCreateAccount(pickleKeyBase64 string, oneTimeKeyCount int) (string, error) {
	key, err := decodeKey(pickleKeyBase64)
	if err != nil {
		return "", err
	}
	defer zero(key)
	return marshal(core.CreateOlmAccount(key, uint(max(oneTimeKeyCount, 0))))
}

func OlmRefillOneTimeKeys(accountPickle, pickleKeyBase64 string, count int) (string, error) {
	key, err := decodeKey(pickleKeyBase64)
	if err != nil {
		return "", err
	}
	defer zero(key)
	return marshal(core.RefillOneTimeKeys(accountPickle, key, uint(max(count, 0))))
}

func OlmMarkKeysPublished(accountPickle, pickleKeyBase64 string) (string, error) {
	key, err := decodeKey(pickleKeyBase64)
	if err != nil {
		return "", err
	}
	defer zero(key)
	return core.MarkOneTimeKeysPublished(accountPickle, key)
}

func OlmCreateOutbound(accountPickle, pickleKeyBase64, identityKey, oneTimeKey string) (string, error) {
	key, err := decodeKey(pickleKeyBase64)
	if err != nil {
		return "", err
	}
	defer zero(key)
	return marshal(core.CreateOutboundOlmSession(accountPickle, key, identityKey, oneTimeKey))
}

func OlmEncrypt(sessionPickle, pickleKeyBase64, plaintextBase64 string) (string, error) {
	key, plaintext, err := decodeKeyAndData(pickleKeyBase64, plaintextBase64)
	if err != nil {
		return "", err
	}
	defer zero(key)
	defer zero(plaintext)
	return marshal(core.EncryptOlm(sessionPickle, key, plaintext))
}

func OlmCreateInbound(accountPickle, pickleKeyBase64, identityKey, ciphertext string, messageType int) (string, error) {
	key, err := decodeKey(pickleKeyBase64)
	if err != nil {
		return "", err
	}
	defer zero(key)
	return marshal(core.CreateInboundOlmSession(accountPickle, key, identityKey, ciphertext, messageType))
}

func OlmDecrypt(sessionPickle, pickleKeyBase64, ciphertext string, messageType int) (string, error) {
	key, err := decodeKey(pickleKeyBase64)
	if err != nil {
		return "", err
	}
	defer zero(key)
	return marshal(core.DecryptOlm(sessionPickle, key, ciphertext, messageType))
}

func MegolmCreateOutbound(pickleKeyBase64 string) (string, error) {
	key, err := decodeKey(pickleKeyBase64)
	if err != nil {
		return "", err
	}
	defer zero(key)
	return marshal(core.CreateOutboundMegolmSession(key))
}

func MegolmEncrypt(sessionPickle, pickleKeyBase64, plaintextBase64 string) (string, error) {
	key, plaintext, err := decodeKeyAndData(pickleKeyBase64, plaintextBase64)
	if err != nil {
		return "", err
	}
	defer zero(key)
	defer zero(plaintext)
	return marshal(core.EncryptMegolm(sessionPickle, key, plaintext))
}

func MegolmCreateInbound(sessionKey, pickleKeyBase64 string) (string, error) {
	key, err := decodeKey(pickleKeyBase64)
	if err != nil {
		return "", err
	}
	defer zero(key)
	return core.CreateInboundMegolmSession(sessionKey, key)
}

func MegolmDecrypt(sessionPickle, pickleKeyBase64, ciphertext string) (string, error) {
	key, err := decodeKey(pickleKeyBase64)
	if err != nil {
		return "", err
	}
	defer zero(key)
	return marshal(core.DecryptMegolm(sessionPickle, key, ciphertext))
}

func marshal(value any, err error) (string, error) {
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func decodeKey(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 {
		zero(decoded)
		return nil, errors.New("invalid 32-byte key")
	}
	return decoded, nil
}

func decodeKeyAndData(keyValue, dataValue string) ([]byte, []byte, error) {
	key, err := decodeKey(keyValue)
	if err != nil {
		return nil, nil, err
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(dataValue)
	if err != nil || len(data) == 0 || len(data) > 16<<20 {
		zero(key)
		zero(data)
		return nil, nil, errors.New("invalid data")
	}
	return key, data, nil
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
