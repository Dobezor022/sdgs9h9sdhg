package provisioning

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const (
	registrationResultKeyBytes = 32
	registrationNonceBytes     = 12
	maximumIdempotencyKeyBytes = 128
	minimumIdempotencyKeyBytes = 16
)

type registrationResultProtector struct {
	aead    cipher.AEAD
	entropy io.Reader
}

func newRegistrationResultProtector(key []byte, entropy io.Reader) (*registrationResultProtector, error) {
	if len(key) != registrationResultKeyBytes {
		return nil, newError(CodeInvalidConfiguration, "registration_result_key")
	}
	if entropy == nil {
		return nil, newError(CodeInvalidConfiguration, "entropy")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, wrapError(CodeInvalidConfiguration, "registration_result_key", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, wrapError(CodeInvalidConfiguration, "registration_result_key", err)
	}
	return &registrationResultProtector{aead: aead, entropy: entropy}, nil
}

func (p *registrationResultProtector) protect(
	idempotencyKey string,
	requestDigest TokenDigest,
	token string,
) ([]byte, error) {
	if p == nil || p.aead == nil || !validIdempotencyKey(idempotencyKey) {
		return nil, newError(CodeInvariantViolation, "registration_result")
	}
	plaintext := []byte(token)
	defer clear(plaintext)
	if len(plaintext) < MinimumTokenBytes || len(plaintext) > 256 {
		return nil, newError(CodeInvariantViolation, "session_token")
	}
	nonce := make([]byte, registrationNonceBytes)
	if _, err := io.ReadFull(p.entropy, nonce); err != nil {
		clear(nonce)
		return nil, wrapError(CodeEntropyUnavailable, "registration_result_nonce", err)
	}
	aad := registrationResultAAD(idempotencyKey, requestDigest)
	defer clear(aad)
	sealed := p.aead.Seal(nil, nonce, plaintext, aad)
	result := make([]byte, 1+len(nonce)+len(sealed))
	result[0] = 1
	copy(result[1:], nonce)
	copy(result[1+len(nonce):], sealed)
	clear(nonce)
	clear(sealed)
	return result, nil
}

func (p *registrationResultProtector) unprotect(
	idempotencyKey string,
	requestDigest TokenDigest,
	protected []byte,
) (string, error) {
	if p == nil || p.aead == nil || !validIdempotencyKey(idempotencyKey) {
		return "", newError(CodeInvariantViolation, "registration_result")
	}
	minimum := 1 + registrationNonceBytes + p.aead.Overhead() + MinimumTokenBytes
	if len(protected) < minimum || len(protected) > 512 || protected[0] != 1 {
		return "", newError(CodeInvariantViolation, "registration_result")
	}
	nonce := make([]byte, registrationNonceBytes)
	copy(nonce, protected[1:1+registrationNonceBytes])
	ciphertext := make([]byte, len(protected)-1-registrationNonceBytes)
	copy(ciphertext, protected[1+registrationNonceBytes:])
	defer clear(nonce)
	defer clear(ciphertext)
	aad := registrationResultAAD(idempotencyKey, requestDigest)
	defer clear(aad)
	plaintext, err := p.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return "", wrapError(CodeInvariantViolation, "registration_result", err)
	}
	defer clear(plaintext)
	encoded := string(plaintext)
	if _, err := parseSessionToken(encoded); err != nil {
		return "", newError(CodeInvariantViolation, "registration_result")
	}
	return encoded, nil
}

func registrationResultAAD(idempotencyKey string, requestDigest TokenDigest) []byte {
	result := make([]byte, 0, len(idempotencyKey)+1+len(requestDigest)+32)
	result = append(result, "fedmes-registration-result-v1\n"...)
	result = append(result, idempotencyKey...)
	result = append(result, '\n')
	result = append(result, requestDigest[:]...)
	return result
}

func validIdempotencyKey(value string) bool {
	if len(value) < minimumIdempotencyKeyBytes || len(value) > maximumIdempotencyKeyBytes {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func registrationRequestDigest(
	protocolVersion int,
	username Username,
	tokenDigest TokenDigest,
	deviceKey DevicePublicKey,
	encryptionKey MessageEncryptionKey,
) TokenDigest {
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "fedmes-registration-request-v1\n%d\n%s\n", protocolVersion, username)
	_, _ = hash.Write(tokenDigest[:])
	_, _ = hash.Write([]byte{'\n'})
	identityFingerprint := deviceKey.Fingerprint()
	_, _ = hash.Write(identityFingerprint[:])
	_, _ = hash.Write([]byte{'\n'})
	encryptionFingerprint := encryptionKey.Fingerprint()
	_, _ = hash.Write(encryptionFingerprint[:])
	var result TokenDigest
	copy(result[:], hash.Sum(nil))
	return result
}

func generateIdempotencyKey(entropy io.Reader) (string, error) {
	raw := make([]byte, 24)
	if _, err := io.ReadFull(entropy, raw); err != nil {
		clear(raw)
		return "", wrapError(CodeEntropyUnavailable, "idempotency_key", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	return encoded, nil
}

func parseSessionToken(encoded string) (SessionToken, error) {
	if len(encoded) < base64.RawURLEncoding.EncodedLen(MinimumTokenBytes) || len(encoded) > base64.RawURLEncoding.EncodedLen(MaximumTokenBytes) {
		return SessionToken{}, errors.New("invalid session token length")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) < MinimumTokenBytes || len(raw) > MaximumTokenBytes {
		clear(raw)
		return SessionToken{}, errors.New("invalid session token")
	}
	defer clear(raw)
	if !hmac.Equal([]byte(base64.RawURLEncoding.EncodeToString(raw)), []byte(encoded)) {
		return SessionToken{}, errors.New("non-canonical session token")
	}
	return SessionToken{encoded: encoded}, nil
}
