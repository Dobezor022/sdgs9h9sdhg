package provisioning

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
)

const MessageEncryptionAlgorithmRSAOAEP256 = "rsa-oaep-sha256"

// MessageEncryptionKeyInput is supplied by the client while redeeming a QR.
// Only the public key crosses the network; the private key remains in Android
// Keystore on the client.
type MessageEncryptionKeyInput struct {
	Algorithm            string
	SubjectPublicKeyInfo []byte
}

// MessageEncryptionKey is a canonical RSA public key accepted for wrapping
// per-message AES keys.
type MessageEncryptionKey struct {
	algorithm    string
	canonicalDER []byte
	fingerprint  [sha256.Size]byte
}

func ValidateMessageEncryptionKey(input MessageEncryptionKeyInput) (MessageEncryptionKey, error) {
	if input.Algorithm != MessageEncryptionAlgorithmRSAOAEP256 ||
		len(input.SubjectPublicKeyInfo) < 256 || len(input.SubjectPublicKeyInfo) > 1024 {
		return MessageEncryptionKey{}, newError(CodeInvalidEncryptionKey, "encryption_key")
	}
	parsed, err := x509.ParsePKIXPublicKey(input.SubjectPublicKeyInfo)
	if err != nil {
		return MessageEncryptionKey{}, newError(CodeInvalidEncryptionKey, "encryption_key")
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok || publicKey.N == nil || publicKey.N.BitLen() < 3072 || publicKey.N.BitLen() > 8192 || publicKey.E != 65537 {
		return MessageEncryptionKey{}, newError(CodeInvalidEncryptionKey, "encryption_key")
	}
	canonical, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil || !bytes.Equal(canonical, input.SubjectPublicKeyInfo) {
		clear(canonical)
		return MessageEncryptionKey{}, newError(CodeInvalidEncryptionKey, "encryption_key")
	}
	return MessageEncryptionKey{
		algorithm:    input.Algorithm,
		canonicalDER: canonical,
		fingerprint:  sha256.Sum256(canonical),
	}, nil
}

func (key MessageEncryptionKey) Algorithm() string { return key.algorithm }

func (key MessageEncryptionKey) SubjectPublicKeyInfo() []byte {
	result := make([]byte, len(key.canonicalDER))
	copy(result, key.canonicalDER)
	return result
}

func (key MessageEncryptionKey) Fingerprint() [sha256.Size]byte { return key.fingerprint }

func (key MessageEncryptionKey) clone() MessageEncryptionKey {
	return MessageEncryptionKey{
		algorithm:    key.algorithm,
		canonicalDER: key.SubjectPublicKeyInfo(),
		fingerprint:  key.fingerprint,
	}
}
