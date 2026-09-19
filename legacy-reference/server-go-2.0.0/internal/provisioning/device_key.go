package provisioning

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
)

const maximumPublicKeyBytes = 512

type DeviceKeyAlgorithm string

const (
	DeviceKeyEd25519   DeviceKeyAlgorithm = "ed25519"
	DeviceKeyECDSAP256 DeviceKeyAlgorithm = "ecdsa-p256-sha256"
)

// DevicePublicKeyInput is accepted only at the validation boundary. DER must
// contain an X.509 SubjectPublicKeyInfo structure, never a private key.
type DevicePublicKeyInput struct {
	Algorithm            DeviceKeyAlgorithm
	SubjectPublicKeyInfo []byte
}

func (input DevicePublicKeyInput) String() string {
	return "DevicePublicKeyInput{algorithm=" + string(input.Algorithm) + ", key=[REDACTED]}"
}

type DevicePublicKey struct {
	algorithm    DeviceKeyAlgorithm
	canonicalDER []byte
	fingerprint  [sha256.Size]byte
}

func (key DevicePublicKey) Algorithm() DeviceKeyAlgorithm {
	return key.algorithm
}

func (key DevicePublicKey) SubjectPublicKeyInfo() []byte {
	result := make([]byte, len(key.canonicalDER))
	copy(result, key.canonicalDER)
	return result
}

func (key DevicePublicKey) Fingerprint() [sha256.Size]byte {
	return key.fingerprint
}

func (key DevicePublicKey) FingerprintHex() string {
	return fingerprintHex(key.fingerprint)
}

func (key DevicePublicKey) String() string {
	return "DevicePublicKey{algorithm=" + string(key.algorithm) + ", fingerprint=" + key.FingerprintHex() + ", key=[REDACTED]}"
}

func (key DevicePublicKey) GoString() string {
	return key.String()
}

func (key DevicePublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Algorithm   DeviceKeyAlgorithm `json:"algorithm"`
		Fingerprint string             `json:"fingerprint"`
	}{
		Algorithm:   key.algorithm,
		Fingerprint: key.FingerprintHex(),
	})
}

func (key DevicePublicKey) clone() DevicePublicKey {
	cloned := key
	cloned.canonicalDER = key.SubjectPublicKeyInfo()
	return cloned
}

// ValidateDevicePublicKey parses, constrains, and canonicalizes a device key.
// The returned value is detached from the caller-owned input buffer.
func ValidateDevicePublicKey(input DevicePublicKeyInput) (DevicePublicKey, error) {
	if len(input.SubjectPublicKeyInfo) == 0 || len(input.SubjectPublicKeyInfo) > maximumPublicKeyBytes {
		return DevicePublicKey{}, newError(CodeInvalidDeviceKey, "public_key")
	}

	parsed, err := x509.ParsePKIXPublicKey(input.SubjectPublicKeyInfo)
	if err != nil {
		return DevicePublicKey{}, wrapError(CodeInvalidDeviceKey, "public_key", err)
	}

	switch input.Algorithm {
	case DeviceKeyEd25519:
		key, ok := parsed.(ed25519.PublicKey)
		if !ok || len(key) != ed25519.PublicKeySize {
			return DevicePublicKey{}, newError(CodeInvalidDeviceKey, "algorithm")
		}
	case DeviceKeyECDSAP256:
		key, ok := parsed.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() || key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
			return DevicePublicKey{}, newError(CodeInvalidDeviceKey, "algorithm")
		}
	default:
		return DevicePublicKey{}, newError(CodeInvalidDeviceKey, "algorithm")
	}

	canonical, err := x509.MarshalPKIXPublicKey(parsed)
	if err != nil {
		return DevicePublicKey{}, wrapError(CodeInvalidDeviceKey, "public_key", err)
	}
	if len(canonical) > maximumPublicKeyBytes {
		return DevicePublicKey{}, newError(CodeInvalidDeviceKey, "public_key")
	}

	// Reject alternate encodings so fingerprints have one stable byte form.
	if !bytes.Equal(canonical, input.SubjectPublicKeyInfo) {
		return DevicePublicKey{}, newError(CodeInvalidDeviceKey, "public_key")
	}

	return DevicePublicKey{
		algorithm:    input.Algorithm,
		canonicalDER: append([]byte(nil), canonical...),
		fingerprint:  sha256.Sum256(canonical),
	}, nil
}
