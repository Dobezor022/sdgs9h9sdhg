package provisioning

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
)

func TestValidateDevicePublicKeyAcceptsCanonicalP256SPKI(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	validated, err := ValidateDevicePublicKey(DevicePublicKeyInput{
		Algorithm:            DeviceKeyECDSAP256,
		SubjectPublicKeyInfo: encoded,
	})
	if err != nil {
		t.Fatalf("ValidateDevicePublicKey() error = %v", err)
	}
	if validated.Algorithm() != DeviceKeyECDSAP256 {
		t.Fatalf("algorithm = %q, want %q", validated.Algorithm(), DeviceKeyECDSAP256)
	}
	copyOfDER := validated.SubjectPublicKeyInfo()
	copyOfDER[0] ^= 0xff
	if validated.SubjectPublicKeyInfo()[0] == copyOfDER[0] {
		t.Fatal("SubjectPublicKeyInfo() exposed mutable internal storage")
	}
}

func TestValidateDevicePublicKeyRejectsAlgorithmMismatch(t *testing.T) {
	input := validEd25519Input(t)
	input.Algorithm = DeviceKeyECDSAP256
	_, err := ValidateDevicePublicKey(input)
	if !errors.Is(err, ErrInvalidDeviceKey) {
		t.Fatalf("ValidateDevicePublicKey() error = %v, want %v", err, ErrInvalidDeviceKey)
	}
}
