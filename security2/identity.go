package security2

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

type UserRoot struct {
	ID          string `json:"id"`
	SignPublic  string `json:"sign_public"`
	SignPrivate string `json:"sign_private"`
}

type DeviceIdentity struct {
	ID               string `json:"id"`
	SignPublic       string `json:"sign_public"`
	SignPrivate      string `json:"sign_private"`
	AgreementPublic  string `json:"agreement_public"`
	AgreementPrivate string `json:"agreement_private"`
}

func GenerateUserRoot() (UserRoot, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return UserRoot{}, err
	}
	id := identifier("user", pub)
	return UserRoot{ID: id, SignPublic: b64(pub), SignPrivate: b64(priv)}, nil
}

func GenerateDeviceIdentity() (DeviceIdentity, error) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return DeviceIdentity{}, err
	}
	curve := ecdh.X25519()
	agreePriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return DeviceIdentity{}, err
	}
	agreePub := agreePriv.PublicKey().Bytes()
	idMaterial := append(append([]byte(nil), signPub...), agreePub...)
	id := identifier("device", idMaterial)
	Zero(idMaterial)
	return DeviceIdentity{
		ID:         id,
		SignPublic: b64(signPub), SignPrivate: b64(signPriv),
		AgreementPublic: b64(agreePub), AgreementPrivate: b64(agreePriv.Bytes()),
	}, nil
}

func UserRootIDFromPublic(publicB64 string) (string, error) {
	pub, err := unb64(publicB64, ed25519.PublicKeySize)
	if err != nil {
		return "", err
	}
	defer Zero(pub)
	return identifier("user", pub), nil
}

func DeviceIDFromPublic(signPublicB64, agreementPublicB64 string) (string, error) {
	signPub, err := unb64(signPublicB64, ed25519.PublicKeySize)
	if err != nil {
		return "", err
	}
	defer Zero(signPub)
	agreePub, err := unb64(agreementPublicB64, 32)
	if err != nil {
		return "", err
	}
	defer Zero(agreePub)
	material := make([]byte, 0, len(signPub)+len(agreePub))
	material = append(material, signPub...)
	material = append(material, agreePub...)
	id := identifier("device", material)
	Zero(material)
	return id, nil
}

func SharedSecret(localPrivateB64, peerPublicB64 string) ([]byte, error) {
	privBytes, err := unb64(localPrivateB64, 32)
	if err != nil {
		return nil, err
	}
	defer Zero(privBytes)
	pubBytes, err := unb64(peerPublicB64, 32)
	if err != nil {
		return nil, err
	}
	defer Zero(pubBytes)
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return nil, ErrInvalidInput
	}
	pub, err := curve.NewPublicKey(pubBytes)
	if err != nil {
		return nil, ErrInvalidInput
	}
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, ErrAuthentication
	}
	if allZero(secret) {
		Zero(secret)
		return nil, ErrAuthentication
	}
	return secret, nil
}

func Sign(privateB64 string, message []byte) (string, error) {
	key, err := unb64(privateB64, ed25519.PrivateKeySize)
	if err != nil {
		return "", err
	}
	defer Zero(key)
	return b64(ed25519.Sign(ed25519.PrivateKey(key), message)), nil
}

func Verify(publicB64 string, message []byte, signatureB64 string) bool {
	pub, err := unb64(publicB64, ed25519.PublicKeySize)
	if err != nil {
		return false
	}
	defer Zero(pub)
	sig, err := unb64(signatureB64, ed25519.SignatureSize)
	if err != nil {
		return false
	}
	defer Zero(sig)
	return ed25519.Verify(ed25519.PublicKey(pub), message, sig)
}

func identifier(domain string, material []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte("FedMes2/" + domain + "/"))
	_, _ = h.Write(material)
	sum := h.Sum(nil)
	defer Zero(sum)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func unb64(s string, exact int) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || (exact > 0 && len(b) != exact) {
		Zero(b)
		return nil, ErrInvalidInput
	}
	return b, nil
}
func allZero(b []byte) bool {
	var v byte
	for _, x := range b {
		v |= x
	}
	return v == 0
}
