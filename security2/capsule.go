package security2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
)

const CapsuleVersion uint16 = 1

type Capsule struct {
	Version        uint16 `json:"version"`
	Route          string `json:"route"`
	TransportEpoch uint64 `json:"transport_epoch"`
	Generation     uint64 `json:"generation"`
	Position       uint64 `json:"position"`
	LengthClass    uint16 `json:"length_class"`
	Nonce          string `json:"nonce"`
	Ciphertext     string `json:"ciphertext"`
}

func EncryptCapsule(state *RatchetState, route []byte, transportEpoch uint64, plaintext []byte, padTo int) (Capsule, error) {
	if state == nil || len(route) < 16 || transportEpoch == 0 || len(plaintext) == 0 || len(plaintext) > 32<<20 {
		return Capsule{}, ErrInvalidInput
	}
	if padTo < len(plaintext)+4 {
		padTo = len(plaintext) + 4
	}
	if padTo > 32<<20 {
		return Capsule{}, ErrInvalidInput
	}
	padded := make([]byte, padTo)
	binary.BigEndian.PutUint32(padded[:4], uint32(len(plaintext)))
	copy(padded[4:], plaintext)
	if _, err := rand.Read(padded[4+len(plaintext):]); err != nil {
		Zero(padded)
		return Capsule{}, err
	}
	position := state.Counter
	generation := state.Generation
	nextState := *state
	key, err := nextState.Advance()
	if err != nil {
		Zero(padded)
		return Capsule{}, err
	}
	defer Zero(key[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		Zero(padded)
		return Capsule{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		Zero(padded)
		return Capsule{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		Zero(padded)
		return Capsule{}, err
	}
	aad := capsuleAAD(route, transportEpoch, generation, position, uint16(lengthClass(padTo)))
	ct := aead.Seal(nil, nonce, padded, aad)
	Zero(padded)
	*state = nextState
	return Capsule{Version: CapsuleVersion, Route: b64(route), TransportEpoch: transportEpoch, Generation: generation, Position: position, LengthClass: uint16(lengthClass(padTo)), Nonce: b64(nonce), Ciphertext: b64(ct)}, nil
}

func DecryptCapsule(state *RatchetState, c Capsule, expectedRoute []byte, expectedEpoch uint64) ([]byte, error) {
	if state == nil || c.Version != CapsuleVersion || c.TransportEpoch != expectedEpoch || c.Generation != state.Generation || c.Position != state.Counter {
		return nil, ErrReplay
	}
	route, err := base64.RawURLEncoding.Strict().DecodeString(c.Route)
	if err != nil || !equalMAC(route, expectedRoute) {
		Zero(route)
		return nil, ErrAuthentication
	}
	defer Zero(route)
	nonce, err := unb64(c.Nonce, 12)
	if err != nil {
		return nil, err
	}
	defer Zero(nonce)
	ct, err := base64.RawURLEncoding.Strict().DecodeString(c.Ciphertext)
	if err != nil {
		return nil, ErrInvalidInput
	}
	defer Zero(ct)
	nextState := *state
	key, err := nextState.Advance()
	if err != nil {
		return nil, err
	}
	defer Zero(key[:])
	block, _ := aes.NewCipher(key[:])
	aead, _ := cipher.NewGCM(block)
	aad := capsuleAAD(expectedRoute, c.TransportEpoch, c.Generation, c.Position, c.LengthClass)
	padded, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrAuthentication
	}
	if len(padded) < 4 {
		return nil, ErrAuthentication
	}
	n := int(binary.BigEndian.Uint32(padded[:4]))
	if n < 1 || n > len(padded)-4 {
		Zero(padded)
		return nil, ErrAuthentication
	}
	out := append([]byte(nil), padded[4:4+n]...)
	Zero(padded)
	*state = nextState
	return out, nil
}

func capsuleAAD(route []byte, epoch, generation, position uint64, class uint16) []byte {
	b := make([]byte, 0, len(route)+34)
	b = append(b, []byte("FedMes2/Capsule/v1")...)
	b = append(b, route...)
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], epoch)
	b = append(b, u[:]...)
	binary.BigEndian.PutUint64(u[:], generation)
	b = append(b, u[:]...)
	binary.BigEndian.PutUint64(u[:], position)
	b = append(b, u[:]...)
	var s [2]byte
	binary.BigEndian.PutUint16(s[:], class)
	b = append(b, s[:]...)
	return b
}
func lengthClass(n int) int {
	switch {
	case n <= 256:
		return 1
	case n <= 1024:
		return 2
	case n <= 4096:
		return 3
	case n <= 16384:
		return 4
	case n <= 65536:
		return 5
	default:
		return 6
	}
}
