package security2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
)

type MediaDomain uint8

const (
	MediaAudio   MediaDomain = 1
	MediaVideo   MediaDomain = 2
	MediaScreen  MediaDomain = 3
	MediaControl MediaDomain = 4
	MediaRouting MediaDomain = 5
)

type MediaPacket struct {
	Route      string `json:"route"`
	Epoch      uint64 `json:"epoch"`
	Sequence   uint64 `json:"sequence"`
	Ciphertext string `json:"ciphertext"`
}

func NewCallRoot(sharedSecret, transcript []byte) ([32]byte, error) {
	if len(sharedSecret) < 32 || len(transcript) < 16 {
		return [32]byte{}, ErrInvalidInput
	}
	return Derive32(sharedSecret, "call/root", transcript), nil
}
func MediaEpochKey(callRoot [32]byte, domain MediaDomain, direction byte, epoch uint64, fresh []byte) [32]byte {
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], epoch)
	ctx := []byte{byte(domain), direction}
	if len(fresh) > 0 {
		mixed := append(append([]byte(nil), callRoot[:]...), fresh...)
		k := Derive32(mixed, "call/media-epoch", ctx, e[:])
		Zero(mixed)
		return k
	}
	return Derive32(callRoot[:], "call/media-epoch", ctx, e[:])
}
func EncryptMediaPacket(epochKey [32]byte, route []byte, epoch, seq uint64, plaintext []byte) (MediaPacket, error) {
	if len(route) < 16 || epoch == 0 || len(plaintext) == 0 || len(plaintext) > 2<<20 {
		return MediaPacket{}, ErrInvalidInput
	}
	k := packetKey(epochKey, seq)
	defer Zero(k[:])
	block, _ := aes.NewCipher(k[:])
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return MediaPacket{}, err
	}
	aad := mediaAAD(route, epoch, seq)
	sealed := aead.Seal(nonce, nonce, plaintext, aad)
	return MediaPacket{Route: b64(route), Epoch: epoch, Sequence: seq, Ciphertext: b64(sealed)}, nil
}
func DecryptMediaPacket(epochKey [32]byte, route []byte, p MediaPacket) ([]byte, error) {
	if p.Epoch == 0 {
		return nil, ErrInvalidInput
	}
	raw, err := unb64(p.Ciphertext, 0)
	if err != nil {
		return nil, err
	}
	defer Zero(raw)
	if len(raw) < 12 {
		return nil, ErrAuthentication
	}
	k := packetKey(epochKey, p.Sequence)
	defer Zero(k[:])
	block, _ := aes.NewCipher(k[:])
	aead, _ := cipher.NewGCM(block)
	n := aead.NonceSize()
	if len(raw) < n {
		return nil, ErrAuthentication
	}
	out, err := aead.Open(nil, raw[:n], raw[n:], mediaAAD(route, p.Epoch, p.Sequence))
	if err != nil {
		return nil, ErrAuthentication
	}
	return out, nil
}
func packetKey(epochKey [32]byte, seq uint64) [32]byte {
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	return Derive32(epochKey[:], "call/packet", s[:])
}
func mediaAAD(route []byte, epoch, seq uint64) []byte {
	b := append([]byte("FedMes2/Media/v1"), route...)
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], epoch)
	b = append(b, x[:]...)
	binary.BigEndian.PutUint64(x[:], seq)
	return append(b, x[:]...)
}

type MediaReceiveState struct {
	Epoch  uint64       `json:"epoch"`
	Replay ReplayWindow `json:"replay"`
}

// DecryptMediaPacketStateful authenticates first and commits replay state only
// after successful AEAD verification, preventing forged packets from consuming
// the replay window or advancing receiver state.
func DecryptMediaPacketStateful(epochKey [32]byte, route []byte, p MediaPacket, state *MediaReceiveState) ([]byte, error) {
	if state == nil || p.Epoch == 0 {
		return nil, ErrInvalidInput
	}
	if state.Epoch != 0 && p.Epoch < state.Epoch {
		return nil, ErrReplay
	}
	plain, err := DecryptMediaPacket(epochKey, route, p)
	if err != nil {
		return nil, err
	}
	next := *state
	if next.Epoch == 0 || p.Epoch > next.Epoch {
		next.Epoch = p.Epoch
		next.Replay = ReplayWindow{}
	}
	if err := next.Replay.Accept(p.Sequence); err != nil {
		Zero(plain)
		return nil, err
	}
	*state = next
	return plain, nil
}
