package security2

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

const RatchetVersion uint16 = 1

type RatchetState struct {
	Version    uint16 `json:"version"`
	Domain     string `json:"domain"`
	RootKey    string `json:"root_key"`
	ChainKey   string `json:"chain_key"`
	Counter    uint64 `json:"counter"`
	Generation uint64 `json:"generation"`
}

func NewRatchet(seed []byte, domain string, generation uint64) (RatchetState, error) {
	if len(seed) < 32 || domain == "" || generation == 0 {
		return RatchetState{}, ErrInvalidInput
	}
	root := Derive32(seed, "ratchet/root", []byte(domain))
	chain := Derive32(root[:], "ratchet/chain", []byte(domain))
	return RatchetState{Version: RatchetVersion, Domain: domain, RootKey: b64(root[:]), ChainKey: b64(chain[:]), Counter: 0, Generation: generation}, nil
}

func (s RatchetState) derive() (msg [32]byte, next [32]byte, err error) {
	if s.Version != RatchetVersion || s.Domain == "" || s.Generation == 0 {
		return msg, next, ErrInvalidInput
	}
	ck, e := unb64(s.ChainKey, 32)
	if e != nil {
		return msg, next, e
	}
	defer Zero(ck)
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], s.Counter)
	msg = Derive32(ck, "ratchet/message", []byte(s.Domain), ctr[:])
	next = Derive32(ck, "ratchet/next", []byte(s.Domain), ctr[:])
	return
}
func (s *RatchetState) Advance() ([32]byte, error) {
	msg, next, err := s.derive()
	if err != nil {
		return msg, err
	}
	s.ChainKey = b64(next[:])
	s.Counter++
	Zero(next[:])
	return msg, nil
}

func (s *RatchetState) MixFreshEntropy(shared, transcript []byte) error {
	if len(shared) < 32 || len(transcript) == 0 {
		return ErrInvalidInput
	}
	root, e := unb64(s.RootKey, 32)
	if e != nil {
		return e
	}
	defer Zero(root)
	mix := make([]byte, 0, len(root)+len(shared))
	mix = append(mix, root...)
	mix = append(mix, shared...)
	nr := Derive32(mix, "ratchet/heal", []byte(s.Domain), transcript)
	Zero(mix)
	nc := Derive32(nr[:], "ratchet/healed-chain", []byte(s.Domain))
	s.RootKey = b64(nr[:])
	s.ChainKey = b64(nc[:])
	s.Counter = 0
	s.Generation++
	Zero(nr[:])
	Zero(nc[:])
	return nil
}

func RandomSeed() ([]byte, error) { b := make([]byte, 32); _, err := rand.Read(b); return b, err }
func equalMAC(a, b []byte) bool   { return hmac.Equal(a, b) }
func hash32(b []byte) [32]byte    { return sha256.Sum256(b) }
