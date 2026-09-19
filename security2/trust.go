package security2

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

const TrustVersion uint16 = 1

type DeviceStatus uint8

const (
	DeviceProvisional DeviceStatus = 1
	DeviceActive      DeviceStatus = 2
	DeviceQuarantined DeviceStatus = 3
	DeviceRevoked     DeviceStatus = 4
	DeviceExpired     DeviceStatus = 5
)

type TrustedDevice struct {
	ID                   string       `json:"id"`
	SignPublic           string       `json:"sign_public"`
	AgreementPublic      string       `json:"agreement_public"`
	Status               DeviceStatus `json:"status"`
	AdmittedAtGeneration uint64       `json:"admitted_at_generation"`
}

type TrustState struct {
	Version       uint16          `json:"version"`
	UserRootID    string          `json:"user_root_id"`
	Generation    uint64          `json:"generation"`
	SecurityEpoch uint64          `json:"security_epoch"`
	PreviousHash  string          `json:"previous_hash"`
	Devices       []TrustedDevice `json:"devices"`
	RootSignature string          `json:"root_signature"`
}

func (s TrustState) CanonicalUnsigned() ([]byte, error) {
	if s.Version != TrustVersion || s.UserRootID == "" || s.Generation == 0 || s.SecurityEpoch == 0 {
		return nil, ErrInvalidInput
	}
	devices := append([]TrustedDevice(nil), s.Devices...)
	sort.Slice(devices, func(i, j int) bool { return devices[i].ID < devices[j].ID })
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, s.Version)
	writeString(&b, s.UserRootID)
	_ = binary.Write(&b, binary.BigEndian, s.Generation)
	_ = binary.Write(&b, binary.BigEndian, s.SecurityEpoch)
	writeString(&b, s.PreviousHash)
	_ = binary.Write(&b, binary.BigEndian, uint32(len(devices)))
	seen := map[string]struct{}{}
	for _, d := range devices {
		if d.ID == "" || d.SignPublic == "" || d.AgreementPublic == "" || d.Status < DeviceProvisional || d.Status > DeviceExpired || d.AdmittedAtGeneration == 0 || d.AdmittedAtGeneration > s.Generation {
			return nil, ErrInvalidInput
		}
		derivedID, err := DeviceIDFromPublic(d.SignPublic, d.AgreementPublic)
		if err != nil || derivedID != d.ID {
			return nil, ErrInvalidInput
		}
		if _, ok := seen[d.ID]; ok {
			return nil, ErrInvalidInput
		}
		seen[d.ID] = struct{}{}
		writeString(&b, d.ID)
		writeString(&b, d.SignPublic)
		writeString(&b, d.AgreementPublic)
		b.WriteByte(byte(d.Status))
		_ = binary.Write(&b, binary.BigEndian, d.AdmittedAtGeneration)
	}
	return b.Bytes(), nil
}

func (s TrustState) Hash() (string, error) {
	b, err := s.CanonicalUnsigned()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return b64(sum[:]), nil
}
func (s *TrustState) Sign(rootPrivate string) error {
	b, err := s.CanonicalUnsigned()
	if err != nil {
		return err
	}
	sig, err := Sign(rootPrivate, b)
	if err != nil {
		return err
	}
	s.RootSignature = sig
	return nil
}
func (s TrustState) Verify(rootPublic string, previous *TrustState) error {
	rootID, err := UserRootIDFromPublic(rootPublic)
	if err != nil || rootID != s.UserRootID {
		return ErrAuthentication
	}
	b, err := s.CanonicalUnsigned()
	if err != nil {
		return err
	}
	if !Verify(rootPublic, b, s.RootSignature) {
		return ErrAuthentication
	}
	if previous == nil {
		if s.Generation != 1 || s.PreviousHash != "" {
			return ErrRollback
		}
	} else {
		if s.Generation != previous.Generation+1 || s.SecurityEpoch < previous.SecurityEpoch {
			return ErrRollback
		}
		h, err := previous.Hash()
		if err != nil {
			return err
		}
		if s.PreviousHash != h {
			return ErrTrustFork
		}
	}
	return nil
}

func writeString(b *bytes.Buffer, s string) {
	_ = binary.Write(b, binary.BigEndian, uint32(len(s)))
	b.WriteString(s)
}
