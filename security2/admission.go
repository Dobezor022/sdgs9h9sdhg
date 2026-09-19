package security2

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"strings"
)

type AdmissionRequest struct {
	UserRootID        string        `json:"user_root_id"`
	CurrentGeneration uint64        `json:"current_generation"`
	SecurityEpoch     uint64        `json:"security_epoch"`
	Device            TrustedDevice `json:"device"`
	Nonce             string        `json:"nonce"`
}

type DeviceApproval struct {
	DeviceID  string `json:"device_id"`
	Signature string `json:"signature"`
}

type AdmissionCertificate struct {
	Request   AdmissionRequest `json:"request"`
	Approvals []DeviceApproval `json:"approvals"`
}

func NewAdmissionRequest(userRootID string, generation, securityEpoch uint64, d TrustedDevice) (AdmissionRequest, error) {
	if userRootID == "" || generation == 0 || securityEpoch == 0 || d.ID == "" {
		return AdmissionRequest{}, ErrInvalidInput
	}
	n := make([]byte, 24)
	if _, err := rand.Read(n); err != nil {
		return AdmissionRequest{}, err
	}
	defer Zero(n)
	derivedID, err := DeviceIDFromPublic(d.SignPublic, d.AgreementPublic)
	if err != nil || derivedID != d.ID {
		return AdmissionRequest{}, ErrInvalidInput
	}
	d.Status = DeviceProvisional
	d.AdmittedAtGeneration = generation + 1
	return AdmissionRequest{UserRootID: userRootID, CurrentGeneration: generation, SecurityEpoch: securityEpoch, Device: d, Nonce: b64(n)}, nil
}
func (r AdmissionRequest) Canonical() ([]byte, error) {
	if r.UserRootID == "" || r.CurrentGeneration == 0 || r.SecurityEpoch == 0 || r.Device.ID == "" || r.Nonce == "" {
		return nil, ErrInvalidInput
	}
	var b bytes.Buffer
	writeString(&b, r.UserRootID)
	_ = binary.Write(&b, binary.BigEndian, r.CurrentGeneration)
	_ = binary.Write(&b, binary.BigEndian, r.SecurityEpoch)
	writeString(&b, r.Device.ID)
	writeString(&b, r.Device.SignPublic)
	writeString(&b, r.Device.AgreementPublic)
	b.WriteByte(byte(r.Device.Status))
	_ = binary.Write(&b, binary.BigEndian, r.Device.AdmittedAtGeneration)
	writeString(&b, r.Nonce)
	return b.Bytes(), nil
}
func (r AdmissionRequest) HumanCode() (string, error) {
	b, err := r.Canonical()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(append([]byte("FedMes2/admission-code/"), b...))
	alphabet := "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	chars := make([]byte, 6)
	v := binary.BigEndian.Uint64(h[:8])
	for i := range chars {
		chars[i] = alphabet[v%uint64(len(alphabet))]
		v /= uint64(len(alphabet))
	}
	return strings.Join([]string{string(chars[:2]), string(chars[2:4]), string(chars[4:])}, " "), nil
}
func ApproveAdmission(r AdmissionRequest, approverDeviceID, approverSignPrivate string) (DeviceApproval, error) {
	b, err := r.Canonical()
	if err != nil {
		return DeviceApproval{}, err
	}
	sig, err := Sign(approverSignPrivate, b)
	if err != nil {
		return DeviceApproval{}, err
	}
	return DeviceApproval{DeviceID: approverDeviceID, Signature: sig}, nil
}
func VerifyAdmission(cert AdmissionCertificate, current TrustState, quorum int) error {
	if quorum < 1 {
		return ErrInvalidInput
	}
	if cert.Request.CurrentGeneration != current.Generation || cert.Request.SecurityEpoch != current.SecurityEpoch || cert.Request.UserRootID != current.UserRootID {
		return ErrRollback
	}
	if cert.Request.Device.Status != DeviceProvisional || cert.Request.Device.AdmittedAtGeneration != current.Generation+1 {
		return ErrInvalidInput
	}
	derivedID, err := DeviceIDFromPublic(cert.Request.Device.SignPublic, cert.Request.Device.AgreementPublic)
	if err != nil || derivedID != cert.Request.Device.ID {
		return ErrInvalidInput
	}
	for _, existing := range current.Devices {
		if existing.ID == cert.Request.Device.ID {
			return ErrInvalidInput
		}
	}
	payload, err := cert.Request.Canonical()
	if err != nil {
		return err
	}
	pubs := map[string]string{}
	for _, d := range current.Devices {
		if d.Status == DeviceActive {
			pubs[d.ID] = d.SignPublic
		}
	}
	valid := map[string]struct{}{}
	for _, a := range cert.Approvals {
		pub, ok := pubs[a.DeviceID]
		if !ok {
			continue
		}
		if Verify(pub, payload, a.Signature) {
			valid[a.DeviceID] = struct{}{}
		}
	}
	if len(valid) < quorum {
		return ErrQuorum
	}
	return nil
}
