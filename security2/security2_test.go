package security2

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestIdentitySharedSecret(t *testing.T) {
	a, e := GenerateDeviceIdentity()
	if e != nil {
		t.Fatal(e)
	}
	b, e := GenerateDeviceIdentity()
	if e != nil {
		t.Fatal(e)
	}
	sa, e := SharedSecret(a.AgreementPrivate, b.AgreementPublic)
	if e != nil {
		t.Fatal(e)
	}
	defer Zero(sa)
	sb, e := SharedSecret(b.AgreementPrivate, a.AgreementPublic)
	if e != nil {
		t.Fatal(e)
	}
	defer Zero(sb)
	if !bytes.Equal(sa, sb) {
		t.Fatal("shared secret mismatch")
	}
}
func TestTrustChain(t *testing.T) {
	r, e := GenerateUserRoot()
	if e != nil {
		t.Fatal(e)
	}
	d, e := GenerateDeviceIdentity()
	if e != nil {
		t.Fatal(e)
	}
	s1 := TrustState{Version: TrustVersion, UserRootID: r.ID, Generation: 1, SecurityEpoch: 1, Devices: []TrustedDevice{{ID: d.ID, SignPublic: d.SignPublic, AgreementPublic: d.AgreementPublic, Status: DeviceActive, AdmittedAtGeneration: 1}}}
	if e = s1.Sign(r.SignPrivate); e != nil {
		t.Fatal(e)
	}
	if e = s1.Verify(r.SignPublic, nil); e != nil {
		t.Fatal(e)
	}
	h, _ := s1.Hash()
	s2 := s1
	s2.Generation = 2
	s2.PreviousHash = h
	s2.RootSignature = ""
	if e = s2.Sign(r.SignPrivate); e != nil {
		t.Fatal(e)
	}
	if e = s2.Verify(r.SignPublic, &s1); e != nil {
		t.Fatal(e)
	}
}
func TestAdmission(t *testing.T) {
	r, _ := GenerateUserRoot()
	old, _ := GenerateDeviceIdentity()
	next, _ := GenerateDeviceIdentity()
	state := TrustState{Version: TrustVersion, UserRootID: r.ID, Generation: 9, SecurityEpoch: 3, Devices: []TrustedDevice{{ID: old.ID, SignPublic: old.SignPublic, AgreementPublic: old.AgreementPublic, Status: DeviceActive, AdmittedAtGeneration: 1}}}
	_ = state.Sign(r.SignPrivate)
	req, e := NewAdmissionRequest(r.ID, 9, 3, TrustedDevice{ID: next.ID, SignPublic: next.SignPublic, AgreementPublic: next.AgreementPublic})
	if e != nil {
		t.Fatal(e)
	}
	code, e := req.HumanCode()
	if e != nil || len(code) != 8 {
		t.Fatalf("code=%q err=%v", code, e)
	}
	a, e := ApproveAdmission(req, old.ID, old.SignPrivate)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyAdmission(AdmissionCertificate{Request: req, Approvals: []DeviceApproval{a}}, state, 1); e != nil {
		t.Fatal(e)
	}
}
func TestCapsuleRoundTrip(t *testing.T) {
	seed, _ := RandomSeed()
	defer Zero(seed)
	send, _ := NewRatchet(seed, "conversation/A-to-B", 7)
	recv := send
	route := bytes.Repeat([]byte{7}, 16)
	plain := []byte("fedmes-2-secret")
	c, e := EncryptCapsule(&send, route, 11, plain, 256)
	if e != nil {
		t.Fatal(e)
	}
	out, e := DecryptCapsule(&recv, c, route, 11)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(out, plain) {
		t.Fatal("plaintext mismatch")
	}
	if _, e = DecryptCapsule(&recv, c, route, 11); e != ErrReplay {
		t.Fatalf("wanted replay, got %v", e)
	}
}
func TestHealing(t *testing.T) {
	seed, _ := RandomSeed()
	a, _ := NewRatchet(seed, "x", 1)
	before := a.RootKey
	shared, _ := RandomSeed()
	if e := a.MixFreshEntropy(shared, []byte("0123456789abcdef transcript")); e != nil {
		t.Fatal(e)
	}
	if a.RootKey == before || a.Generation != 2 || a.Counter != 0 {
		t.Fatal("healing did not rotate state")
	}
}
func TestBlob(t *testing.T) {
	seed, _ := RandomSeed()
	root, _ := DeriveFileRoot(seed, bytes.Repeat([]byte{1}, 16))
	ct, e := EncryptChunk(root, bytes.Repeat([]byte{1}, 16), 4, []byte("hello"))
	if e != nil {
		t.Fatal(e)
	}
	pt, e := DecryptChunk(root, bytes.Repeat([]byte{1}, 16), 4, ct)
	if e != nil || string(pt) != "hello" {
		t.Fatalf("%q %v", pt, e)
	}
}
func TestRealtime(t *testing.T) {
	shared, _ := RandomSeed()
	root, e := NewCallRoot(shared, []byte("0123456789abcdef call transcript"))
	if e != nil {
		t.Fatal(e)
	}
	key := MediaEpochKey(root, MediaAudio, 1, 5, nil)
	route := bytes.Repeat([]byte{2}, 16)
	p, e := EncryptMediaPacket(key, route, 5, 44, []byte("audio"))
	if e != nil {
		t.Fatal(e)
	}
	out, e := DecryptMediaPacket(key, route, p)
	if e != nil || string(out) != "audio" {
		t.Fatalf("%q %v", out, e)
	}
}
func TestReplayWindow(t *testing.T) {
	var w ReplayWindow
	if e := w.Accept(5); e != nil {
		t.Fatal(e)
	}
	if e := w.Accept(4); e != nil {
		t.Fatal(e)
	}
	if e := w.Accept(4); e != ErrReplay {
		t.Fatalf("got %v", e)
	}
}

func TestCapsuleAuthenticationFailureDoesNotAdvanceState(t *testing.T) {
	seed, _ := RandomSeed()
	send, _ := NewRatchet(seed, "tx", 1)
	recv := send
	route := bytes.Repeat([]byte{8}, 16)
	c, err := EncryptCapsule(&send, route, 1, []byte("ok"), 256)
	if err != nil {
		t.Fatal(err)
	}
	before := recv
	bad := c
	forged, err := base64.RawURLEncoding.Strict().DecodeString(c.Ciphertext)
	if err != nil || len(forged) == 0 {
		t.Fatalf("decode ciphertext: %v", err)
	}
	forged[len(forged)/2] ^= 0x80
	bad.Ciphertext = base64.RawURLEncoding.EncodeToString(forged)
	Zero(forged)
	if _, err = DecryptCapsule(&recv, bad, route, 1); err == nil {
		t.Fatal("expected authentication failure")
	}
	if recv.Counter != before.Counter || recv.ChainKey != before.ChainKey {
		t.Fatal("receiver state advanced on forged ciphertext")
	}
	if _, err = DecryptCapsule(&recv, c, route, 1); err != nil {
		t.Fatalf("valid capsule failed after forgery: %v", err)
	}
}

func TestRealtimeReplayState(t *testing.T) {
	shared, _ := RandomSeed()
	root, _ := NewCallRoot(shared, []byte("0123456789abcdef call transcript"))
	key := MediaEpochKey(root, MediaAudio, 1, 1, nil)
	route := bytes.Repeat([]byte{3}, 16)
	p, _ := EncryptMediaPacket(key, route, 1, 7, []byte("x"))
	var st MediaReceiveState
	plain, err := DecryptMediaPacketStateful(key, route, p, &st)
	if err != nil {
		t.Fatal(err)
	}
	Zero(plain)
	if _, err = DecryptMediaPacketStateful(key, route, p, &st); err != ErrReplay {
		t.Fatalf("expected replay, got %v", err)
	}
}

func TestTrustRejectsMismatchedRootIdentity(t *testing.T) {
	r1, _ := GenerateUserRoot()
	r2, _ := GenerateUserRoot()
	d, _ := GenerateDeviceIdentity()
	s := TrustState{Version: TrustVersion, UserRootID: r1.ID, Generation: 1, SecurityEpoch: 1, Devices: []TrustedDevice{{ID: d.ID, SignPublic: d.SignPublic, AgreementPublic: d.AgreementPublic, Status: DeviceActive, AdmittedAtGeneration: 1}}}
	if err := s.Sign(r1.SignPrivate); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(r2.SignPublic, nil); err != ErrAuthentication {
		t.Fatalf("expected authentication error, got %v", err)
	}
}

func TestAdmissionRejectsDeviceIDKeyMismatch(t *testing.T) {
	r, _ := GenerateUserRoot()
	old, _ := GenerateDeviceIdentity()
	next, _ := GenerateDeviceIdentity()
	state := TrustState{Version: TrustVersion, UserRootID: r.ID, Generation: 3, SecurityEpoch: 1, Devices: []TrustedDevice{{ID: old.ID, SignPublic: old.SignPublic, AgreementPublic: old.AgreementPublic, Status: DeviceActive, AdmittedAtGeneration: 1}}}
	if err := state.Sign(r.SignPrivate); err != nil {
		t.Fatal(err)
	}
	bad := TrustedDevice{ID: old.ID, SignPublic: next.SignPublic, AgreementPublic: next.AgreementPublic}
	if _, err := NewAdmissionRequest(r.ID, 3, 1, bad); err != ErrInvalidInput {
		t.Fatalf("expected invalid input, got %v", err)
	}
}
