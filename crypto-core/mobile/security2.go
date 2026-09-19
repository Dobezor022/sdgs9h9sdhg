package mobile

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	security2 "fedmes/security2"
)

func Security2Version() string { return "2.0.1/FSA2-1" }

func Security2GenerateUserRoot() (string, error) {
	return marshal(security2.GenerateUserRoot())
}

func Security2GenerateDeviceIdentity() (string, error) {
	return marshal(security2.GenerateDeviceIdentity())
}

func Security2SharedSecret(localPrivate, peerPublic string) (string, error) {
	secret, err := security2.SharedSecret(localPrivate, peerPublic)
	if err != nil {
		return "", err
	}
	defer security2.Zero(secret)
	return base64.RawURLEncoding.EncodeToString(secret), nil
}

func Security2NewRatchet(seedBase64, domain string, generation int64) (string, error) {
	seed, err := decodeFlexible(seedBase64, 32)
	if err != nil {
		return "", err
	}
	defer security2.Zero(seed)
	if generation <= 0 {
		return "", security2.ErrInvalidInput
	}
	return marshal(security2.NewRatchet(seed, domain, uint64(generation)))
}

type s2CapsuleResult struct {
	State   security2.RatchetState `json:"state"`
	Capsule security2.Capsule      `json:"capsule"`
}

func Security2EncryptCapsule(stateJSON, routeBase64 string, transportEpoch int64, plaintextBase64 string, padTo int) (string, error) {
	var state security2.RatchetState
	if err := decodeStrictJSON(stateJSON, &state); err != nil {
		return "", err
	}
	route, err := decodeFlexible(routeBase64, 16)
	if err != nil {
		return "", err
	}
	defer security2.Zero(route)
	plain, err := decodeFlexible(plaintextBase64, 0)
	if err != nil {
		return "", err
	}
	defer security2.Zero(plain)
	if transportEpoch <= 0 {
		return "", security2.ErrInvalidInput
	}
	capsule, err := security2.EncryptCapsule(&state, route, uint64(transportEpoch), plain, padTo)
	if err != nil {
		return "", err
	}
	return marshal(s2CapsuleResult{State: state, Capsule: capsule}, nil)
}

type s2PlainResult struct {
	State     security2.RatchetState `json:"state"`
	Plaintext string                 `json:"plaintext"`
}

func Security2DecryptCapsule(stateJSON, capsuleJSON, routeBase64 string, transportEpoch int64) (string, error) {
	var state security2.RatchetState
	if err := decodeStrictJSON(stateJSON, &state); err != nil {
		return "", err
	}
	var capsule security2.Capsule
	if err := decodeStrictJSON(capsuleJSON, &capsule); err != nil {
		return "", err
	}
	route, err := decodeFlexible(routeBase64, 16)
	if err != nil {
		return "", err
	}
	defer security2.Zero(route)
	if transportEpoch <= 0 {
		return "", security2.ErrInvalidInput
	}
	plain, err := security2.DecryptCapsule(&state, capsule, route, uint64(transportEpoch))
	if err != nil {
		return "", err
	}
	defer security2.Zero(plain)
	return marshal(s2PlainResult{State: state, Plaintext: base64.RawURLEncoding.EncodeToString(plain)}, nil)
}

func Security2HealRatchet(stateJSON, sharedBase64, transcriptBase64 string) (string, error) {
	var state security2.RatchetState
	if err := decodeStrictJSON(stateJSON, &state); err != nil {
		return "", err
	}
	shared, err := decodeFlexible(sharedBase64, 32)
	if err != nil {
		return "", err
	}
	defer security2.Zero(shared)
	transcript, err := decodeFlexible(transcriptBase64, 0)
	if err != nil {
		return "", err
	}
	defer security2.Zero(transcript)
	if err := state.MixFreshEntropy(shared, transcript); err != nil {
		return "", err
	}
	return marshal(state, nil)
}

func Security2NewCallRoot(sharedBase64, transcriptBase64 string) (string, error) {
	shared, err := decodeFlexible(sharedBase64, 32)
	if err != nil {
		return "", err
	}
	defer security2.Zero(shared)
	transcript, err := decodeFlexible(transcriptBase64, 0)
	if err != nil {
		return "", err
	}
	defer security2.Zero(transcript)
	root, err := security2.NewCallRoot(shared, transcript)
	if err != nil {
		return "", err
	}
	defer security2.Zero(root[:])
	return base64.RawURLEncoding.EncodeToString(root[:]), nil
}

func Security2MediaEpochKey(callRootBase64 string, domain int, direction int, epoch int64, freshBase64 string) (string, error) {
	rootBytes, err := decodeFlexible(callRootBase64, 32)
	if err != nil {
		return "", err
	}
	defer security2.Zero(rootBytes)
	var root [32]byte
	copy(root[:], rootBytes)
	var fresh []byte
	if freshBase64 != "" {
		fresh, err = decodeFlexible(freshBase64, 0)
		if err != nil {
			return "", err
		}
		defer security2.Zero(fresh)
	}
	if domain < int(security2.MediaAudio) || domain > int(security2.MediaRouting) || direction < 0 || direction > 255 || epoch <= 0 {
		return "", security2.ErrInvalidInput
	}
	key := security2.MediaEpochKey(root, security2.MediaDomain(domain), byte(direction), uint64(epoch), fresh)
	defer security2.Zero(key[:])
	return base64.RawURLEncoding.EncodeToString(key[:]), nil
}

func Security2EncryptMedia(epochKeyBase64, routeBase64 string, epoch, sequence int64, plaintextBase64 string) (string, error) {
	keyBytes, err := decodeFlexible(epochKeyBase64, 32)
	if err != nil {
		return "", err
	}
	defer security2.Zero(keyBytes)
	var key [32]byte
	copy(key[:], keyBytes)
	route, err := decodeFlexible(routeBase64, 16)
	if err != nil {
		return "", err
	}
	defer security2.Zero(route)
	plain, err := decodeFlexible(plaintextBase64, 0)
	if err != nil {
		return "", err
	}
	defer security2.Zero(plain)
	if epoch <= 0 || sequence < 0 {
		return "", security2.ErrInvalidInput
	}
	return marshal(security2.EncryptMediaPacket(key, route, uint64(epoch), uint64(sequence), plain))
}

func Security2DecryptMedia(epochKeyBase64, routeBase64, packetJSON string) (string, error) {
	keyBytes, err := decodeFlexible(epochKeyBase64, 32)
	if err != nil {
		return "", err
	}
	defer security2.Zero(keyBytes)
	var key [32]byte
	copy(key[:], keyBytes)
	route, err := decodeFlexible(routeBase64, 16)
	if err != nil {
		return "", err
	}
	defer security2.Zero(route)
	var packet security2.MediaPacket
	if err := decodeStrictJSON(packetJSON, &packet); err != nil {
		return "", err
	}
	plain, err := security2.DecryptMediaPacket(key, route, packet)
	if err != nil {
		return "", err
	}
	defer security2.Zero(plain)
	return base64.RawURLEncoding.EncodeToString(plain), nil
}

func Security2DeriveFileRoot(seedBase64, fileIDBase64 string) (string, error) {
	seed, err := decodeFlexible(seedBase64, 32)
	if err != nil {
		return "", err
	}
	defer security2.Zero(seed)
	id, err := decodeFlexible(fileIDBase64, 16)
	if err != nil {
		return "", err
	}
	defer security2.Zero(id)
	root, err := security2.DeriveFileRoot(seed, id)
	if err != nil {
		return "", err
	}
	defer security2.Zero(root[:])
	return base64.RawURLEncoding.EncodeToString(root[:]), nil
}
func Security2EncryptChunk(rootBase64, fileIDBase64 string, index int64, plainBase64 string) (string, error) {
	rootBytes, err := decodeFlexible(rootBase64, 32)
	if err != nil {
		return "", err
	}
	defer security2.Zero(rootBytes)
	var root [32]byte
	copy(root[:], rootBytes)
	id, err := decodeFlexible(fileIDBase64, 16)
	if err != nil {
		return "", err
	}
	defer security2.Zero(id)
	plain, err := decodeFlexible(plainBase64, 0)
	if err != nil {
		return "", err
	}
	defer security2.Zero(plain)
	if index < 0 {
		return "", security2.ErrInvalidInput
	}
	ct, err := security2.EncryptChunk(root, id, uint64(index), plain)
	if err != nil {
		return "", err
	}
	defer security2.Zero(ct)
	return base64.RawURLEncoding.EncodeToString(ct), nil
}
func Security2DecryptChunk(rootBase64, fileIDBase64 string, index int64, cipherBase64 string) (string, error) {
	rootBytes, err := decodeFlexible(rootBase64, 32)
	if err != nil {
		return "", err
	}
	defer security2.Zero(rootBytes)
	var root [32]byte
	copy(root[:], rootBytes)
	id, err := decodeFlexible(fileIDBase64, 16)
	if err != nil {
		return "", err
	}
	defer security2.Zero(id)
	ct, err := decodeFlexible(cipherBase64, 0)
	if err != nil {
		return "", err
	}
	defer security2.Zero(ct)
	if index < 0 {
		return "", security2.ErrInvalidInput
	}
	plain, err := security2.DecryptChunk(root, id, uint64(index), ct)
	if err != nil {
		return "", err
	}
	defer security2.Zero(plain)
	return base64.RawURLEncoding.EncodeToString(plain), nil
}

func Security2NewAdmissionRequest(userRootID string, generation, securityEpoch int64, deviceJSON string) (string, error) {
	if generation <= 0 || securityEpoch <= 0 {
		return "", security2.ErrInvalidInput
	}
	var d security2.TrustedDevice
	if err := decodeStrictJSON(deviceJSON, &d); err != nil {
		return "", err
	}
	return marshal(security2.NewAdmissionRequest(userRootID, uint64(generation), uint64(securityEpoch), d))
}
func Security2AdmissionCode(requestJSON string) (string, error) {
	var r security2.AdmissionRequest
	if err := decodeStrictJSON(requestJSON, &r); err != nil {
		return "", err
	}
	return r.HumanCode()
}
func Security2ApproveAdmission(requestJSON, approverDeviceID, signPrivate string) (string, error) {
	var r security2.AdmissionRequest
	if err := decodeStrictJSON(requestJSON, &r); err != nil {
		return "", err
	}
	return marshal(security2.ApproveAdmission(r, approverDeviceID, signPrivate))
}

func decodeFlexible(value string, minimum int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || (minimum > 0 && len(decoded) < minimum) {
		security2.Zero(decoded)
		return nil, security2.ErrInvalidInput
	}
	return decoded, nil
}
func decodeStrictJSON(value string, target any) error {
	dec := json.NewDecoder(strings.NewReader(value))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return security2.ErrInvalidInput
	}
	return nil
}

type s2MediaPlainResult struct {
	State     security2.MediaReceiveState `json:"state"`
	Plaintext string                      `json:"plaintext"`
}

func Security2DecryptMediaStateful(epochKeyBase64, routeBase64, packetJSON, stateJSON string) (string, error) {
	keyBytes, err := decodeFlexible(epochKeyBase64, 32)
	if err != nil {
		return "", err
	}
	defer security2.Zero(keyBytes)
	var key [32]byte
	copy(key[:], keyBytes)
	route, err := decodeFlexible(routeBase64, 16)
	if err != nil {
		return "", err
	}
	defer security2.Zero(route)
	var packet security2.MediaPacket
	if err := decodeStrictJSON(packetJSON, &packet); err != nil {
		return "", err
	}
	var state security2.MediaReceiveState
	if stateJSON != "" {
		if err := decodeStrictJSON(stateJSON, &state); err != nil {
			return "", err
		}
	}
	plain, err := security2.DecryptMediaPacketStateful(key, route, packet, &state)
	if err != nil {
		return "", err
	}
	defer security2.Zero(plain)
	return marshal(s2MediaPlainResult{State: state, Plaintext: base64.RawURLEncoding.EncodeToString(plain)}, nil)
}
