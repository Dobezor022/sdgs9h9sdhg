package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"fedmes/crypto/mobile"
)

const maxRequestBytes = 32 << 20

type request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type response struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Value string `json:"value,omitempty"`
	Error string `json:"error,omitempty"`
}

type opaqueStartParams struct {
	Password string `json:"password"`
}
type opaqueFinishParams struct {
	Handle         string `json:"handle"`
	Response       string `json:"response"`
	Username       string `json:"username"`
	ServerIdentity string `json:"server_identity"`
}
type cancelParams struct {
	Handle string `json:"handle"`
}
type olmCreateParams struct {
	PickleKey string `json:"pickle_key"`
	Count     int    `json:"count"`
}
type olmRefillParams struct {
	AccountPickle string `json:"account_pickle"`
	PickleKey     string `json:"pickle_key"`
	Count         int    `json:"count"`
}
type olmMarkParams struct {
	AccountPickle string `json:"account_pickle"`
	PickleKey     string `json:"pickle_key"`
}
type olmOutboundParams struct {
	AccountPickle string `json:"account_pickle"`
	PickleKey     string `json:"pickle_key"`
	IdentityKey   string `json:"identity_key"`
	OneTimeKey    string `json:"one_time_key"`
}
type olmEncryptParams struct {
	SessionPickle string `json:"session_pickle"`
	PickleKey     string `json:"pickle_key"`
	Plaintext     string `json:"plaintext"`
}
type olmInboundParams struct {
	AccountPickle string `json:"account_pickle"`
	PickleKey     string `json:"pickle_key"`
	IdentityKey   string `json:"identity_key"`
	Ciphertext    string `json:"ciphertext"`
	MessageType   int    `json:"message_type"`
}
type olmDecryptParams struct {
	SessionPickle string `json:"session_pickle"`
	PickleKey     string `json:"pickle_key"`
	Ciphertext    string `json:"ciphertext"`
	MessageType   int    `json:"message_type"`
}
type megolmCreateParams struct {
	PickleKey string `json:"pickle_key"`
}
type megolmEncryptParams struct {
	SessionPickle string `json:"session_pickle"`
	PickleKey     string `json:"pickle_key"`
	Plaintext     string `json:"plaintext"`
}
type megolmInboundParams struct {
	SessionKey string `json:"session_key"`
	PickleKey  string `json:"pickle_key"`
}
type megolmDecryptParams struct {
	SessionPickle string `json:"session_pickle"`
	PickleKey     string `json:"pickle_key"`
	Ciphertext    string `json:"ciphertext"`
}

type s2SharedParams struct {
	LocalPrivate string `json:"local_private"`
	PeerPublic   string `json:"peer_public"`
}
type s2RatchetParams struct {
	Seed       string `json:"seed"`
	Domain     string `json:"domain"`
	Generation int64  `json:"generation"`
}
type s2EncryptCapsuleParams struct {
	State          string `json:"state"`
	Route          string `json:"route"`
	TransportEpoch int64  `json:"transport_epoch"`
	Plaintext      string `json:"plaintext"`
	PadTo          int    `json:"pad_to"`
}
type s2DecryptCapsuleParams struct {
	State          string `json:"state"`
	Capsule        string `json:"capsule"`
	Route          string `json:"route"`
	TransportEpoch int64  `json:"transport_epoch"`
}
type s2HealParams struct {
	State      string `json:"state"`
	Shared     string `json:"shared"`
	Transcript string `json:"transcript"`
}
type s2CallRootParams struct {
	Shared     string `json:"shared"`
	Transcript string `json:"transcript"`
}
type s2MediaEpochParams struct {
	CallRoot  string `json:"call_root"`
	Domain    int    `json:"domain"`
	Direction int    `json:"direction"`
	Epoch     int64  `json:"epoch"`
	Fresh     string `json:"fresh"`
}
type s2EncryptMediaParams struct {
	EpochKey  string `json:"epoch_key"`
	Route     string `json:"route"`
	Epoch     int64  `json:"epoch"`
	Sequence  int64  `json:"sequence"`
	Plaintext string `json:"plaintext"`
}
type s2DecryptMediaParams struct {
	EpochKey string `json:"epoch_key"`
	Route    string `json:"route"`
	Packet   string `json:"packet"`
}
type s2DecryptMediaStateParams struct {
	EpochKey string `json:"epoch_key"`
	Route    string `json:"route"`
	Packet   string `json:"packet"`
	State    string `json:"state"`
}
type s2FileRootParams struct {
	Seed   string `json:"seed"`
	FileID string `json:"file_id"`
}
type s2ChunkParams struct {
	Root   string `json:"root"`
	FileID string `json:"file_id"`
	Index  int64  `json:"index"`
	Data   string `json:"data"`
}
type s2AdmissionRequestParams struct {
	UserRootID    string `json:"user_root_id"`
	Generation    int64  `json:"generation"`
	SecurityEpoch int64  `json:"security_epoch"`
	Device        string `json:"device"`
}
type s2AdmissionCodeParams struct {
	Request string `json:"request"`
}
type s2ApprovalParams struct {
	Request          string `json:"request"`
	ApproverDeviceID string `json:"approver_device_id"`
	SignPrivate      string `json:"sign_private"`
}

func main() {
	debug.SetMemoryLimit(512 << 20)
	scanner := bufio.NewScanner(io.LimitReader(os.Stdin, 1<<40))
	scanner.Buffer(make([]byte, 64<<10), maxRequestBytes)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	for scanner.Scan() {
		raw := append([]byte(nil), scanner.Bytes()...)
		result := handle(raw)
		clear(raw)
		if err := encoder.Encode(result); err != nil {
			return
		}
	}
}

func handle(raw []byte) (out response) {
	defer func() {
		if recovered := recover(); recovered != nil {
			out.OK = false
			out.Value = ""
			out.Error = "crypto worker internal failure"
		}
	}()
	var req request
	decoder := json.NewDecoder(bytesReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || req.ID == "" || req.Method == "" {
		return response{ID: req.ID, Error: "invalid request"}
	}
	value, err := dispatch(req.Method, req.Params)
	if err != nil {
		return response{ID: req.ID, Error: sanitize(err)}
	}
	return response{ID: req.ID, OK: true, Value: value}
}

func dispatch(method string, raw json.RawMessage) (string, error) {
	switch method {
	case "version":
		return mobile.Version(), nil
	case "opaque.registration.start":
		var p opaqueStartParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.OpaqueRegistrationStart(p.Password)
	case "opaque.registration.finish":
		var p opaqueFinishParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.OpaqueRegistrationFinish(p.Handle, p.Response, p.Username, p.ServerIdentity)
	case "opaque.login.start":
		var p opaqueStartParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.OpaqueLoginStart(p.Password)
	case "opaque.login.finish":
		var p opaqueFinishParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.OpaqueLoginFinish(p.Handle, p.Response, p.Username, p.ServerIdentity)
	case "opaque.cancel":
		var p cancelParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		mobile.OpaqueCancel(p.Handle)
		return "{}", nil
	case "olm.account.create":
		var p olmCreateParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.OlmCreateAccount(p.PickleKey, p.Count)
	case "olm.account.refill":
		var p olmRefillParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.OlmRefillOneTimeKeys(p.AccountPickle, p.PickleKey, p.Count)
	case "olm.account.mark_published":
		var p olmMarkParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.OlmMarkKeysPublished(p.AccountPickle, p.PickleKey)
	case "olm.session.outbound":
		var p olmOutboundParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.OlmCreateOutbound(p.AccountPickle, p.PickleKey, p.IdentityKey, p.OneTimeKey)
	case "olm.encrypt":
		var p olmEncryptParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.OlmEncrypt(p.SessionPickle, p.PickleKey, p.Plaintext)
	case "olm.session.inbound":
		var p olmInboundParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.OlmCreateInbound(p.AccountPickle, p.PickleKey, p.IdentityKey, p.Ciphertext, p.MessageType)
	case "olm.decrypt":
		var p olmDecryptParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.OlmDecrypt(p.SessionPickle, p.PickleKey, p.Ciphertext, p.MessageType)
	case "megolm.outbound.create":
		var p megolmCreateParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.MegolmCreateOutbound(p.PickleKey)
	case "megolm.encrypt":
		var p megolmEncryptParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.MegolmEncrypt(p.SessionPickle, p.PickleKey, p.Plaintext)
	case "megolm.inbound.create":
		var p megolmInboundParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.MegolmCreateInbound(p.SessionKey, p.PickleKey)
	case "megolm.decrypt":
		var p megolmDecryptParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.MegolmDecrypt(p.SessionPickle, p.PickleKey, p.Ciphertext)

	case "security2.version":
		return mobile.Security2Version(), nil
	case "security2.identity.user_root.generate":
		return mobile.Security2GenerateUserRoot()
	case "security2.identity.device.generate":
		return mobile.Security2GenerateDeviceIdentity()
	case "security2.identity.shared_secret":
		var p s2SharedParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.Security2SharedSecret(p.LocalPrivate, p.PeerPublic)
	case "security2.ratchet.new":
		var p s2RatchetParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.Security2NewRatchet(p.Seed, p.Domain, p.Generation)
	case "security2.capsule.encrypt":
		var p s2EncryptCapsuleParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.Security2EncryptCapsule(p.State, p.Route, p.TransportEpoch, p.Plaintext, p.PadTo)
	case "security2.capsule.decrypt":
		var p s2DecryptCapsuleParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.Security2DecryptCapsule(p.State, p.Capsule, p.Route, p.TransportEpoch)
	case "security2.ratchet.heal":
		var p s2HealParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.Security2HealRatchet(p.State, p.Shared, p.Transcript)
	case "security2.call.root":
		var p s2CallRootParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.Security2NewCallRoot(p.Shared, p.Transcript)
	case "security2.call.media_epoch":
		var p s2MediaEpochParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.Security2MediaEpochKey(p.CallRoot, p.Domain, p.Direction, p.Epoch, p.Fresh)
	case "security2.call.media_encrypt":
		var p s2EncryptMediaParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.Security2EncryptMedia(p.EpochKey, p.Route, p.Epoch, p.Sequence, p.Plaintext)
	case "security2.call.media_decrypt":
		var p s2DecryptMediaParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.Security2DecryptMedia(p.EpochKey, p.Route, p.Packet)
	case "security2.call.media_decrypt_stateful":
		var p s2DecryptMediaStateParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.Security2DecryptMediaStateful(p.EpochKey, p.Route, p.Packet, p.State)
	case "security2.blob.file_root":
		var p s2FileRootParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.Security2DeriveFileRoot(p.Seed, p.FileID)
	case "security2.blob.encrypt_chunk":
		var p s2ChunkParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.Security2EncryptChunk(p.Root, p.FileID, p.Index, p.Data)
	case "security2.blob.decrypt_chunk":
		var p s2ChunkParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.Security2DecryptChunk(p.Root, p.FileID, p.Index, p.Data)
	case "security2.admission.new":
		var p s2AdmissionRequestParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.Security2NewAdmissionRequest(p.UserRootID, p.Generation, p.SecurityEpoch, p.Device)
	case "security2.admission.code":
		var p s2AdmissionCodeParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.Security2AdmissionCode(p.Request)
	case "security2.admission.approve":
		var p s2ApprovalParams
		if err := decode(raw, &p); err != nil {
			return "", err
		}
		return mobile.Security2ApproveAdmission(p.Request, p.ApproverDeviceID, p.SignPrivate)
	default:
		return "", errors.New("unknown method")
	}
}

func decode(raw json.RawMessage, target any) error {
	if len(raw) == 0 || len(raw) > maxRequestBytes {
		return errors.New("invalid params")
	}
	decoder := json.NewDecoder(bytesReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid params")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid params")
	}
	return nil
}

func sanitize(err error) string {
	if err == nil {
		return ""
	}
	switch err.Error() {
	case "invalid input", "unknown or expired operation handle", "password phrase does not meet policy", "invalid 32-byte key", "invalid data", "unknown method", "invalid params":
		return err.Error()
	default:
		return fmt.Sprintf("crypto operation failed: %T", err)
	}
}

func clear(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

type sliceReader struct {
	value  []byte
	offset int
}

func bytesReader(value []byte) *sliceReader { return &sliceReader{value: value} }
func (r *sliceReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.value) {
		return 0, io.EOF
	}
	n := copy(p, r.value[r.offset:])
	r.offset += n
	return n, nil
}
