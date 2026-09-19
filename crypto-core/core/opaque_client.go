package core

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/bytemare/opaque"
)

const (
	OpaqueSuite              = "OPAQUE-Ristretto255-SHA512-Argon2id-RFC9807"
	MinimumPasswordUTF8Bytes = 12
	MaximumPasswordUTF8Bytes = 1024
	opaqueHandleTTL          = 10 * time.Minute
)

type opaqueClientOperation struct {
	client    *opaque.Client
	createdAt time.Time
}

type OpaqueClientRegistry struct {
	mu         sync.Mutex
	operations map[string]opaqueClientOperation
	now        func() time.Time
}

func NewOpaqueClientRegistry() *OpaqueClientRegistry {
	return &OpaqueClientRegistry{operations: make(map[string]opaqueClientOperation), now: time.Now}
}

type OpaqueStart struct {
	Handle  string `json:"handle"`
	Message string `json:"message"`
	Suite   string `json:"suite"`
}

type OpaqueClientFinish struct {
	Message    string `json:"message"`
	SessionKey string `json:"session_key,omitempty"`
	ExportKey  string `json:"export_key"`
	Suite      string `json:"suite"`
}

func (r *OpaqueClientRegistry) RegistrationStart(password []byte) (OpaqueStart, error) {
	if err := validatePassword(password); err != nil {
		return OpaqueStart{}, err
	}
	configuration := opaque.DefaultConfiguration()
	client, err := configuration.Client()
	if err != nil {
		return OpaqueStart{}, err
	}
	request, err := client.RegistrationInit(password)
	if err != nil {
		client.ClearState()
		return OpaqueStart{}, err
	}
	handle, err := newHandle()
	if err != nil {
		client.ClearState()
		return OpaqueStart{}, err
	}
	r.store(handle, client)
	return OpaqueStart{
		Handle: handle, Message: base64.RawURLEncoding.EncodeToString(request.Serialize()), Suite: OpaqueSuite,
	}, nil
}

func (r *OpaqueClientRegistry) RegistrationFinish(handle, responseBase64 string, clientIdentity, serverIdentity []byte) (OpaqueClientFinish, error) {
	client, err := r.take(handle)
	if err != nil {
		return OpaqueClientFinish{}, err
	}
	defer client.ClearState()
	responseBytes, err := decodeOpaqueMessage(responseBase64)
	if err != nil {
		return OpaqueClientFinish{}, err
	}
	response, err := client.Deserialize.RegistrationResponse(responseBytes)
	clearBytes(responseBytes)
	if err != nil {
		return OpaqueClientFinish{}, err
	}
	record, exportKey, err := client.RegistrationFinalize(response, clientIdentity, serverIdentity)
	if err != nil {
		clearBytes(exportKey)
		return OpaqueClientFinish{}, err
	}
	defer clearBytes(exportKey)
	return OpaqueClientFinish{
		Message:   base64.RawURLEncoding.EncodeToString(record.Serialize()),
		ExportKey: base64.RawURLEncoding.EncodeToString(exportKey),
		Suite:     OpaqueSuite,
	}, nil
}

func (r *OpaqueClientRegistry) LoginStart(password []byte) (OpaqueStart, error) {
	if err := validatePassword(password); err != nil {
		return OpaqueStart{}, err
	}
	configuration := opaque.DefaultConfiguration()
	client, err := configuration.Client()
	if err != nil {
		return OpaqueStart{}, err
	}
	ke1, err := client.GenerateKE1(password)
	if err != nil {
		client.ClearState()
		return OpaqueStart{}, err
	}
	handle, err := newHandle()
	if err != nil {
		client.ClearState()
		return OpaqueStart{}, err
	}
	r.store(handle, client)
	return OpaqueStart{
		Handle: handle, Message: base64.RawURLEncoding.EncodeToString(ke1.Serialize()), Suite: OpaqueSuite,
	}, nil
}

func (r *OpaqueClientRegistry) LoginFinish(handle, responseBase64 string, clientIdentity, serverIdentity []byte) (OpaqueClientFinish, error) {
	client, err := r.take(handle)
	if err != nil {
		return OpaqueClientFinish{}, err
	}
	defer client.ClearState()
	responseBytes, err := decodeOpaqueMessage(responseBase64)
	if err != nil {
		return OpaqueClientFinish{}, err
	}
	ke2, err := client.Deserialize.KE2(responseBytes)
	clearBytes(responseBytes)
	if err != nil {
		return OpaqueClientFinish{}, err
	}
	ke3, sessionKey, exportKey, err := client.GenerateKE3(ke2, clientIdentity, serverIdentity)
	if err != nil {
		clearBytes(sessionKey)
		clearBytes(exportKey)
		return OpaqueClientFinish{}, err
	}
	defer clearBytes(sessionKey)
	defer clearBytes(exportKey)
	return OpaqueClientFinish{
		Message:    base64.RawURLEncoding.EncodeToString(ke3.Serialize()),
		SessionKey: base64.RawURLEncoding.EncodeToString(sessionKey),
		ExportKey:  base64.RawURLEncoding.EncodeToString(exportKey),
		Suite:      OpaqueSuite,
	}, nil
}

func (r *OpaqueClientRegistry) Cancel(handle string) {
	client, err := r.take(handle)
	if err == nil {
		client.ClearState()
	}
}

func (r *OpaqueClientRegistry) store(handle string, client *opaque.Client) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(r.now())
	r.operations[handle] = opaqueClientOperation{client: client, createdAt: r.now()}
}

func (r *OpaqueClientRegistry) take(handle string) (*opaque.Client, error) {
	if len(handle) != 32 {
		return nil, ErrUnknownHandle
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(r.now())
	operation, ok := r.operations[handle]
	if !ok {
		return nil, ErrUnknownHandle
	}
	delete(r.operations, handle)
	return operation.client, nil
}

func (r *OpaqueClientRegistry) expireLocked(now time.Time) {
	for handle, operation := range r.operations {
		if now.Sub(operation.createdAt) >= opaqueHandleTTL {
			operation.client.ClearState()
			delete(r.operations, handle)
		}
	}
}

func validatePassword(password []byte) error {
	if len(password) < MinimumPasswordUTF8Bytes || len(password) > MaximumPasswordUTF8Bytes {
		return ErrPasswordPolicy
	}
	allWhitespace := true
	for _, b := range password {
		if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
			allWhitespace = false
			break
		}
	}
	if allWhitespace {
		return ErrPasswordPolicy
	}
	return nil
}

func newHandle() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func decodeOpaqueMessage(value string) ([]byte, error) {
	if len(value) < 16 || len(value) > 1<<20 {
		return nil, ErrInvalidInput
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 {
		clearBytes(decoded)
		return nil, errors.Join(ErrInvalidInput, err)
	}
	return decoded, nil
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
