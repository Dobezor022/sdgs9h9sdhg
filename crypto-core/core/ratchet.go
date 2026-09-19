package core

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"maunium.net/go/mautrix/crypto/goolm"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

var registerOlmOnce sync.Once

func registerOlm() { registerOlmOnce.Do(goolm.Register) }

type OlmAccountBundle struct {
	Pickle       string `json:"pickle"`
	IdentityKeys string `json:"identity_keys"`
	OneTimeKeys  string `json:"one_time_keys"`
}

type OlmEncrypted struct {
	Pickle      string `json:"pickle"`
	SessionID   string `json:"session_id"`
	MessageType int    `json:"message_type"`
	Ciphertext  string `json:"ciphertext"`
}

type OlmDecrypted struct {
	AccountPickle string `json:"account_pickle,omitempty"`
	SessionPickle string `json:"session_pickle"`
	SessionID     string `json:"session_id"`
	Plaintext     string `json:"plaintext"`
}

type MegolmOutbound struct {
	Pickle       string `json:"pickle"`
	SessionID    string `json:"session_id"`
	SessionKey   string `json:"session_key"`
	MessageIndex uint   `json:"message_index"`
}

type MegolmEncrypted struct {
	Pickle       string `json:"pickle"`
	SessionID    string `json:"session_id"`
	MessageIndex uint   `json:"message_index"`
	Ciphertext   string `json:"ciphertext"`
}

type MegolmDecrypted struct {
	Pickle       string `json:"pickle"`
	SessionID    string `json:"session_id"`
	MessageIndex uint   `json:"message_index"`
	Plaintext    string `json:"plaintext"`
}

func CreateOlmAccount(pickleKey []byte, oneTimeKeyCount uint) (OlmAccountBundle, error) {
	registerOlm()
	if err := validatePickleKey(pickleKey); err != nil {
		return OlmAccountBundle{}, err
	}
	account, err := olm.NewAccount()
	if err != nil {
		return OlmAccountBundle{}, err
	}
	if oneTimeKeyCount == 0 {
		oneTimeKeyCount = 32
	}
	if oneTimeKeyCount > account.MaxNumberOfOneTimeKeys() {
		oneTimeKeyCount = account.MaxNumberOfOneTimeKeys()
	}
	if err := account.GenOneTimeKeys(oneTimeKeyCount); err != nil {
		return OlmAccountBundle{}, err
	}
	identity, err := account.IdentityKeysJSON()
	if err != nil {
		return OlmAccountBundle{}, err
	}
	oneTime, err := account.OneTimeKeys()
	if err != nil {
		return OlmAccountBundle{}, err
	}
	oneTimeJSON, err := json.Marshal(map[string]any{"curve25519": oneTime})
	if err != nil {
		return OlmAccountBundle{}, err
	}
	pickle, err := account.Pickle(pickleKey)
	if err != nil {
		return OlmAccountBundle{}, err
	}
	return OlmAccountBundle{
		Pickle:       base64.RawURLEncoding.EncodeToString(pickle),
		IdentityKeys: string(identity), OneTimeKeys: string(oneTimeJSON),
	}, nil
}

func RefillOneTimeKeys(accountPickle string, pickleKey []byte, count uint) (OlmAccountBundle, error) {
	registerOlm()
	account, err := unpickleAccount(accountPickle, pickleKey)
	if err != nil {
		return OlmAccountBundle{}, err
	}
	if count > account.MaxNumberOfOneTimeKeys() {
		count = account.MaxNumberOfOneTimeKeys()
	}
	if err := account.GenOneTimeKeys(count); err != nil {
		return OlmAccountBundle{}, err
	}
	identity, err := account.IdentityKeysJSON()
	if err != nil {
		return OlmAccountBundle{}, err
	}
	oneTime, err := account.OneTimeKeys()
	if err != nil {
		return OlmAccountBundle{}, err
	}
	oneTimeJSON, err := json.Marshal(map[string]any{"curve25519": oneTime})
	if err != nil {
		return OlmAccountBundle{}, err
	}
	pickle, err := account.Pickle(pickleKey)
	if err != nil {
		return OlmAccountBundle{}, err
	}
	return OlmAccountBundle{Pickle: encodePickle(pickle), IdentityKeys: string(identity), OneTimeKeys: string(oneTimeJSON)}, nil
}

func MarkOneTimeKeysPublished(accountPickle string, pickleKey []byte) (string, error) {
	registerOlm()
	account, err := unpickleAccount(accountPickle, pickleKey)
	if err != nil {
		return "", err
	}
	account.MarkKeysAsPublished()
	pickle, err := account.Pickle(pickleKey)
	if err != nil {
		return "", err
	}
	return encodePickle(pickle), nil
}

func CreateOutboundOlmSession(accountPickle string, pickleKey []byte, theirIdentityKey, theirOneTimeKey string) (OlmEncrypted, error) {
	registerOlm()
	account, err := unpickleAccount(accountPickle, pickleKey)
	if err != nil {
		return OlmEncrypted{}, err
	}
	if theirIdentityKey == "" || theirOneTimeKey == "" {
		return OlmEncrypted{}, ErrInvalidInput
	}
	session, err := account.NewOutboundSession(id.Curve25519(theirIdentityKey), id.Curve25519(theirOneTimeKey))
	if err != nil {
		return OlmEncrypted{}, err
	}
	pickle, err := session.Pickle(pickleKey)
	if err != nil {
		return OlmEncrypted{}, err
	}
	return OlmEncrypted{Pickle: encodePickle(pickle), SessionID: string(session.ID())}, nil
}

func EncryptOlm(sessionPickle string, pickleKey, plaintext []byte) (OlmEncrypted, error) {
	registerOlm()
	if len(plaintext) == 0 || len(plaintext) > 16<<20 {
		return OlmEncrypted{}, ErrInvalidInput
	}
	session, err := unpickleSession(sessionPickle, pickleKey)
	if err != nil {
		return OlmEncrypted{}, err
	}
	messageType, ciphertext, err := session.Encrypt(plaintext)
	if err != nil {
		return OlmEncrypted{}, err
	}
	pickle, err := session.Pickle(pickleKey)
	if err != nil {
		return OlmEncrypted{}, err
	}
	return OlmEncrypted{
		Pickle: encodePickle(pickle), SessionID: string(session.ID()), MessageType: int(messageType), Ciphertext: string(ciphertext),
	}, nil
}

func CreateInboundOlmSession(accountPickle string, pickleKey []byte, theirIdentityKey, ciphertext string, messageType int) (OlmDecrypted, error) {
	registerOlm()
	if messageType != int(id.OlmMsgTypePreKey) || ciphertext == "" {
		return OlmDecrypted{}, ErrInvalidInput
	}
	account, err := unpickleAccount(accountPickle, pickleKey)
	if err != nil {
		return OlmDecrypted{}, err
	}
	identity := id.Curve25519(theirIdentityKey)
	session, err := account.NewInboundSessionFrom(&identity, ciphertext)
	if err != nil {
		return OlmDecrypted{}, err
	}
	plaintext, err := session.Decrypt(ciphertext, id.OlmMsgType(messageType))
	if err != nil {
		return OlmDecrypted{}, err
	}
	if err := account.RemoveOneTimeKeys(session); err != nil {
		return OlmDecrypted{}, err
	}
	accountPickleBytes, err := account.Pickle(pickleKey)
	if err != nil {
		return OlmDecrypted{}, err
	}
	sessionPickleBytes, err := session.Pickle(pickleKey)
	if err != nil {
		return OlmDecrypted{}, err
	}
	return OlmDecrypted{
		AccountPickle: encodePickle(accountPickleBytes), SessionPickle: encodePickle(sessionPickleBytes),
		SessionID: string(session.ID()), Plaintext: base64.RawURLEncoding.EncodeToString(plaintext),
	}, nil
}

func DecryptOlm(sessionPickle string, pickleKey []byte, ciphertext string, messageType int) (OlmDecrypted, error) {
	registerOlm()
	if ciphertext == "" || (messageType != int(id.OlmMsgTypePreKey) && messageType != int(id.OlmMsgTypeMsg)) {
		return OlmDecrypted{}, ErrInvalidInput
	}
	session, err := unpickleSession(sessionPickle, pickleKey)
	if err != nil {
		return OlmDecrypted{}, err
	}
	plaintext, err := session.Decrypt(ciphertext, id.OlmMsgType(messageType))
	if err != nil {
		return OlmDecrypted{}, err
	}
	pickle, err := session.Pickle(pickleKey)
	if err != nil {
		return OlmDecrypted{}, err
	}
	return OlmDecrypted{
		SessionPickle: encodePickle(pickle), SessionID: string(session.ID()),
		Plaintext: base64.RawURLEncoding.EncodeToString(plaintext),
	}, nil
}

func CreateOutboundMegolmSession(pickleKey []byte) (MegolmOutbound, error) {
	registerOlm()
	if err := validatePickleKey(pickleKey); err != nil {
		return MegolmOutbound{}, err
	}
	session, err := olm.NewOutboundGroupSession()
	if err != nil {
		return MegolmOutbound{}, err
	}
	pickle, err := session.Pickle(pickleKey)
	if err != nil {
		return MegolmOutbound{}, err
	}
	return MegolmOutbound{
		Pickle: encodePickle(pickle), SessionID: string(session.ID()), SessionKey: session.Key(), MessageIndex: session.MessageIndex(),
	}, nil
}

func EncryptMegolm(sessionPickle string, pickleKey, plaintext []byte) (MegolmEncrypted, error) {
	registerOlm()
	if len(plaintext) == 0 || len(plaintext) > 16<<20 {
		return MegolmEncrypted{}, ErrInvalidInput
	}
	pickled, err := decodePickle(sessionPickle)
	if err != nil {
		return MegolmEncrypted{}, err
	}
	session, err := olm.OutboundGroupSessionFromPickled(pickled, pickleKey)
	clearBytes(pickled)
	if err != nil {
		return MegolmEncrypted{}, err
	}
	index := session.MessageIndex()
	ciphertext, err := session.Encrypt(plaintext)
	if err != nil {
		return MegolmEncrypted{}, err
	}
	updated, err := session.Pickle(pickleKey)
	if err != nil {
		return MegolmEncrypted{}, err
	}
	return MegolmEncrypted{
		Pickle: encodePickle(updated), SessionID: string(session.ID()), MessageIndex: index, Ciphertext: string(ciphertext),
	}, nil
}

func CreateInboundMegolmSession(sessionKey string, pickleKey []byte) (string, error) {
	registerOlm()
	if sessionKey == "" || len(sessionKey) > 4096 {
		return "", ErrInvalidInput
	}
	session, err := olm.NewInboundGroupSession([]byte(sessionKey))
	if err != nil {
		return "", err
	}
	pickle, err := session.Pickle(pickleKey)
	if err != nil {
		return "", err
	}
	return encodePickle(pickle), nil
}

func DecryptMegolm(sessionPickle string, pickleKey []byte, ciphertext string) (MegolmDecrypted, error) {
	registerOlm()
	pickled, err := decodePickle(sessionPickle)
	if err != nil {
		return MegolmDecrypted{}, err
	}
	session, err := olm.InboundGroupSessionFromPickled(pickled, pickleKey)
	clearBytes(pickled)
	if err != nil {
		return MegolmDecrypted{}, err
	}
	plaintext, index, err := session.Decrypt([]byte(ciphertext))
	if err != nil {
		return MegolmDecrypted{}, err
	}
	updated, err := session.Pickle(pickleKey)
	if err != nil {
		return MegolmDecrypted{}, err
	}
	return MegolmDecrypted{
		Pickle: encodePickle(updated), SessionID: string(session.ID()), MessageIndex: index,
		Plaintext: base64.RawURLEncoding.EncodeToString(plaintext),
	}, nil
}

func unpickleAccount(value string, key []byte) (olm.Account, error) {
	if err := validatePickleKey(key); err != nil {
		return nil, err
	}
	pickled, err := decodePickle(value)
	if err != nil {
		return nil, err
	}
	defer clearBytes(pickled)
	return olm.AccountFromPickled(pickled, key)
}

func unpickleSession(value string, key []byte) (olm.Session, error) {
	if err := validatePickleKey(key); err != nil {
		return nil, err
	}
	pickled, err := decodePickle(value)
	if err != nil {
		return nil, err
	}
	defer clearBytes(pickled)
	return olm.SessionFromPickled(pickled, key)
}

func validatePickleKey(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("%w: pickle key must be 32 bytes", ErrInvalidInput)
	}
	return nil
}

func encodePickle(value []byte) string {
	defer clearBytes(value)
	return base64.RawURLEncoding.EncodeToString(value)
}

func decodePickle(value string) ([]byte, error) {
	if len(value) < 16 || len(value) > 16<<20 {
		return nil, ErrInvalidInput
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		clearBytes(decoded)
		return nil, errors.Join(ErrInvalidInput, err)
	}
	return decoded, nil
}
