//go:build windows

package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"fedmes/crypto/mobile"
)

type nativeResult struct {
	OK    bool   `json:"ok"`
	Value string `json:"value,omitempty"`
	Error string `json:"error,omitempty"`
}

func main() {}

func result(value string, err error) *C.char {
	payload := nativeResult{OK: err == nil, Value: value}
	if err != nil {
		payload.Error = err.Error()
		payload.Value = ""
	}
	encoded, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		encoded = []byte(fmt.Sprintf(`{"ok":false,"error":%q}`, marshalErr.Error()))
	}
	return C.CString(string(encoded))
}

func goString(value *C.char) string {
	if value == nil {
		return ""
	}
	return C.GoString(value)
}

//export FedMesCryptoVersion
func FedMesCryptoVersion() *C.char { return result(mobile.Version(), nil) }

//export FedMesOpaqueRegistrationStart
func FedMesOpaqueRegistrationStart(password *C.char) *C.char {
	value, err := mobile.OpaqueRegistrationStart(goString(password))
	return result(value, err)
}

//export FedMesOpaqueRegistrationFinish
func FedMesOpaqueRegistrationFinish(handle, response, username, serverIdentity *C.char) *C.char {
	value, err := mobile.OpaqueRegistrationFinish(goString(handle), goString(response), goString(username), goString(serverIdentity))
	return result(value, err)
}

//export FedMesOpaqueLoginStart
func FedMesOpaqueLoginStart(password *C.char) *C.char {
	value, err := mobile.OpaqueLoginStart(goString(password))
	return result(value, err)
}

//export FedMesOpaqueLoginFinish
func FedMesOpaqueLoginFinish(handle, response, username, serverIdentity *C.char) *C.char {
	value, err := mobile.OpaqueLoginFinish(goString(handle), goString(response), goString(username), goString(serverIdentity))
	return result(value, err)
}

//export FedMesOpaqueCancel
func FedMesOpaqueCancel(handle *C.char) { mobile.OpaqueCancel(goString(handle)) }

//export FedMesOlmCreateAccount
func FedMesOlmCreateAccount(pickleKey *C.char, count C.int) *C.char {
	value, err := mobile.OlmCreateAccount(goString(pickleKey), int(count))
	return result(value, err)
}

//export FedMesOlmRefillOneTimeKeys
func FedMesOlmRefillOneTimeKeys(accountPickle, pickleKey *C.char, count C.int) *C.char {
	value, err := mobile.OlmRefillOneTimeKeys(goString(accountPickle), goString(pickleKey), int(count))
	return result(value, err)
}

//export FedMesOlmMarkKeysPublished
func FedMesOlmMarkKeysPublished(accountPickle, pickleKey *C.char) *C.char {
	value, err := mobile.OlmMarkKeysPublished(goString(accountPickle), goString(pickleKey))
	return result(value, err)
}

//export FedMesOlmCreateOutbound
func FedMesOlmCreateOutbound(accountPickle, pickleKey, identityKey, oneTimeKey *C.char) *C.char {
	value, err := mobile.OlmCreateOutbound(goString(accountPickle), goString(pickleKey), goString(identityKey), goString(oneTimeKey))
	return result(value, err)
}

//export FedMesOlmEncrypt
func FedMesOlmEncrypt(sessionPickle, pickleKey, plaintext *C.char) *C.char {
	value, err := mobile.OlmEncrypt(goString(sessionPickle), goString(pickleKey), goString(plaintext))
	return result(value, err)
}

//export FedMesOlmCreateInbound
func FedMesOlmCreateInbound(accountPickle, pickleKey, identityKey, ciphertext *C.char, messageType C.int) *C.char {
	value, err := mobile.OlmCreateInbound(goString(accountPickle), goString(pickleKey), goString(identityKey), goString(ciphertext), int(messageType))
	return result(value, err)
}

//export FedMesOlmDecrypt
func FedMesOlmDecrypt(sessionPickle, pickleKey, ciphertext *C.char, messageType C.int) *C.char {
	value, err := mobile.OlmDecrypt(goString(sessionPickle), goString(pickleKey), goString(ciphertext), int(messageType))
	return result(value, err)
}

//export FedMesMegolmCreateOutbound
func FedMesMegolmCreateOutbound(pickleKey *C.char) *C.char {
	value, err := mobile.MegolmCreateOutbound(goString(pickleKey))
	return result(value, err)
}

//export FedMesMegolmEncrypt
func FedMesMegolmEncrypt(sessionPickle, pickleKey, plaintext *C.char) *C.char {
	value, err := mobile.MegolmEncrypt(goString(sessionPickle), goString(pickleKey), goString(plaintext))
	return result(value, err)
}

//export FedMesMegolmCreateInbound
func FedMesMegolmCreateInbound(sessionKey, pickleKey *C.char) *C.char {
	value, err := mobile.MegolmCreateInbound(goString(sessionKey), goString(pickleKey))
	return result(value, err)
}

//export FedMesMegolmDecrypt
func FedMesMegolmDecrypt(sessionPickle, pickleKey, ciphertext *C.char) *C.char {
	value, err := mobile.MegolmDecrypt(goString(sessionPickle), goString(pickleKey), goString(ciphertext))
	return result(value, err)
}

//export FedMesCryptoFree
func FedMesCryptoFree(value *C.char) {
	if value != nil {
		C.free(unsafe.Pointer(value))
	}
}
