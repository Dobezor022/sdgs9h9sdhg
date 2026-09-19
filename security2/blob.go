package security2

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

func DeriveFileRoot(seed []byte, fileID []byte) ([32]byte, error) {
	if len(seed) < 32 || len(fileID) < 16 {
		return [32]byte{}, ErrInvalidInput
	}
	return Derive32(seed, "blob/file-root", fileID), nil
}
func EncryptChunk(fileRoot [32]byte, fileID []byte, index uint64, plaintext []byte) ([]byte, error) {
	return cryptChunk(true, fileRoot, fileID, index, plaintext)
}
func DecryptChunk(fileRoot [32]byte, fileID []byte, index uint64, ciphertext []byte) ([]byte, error) {
	return cryptChunk(false, fileRoot, fileID, index, ciphertext)
}
func cryptChunk(enc bool, root [32]byte, fileID []byte, index uint64, input []byte) ([]byte, error) {
	if len(fileID) < 16 || len(input) == 0 || len(input) > 8<<20 {
		return nil, ErrInvalidInput
	}
	var ix [8]byte
	binary.BigEndian.PutUint64(ix[:], index)
	k := Derive32(root[:], "blob/chunk", fileID, ix[:])
	defer Zero(k[:])
	block, _ := aes.NewCipher(k[:])
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, aead.NonceSize())
	copy(nonce[len(nonce)-8:], ix[:])
	aad := append(append([]byte("FedMes2/Blob/v1"), fileID...), ix[:]...)
	if enc {
		return aead.Seal(nil, nonce, input, aad), nil
	}
	out, err := aead.Open(nil, nonce, input, aad)
	if err != nil {
		return nil, ErrAuthentication
	}
	return out, nil
}
