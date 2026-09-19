package security2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

func hkdfExtract(salt, ikm []byte) [32]byte {
	if len(salt) == 0 {
		salt = make([]byte, 32)
	}
	m := hmac.New(sha256.New, salt)
	_, _ = m.Write(ikm)
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

func hkdfExpand(prk [32]byte, info []byte, n int) []byte {
	if n <= 0 || n > 255*sha256.Size {
		return nil
	}
	result := make([]byte, 0, n)
	var previous []byte
	for counter := byte(1); len(result) < n; counter++ {
		m := hmac.New(sha256.New, prk[:])
		_, _ = m.Write(previous)
		_, _ = m.Write(info)
		_, _ = m.Write([]byte{counter})
		previous = m.Sum(nil)
		need := n - len(result)
		if need > len(previous) {
			need = len(previous)
		}
		result = append(result, previous[:need]...)
	}
	Zero(previous)
	return result
}

func Derive32(secret []byte, domain string, context ...[]byte) [32]byte {
	prk := hkdfExtract([]byte("FedMes-2.0/FSA2"), secret)
	info := make([]byte, 0, 128)
	info = appendLen(info, []byte(domain))
	for _, c := range context {
		info = appendLen(info, c)
	}
	out := hkdfExpand(prk, info, 32)
	var result [32]byte
	copy(result[:], out)
	Zero(out)
	Zero(info)
	return result
}

func appendLen(dst, b []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	dst = append(dst, l[:]...)
	return append(dst, b...)
}
