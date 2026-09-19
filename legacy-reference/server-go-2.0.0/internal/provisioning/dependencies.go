package provisioning

import (
	"crypto/rand"
	"time"
)

// Clock makes expiration behavior deterministic in tests and replaceable in
// hosts that use a centrally monitored time source.
type Clock interface {
	Now() time.Time
}

// EntropySource must be concurrency-safe and cryptographically secure in
// production. CryptoEntropy is the production implementation.
type EntropySource interface {
	Read(p []byte) (int, error)
}

type SystemClock struct{}

func (SystemClock) Now() time.Time {
	return time.Now()
}

type CryptoEntropy struct{}

func (CryptoEntropy) Read(p []byte) (int, error) {
	return rand.Read(p)
}
