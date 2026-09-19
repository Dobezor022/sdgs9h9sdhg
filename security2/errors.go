package security2

import "errors"

var (
	ErrInvalidInput       = errors.New("invalid input")
	ErrAuthentication     = errors.New("authentication failed")
	ErrReplay             = errors.New("replay detected")
	ErrRollback           = errors.New("state rollback detected")
	ErrTrustFork          = errors.New("trust state fork detected")
	ErrQuorum             = errors.New("approval quorum not satisfied")
	ErrExpired            = errors.New("state expired")
	ErrWrongDomain        = errors.New("wrong security domain")
	ErrUnsupportedVersion = errors.New("unsupported security version")
)
