package ratchet

import "errors"

var (
	ErrInvalid   = errors.New("ratchet request invalid")
	ErrForbidden = errors.New("ratchet operation forbidden")
	ErrNotFound  = errors.New("ratchet object not found")
	ErrConflict  = errors.New("ratchet state conflict")
	ErrNoKey     = errors.New("no one-time key available")
)
