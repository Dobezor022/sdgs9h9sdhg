package opaqueauth

import "errors"

var (
	ErrInvalidRequest     = errors.New("opaque request invalid")
	ErrAuthentication     = errors.New("authentication failed")
	ErrForbidden          = errors.New("opaque operation forbidden")
	ErrNotFound           = errors.New("opaque record not found")
	ErrExpired            = errors.New("opaque attempt expired")
	ErrReplayed           = errors.New("opaque request replay conflict")
	ErrAlreadyCompleted   = errors.New("opaque attempt already completed")
	ErrServerStateMissing = errors.New("opaque transient server state missing")
)
