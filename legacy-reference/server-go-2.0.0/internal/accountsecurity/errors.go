package accountsecurity

import "errors"

var (
	ErrNotFound         = errors.New("security record not found")
	ErrConflict         = errors.New("security state conflict")
	ErrForbidden        = errors.New("security operation forbidden")
	ErrInvalidState     = errors.New("invalid security state")
	ErrRequestReplayed  = errors.New("request id was used with different content")
	ErrRequestExpired   = errors.New("security request expired")
	ErrAlreadyCompleted = errors.New("security request already completed")
)
