package core

import "errors"

var (
	ErrInvalidInput   = errors.New("invalid input")
	ErrUnknownHandle  = errors.New("unknown or expired operation handle")
	ErrPasswordPolicy = errors.New("password phrase does not meet policy")
)
