package provisioning

import "errors"

// ErrorCode is a stable, machine-readable provisioning error identifier.
// API transports may map these codes to protocol-specific responses without
// exposing token, key, or repository details.
type ErrorCode string

const (
	CodeInvalidConfiguration ErrorCode = "invalid_configuration"
	CodeUnknownUser          ErrorCode = "unknown_user"
	CodeInvalidTTL           ErrorCode = "invalid_invitation_ttl"
	CodeEntropyUnavailable   ErrorCode = "entropy_unavailable"
	CodeEntropyCollision     ErrorCode = "entropy_collision"
	CodeInvalidToken         ErrorCode = "invalid_invitation_token"
	CodeInvitationNotFound   ErrorCode = "invitation_not_found"
	CodeInvitationExpired    ErrorCode = "invitation_expired"
	CodeInvitationUsed       ErrorCode = "invitation_used"
	CodeInvitationUser       ErrorCode = "invitation_user_mismatch"
	CodeInvalidDeviceKey     ErrorCode = "invalid_device_public_key"
	CodeInvalidEncryptionKey ErrorCode = "invalid_message_encryption_key"
	CodeUnknownDevice        ErrorCode = "unknown_device"
	CodeChallengeNotFound    ErrorCode = "challenge_not_found"
	CodeChallengeExpired     ErrorCode = "challenge_expired"
	CodeChallengeUsed        ErrorCode = "challenge_used"
	CodeChallengeContext     ErrorCode = "challenge_context_mismatch"
	CodeInvalidSignature     ErrorCode = "invalid_device_signature"
	CodeConflict             ErrorCode = "repository_conflict"
	CodeInvariantViolation   ErrorCode = "repository_invariant_violation"
)

// Error is safe to expose after a transport has selected an appropriate
// status code. Field never contains the rejected value, and Error deliberately
// omits wrapped error text because lower layers may include sensitive data.
type Error struct {
	Code  ErrorCode
	Field string
	cause error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Field == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Field
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Is compares provisioning errors by stable code, not pointer identity.
func (e *Error) Is(target error) bool {
	typed, ok := target.(*Error)
	return ok && e != nil && e.Code == typed.Code
}

var (
	ErrInvalidConfiguration = &Error{Code: CodeInvalidConfiguration}
	ErrUnknownUser          = &Error{Code: CodeUnknownUser}
	ErrInvalidTTL           = &Error{Code: CodeInvalidTTL}
	ErrEntropyUnavailable   = &Error{Code: CodeEntropyUnavailable}
	ErrEntropyCollision     = &Error{Code: CodeEntropyCollision}
	ErrInvalidToken         = &Error{Code: CodeInvalidToken}
	ErrInvitationNotFound   = &Error{Code: CodeInvitationNotFound}
	ErrInvitationExpired    = &Error{Code: CodeInvitationExpired}
	ErrInvitationUsed       = &Error{Code: CodeInvitationUsed}
	ErrInvitationUser       = &Error{Code: CodeInvitationUser}
	ErrInvalidDeviceKey     = &Error{Code: CodeInvalidDeviceKey}
	ErrInvalidEncryptionKey = &Error{Code: CodeInvalidEncryptionKey}
	ErrUnknownDevice        = &Error{Code: CodeUnknownDevice}
	ErrChallengeNotFound    = &Error{Code: CodeChallengeNotFound}
	ErrChallengeExpired     = &Error{Code: CodeChallengeExpired}
	ErrChallengeUsed        = &Error{Code: CodeChallengeUsed}
	ErrChallengeContext     = &Error{Code: CodeChallengeContext}
	ErrInvalidSignature     = &Error{Code: CodeInvalidSignature}
	ErrConflict             = &Error{Code: CodeConflict}
	ErrInvariantViolation   = &Error{Code: CodeInvariantViolation}
)

func newError(code ErrorCode, field string) error {
	return &Error{Code: code, Field: field}
}

func wrapError(code ErrorCode, field string, cause error) error {
	return &Error{Code: code, Field: field, cause: cause}
}

// RepositoryError lets durable adapters preserve stable service error codes
// without exposing database error text through the public transport.
func RepositoryError(code ErrorCode, field string, cause error) error {
	return &Error{Code: code, Field: field, cause: cause}
}

// CodeOf extracts a stable provisioning code through wrapped errors.
func CodeOf(err error) (ErrorCode, bool) {
	var typed *Error
	if !errors.As(err, &typed) {
		return "", false
	}
	return typed.Code, true
}
