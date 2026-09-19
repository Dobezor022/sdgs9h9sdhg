package cryptomigration

import "errors"

var (
	ErrInvalid    = errors.New("migration request invalid")
	ErrForbidden  = errors.New("migration forbidden")
	ErrNotFound   = errors.New("migration object not found")
	ErrConflict   = errors.New("migration conflict")
	ErrIncomplete = errors.New("migration incomplete")
)
