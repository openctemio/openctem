package sla

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound      = errors.New("SLA policy not found")
	ErrAlreadyExists = errors.New("SLA policy already exists")

	// ErrDefaultProtected is returned when a change would leave the tenant's
	// default policy inactive, deleted or unset. The default governs every new
	// deadline; replace it by making another policy the default.
	ErrDefaultProtected = errors.New("the default SLA policy cannot be deactivated, deleted or unset; make another policy the default first")
)

// NotFoundError returns a formatted not found error.
func NotFoundError(id string) error {
	return fmt.Errorf("%w: %s", ErrNotFound, id)
}

// AlreadyExistsError returns a formatted already exists error.
func AlreadyExistsError(name string) error {
	return fmt.Errorf("%w: %s", ErrAlreadyExists, name)
}
