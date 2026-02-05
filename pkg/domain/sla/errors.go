package sla

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound      = errors.New("SLA policy not found")
	ErrAlreadyExists = errors.New("SLA policy already exists")
)

// NotFoundError returns a formatted not found error.
func NotFoundError(id string) error {
	return fmt.Errorf("%w: %s", ErrNotFound, id)
}

// AlreadyExistsError returns a formatted already exists error.
func AlreadyExistsError(name string) error {
	return fmt.Errorf("%w: %s", ErrAlreadyExists, name)
}
