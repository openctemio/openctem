package branch

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound      = errors.New("branch not found")
	ErrAlreadyExists = errors.New("branch already exists")
)

// NotFoundError returns a formatted not found error.
func NotFoundError(name string) error {
	return fmt.Errorf("%w: %s", ErrNotFound, name)
}

// AlreadyExistsError returns a formatted already exists error.
func AlreadyExistsError(name string) error {
	return fmt.Errorf("%w: %s", ErrAlreadyExists, name)
}
