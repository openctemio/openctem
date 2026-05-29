package branch

import (
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Wrap the shared sentinels so handlers that switch on errors.Is(err,
// shared.ErrNotFound) / shared.ErrConflict map these to 404 / 409 instead of
// falling through to a 500.
var (
	ErrNotFound      = fmt.Errorf("%w: branch not found", shared.ErrNotFound)
	ErrAlreadyExists = fmt.Errorf("%w: branch already exists", shared.ErrAlreadyExists)
)

// NotFoundError returns a formatted not found error.
func NotFoundError(name string) error {
	return fmt.Errorf("%w: %s", ErrNotFound, name)
}

// AlreadyExistsError returns a formatted already exists error.
func AlreadyExistsError(name string) error {
	return fmt.Errorf("%w: %s", ErrAlreadyExists, name)
}
