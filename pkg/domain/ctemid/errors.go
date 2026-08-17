package ctemid

import (
	"errors"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ErrCTEMIDNotFound is returned when a catalog entry does not exist.
var ErrCTEMIDNotFound = fmt.Errorf("%w: ctem-id not found", shared.ErrNotFound)

// IsNotFound reports whether err is a not-found error.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrCTEMIDNotFound)
}
