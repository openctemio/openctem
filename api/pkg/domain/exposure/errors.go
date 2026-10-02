package exposure

import (
	"errors"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Domain errors for exposure events.
var (
	ErrExposureEventNotFound  = errors.New("exposure event not found")
	ErrExposureEventExists    = errors.New("exposure event already exists")
	ErrStateHistoryNotFound   = errors.New("state history not found")
	ErrInvalidStateTransition = errors.New("invalid state transition")
)

// NewExposureEventNotFoundError creates a new exposure event not found error.
func NewExposureEventNotFoundError(id string) error {
	return fmt.Errorf("%w: %s", ErrExposureEventNotFound, id)
}

// NewExposureEventExistsError creates a new exposure event exists error.
func NewExposureEventExistsError(fingerprint string) error {
	return fmt.Errorf("%w: fingerprint=%s", ErrExposureEventExists, fingerprint)
}

// NewInvalidStateTransitionError creates a new invalid state transition error.
func NewInvalidStateTransitionError(from, to State) error {
	return fmt.Errorf("%w: cannot transition from %s to %s", ErrInvalidStateTransition, from, to)
}

// IsExposureEventNotFound checks if the error is an exposure event not found error.
func IsExposureEventNotFound(err error) bool {
	return errors.Is(err, ErrExposureEventNotFound) || errors.Is(err, shared.ErrNotFound)
}

// IsExposureEventExists checks if the error is an exposure event exists error.
func IsExposureEventExists(err error) bool {
	return errors.Is(err, ErrExposureEventExists) || errors.Is(err, shared.ErrAlreadyExists)
}

// IsInvalidStateTransition checks if the error is an invalid state transition error.
func IsInvalidStateTransition(err error) bool {
	return errors.Is(err, ErrInvalidStateTransition)
}

// IsStateHistoryNotFound checks if the error is a state history not found error.
func IsStateHistoryNotFound(err error) bool {
	return errors.Is(err, ErrStateHistoryNotFound)
}
