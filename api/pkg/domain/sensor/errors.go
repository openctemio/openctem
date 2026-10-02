// Package sensor defines domain errors for sensor-related operations.
package sensor

import (
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// =============================================================================
// Sensor Errors
// =============================================================================

var (
	// ErrSensorNotFound is returned when a sensor is not found.
	ErrSensorNotFound = fmt.Errorf("%w: sensor not found", shared.ErrNotFound)

	// ErrSensorAlreadyExists is returned when a sensor with the same name exists.
	ErrSensorAlreadyExists = fmt.Errorf("%w: sensor already exists", shared.ErrAlreadyExists)

	// ErrSensorDisabled is returned when trying to use a disabled sensor.
	ErrSensorDisabled = fmt.Errorf("%w: sensor is disabled", shared.ErrForbidden)

	// ErrSensorRevoked is returned when trying to use a revoked sensor.
	ErrSensorRevoked = fmt.Errorf("%w: sensor access has been revoked", shared.ErrForbidden)

	// ErrSensorLimitReached is returned when the sensor limit for a tenant is reached.
	ErrSensorLimitReached = fmt.Errorf("%w: sensor limit reached for this plan", shared.ErrForbidden)

	// ErrSensorNoCapacity is returned when a sensor has no capacity for more jobs.
	ErrSensorNoCapacity = fmt.Errorf("%w: sensor has no capacity for more jobs", shared.ErrConflict)

	// ErrInvalidAPIKey is returned when an API key is invalid.
	ErrInvalidAPIKey = fmt.Errorf("%w: invalid API key", shared.ErrUnauthorized)
)

// =============================================================================
// Platform Sensor Errors (v3.2)
// =============================================================================

var (
	// ErrPlatformSensorNotFound is returned when a platform sensor is not found.
	ErrPlatformSensorNotFound = fmt.Errorf("%w: platform sensor not found", shared.ErrNotFound)

	// ErrNoPlatformSensorAvailable is returned when no platform sensor is available.
	ErrNoPlatformSensorAvailable = fmt.Errorf("%w: no platform sensor available", shared.ErrConflict)

	// ErrAllPlatformSensorsOverloaded is returned when sensors exist but all are at capacity.
	ErrAllPlatformSensorsOverloaded = fmt.Errorf("%w: all platform sensors are at capacity", shared.ErrConflict)

	// ErrPlatformSensorAccessDenied is returned when tenant doesn't have platform sensor access.
	ErrPlatformSensorAccessDenied = fmt.Errorf("%w: platform sensor access not included in plan", shared.ErrForbidden)

	// ErrPlatformConcurrentLimitReached is returned when concurrent platform job limit is reached.
	ErrPlatformConcurrentLimitReached = fmt.Errorf("%w: concurrent platform job limit reached", shared.ErrConflict)

	// ErrPlatformQueueLimitReached is returned when queue limit is reached.
	ErrPlatformQueueLimitReached = fmt.Errorf("%w: platform job queue limit reached", shared.ErrConflict)

	// ErrPlatformJobNotFound is returned when a platform job is not found.
	ErrPlatformJobNotFound = fmt.Errorf("%w: platform job not found", shared.ErrNotFound)

	// ErrInvalidAuthToken is returned when the command auth token is invalid.
	ErrInvalidAuthToken = fmt.Errorf("%w: invalid command auth token", shared.ErrUnauthorized)

	// ErrAuthTokenExpired is returned when the command auth token has expired.
	ErrAuthTokenExpired = fmt.Errorf("%w: command auth token has expired", shared.ErrUnauthorized)

	// ErrSensorMismatch is returned when sensor ID doesn't match the command's assigned sensor.
	ErrSensorMismatch = fmt.Errorf("%w: sensor not authorized for this command", shared.ErrForbidden)
)

// =============================================================================
// Error Helpers
// =============================================================================

// IsSensorNotFound checks if the error is a sensor not found error.
func IsSensorNotFound(err error) bool {
	return errors.Is(err, ErrSensorNotFound)
}

// IsPlatformSensorNotFound checks if the error is a platform sensor not found error.
func IsPlatformSensorNotFound(err error) bool {
	return errors.Is(err, ErrPlatformSensorNotFound)
}

// IsNoPlatformSensorAvailable checks if the error indicates no platform sensor is available.
func IsNoPlatformSensorAvailable(err error) bool {
	return errors.Is(err, ErrNoPlatformSensorAvailable)
}

// IsAllPlatformSensorsOverloaded checks if all platform sensors are at capacity.
func IsAllPlatformSensorsOverloaded(err error) bool {
	return errors.Is(err, ErrAllPlatformSensorsOverloaded)
}

// IsPlatformLimitReached checks if the error is a platform limit error.
func IsPlatformLimitReached(err error) bool {
	return errors.Is(err, ErrPlatformConcurrentLimitReached) ||
		errors.Is(err, ErrPlatformQueueLimitReached)
}

// IsAuthTokenError checks if the error is an auth token error.
func IsAuthTokenError(err error) bool {
	return errors.Is(err, ErrInvalidAuthToken) ||
		errors.Is(err, ErrAuthTokenExpired) ||
		errors.Is(err, ErrSensorMismatch)
}
