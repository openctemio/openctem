package datasource

import (
	"errors"
	"fmt"
)

// Domain errors for data source operations.
var (
	// Validation errors
	ErrTenantIDRequired  = errors.New("tenant ID is required")
	ErrNameRequired      = errors.New("name is required")
	ErrInvalidSourceType = errors.New("invalid source type")
	ErrInvalidStatus     = errors.New("invalid source status")
	ErrAPIKeyRequired    = errors.New("API key is required for this source type")

	// Not found errors
	ErrDataSourceNotFound  = errors.New("data source not found")
	ErrAssetSourceNotFound = errors.New("asset source not found")

	// Conflict errors
	ErrDataSourceExists = errors.New("data source with this name already exists")

	// Authentication errors
	ErrInvalidAPIKey  = errors.New("invalid API key")
	ErrAPIKeyExpired  = errors.New("API key has expired")
	ErrSourceDisabled = errors.New("data source is disabled")
	ErrSourceInactive = errors.New("data source is inactive")

	// Operation errors
	ErrCannotAcceptData = errors.New("data source cannot accept data in current state")
)

// NotFoundError returns a not found error for a specific data source.
func NotFoundError(id string) error {
	return fmt.Errorf("%w: %s", ErrDataSourceNotFound, id)
}

// AlreadyExistsError returns an already exists error for a specific data source name.
func AlreadyExistsError(name string) error {
	return fmt.Errorf("%w: %s", ErrDataSourceExists, name)
}

// ValidationError creates a validation error with a custom message.
func ValidationError(msg string) error {
	return fmt.Errorf("validation error: %s", msg)
}
