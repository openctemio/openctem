package integration

import (
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Domain errors for integration.
var (
	// Not found errors
	ErrIntegrationNotFound           = fmt.Errorf("%w: integration not found", shared.ErrNotFound)
	ErrSCMExtensionNotFound          = fmt.Errorf("%w: SCM extension not found", shared.ErrNotFound)
	ErrNotificationExtensionNotFound = fmt.Errorf("%w: notification extension not found", shared.ErrNotFound)

	// Conflict errors
	ErrIntegrationNameExists = fmt.Errorf("%w: integration name already exists", shared.ErrConflict)
	ErrIntegrationInUse      = fmt.Errorf("%w: integration is in use", shared.ErrConflict)

	// Validation errors
	ErrInvalidCategory          = fmt.Errorf("%w: invalid integration category", shared.ErrValidation)
	ErrInvalidProvider          = fmt.Errorf("%w: invalid integration provider", shared.ErrValidation)
	ErrInvalidStatus            = fmt.Errorf("%w: invalid integration status", shared.ErrValidation)
	ErrInvalidAuthType          = fmt.Errorf("%w: invalid authentication type", shared.ErrValidation)
	ErrCredentialsRequired      = fmt.Errorf("%w: credentials are required", shared.ErrValidation)
	ErrProviderCategoryMismatch = fmt.Errorf("%w: provider does not match category", shared.ErrValidation)

	// Connection errors
	ErrConnectionFailed   = fmt.Errorf("%w: connection test failed", shared.ErrValidation)
	ErrCredentialsInvalid = fmt.Errorf("%w: credentials are invalid", shared.ErrValidation)
)
