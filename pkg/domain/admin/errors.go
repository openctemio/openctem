package admin

import (
	"errors"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Domain errors for admin operations.
var (
	// ==========================================================================
	// Admin User Errors
	// ==========================================================================

	// ErrAdminNotFound is returned when an admin user is not found.
	ErrAdminNotFound = fmt.Errorf("%w: admin user not found", shared.ErrNotFound)

	// ErrAdminAlreadyExists is returned when an admin with the same email exists.
	ErrAdminAlreadyExists = fmt.Errorf("%w: admin user with this email already exists", shared.ErrAlreadyExists)

	// ErrInvalidAPIKey is returned when the API key is invalid.
	ErrInvalidAPIKey = fmt.Errorf("%w: invalid admin API key", shared.ErrUnauthorized)

	// ErrAdminInactive is returned when the admin user is inactive.
	ErrAdminInactive = fmt.Errorf("%w: admin user is inactive", shared.ErrForbidden)

	// ErrInsufficientRole is returned when the admin lacks required permissions.
	ErrInsufficientRole = fmt.Errorf("%w: insufficient role permissions", shared.ErrForbidden)

	// ErrCannotDeleteSelf is returned when an admin tries to delete themselves.
	ErrCannotDeleteSelf = fmt.Errorf("%w: cannot delete your own admin account", shared.ErrForbidden)

	// ErrCannotDeactivateSelf is returned when an admin tries to deactivate themselves.
	ErrCannotDeactivateSelf = fmt.Errorf("%w: cannot deactivate your own admin account", shared.ErrForbidden)

	// ErrCannotDemoteSelf is returned when an admin tries to demote themselves.
	ErrCannotDemoteSelf = fmt.Errorf("%w: cannot demote your own admin account", shared.ErrForbidden)

	// ErrLastSuperAdmin is returned when trying to remove the last super admin.
	ErrLastSuperAdmin = fmt.Errorf("%w: cannot remove the last super admin", shared.ErrForbidden)

	// ==========================================================================
	// Audit Log Errors
	// ==========================================================================

	// ErrAuditLogNotFound is returned when an audit log is not found.
	ErrAuditLogNotFound = fmt.Errorf("%w: audit log not found", shared.ErrNotFound)
)

// =============================================================================
// Error Helpers
// =============================================================================

// IsAdminNotFound checks if the error indicates an admin was not found.
func IsAdminNotFound(err error) bool {
	return errors.Is(err, ErrAdminNotFound)
}

// IsAdminAlreadyExists checks if the error indicates an admin already exists.
func IsAdminAlreadyExists(err error) bool {
	return errors.Is(err, ErrAdminAlreadyExists)
}

// IsInvalidAPIKey checks if the error indicates an invalid API key.
func IsInvalidAPIKey(err error) bool {
	return errors.Is(err, ErrInvalidAPIKey)
}

// IsAdminInactive checks if the error indicates an inactive admin.
func IsAdminInactive(err error) bool {
	return errors.Is(err, ErrAdminInactive)
}

// IsAuthError checks if the error is an authentication error.
func IsAuthError(err error) bool {
	return errors.Is(err, ErrInvalidAPIKey) || errors.Is(err, ErrAdminInactive)
}

// IsAuthorizationError checks if the error is an authorization error.
func IsAuthorizationError(err error) bool {
	return errors.Is(err, ErrInsufficientRole) ||
		errors.Is(err, ErrCannotDeleteSelf) ||
		errors.Is(err, ErrCannotDeactivateSelf) ||
		errors.Is(err, ErrCannotDemoteSelf) ||
		errors.Is(err, ErrLastSuperAdmin)
}

// IsSelfModificationError checks if the error is a self-modification error.
func IsSelfModificationError(err error) bool {
	return errors.Is(err, ErrCannotDeleteSelf) ||
		errors.Is(err, ErrCannotDeactivateSelf) ||
		errors.Is(err, ErrCannotDemoteSelf)
}

// IsAuditLogNotFound checks if the error indicates an audit log was not found.
func IsAuditLogNotFound(err error) bool {
	return errors.Is(err, ErrAuditLogNotFound)
}
