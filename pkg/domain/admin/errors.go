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

	// ErrUserHasMemberships: a platform administrator belongs to no organization.
	ErrUserHasMemberships = fmt.Errorf("%w: this account belongs to an organization; platform administrators cannot", shared.ErrConflict)

	// ErrUserAlreadyAdmin: the user account is already an administrator.
	ErrUserAlreadyAdmin = fmt.Errorf("%w: this account is already a platform administrator", shared.ErrConflict)

	// ErrEmailHasAccount is returned when provisioning an administrator for an
	// email that already has a sign-in account. Existing accounts are never
	// linked (their owner, not the provisioning admin, controls the password).
	ErrEmailHasAccount = fmt.Errorf("%w: an account with this email already exists", shared.ErrConflict)

	// ErrAdminNotFound is returned when an admin user is not found.
	ErrAdminNotFound = fmt.Errorf("%w: admin user not found", shared.ErrNotFound)

	// ErrAdminAlreadyExists is returned when an admin with the same email exists.
	ErrAdminAlreadyExists = fmt.Errorf("%w: admin user with this email already exists", shared.ErrAlreadyExists)

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
