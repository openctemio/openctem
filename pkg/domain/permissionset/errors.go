package permissionset

import (
	"errors"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Domain errors for permission sets.
var (
	ErrPermissionSetNotFound   = fmt.Errorf("%w: permission set not found", shared.ErrNotFound)
	ErrPermissionSetSlugExists = fmt.Errorf("%w: permission set slug already exists", shared.ErrAlreadyExists)
	ErrSystemSetImmutable      = fmt.Errorf("%w: system permission sets cannot be modified", shared.ErrForbidden)
	ErrParentNotFound          = fmt.Errorf("%w: parent permission set not found", shared.ErrNotFound)
	ErrCircularInheritance     = fmt.Errorf("%w: circular inheritance detected", shared.ErrValidation)
	ErrInvalidPermission       = fmt.Errorf("%w: invalid permission ID", shared.ErrValidation)
	ErrPermissionAlreadyInSet  = fmt.Errorf("%w: permission already in set", shared.ErrAlreadyExists)
	ErrPermissionNotInSet      = fmt.Errorf("%w: permission not in set", shared.ErrNotFound)
	ErrVersionConflict         = fmt.Errorf("%w: version conflict", shared.ErrConflict)
	ErrInactivePermissionSet   = fmt.Errorf("%w: permission set is inactive", shared.ErrValidation)
	ErrCannotDeleteSystemSet   = fmt.Errorf("%w: cannot delete system permission set", shared.ErrForbidden)
	ErrPermissionSetInUse      = fmt.Errorf("%w: permission set is in use by groups", shared.ErrConflict)
)

// IsPermissionSetNotFound checks if the error is a not found error.
func IsPermissionSetNotFound(err error) bool {
	return errors.Is(err, ErrPermissionSetNotFound)
}

// IsPermissionSetSlugExists checks if the error is a slug exists error.
func IsPermissionSetSlugExists(err error) bool {
	return errors.Is(err, ErrPermissionSetSlugExists)
}

// IsSystemSetImmutable checks if the error is a system set immutable error.
func IsSystemSetImmutable(err error) bool {
	return errors.Is(err, ErrSystemSetImmutable)
}

// IsPermissionSetInUse checks if the error is a permission set in use error.
func IsPermissionSetInUse(err error) bool {
	return errors.Is(err, ErrPermissionSetInUse)
}
