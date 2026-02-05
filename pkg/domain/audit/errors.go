package audit

import (
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

// AuditLogNotFoundError returns a not found error for an audit log.
func AuditLogNotFoundError(id shared.ID) error {
	return fmt.Errorf("%w: audit log with id %s not found", shared.ErrNotFound, id)
}

// InvalidFilterError returns a validation error for invalid filter.
func InvalidFilterError(reason string) error {
	return fmt.Errorf("%w: invalid filter: %s", shared.ErrValidation, reason)
}
