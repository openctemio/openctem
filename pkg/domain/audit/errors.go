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

// ErrChainRebaselineConflict means the audit hash-chain changed between the
// rebaseline reading it and applying the rewrite, so nothing was applied.
var ErrChainRebaselineConflict = fmt.Errorf("%w: audit chain changed during rebaseline", shared.ErrConflict)

// ErrChainSourceMissing means a chain entry points at an audit log that no
// longer exists. That is a tamper signal, so a rebaseline refuses to run.
var ErrChainSourceMissing = fmt.Errorf("%w: audit log behind a chain entry is missing", shared.ErrConflict)
