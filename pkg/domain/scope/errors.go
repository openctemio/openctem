package scope

import (
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Domain errors for scope operations.
var (
	// Target errors
	ErrInvalidTenantID     = fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	ErrInvalidTargetType   = fmt.Errorf("%w: invalid target type", shared.ErrValidation)
	ErrTargetNotFound      = fmt.Errorf("%w: scope target not found", shared.ErrNotFound)
	ErrTargetAlreadyExists = fmt.Errorf("%w: scope target already exists", shared.ErrConflict)

	// Exclusion errors
	ErrInvalidExclusionType   = fmt.Errorf("%w: invalid exclusion type", shared.ErrValidation)
	ErrExclusionNotFound      = fmt.Errorf("%w: scope exclusion not found", shared.ErrNotFound)
	ErrExclusionAlreadyExists = fmt.Errorf("%w: scope exclusion already exists", shared.ErrConflict)
	ErrReasonRequired         = fmt.Errorf("%w: reason is required for exclusion", shared.ErrValidation)

	// Schedule errors
	ErrInvalidScanType       = fmt.Errorf("%w: invalid scan type", shared.ErrValidation)
	ErrInvalidScheduleType   = fmt.Errorf("%w: invalid schedule type", shared.ErrValidation)
	ErrScheduleNotFound      = fmt.Errorf("%w: scan schedule not found", shared.ErrNotFound)
	ErrScheduleAlreadyExists = fmt.Errorf("%w: scan schedule already exists", shared.ErrConflict)
	ErrNameRequired          = fmt.Errorf("%w: name is required", shared.ErrValidation)

	// Pattern errors
	ErrInvalidPattern = fmt.Errorf("%w: invalid pattern", shared.ErrValidation)
	ErrPatternTooLong = fmt.Errorf("%w: pattern too long", shared.ErrValidation)
)
