package scope

import "errors"

// Domain errors for scope operations.
var (
	// Target errors
	ErrInvalidTenantID     = errors.New("invalid tenant ID")
	ErrInvalidTargetType   = errors.New("invalid target type")
	ErrTargetNotFound      = errors.New("scope target not found")
	ErrTargetAlreadyExists = errors.New("scope target already exists")

	// Exclusion errors
	ErrInvalidExclusionType   = errors.New("invalid exclusion type")
	ErrExclusionNotFound      = errors.New("scope exclusion not found")
	ErrExclusionAlreadyExists = errors.New("scope exclusion already exists")
	ErrReasonRequired         = errors.New("reason is required for exclusion")

	// Schedule errors
	ErrInvalidScanType       = errors.New("invalid scan type")
	ErrInvalidScheduleType   = errors.New("invalid schedule type")
	ErrScheduleNotFound      = errors.New("scan schedule not found")
	ErrScheduleAlreadyExists = errors.New("scan schedule already exists")
	ErrNameRequired          = errors.New("name is required")

	// Pattern errors
	ErrInvalidPattern = errors.New("invalid pattern")
	ErrPatternTooLong = errors.New("pattern too long")
)
