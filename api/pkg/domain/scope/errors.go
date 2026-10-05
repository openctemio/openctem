package scope

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
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
	// ErrExclusionSelfApproval: the requester of an exclusion cannot approve it.
	ErrExclusionSelfApproval = fmt.Errorf("%w: cannot approve a scope exclusion you requested", shared.ErrForbidden)
	// ErrExclusionReduceNeedsApprover: deactivating, deleting or shortening an
	// exclusion in effect takes the approval permission, like approving it.
	ErrExclusionReduceNeedsApprover = fmt.Errorf("%w: removing or shortening an approved scope exclusion needs the exclusion approval permission", shared.ErrForbidden)
	// ErrExclusionSelfReduce: the requester of an exclusion in effect cannot
	// take it out of effect or shorten it alone (separation of duties).
	ErrExclusionSelfReduce = fmt.Errorf("%w: cannot remove or shorten a scope exclusion you requested; another approver must", shared.ErrForbidden)
	// ErrExclusionNotPending: approve/reject on an exclusion that is not
	// awaiting review (already approved, or rejected).
	ErrExclusionNotPending = fmt.Errorf("%w: scope exclusion is not awaiting approval", shared.ErrConflict)
	// ErrExclusionNotApproved: activating an exclusion nobody approved.
	ErrExclusionNotApproved = fmt.Errorf("%w: scope exclusion has not been approved", shared.ErrConflict)
	// ErrExclusionRejected: the exclusion was rejected and cannot be changed
	// back into effect; create a new request instead.
	ErrExclusionRejected = fmt.Errorf("%w: scope exclusion was rejected", shared.ErrConflict)

	// Pattern errors
	ErrInvalidPattern = fmt.Errorf("%w: invalid pattern", shared.ErrValidation)
	ErrPatternTooLong = fmt.Errorf("%w: pattern too long", shared.ErrValidation)
)
