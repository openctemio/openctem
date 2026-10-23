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
	// ErrWildcardNotAllowed: a "*" in a pattern of a type that has no
	// wildcard matcher (or in the host of a URL entry).
	ErrWildcardNotAllowed = shared.NewDomainError("SCOPE_WILDCARD_NOT_ALLOWED",
		"this kind of scope entry takes no wildcard: name one exact value, or use a domain such as *.example.com", shared.ErrValidation)
	// ErrTargetTypeRetired: a new entry of a type that names no network
	// location.
	ErrTargetTypeRetired = shared.NewDomainError("SCOPE_TARGET_TYPE_RETIRED",
		"this type cannot be a scope entry: add the domain, address or network that serves it", shared.ErrValidation)
)

// Existing is the entry or exclusion a new one collides with: its id and
// the status it is in now. It is always the caller's tenant's own row.
type Existing struct {
	ID     shared.ID
	Status Status
}

// DuplicateError refuses a new scope entry or exclusion whose pattern the
// tenant already has, and names the existing row so the caller can act on
// it (approve, activate, renew, remove) instead of retrying. It wraps
// ErrTargetAlreadyExists or ErrExclusionAlreadyExists.
type DuplicateError struct {
	Existing  Existing
	exclusion bool
}

// NewTargetDuplicate is the refusal for a scope entry that already exists.
func NewTargetDuplicate(e Existing) *DuplicateError {
	return &DuplicateError{Existing: e}
}

// NewExclusionDuplicate is the refusal for a scope exclusion that already exists.
func NewExclusionDuplicate(e Existing) *DuplicateError {
	return &DuplicateError{Existing: e, exclusion: true}
}

func (e *DuplicateError) Error() string { return e.Unwrap().Error() }

// Unwrap is ErrExclusionAlreadyExists or ErrTargetAlreadyExists.
func (e *DuplicateError) Unwrap() error {
	if e.exclusion {
		return ErrExclusionAlreadyExists
	}
	return ErrTargetAlreadyExists
}

// Duplicate codes the API answers a DuplicateError with.
const (
	CodeEntryExists     = "SCOPE_ENTRY_EXISTS"
	CodeExclusionExists = "SCOPE_EXCLUSION_EXISTS"
)

// Code is the API code of the refusal.
func (e *DuplicateError) Code() string {
	if e.exclusion {
		return CodeExclusionExists
	}
	return CodeEntryExists
}

// Message is the refusal as a sentence, with the existing row's status.
func (e *DuplicateError) Message() string {
	what := "scope entry"
	if e.exclusion {
		what = "scope exclusion"
	}
	return fmt.Sprintf("this %s already exists (status: %s)", what, e.Existing.Status)
}
