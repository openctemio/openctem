package exposure

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A disposition request is the first half of a four-eyes decision on a high
// or critical exposure (leaked credentials included): one approver asks to
// accept its risk or mark it a false positive, and a different approver
// confirms. Lower severities keep the one-step path.
//
// Design: api/docs/architecture/finding-status-lifecycle.md ("Four-eyes on
// exposure dispositions").

// DispositionStatus is the lifecycle of a disposition request.
type DispositionStatus string

const (
	DispositionPending  DispositionStatus = "pending"
	DispositionApproved DispositionStatus = "approved"
	DispositionRejected DispositionStatus = "rejected"
	DispositionCanceled DispositionStatus = "canceled"
)

// MaxDispositionReasonLength bounds a request or decision reason.
const MaxDispositionReasonLength = 1000

// ErrDispositionSelfApproval: the requester cannot confirm their own request.
var ErrDispositionSelfApproval = fmt.Errorf("%w: a second approver must confirm this request; you cannot approve your own", shared.ErrForbidden)

// ErrDispositionSelfApprovalNotAllowed: an owner may approve their own
// request only when no second eligible approver exists.
var ErrDispositionSelfApprovalNotAllowed = fmt.Errorf("%w: you may approve your own request only as the owner when no other approver exists", shared.ErrForbidden)

// ErrDispositionSelfApprovalNeedsReason: an owner's own approval states why.
var ErrDispositionSelfApprovalNeedsReason = fmt.Errorf("%w: approving your own request needs a reason", shared.ErrValidation)

// ErrDispositionSelfApprovalNeedsTOTP: the owner has no authenticator app,
// so their own approval cannot be proven fresh.
var ErrDispositionSelfApprovalNeedsTOTP = fmt.Errorf("%w: approving your own request needs an authenticator app; set one up first", shared.ErrForbidden)

// ErrDispositionSelfApprovalBadCode: the authenticator code is missing,
// wrong or already used.
var ErrDispositionSelfApprovalBadCode = fmt.Errorf("%w: the authenticator code is missing, wrong or already used", shared.ErrForbidden)

// ErrDispositionConflict: another disposition is already pending.
var ErrDispositionConflict = fmt.Errorf("%w: a different disposition is already pending for this exposure; reject it first", shared.ErrConflict)

// ErrNoPendingDisposition: there is no pending request to decide.
var ErrNoPendingDisposition = fmt.Errorf("%w: no pending disposition request", shared.ErrNotFound)

// NeedsSecondApprover reports whether a disposition of an exposure of this
// severity needs a second person.
func NeedsSecondApprover(s Severity) bool {
	return s == SeverityCritical || s == SeverityHigh
}

// IsGatedState reports whether a state is a disposition that the four-eyes
// rule covers (accepted risk, false positive).
func IsGatedState(s State) bool {
	return s == StateAccepted || s == StateFalsePositive
}

// DispositionRequest is one request to set an exposure's disposition.
type DispositionRequest struct {
	ID             shared.ID
	TenantID       shared.ID
	ExposureID     shared.ID
	RequestedState State
	RequestedBy    *shared.ID
	Reason         string
	Status         DispositionStatus
	DecidedBy      *shared.ID
	DecidedAt      *time.Time
	DecisionReason string
	SelfApproved   bool
	CreatedAt      time.Time
}

// NewDispositionRequest builds a pending request.
func NewDispositionRequest(tenantID, exposureID, requestedBy shared.ID, state State, reason string) (*DispositionRequest, error) {
	if !IsGatedState(state) {
		return nil, fmt.Errorf("%w: %s is not a disposition", shared.ErrValidation, state)
	}
	if len(reason) > MaxDispositionReasonLength {
		return nil, fmt.Errorf("%w: reason is longer than %d characters", shared.ErrValidation, MaxDispositionReasonLength)
	}
	by := requestedBy
	return &DispositionRequest{
		ID:             shared.NewID(),
		TenantID:       tenantID,
		ExposureID:     exposureID,
		RequestedState: state,
		RequestedBy:    &by,
		Reason:         reason,
		Status:         DispositionPending,
		CreatedAt:      time.Now().UTC(),
	}, nil
}

// IsRequestedBy reports whether the user made this request.
func (r *DispositionRequest) IsRequestedBy(userID shared.ID) bool {
	return r.RequestedBy != nil && *r.RequestedBy == userID
}

// DispositionRepository stores disposition requests. Every method is
// tenant-scoped.
type DispositionRepository interface {
	// Create stores a pending request for an exposure of the same tenant. A
	// second pending request for the same exposure is ErrDispositionConflict.
	Create(ctx context.Context, req *DispositionRequest) error
	// GetPending returns the exposure's pending request, or nil.
	GetPending(ctx context.Context, tenantID, exposureID shared.ID) (*DispositionRequest, error)
	// ListPending returns the pending requests of the given exposures.
	ListPending(ctx context.Context, tenantID shared.ID, exposureIDs []shared.ID) (map[shared.ID]*DispositionRequest, error)
	// Decide moves a pending request to status, recording who decided and
	// why. It returns false when the request is no longer pending (another
	// approver decided first).
	Decide(ctx context.Context, tenantID, id shared.ID, status DispositionStatus, by shared.ID, reason string, selfApproved bool) (bool, error)
	// Reopen puts an approved request back to pending (the state change it
	// approved could not be applied).
	Reopen(ctx context.Context, tenantID, id shared.ID) error
	// CountEligibleApprovers counts the tenant's active members who hold
	// every one of perms (owners and admins hold all).
	CountEligibleApprovers(ctx context.Context, tenantID shared.ID, perms []string) (int, error)
	// IsTenantOwner reports whether the user is an active owner.
	IsTenantOwner(ctx context.Context, tenantID, userID shared.ID) (bool, error)
}
