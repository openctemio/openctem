package tenant

// Ownership transfer: the owner hands the organization to an existing member,
// who accepts with their own re-authentication. Design:
// docs/rfcs/RFC-095-role-templates-and-invitations.md.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// OwnershipTransferTTL is how long a request waits for the new owner.
const OwnershipTransferTTL = 72 * time.Hour

// OwnershipTransferStatus is the state of a transfer request.
type OwnershipTransferStatus string

// Transfer states. Only pending is open; the others are final.
const (
	OwnershipTransferPending  OwnershipTransferStatus = "pending"
	OwnershipTransferAccepted OwnershipTransferStatus = "accepted"
	OwnershipTransferCanceled OwnershipTransferStatus = "canceled"
	OwnershipTransferDeclined OwnershipTransferStatus = "declined"
	OwnershipTransferExpired  OwnershipTransferStatus = "expired"
)

// Errors of the transfer flow. Each maps to a stable API code.
var (
	// ErrOwnershipTransferNotOwner: only the organization's active owner
	// starts or cancels a transfer.
	ErrOwnershipTransferNotOwner = fmt.Errorf("%w: only the organization owner can transfer ownership", shared.ErrForbidden)
	// ErrOwnershipTransferPending: a request is already waiting.
	ErrOwnershipTransferPending = fmt.Errorf("%w: an ownership transfer is already waiting for an answer; cancel it first", shared.ErrConflict)
	// ErrOwnershipTransferNotFound: no open request (or not one the caller
	// may see).
	ErrOwnershipTransferNotFound = fmt.Errorf("%w: no pending ownership transfer", shared.ErrNotFound)
	// ErrOwnershipTransferExpired: the request lapsed before it was accepted.
	ErrOwnershipTransferExpired = fmt.Errorf("%w: this ownership transfer has expired; ask the owner for a new one", shared.ErrConflict)
	// ErrOwnershipTransferStale: the person who asked is no longer the
	// owner, so the request is void.
	ErrOwnershipTransferStale = fmt.Errorf("%w: the person who asked is no longer the owner; this transfer is void", shared.ErrConflict)

	// ErrOwnershipTargetSelf: the owner cannot transfer to themself.
	ErrOwnershipTargetSelf = fmt.Errorf("%w: you already own this organization", shared.ErrValidation)
	// ErrOwnershipTargetInactive: the new owner must be an active member.
	ErrOwnershipTargetInactive = fmt.Errorf("%w: the new owner must be an active member of the organization", shared.ErrValidation)
	// ErrOwnershipTargetService: a service account never owns anything.
	ErrOwnershipTargetService = fmt.Errorf("%w: a service account cannot own an organization", shared.ErrValidation)
	// ErrOwnershipTargetNoMFA: the new owner must have two-factor
	// authentication turned on.
	ErrOwnershipTargetNoMFA = fmt.Errorf("%w: the new owner must turn on two-factor authentication first", shared.ErrValidation)
	// ErrOwnershipTargetManaged: someone another organization manages
	// cannot own this one.
	ErrOwnershipTargetManaged = fmt.Errorf("%w: this person is managed by another organization and cannot become the owner", shared.ErrValidation)
	// ErrOwnershipTargetNeedsInternal: an unmanaged outside member becomes
	// internal on transfer; the owner must confirm it.
	ErrOwnershipTargetNeedsInternal = fmt.Errorf("%w: this person is outside the organization; confirm that they become an internal member", shared.ErrValidation)
	// ErrOwnershipPreviousRole: the previous owner becomes admin, member or
	// viewer.
	ErrOwnershipPreviousRole = fmt.Errorf("%w: the previous owner can become an administrator, a member or a viewer", shared.ErrValidation)
)

// OwnershipTransfer is one request to hand an organization to a member.
type OwnershipTransfer struct {
	ID                shared.ID
	TenantID          shared.ID
	FromUserID        shared.ID
	ToUserID          shared.ID
	PreviousOwnerRole Role
	// MakeInternal: the new owner is an unmanaged outside member who becomes
	// internal on acceptance (the owner confirmed it).
	MakeInternal bool
	Status       OwnershipTransferStatus
	CreatedAt    time.Time
	ExpiresAt    time.Time
	DecidedAt    *time.Time
	DecidedBy    *shared.ID
}

// NewOwnershipTransfer builds a pending request from fromUser to toUser.
func NewOwnershipTransfer(tenantID, fromUser, toUser shared.ID, previousRole Role, makeInternal bool, now time.Time) (*OwnershipTransfer, error) {
	if fromUser == toUser {
		return nil, ErrOwnershipTargetSelf
	}
	if previousRole == "" {
		previousRole = RoleAdmin
	}
	if !ValidPreviousOwnerRole(previousRole) {
		return nil, ErrOwnershipPreviousRole
	}
	return &OwnershipTransfer{
		ID:                shared.NewID(),
		TenantID:          tenantID,
		FromUserID:        fromUser,
		ToUserID:          toUser,
		PreviousOwnerRole: previousRole,
		MakeInternal:      makeInternal,
		Status:            OwnershipTransferPending,
		CreatedAt:         now,
		ExpiresAt:         now.Add(OwnershipTransferTTL),
	}, nil
}

// ValidPreviousOwnerRole reports whether r is a role the previous owner may
// take: administrator, member or viewer.
func ValidPreviousOwnerRole(r Role) bool {
	return r == RoleAdmin || r == RoleMember || r == RoleViewer
}

// IsExpired reports whether a pending request has lapsed at now.
func (t *OwnershipTransfer) IsExpired(now time.Time) bool {
	return t.Status == OwnershipTransferPending && !now.Before(t.ExpiresAt)
}

// OwnershipCandidate is what decides whether a member may become the owner.
type OwnershipCandidate struct {
	MembershipID shared.ID
	UserID       shared.ID
	Active       bool
	Service      bool
	MFAEnabled   bool
	External     bool
	// Managed: another organization holds the person's domain
	// (home_tenant_id set).
	Managed bool
}

// CheckOwnershipCandidate applies the rules for a new owner: an active person
// (not a service account) with two-factor authentication, not managed by
// another organization. An unmanaged outside member qualifies only when
// confirmInternal is set: they become internal on acceptance.
func CheckOwnershipCandidate(c OwnershipCandidate, confirmInternal bool) error {
	switch {
	case !c.Active:
		return ErrOwnershipTargetInactive
	case c.Service:
		return ErrOwnershipTargetService
	case c.External && c.Managed:
		return ErrOwnershipTargetManaged
	case !c.MFAEnabled:
		return ErrOwnershipTargetNoMFA
	case c.External && !confirmInternal:
		return ErrOwnershipTargetNeedsInternal
	}
	return nil
}

// OwnershipTransferResult is what an accepted transfer changed.
type OwnershipTransferResult struct {
	Transfer          *OwnershipTransfer
	FromMembershipID  shared.ID
	ToMembershipID    shared.ID
	BecameInternal    bool
	PreviousOwnerRole Role
}

// IsOwnershipTransferError reports whether err is one of the transfer errors
// above (for the API's code mapping).
func IsOwnershipTransferError(err error) bool {
	for _, e := range []error{
		ErrOwnershipTransferNotOwner, ErrOwnershipTransferPending, ErrOwnershipTransferNotFound,
		ErrOwnershipTransferExpired, ErrOwnershipTransferStale, ErrOwnershipTargetSelf,
		ErrOwnershipTargetInactive, ErrOwnershipTargetService, ErrOwnershipTargetNoMFA,
		ErrOwnershipTargetManaged, ErrOwnershipTargetNeedsInternal, ErrOwnershipPreviousRole,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// OwnershipTransferRepository stores transfer requests and applies an
// accepted one atomically. Every method is scoped to tenantID.
type OwnershipTransferRepository interface {
	// OwnershipCandidate reads what decides whether the member with
	// membershipID may become the owner. shared.ErrNotFound when the
	// membership is not in tenantID.
	OwnershipCandidate(ctx context.Context, tenantID, membershipID shared.ID) (*OwnershipCandidate, error)
	// CreateOwnershipTransfer stores a pending request after checking, under
	// a lock, that t.FromUserID is still the active owner. A lapsed pending
	// request is closed as expired first; another open one is
	// ErrOwnershipTransferPending.
	CreateOwnershipTransfer(ctx context.Context, t *OwnershipTransfer) error
	// PendingOwnershipTransfer returns the open, unexpired request, or
	// ErrOwnershipTransferNotFound.
	PendingOwnershipTransfer(ctx context.Context, tenantID shared.ID, now time.Time) (*OwnershipTransfer, error)
	// CloseOwnershipTransfer moves the open request id to status (canceled
	// or declined). ErrOwnershipTransferNotFound when it is no longer open.
	CloseOwnershipTransfer(ctx context.Context, tenantID, id shared.ID, status OwnershipTransferStatus, by shared.ID, now time.Time) (*OwnershipTransfer, error)
	// AcceptOwnershipTransfer applies the open request id for acceptor in one
	// transaction: the new owner, the previous owner's role, one owner left.
	AcceptOwnershipTransfer(ctx context.Context, tenantID, id, acceptor shared.ID, now time.Time) (*OwnershipTransferResult, error)
}
