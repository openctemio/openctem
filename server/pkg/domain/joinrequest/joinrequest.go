// Package joinrequest holds requests to join an organization by a verified
// email domain (docs/rfcs/RFC-104). A request belongs to one organization:
// only that organization's administrators list and decide it, and the
// requester sees only their own.
package joinrequest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Status of a request.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

// TTL is how long a request waits for a decision.
const TTL = 30 * 24 * time.Hour

// Retention is how long a decided or expired request is kept.
const Retention = 30 * 24 * time.Hour

// MaxPerDay bounds the requests one person creates in 24 hours.
const MaxPerDay = 5

var (
	// ErrNotFound: no such request in this organization.
	ErrNotFound = fmt.Errorf("%w: join request not found", shared.ErrNotFound)
	// ErrAlreadyPending: the person already waits on this organization.
	ErrAlreadyPending = fmt.Errorf("%w: a request to join this organization is already waiting", shared.ErrConflict)
	// ErrNotPending: the request was decided or expired.
	ErrNotPending = fmt.Errorf("%w: the request is no longer waiting", shared.ErrConflict)
	// ErrTooMany: the person reached the daily limit.
	ErrTooMany = errors.New("too many requests to join; try again tomorrow")
	// ErrInvalidRole: people never join as administrators by domain.
	ErrInvalidRole = fmt.Errorf("%w: role must be viewer or member", shared.ErrValidation)
)

// ValidRole reports whether role may be granted by a join request.
func ValidRole(role string) bool { return role == "viewer" || role == "member" }

// Request is one request to join.
type Request struct {
	ID            shared.ID
	TenantID      shared.ID
	UserID        shared.ID
	DomainID      *shared.ID
	Status        Status
	RequestedRole string
	DecidedRole   string
	DecidedBy     *shared.ID
	DecidedAt     *time.Time
	ExpiresAt     time.Time
	CreatedAt     time.Time

	// Read-side fields for the organization's inbox (the requester's own
	// identity, shown only to that organization's administrators).
	Email         string
	Name          string
	EmailVerified bool
}

// Pending reports whether the request still waits at t.
func (r *Request) Pending(t time.Time) bool {
	return r.Status == StatusPending && t.Before(r.ExpiresAt)
}

// New creates a pending request.
func New(tenantID, userID shared.ID, domainID *shared.ID, role string, now time.Time) (*Request, error) {
	if !ValidRole(role) {
		return nil, ErrInvalidRole
	}
	now = now.UTC()
	return &Request{
		ID: shared.NewID(), TenantID: tenantID, UserID: userID, DomainID: domainID,
		Status: StatusPending, RequestedRole: role, ExpiresAt: now.Add(TTL), CreatedAt: now,
	}, nil
}

// Repository persists requests. Every read and write is scoped to an
// organization or to the requester.
type Repository interface {
	// Create stores a pending request; ErrAlreadyPending when one waits.
	Create(ctx context.Context, r *Request) error
	// GetForTenant returns a request of the organization.
	GetForTenant(ctx context.Context, tenantID, id shared.ID) (*Request, error)
	// ListPending lists the organization's waiting requests with the
	// requester's identity.
	ListPending(ctx context.Context, tenantID shared.ID, now time.Time, limit int) ([]*Request, error)
	// ListByUser lists the requester's own requests.
	ListByUser(ctx context.Context, userID shared.ID, limit int) ([]*Request, error)
	// CountSince counts the requester's requests created after t.
	CountSince(ctx context.Context, userID shared.ID, t time.Time) (int, error)
	// Decide moves a waiting request of the organization to status;
	// ErrNotPending when it no longer waits.
	Decide(ctx context.Context, tenantID, id shared.ID, status Status, role string, by shared.ID, at time.Time) error
	// Purge deletes decided requests and expired ones older than before.
	Purge(ctx context.Context, before time.Time) (int64, error)
}
