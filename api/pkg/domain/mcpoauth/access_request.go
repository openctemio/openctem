package mcpoauth

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AccessRequestStatus is the state of a request to approve a publisher.
type AccessRequestStatus string

const (
	AccessRequestPending  AccessRequestStatus = "pending"
	AccessRequestApproved AccessRequestStatus = "approved"
	AccessRequestDenied   AccessRequestStatus = "denied"
)

// AccessRequest is a member asking the organization to approve the
// publisher (metadata-document host) of an AI application the policy
// blocks. Every field comes from the stored authorization request.
type AccessRequest struct {
	ID         shared.ID
	TenantID   shared.ID
	ClientHost string
	ClientName string
	ClientID   string
	Scopes     []Scope
	// RequestedBy is the first member who asked (nil once that user is
	// deleted).
	RequestedBy *shared.ID
	// RequesterName is the requester's display name (read only).
	RequesterName string
	// RequestCount is how many times members asked while it was pending.
	RequestCount int
	Status       AccessRequestStatus
	DecidedBy    *shared.ID
	DecidedAt    *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// AccessRequestRepository stores access requests. Every method is scoped to
// one tenant.
type AccessRequestRepository interface {
	// UpsertAccessRequest records a pending request for the host, or bumps
	// the existing pending one (count, scopes, time). created is true when
	// a new row was written. r.ID is set to the stored row's id.
	UpsertAccessRequest(ctx context.Context, r *AccessRequest) (created bool, err error)
	// CountAccessRequestsCreatedBy counts the requests the user opened in
	// the tenant since the given time.
	CountAccessRequestsCreatedBy(ctx context.Context, tenantID, userID shared.ID, since time.Time) (int, error)
	// CountPendingAccessRequests counts the tenant's pending requests.
	CountPendingAccessRequests(ctx context.Context, tenantID shared.ID) (int, error)
	// PendingAccessRequestForHost returns the pending request for the host,
	// or ErrNotFound.
	PendingAccessRequestForHost(ctx context.Context, tenantID shared.ID, host string) (*AccessRequest, error)
	// ListPendingAccessRequests lists the tenant's pending requests, newest
	// first.
	ListPendingAccessRequests(ctx context.Context, tenantID shared.ID) ([]AccessRequest, error)
	// GetAccessRequest returns one request of the tenant, or ErrNotFound.
	GetAccessRequest(ctx context.Context, tenantID, id shared.ID) (*AccessRequest, error)
	// DecideAccessRequest moves a pending request of the tenant to
	// approved or denied; anything else is ErrNotFound.
	DecideAccessRequest(ctx context.Context, tenantID, id, decidedBy shared.ID, approve bool, now time.Time) error
	// ActiveAdminIDs returns the tenant's active owners and administrators.
	ActiveAdminIDs(ctx context.Context, tenantID shared.ID) ([]shared.ID, error)
}
