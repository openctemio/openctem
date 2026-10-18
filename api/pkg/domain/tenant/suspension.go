package tenant

// Organization suspension: docs/architecture/organization-suspension.md.
//
// A platform administrator suspends an organization (abuse, non-payment,
// legal hold). While suspended, no credential reaches it: sessions, API
// keys, MCP tokens, sensor keys, SCIM tokens, CI run tokens and inbound
// webhooks are refused, and its scheduled work is skipped. Nothing is
// deleted; lifting the suspension restores everything as it was.

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// OrganizationStatus is the platform-level state of an organization
// (tenants.status).
type OrganizationStatus string

const (
	// OrganizationActive is the normal state.
	OrganizationActive OrganizationStatus = "active"
	// OrganizationSuspended refuses every credential for the organization.
	OrganizationSuspended OrganizationStatus = "suspended"
	// OrganizationPendingDeletion: an owner asked for deletion; refused like
	// a suspended organization until the grace period ends and the purge
	// worker deletes it, or an owner cancels
	// (docs/architecture/organization-deletion.md).
	OrganizationPendingDeletion OrganizationStatus = "pending_deletion"
)

// DeletionGrace is how long a requested organization deletion waits.
const DeletionGrace = 14 * 24 * time.Hour

// IsActive reports whether the organization may be reached. Positive check:
// any value other than active (including one added later) is refused.
func (s OrganizationStatus) IsActive() bool { return s == OrganizationActive }

// CodeOrganizationSuspended is the API error code of a request refused
// because its organization is suspended.
const CodeOrganizationSuspended = "ORGANIZATION_SUSPENDED"

// MessageOrganizationSuspended is the text members see. It says nothing about
// why: the reason is for platform administrators only.
const MessageOrganizationSuspended = "This organization is suspended — contact support"

// ErrOrganizationSuspended is returned when a credential tries to reach a
// suspended organization.
var ErrOrganizationSuspended = fmt.Errorf("%w: organization is suspended", shared.ErrForbidden)

// AccessGate decides whether an organization may be reached at all. Every
// credential path asks it once it knows the organization; nil means yes. An
// error other than ErrOrganizationSuspended (the store is unreachable, the
// organization is gone) must be treated as a refusal: the gate fails closed.
type AccessGate interface {
	CheckAccess(ctx context.Context, tenantID shared.ID) error
}

// Suspension is an organization's platform status with who set it and why.
type Suspension struct {
	Status OrganizationStatus
	At     *time.Time
	// By is the platform administrator who suspended it (nil when that
	// administrator was removed, or for an active organization).
	By     *shared.ID
	Reason string
}
