package admin

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Organization is the platform admin's cross-tenant view of one tenant
// (RFC-022 Phase 2): identity, size and SSO posture, without tenant data.
type Organization struct {
	ID          shared.ID
	Name        string
	Slug        string
	Description string
	CreatedAt   time.Time
	// ActiveMembers counts memberships that are not suspended.
	ActiveMembers int
	OwnerEmails   []string
	// SSO posture.
	SAMLEnabled             bool
	ActiveIdentityProviders int
	VerifiedDomains         int
	SSOEnforced             bool
	// LimitsApply: at least one limit or feature deny is set for the
	// organization (by the operator or a source).
	LimitsApply bool
	// Status is the platform status (tenants.status: active or suspended),
	// with when and why it was suspended (docs/architecture/organization-suspension.md).
	Status          string
	SuspendedAt     *time.Time
	SuspendedReason string
	// DeletionDueAt: an owner scheduled the deletion; the purge worker
	// deletes the organization at this time unless an owner cancels.
	DeletionDueAt *time.Time
}

// Owner filter values for OrganizationFilter.Owner.
const (
	OrganizationOwnerNone    = "none"
	OrganizationOwnerPresent = "present"
)

// OrganizationFilter narrows the organization list.
type OrganizationFilter struct {
	// Search matches name or slug, case-insensitively.
	Search string
	// Owner is OrganizationOwnerNone (no active owner), OrganizationOwnerPresent
	// or empty (any).
	Owner string
	// IncludeSystem lists the platform system tenant too. It is internal
	// (seeded data, no members): left out of the list unless asked for.
	IncludeSystem bool
	// Status, when set, keeps organizations in that platform status.
	Status string
	Limit  int
	Offset int
}

// OrganizationReader is a platform-level (cross-tenant) read model. It exists
// only for the admin console and must never be reachable from tenant routes.
type OrganizationReader interface {
	ListOrganizations(ctx context.Context, f OrganizationFilter) ([]*Organization, int, error)
	// GetOrganization returns shared.ErrNotFound when the tenant does not exist.
	GetOrganization(ctx context.Context, id shared.ID) (*Organization, error)
}
