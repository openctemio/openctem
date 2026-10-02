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
}

// OrganizationFilter narrows the organization list.
type OrganizationFilter struct {
	// Search matches name or slug, case-insensitively.
	Search string
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
