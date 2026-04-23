package tenant

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/api/pkg/domain/tenant"
)

// TenantMembershipAdapter adapts the tenantdom.Repository to the TenantMembershipProvider interface.
// This allows authapp.SessionService to get all tenant IDs a user belongs to for cache invalidation.
type TenantMembershipAdapter struct {
	repo tenantdom.Repository
}

// NewTenantMembershipAdapter creates a new TenantMembershipAdapter.
func NewTenantMembershipAdapter(repo tenantdom.Repository) *TenantMembershipAdapter {
	return &TenantMembershipAdapter{repo: repo}
}

// GetUserTenantIDs returns all tenant IDs that a user belongs to.
// This is used by authapp.SessionService to invalidate permission cache across all tenants
// when a user's session is revoked.
func (a *TenantMembershipAdapter) GetUserTenantIDs(ctx context.Context, userID shared.ID) ([]string, error) {
	memberships, err := a.repo.GetUserMemberships(ctx, userID)
	if err != nil {
		return nil, err
	}

	tenantIDs := make([]string, 0, len(memberships))
	for _, m := range memberships {
		tenantIDs = append(tenantIDs, m.TenantID)
	}

	return tenantIDs, nil
}
