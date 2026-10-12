package retest

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// TenantReader reads a tenant (its settings).
type TenantReader interface {
	GetByID(ctx context.Context, id shared.ID) (*tenant.Tenant, error)
}

// TenantPolicy reads the retest policy from the tenant's settings. It fails
// closed: a tenant that cannot be read never auto-resolves.
type TenantPolicy struct {
	Tenants TenantReader
}

// AutoResolve reports settings.retest.auto_resolve.
func (p TenantPolicy) AutoResolve(ctx context.Context, tenantID shared.ID) bool {
	if p.Tenants == nil {
		return false
	}
	t, err := p.Tenants.GetByID(ctx, tenantID)
	if err != nil || t == nil {
		return false
	}
	return t.TypedSettings().Retest.AutoResolve
}
