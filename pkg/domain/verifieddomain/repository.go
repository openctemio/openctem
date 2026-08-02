package verifieddomain

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Repository defines persistence operations for verified domains. All
// tenant-scoped methods MUST filter by tenant_id (multi-tenant isolation).
type Repository interface {
	Create(ctx context.Context, d *VerifiedDomain) error
	Update(ctx context.Context, d *VerifiedDomain) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*VerifiedDomain, error)
	GetByTenantAndDomain(ctx context.Context, tenantID shared.ID, domain string) (*VerifiedDomain, error)
	ListByTenant(ctx context.Context, tenantID shared.ID) ([]*VerifiedDomain, error)
	// ListDueForRecheck returns verified rows whose last_checked_at is null or
	// older than `checkedBefore`, across all tenants, capped at `limit`. Used by
	// the background re-verify controller.
	ListDueForRecheck(ctx context.Context, checkedBefore time.Time, limit int) ([]*VerifiedDomain, error)
}
