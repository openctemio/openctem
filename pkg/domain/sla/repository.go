package sla

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Repository defines the SLA policy repository interface.
type Repository interface {
	// Create persists a new SLA policy.
	Create(ctx context.Context, policy *Policy) error

	// GetByID retrieves a policy by ID.
	GetByID(ctx context.Context, id shared.ID) (*Policy, error)

	// GetByAsset retrieves the policy for a specific asset.
	// Returns the asset-specific policy if exists, otherwise the tenant default.
	GetByAsset(ctx context.Context, tenantID, assetID shared.ID) (*Policy, error)

	// GetTenantDefault retrieves the default policy for a tenant.
	GetTenantDefault(ctx context.Context, tenantID shared.ID) (*Policy, error)

	// Update updates an existing policy.
	Update(ctx context.Context, policy *Policy) error

	// Delete removes a policy.
	Delete(ctx context.Context, id shared.ID) error

	// ListByTenant returns all policies for a tenant.
	ListByTenant(ctx context.Context, tenantID shared.ID) ([]*Policy, error)

	// ExistsByAsset checks if an asset-specific policy exists.
	ExistsByAsset(ctx context.Context, assetID shared.ID) (bool, error)
}
