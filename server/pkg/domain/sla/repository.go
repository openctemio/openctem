package sla

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Repository defines the SLA policy repository interface.
type Repository interface {
	// Create persists a new SLA policy.
	Create(ctx context.Context, policy *Policy) error

	// GetByTenantAndID retrieves a policy by tenant and ID.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*Policy, error)

	// GetByAsset retrieves the policy for a specific asset.
	// Returns the asset-specific policy if exists, otherwise the tenant default.
	GetByAsset(ctx context.Context, tenantID, assetID shared.ID) (*Policy, error)

	// GetTenantDefault retrieves the default policy for a tenant.
	GetTenantDefault(ctx context.Context, tenantID shared.ID) (*Policy, error)

	// UpdateMakingDefault writes the policy (already marked default) and
	// clears is_default on the tenant's other tenant-wide policies in ONE
	// transaction, serialized per tenant so concurrent calls end with exactly
	// one default. Only the policy's own tenant is read or written.
	UpdateMakingDefault(ctx context.Context, policy *Policy) error

	// Update updates an existing policy. Only the row of the policy's own
	// tenant is written; another tenant's id is not found.
	Update(ctx context.Context, policy *Policy) error

	// Delete removes a policy of the tenant.
	Delete(ctx context.Context, tenantID, id shared.ID) error

	// HasAssetOverride reports whether the tenant has an active policy tied to
	// a single asset. With none, every asset is governed by the tenant default.
	HasAssetOverride(ctx context.Context, tenantID shared.ID) (bool, error)

	// ListByTenant returns all policies for a tenant.
	ListByTenant(ctx context.Context, tenantID shared.ID) ([]*Policy, error)
}
