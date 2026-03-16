package identityprovider

import "context"

// Repository defines persistence operations for identity providers.
type Repository interface {
	Create(ctx context.Context, ip *IdentityProvider) error
	GetByID(ctx context.Context, tenantID, id string) (*IdentityProvider, error)
	GetByTenantAndProvider(ctx context.Context, tenantID string, provider Provider) (*IdentityProvider, error)
	Update(ctx context.Context, ip *IdentityProvider) error
	Delete(ctx context.Context, tenantID, id string) error
	ListByTenant(ctx context.Context, tenantID string) ([]*IdentityProvider, error)
	ListActiveByTenant(ctx context.Context, tenantID string) ([]*IdentityProvider, error)
}
