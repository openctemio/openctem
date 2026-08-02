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
	// ListActiveByProvider returns every active provider of a given type across
	// all tenants. Intentional cross-tenant lookup used to resolve an inbound
	// OIDC logout_token's issuer to the configured providers (client_id/JWKS)
	// that could have signed it. Returns provider config only, never tenant data.
	ListActiveByProvider(ctx context.Context, provider Provider) ([]*IdentityProvider, error)
}
