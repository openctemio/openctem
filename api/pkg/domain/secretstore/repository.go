package secretstore

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ListInput contains parameters for listing credentials.
type ListInput struct {
	TenantID       shared.ID
	CredentialType *CredentialType
	Page           int
	PageSize       int
	SortBy         string
	SortOrder      string
}

// ListOutput contains the result of listing credentials.
type ListOutput struct {
	Items      []*Credential
	TotalCount int
}

// Repository defines the interface for credential persistence.
type Repository interface {
	// Create persists a new credential.
	Create(ctx context.Context, credential *Credential) error

	// GetByTenantAndID retrieves a credential by tenant and ID.
	// This is the primary method for fetching credentials as it enforces tenant isolation.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*Credential, error)

	// GetByTenantAndName retrieves a credential by tenant and name.
	GetByTenantAndName(ctx context.Context, tenantID shared.ID, name string) (*Credential, error)

	// List lists credentials with pagination and filtering.
	List(ctx context.Context, input ListInput) (*ListOutput, error)

	// Update updates a credential.
	// Note: Implementations should validate tenant ownership before updating.
	Update(ctx context.Context, credential *Credential) error

	// DeleteByTenantAndID deletes a credential with tenant validation.
	DeleteByTenantAndID(ctx context.Context, tenantID, id shared.ID) error

	// UpdateLastUsedByTenantAndID updates only the last_used_at field with tenant validation.
	UpdateLastUsedByTenantAndID(ctx context.Context, tenantID, id shared.ID) error

	// CountByTenant counts credentials for a tenant.
	CountByTenant(ctx context.Context, tenantID shared.ID) (int, error)
}
