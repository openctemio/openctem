package integration

import (
	"context"
)

// Filter represents filters for listing integrations.
type Filter struct {
	TenantID  *ID
	Category  *Category
	Provider  *Provider
	Status    *Status
	Search    string
	Page      int
	PerPage   int
	SortBy    string
	SortOrder string
}

// NewFilter creates a new filter with defaults.
func NewFilter() Filter {
	return Filter{
		Page:      1,
		PerPage:   20,
		SortBy:    "created_at",
		SortOrder: "desc",
	}
}

// ListResult represents a paginated list result.
type ListResult struct {
	Data       []*Integration
	Total      int64
	Page       int
	PerPage    int
	TotalPages int
}

// Repository defines the interface for integration persistence.
type Repository interface {
	// CRUD operations
	Create(ctx context.Context, i *Integration) error
	GetByID(ctx context.Context, id ID) (*Integration, error)
	GetByTenantAndName(ctx context.Context, tenantID ID, name string) (*Integration, error)
	Update(ctx context.Context, i *Integration) error
	Delete(ctx context.Context, id ID) error

	// List operations
	List(ctx context.Context, filter Filter) (ListResult, error)
	Count(ctx context.Context, filter Filter) (int64, error)

	// Batch operations
	ListByTenant(ctx context.Context, tenantID ID) ([]*Integration, error)
	ListByCategory(ctx context.Context, tenantID ID, category Category) ([]*Integration, error)
	ListByProvider(ctx context.Context, tenantID ID, provider Provider) ([]*Integration, error)
}

// SCMExtensionRepository defines the interface for SCM extension persistence.
type SCMExtensionRepository interface {
	// CRUD operations
	Create(ctx context.Context, ext *SCMExtension) error
	GetByIntegrationID(ctx context.Context, integrationID ID) (*SCMExtension, error)
	Update(ctx context.Context, ext *SCMExtension) error
	Delete(ctx context.Context, integrationID ID) error

	// Combined operations (integration + extension)
	GetIntegrationWithSCM(ctx context.Context, id ID) (*IntegrationWithSCM, error)
	ListIntegrationsWithSCM(ctx context.Context, tenantID ID) ([]*IntegrationWithSCM, error)
}

// NotificationExtensionRepository defines the interface for notification extension persistence.
type NotificationExtensionRepository interface {
	// CRUD operations
	Create(ctx context.Context, ext *NotificationExtension) error
	GetByIntegrationID(ctx context.Context, integrationID ID) (*NotificationExtension, error)
	Update(ctx context.Context, ext *NotificationExtension) error
	Delete(ctx context.Context, integrationID ID) error

	// Combined operations (integration + extension)
	GetIntegrationWithNotification(ctx context.Context, id ID) (*IntegrationWithNotification, error)
	ListIntegrationsWithNotification(ctx context.Context, tenantID ID) ([]*IntegrationWithNotification, error)
}
