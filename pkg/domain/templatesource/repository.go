package templatesource

import (
	"context"

	"github.com/openctemio/api/pkg/domain/scannertemplate"
	"github.com/openctemio/api/pkg/domain/shared"
)

// ListInput represents the input for listing template sources.
type ListInput struct {
	TenantID     shared.ID
	SourceType   *SourceType                   // Filter by source type
	TemplateType *scannertemplate.TemplateType // Filter by template type
	Enabled      *bool                         // Filter by enabled status
	Page         int
	PageSize     int
	SortBy       string
	SortOrder    string
}

// ListOutput represents the output of listing template sources.
type ListOutput struct {
	Items      []*TemplateSource
	TotalCount int
}

// Repository defines the interface for template source persistence.
type Repository interface {
	// Create creates a new template source.
	Create(ctx context.Context, source *TemplateSource) error

	// GetByID retrieves a template source by ID.
	GetByID(ctx context.Context, id shared.ID) (*TemplateSource, error)

	// GetByTenantAndID retrieves a template source by tenant ID and source ID.
	GetByTenantAndID(ctx context.Context, tenantID, sourceID shared.ID) (*TemplateSource, error)

	// GetByTenantAndName retrieves a template source by tenant and name.
	GetByTenantAndName(ctx context.Context, tenantID shared.ID, name string) (*TemplateSource, error)

	// List lists template sources with pagination and filtering.
	List(ctx context.Context, input ListInput) (*ListOutput, error)

	// ListByTenantAndTemplateType lists sources for a tenant and template type.
	ListByTenantAndTemplateType(ctx context.Context, tenantID shared.ID, templateType scannertemplate.TemplateType) ([]*TemplateSource, error)

	// ListEnabledForSync lists enabled sources that need syncing for a tenant.
	ListEnabledForSync(ctx context.Context, tenantID shared.ID) ([]*TemplateSource, error)

	// ListAllNeedingSync lists all enabled sources across all tenants that need syncing.
	// Used by background sync scheduler.
	ListAllNeedingSync(ctx context.Context) ([]*TemplateSource, error)

	// Update updates a template source.
	Update(ctx context.Context, source *TemplateSource) error

	// Delete deletes a template source.
	Delete(ctx context.Context, id shared.ID) error

	// UpdateSyncStatus updates only the sync-related fields.
	UpdateSyncStatus(ctx context.Context, source *TemplateSource) error

	// CountByTenant counts the total sources for a tenant.
	CountByTenant(ctx context.Context, tenantID shared.ID) (int, error)
}
