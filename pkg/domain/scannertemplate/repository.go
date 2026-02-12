package scannertemplate

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// Filter represents filter options for listing scanner templates.
type Filter struct {
	TenantID     *shared.ID
	TemplateType *TemplateType
	Status       *TemplateStatus
	SourceID     *shared.ID
	Tags         []string
	Search       string
}

// Repository defines the interface for scanner template persistence.
type Repository interface {
	// Create creates a new scanner template.
	Create(ctx context.Context, template *ScannerTemplate) error

	// GetByTenantAndID retrieves a scanner template by tenant and ID.
	// This is the primary method for fetching templates as it enforces tenant isolation.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*ScannerTemplate, error)

	// GetByTenantAndName retrieves a scanner template by tenant, type, and name.
	GetByTenantAndName(ctx context.Context, tenantID shared.ID, templateType TemplateType, name string) (*ScannerTemplate, error)

	// List lists scanner templates with filters and pagination.
	List(ctx context.Context, filter Filter, page pagination.Pagination) (pagination.Result[*ScannerTemplate], error)

	// ListByIDs retrieves multiple templates by their IDs.
	ListByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]*ScannerTemplate, error)

	// Update updates a scanner template.
	Update(ctx context.Context, template *ScannerTemplate) error

	// Delete deletes a scanner template (tenant-scoped).
	Delete(ctx context.Context, tenantID, id shared.ID) error

	// CountByTenant counts the number of templates for a tenant.
	CountByTenant(ctx context.Context, tenantID shared.ID) (int64, error)

	// CountByType counts the number of templates by type for a tenant.
	CountByType(ctx context.Context, tenantID shared.ID, templateType TemplateType) (int64, error)

	// ExistsByName checks if a template with the given name exists.
	ExistsByName(ctx context.Context, tenantID shared.ID, templateType TemplateType, name string) (bool, error)

	// GetUsage returns the current template usage for a tenant.
	GetUsage(ctx context.Context, tenantID shared.ID) (*TemplateUsage, error)
}
