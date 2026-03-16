package module

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ModuleRepository defines the interface for module persistence operations.
type ModuleRepository interface {
	// GetByID retrieves a module by its ID.
	GetByID(ctx context.Context, id string) (*Module, error)

	// GetBySlug retrieves a module by its slug.
	GetBySlug(ctx context.Context, slug string) (*Module, error)

	// ListAll returns all modules.
	ListAll(ctx context.Context) ([]*Module, error)

	// ListActive returns all active modules.
	ListActive(ctx context.Context) ([]*Module, error)

	// ListByCategory returns modules filtered by category.
	ListByCategory(ctx context.Context, category string) ([]*Module, error)
}

// TenantModuleOverride represents a tenant's override for a module's enabled state.
type TenantModuleOverride struct {
	TenantID   shared.ID
	ModuleID   string
	IsEnabled  bool
	EnabledAt  *time.Time
	DisabledAt *time.Time
	UpdatedBy  *shared.ID
	UpdatedAt  time.Time
}

// TenantModuleUpdate represents a single module toggle request.
type TenantModuleUpdate struct {
	ModuleID  string
	IsEnabled bool
}

// TenantModuleRepository defines the interface for per-tenant module configuration.
type TenantModuleRepository interface {
	// ListByTenant returns all module overrides for a tenant.
	ListByTenant(ctx context.Context, tenantID shared.ID) ([]*TenantModuleOverride, error)

	// UpsertBatch creates or updates multiple module overrides for a tenant.
	UpsertBatch(ctx context.Context, tenantID shared.ID, updates []TenantModuleUpdate, updatedBy *shared.ID) error

	// DeleteByTenant removes all module overrides for a tenant (reset to defaults).
	DeleteByTenant(ctx context.Context, tenantID shared.ID) error
}
