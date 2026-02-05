package tool

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// ToolFilter defines filtering options for tool queries.
type ToolFilter struct {
	CategoryID   *shared.ID // Filter by category_id (FK to tool_categories)
	CategoryName *string    // Filter by category name (via join with tool_categories)
	Capabilities []string
	IsActive     *bool
	IsBuiltin    *bool
	Search       string
	Tags         []string

	// Tenant filtering
	TenantID        *shared.ID // Filter by specific tenant's custom tools
	IncludePlatform bool       // Include platform tools (tenant_id IS NULL)
	OnlyPlatform    bool       // Only platform tools (tenant_id IS NULL)
	OnlyCustom      bool       // Only custom tools (tenant_id IS NOT NULL)
}

// TenantToolConfigFilter defines filtering options for tenant tool config queries.
type TenantToolConfigFilter struct {
	TenantID  shared.ID
	ToolID    *shared.ID
	IsEnabled *bool
}

// ToolExecutionFilter defines filtering options for tool execution queries.
type ToolExecutionFilter struct {
	TenantID      shared.ID
	ToolID        *shared.ID
	AgentID       *shared.ID
	PipelineRunID *shared.ID
	Status        *ExecutionStatus
}

// Repository defines the interface for tool persistence.
type Repository interface {
	// Tool operations (system-wide)
	Create(ctx context.Context, tool *Tool) error
	GetByID(ctx context.Context, id shared.ID) (*Tool, error)
	GetByName(ctx context.Context, name string) (*Tool, error)
	List(ctx context.Context, filter ToolFilter, page pagination.Pagination) (pagination.Result[*Tool], error)
	ListByNames(ctx context.Context, names []string) ([]*Tool, error)
	ListByCategoryID(ctx context.Context, categoryID shared.ID) ([]*Tool, error)
	ListByCategoryName(ctx context.Context, categoryName string) ([]*Tool, error)
	ListByCapability(ctx context.Context, capability string) ([]*Tool, error)
	// FindByCapabilities finds an active tool that matches all required capabilities.
	// Searches platform tools first, then tenant-specific tools.
	// Returns nil if no matching active tool is found.
	FindByCapabilities(ctx context.Context, tenantID shared.ID, capabilities []string) (*Tool, error)
	Update(ctx context.Context, tool *Tool) error
	Delete(ctx context.Context, id shared.ID) error

	// Tenant custom tools operations
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*Tool, error)
	GetByTenantAndName(ctx context.Context, tenantID shared.ID, name string) (*Tool, error)
	GetPlatformToolByName(ctx context.Context, name string) (*Tool, error)
	ListPlatformTools(ctx context.Context, filter ToolFilter, page pagination.Pagination) (pagination.Result[*Tool], error)
	ListTenantCustomTools(ctx context.Context, tenantID shared.ID, filter ToolFilter, page pagination.Pagination) (pagination.Result[*Tool], error)
	ListAvailableTools(ctx context.Context, tenantID shared.ID, filter ToolFilter, page pagination.Pagination) (pagination.Result[*Tool], error) // Platform + tenant's custom tools
	DeleteTenantTool(ctx context.Context, tenantID, id shared.ID) error

	// Bulk operations
	BulkCreate(ctx context.Context, tools []*Tool) error
	BulkUpdateVersions(ctx context.Context, versions map[shared.ID]VersionInfo) error

	// Statistics
	Count(ctx context.Context, filter ToolFilter) (int64, error)

	// GetAllCapabilities returns all unique capabilities from all tools.
	// Used for dynamic capability validation.
	GetAllCapabilities(ctx context.Context) ([]string, error)
}

// VersionInfo holds version information for bulk update.
type VersionInfo struct {
	CurrentVersion string
	LatestVersion  string
}

// TenantToolConfigRepository defines the interface for tenant tool config persistence.
type TenantToolConfigRepository interface {
	// CRUD operations
	Create(ctx context.Context, config *TenantToolConfig) error
	GetByID(ctx context.Context, id shared.ID) (*TenantToolConfig, error)
	GetByTenantAndTool(ctx context.Context, tenantID, toolID shared.ID) (*TenantToolConfig, error)
	List(ctx context.Context, filter TenantToolConfigFilter, page pagination.Pagination) (pagination.Result[*TenantToolConfig], error)
	Update(ctx context.Context, config *TenantToolConfig) error
	Delete(ctx context.Context, id shared.ID) error

	// Upsert - Create or update config
	Upsert(ctx context.Context, config *TenantToolConfig) error

	// Get effective config (merged default + tenant override)
	GetEffectiveConfig(ctx context.Context, tenantID, toolID shared.ID) (map[string]any, error)

	// List all enabled tools for a tenant
	ListEnabledTools(ctx context.Context, tenantID shared.ID) ([]*TenantToolConfig, error)

	// List all tools with their tenant-specific enabled status
	// Returns tools joined with tenant configs, where is_enabled defaults to true if no config exists
	ListToolsWithConfig(ctx context.Context, tenantID shared.ID, filter ToolFilter, page pagination.Pagination) (pagination.Result[*ToolWithConfig], error)

	// Bulk enable/disable tools for tenant
	BulkEnable(ctx context.Context, tenantID shared.ID, toolIDs []shared.ID) error
	BulkDisable(ctx context.Context, tenantID shared.ID, toolIDs []shared.ID) error
}

// ToolExecutionRepository defines the interface for tool execution persistence.
type ToolExecutionRepository interface {
	Create(ctx context.Context, execution *ToolExecution) error
	GetByID(ctx context.Context, id shared.ID) (*ToolExecution, error)
	List(ctx context.Context, filter ToolExecutionFilter, page pagination.Pagination) (pagination.Result[*ToolExecution], error)
	Update(ctx context.Context, execution *ToolExecution) error

	// Statistics
	GetToolStats(ctx context.Context, tenantID, toolID shared.ID, days int) (*ToolStats, error)
	GetTenantStats(ctx context.Context, tenantID shared.ID, days int) (*TenantToolStats, error)
}

// ToolStats holds statistics for a specific tool.
type ToolStats struct {
	ToolID         shared.ID
	TotalRuns      int64
	SuccessfulRuns int64
	FailedRuns     int64
	TotalFindings  int64
	AvgDurationMs  int64
}

// TenantToolStats holds aggregated tool statistics for a tenant.
type TenantToolStats struct {
	TenantID       shared.ID
	TotalRuns      int64
	SuccessfulRuns int64
	FailedRuns     int64
	TotalFindings  int64
	ToolBreakdown  []ToolStats
}

// EmbeddedCategory contains minimal category info for embedding in tool responses.
type EmbeddedCategory struct {
	ID          shared.ID
	Name        string // slug: 'sast', 'dast', etc.
	DisplayName string // 'SAST', 'DAST', etc.
	Icon        string
	Color       string
}

// ToolWithConfig represents a tool with its tenant-specific configuration.
// Used when loading tools with their effective configuration for a tenant.
type ToolWithConfig struct {
	Tool            *Tool
	Category        *EmbeddedCategory // Embedded category info for UI grouping
	TenantConfig    *TenantToolConfig
	EffectiveConfig map[string]any
	IsEnabled       bool
	IsAvailable     bool // True if at least one agent (tenant or platform) supports this tool
}
