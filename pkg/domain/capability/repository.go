package capability

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// Filter defines filter options for listing capabilities.
type Filter struct {
	TenantID  *shared.ID // Include tenant custom capabilities
	IsBuiltin *bool      // Filter by builtin status
	Category  *string    // Filter by category (security, recon, analysis)
	Search    string     // Search by name or display name
}

// Repository defines the interface for capability persistence.
type Repository interface {
	// Create creates a new capability.
	Create(ctx context.Context, capability *Capability) error

	// GetByID returns a capability by ID.
	GetByID(ctx context.Context, id shared.ID) (*Capability, error)

	// GetByName returns a capability by name within a scope (tenant or platform).
	// If tenantID is nil, it looks for platform capability.
	GetByName(ctx context.Context, tenantID *shared.ID, name string) (*Capability, error)

	// List returns capabilities matching the filter with pagination.
	// Always includes platform (builtin) capabilities.
	// If filter.TenantID is set, also includes that tenant's custom capabilities.
	List(ctx context.Context, filter Filter, page pagination.Pagination) (pagination.Result[*Capability], error)

	// ListAll returns all capabilities for a tenant context (platform + tenant custom).
	// This is a simpler method without pagination for dropdowns/selects.
	ListAll(ctx context.Context, tenantID *shared.ID) ([]*Capability, error)

	// ListByNames returns capabilities by their names.
	// Useful for resolving capability names to IDs.
	ListByNames(ctx context.Context, tenantID *shared.ID, names []string) ([]*Capability, error)

	// ListByCategory returns all capabilities in a category.
	ListByCategory(ctx context.Context, tenantID *shared.ID, category string) ([]*Capability, error)

	// Update updates an existing capability.
	Update(ctx context.Context, capability *Capability) error

	// Delete deletes a capability by ID.
	// Only tenant custom capabilities can be deleted.
	Delete(ctx context.Context, id shared.ID) error

	// ExistsByName checks if a capability with the given name exists in the scope.
	ExistsByName(ctx context.Context, tenantID *shared.ID, name string) (bool, error)

	// CountByTenant returns the number of custom capabilities for a tenant.
	CountByTenant(ctx context.Context, tenantID shared.ID) (int64, error)

	// GetCategories returns all unique categories.
	GetCategories(ctx context.Context) ([]string, error)

	// GetUsageStats returns usage statistics for a capability (tool count, agent count).
	GetUsageStats(ctx context.Context, capabilityID shared.ID) (*CapabilityUsageStats, error)

	// GetUsageStatsBatch returns usage statistics for multiple capabilities.
	GetUsageStatsBatch(ctx context.Context, capabilityIDs []shared.ID) (map[shared.ID]*CapabilityUsageStats, error)
}

// CapabilityUsageStats contains usage statistics for a capability.
type CapabilityUsageStats struct {
	ToolCount  int      `json:"tool_count"`
	AgentCount int      `json:"agent_count"`
	ToolNames  []string `json:"tool_names,omitempty"`  // Names of tools using this capability
	AgentNames []string `json:"agent_names,omitempty"` // Names of agents with this capability
}

// ToolCapabilityRepository defines the interface for tool-capability junction table.
type ToolCapabilityRepository interface {
	// AddCapabilityToTool adds a capability to a tool.
	// Security: Validates that the tool belongs to the tenant.
	AddCapabilityToTool(ctx context.Context, tenantID *shared.ID, toolID, capabilityID shared.ID) error

	// RemoveCapabilityFromTool removes a capability from a tool.
	// Security: Validates that the tool belongs to the tenant.
	RemoveCapabilityFromTool(ctx context.Context, tenantID *shared.ID, toolID, capabilityID shared.ID) error

	// SetToolCapabilities replaces all capabilities for a tool.
	// Security: Validates that the tool belongs to the tenant and all capabilities are accessible.
	// tenantID can be nil for platform tools (admin operations only).
	SetToolCapabilities(ctx context.Context, tenantID *shared.ID, toolID shared.ID, capabilityIDs []shared.ID) error

	// GetToolCapabilities returns all capabilities for a tool.
	GetToolCapabilities(ctx context.Context, toolID shared.ID) ([]*Capability, error)

	// GetToolsByCapability returns all tool IDs that have a specific capability.
	GetToolsByCapability(ctx context.Context, capabilityID shared.ID) ([]shared.ID, error)

	// GetToolsByCapabilityName returns all tool IDs that have a specific capability by name.
	GetToolsByCapabilityName(ctx context.Context, capabilityName string) ([]shared.ID, error)

	// ValidateCapabilitiesAccessible checks if all capability IDs are accessible by the tenant.
	// Returns an error if any capability is not accessible.
	ValidateCapabilitiesAccessible(ctx context.Context, tenantID *shared.ID, capabilityIDs []shared.ID) error
}
