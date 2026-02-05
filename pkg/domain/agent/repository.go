package agent

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// Filter represents filter options for listing agents.
type Filter struct {
	TenantID      *shared.ID
	Type          *AgentType
	Status        *AgentStatus // Admin-controlled: active, disabled, revoked
	Health        *AgentHealth // Automatic: unknown, online, offline, error
	ExecutionMode *ExecutionMode
	Capabilities  []string
	Tools         []string
	Labels        map[string]string
	Search        string
	HasCapacity   *bool // Filter by agents that have job capacity
}

// Repository defines the interface for agent persistence.
type Repository interface {
	// Create creates a new agent.
	Create(ctx context.Context, agent *Agent) error

	// CountByTenant counts the number of agents for a tenant.
	// Used for enforcing agent limits per plan.
	CountByTenant(ctx context.Context, tenantID shared.ID) (int, error)

	// GetByID retrieves an agent by ID.
	GetByID(ctx context.Context, id shared.ID) (*Agent, error)

	// GetByTenantAndID retrieves an agent by tenant and ID.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*Agent, error)

	// GetByAPIKeyHash retrieves an agent by API key hash.
	GetByAPIKeyHash(ctx context.Context, hash string) (*Agent, error)

	// List lists agents with filters and pagination.
	List(ctx context.Context, filter Filter, page pagination.Pagination) (pagination.Result[*Agent], error)

	// Update updates an agent.
	Update(ctx context.Context, agent *Agent) error

	// Delete deletes an agent.
	Delete(ctx context.Context, id shared.ID) error

	// UpdateLastSeen updates the last seen timestamp for an agent.
	UpdateLastSeen(ctx context.Context, id shared.ID) error

	// IncrementStats increments agent statistics.
	IncrementStats(ctx context.Context, id shared.ID, findings, scans, errors int64) error

	// FindByCapabilities finds agents with the given capabilities.
	FindByCapabilities(ctx context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*Agent, error)

	// FindAvailable finds available agents for a step.
	FindAvailable(ctx context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*Agent, error)

	// FindAvailableWithTool finds the best available agent for a tool.
	// Returns the least-loaded agent that has the required tool.
	FindAvailableWithTool(ctx context.Context, tenantID shared.ID, tool string) (*Agent, error)

	// MarkStaleAsOffline marks agents as offline (health) if they haven't sent heartbeat within the timeout.
	// Note: This updates Health (automatic), not Status (admin-controlled).
	// Agents can still authenticate if their Status is 'active', regardless of Health.
	// Returns the number of agents marked as offline.
	MarkStaleAsOffline(ctx context.Context, timeout time.Duration) (int64, error)

	// FindAvailableWithCapacity finds agents that have capacity for new jobs.
	FindAvailableWithCapacity(ctx context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*Agent, error)

	// ClaimJob atomically claims a job slot for an agent.
	ClaimJob(ctx context.Context, agentID shared.ID) error

	// ReleaseJob releases a job slot for an agent.
	ReleaseJob(ctx context.Context, agentID shared.ID) error

	// ==========================================================================
	// Online/Offline Tracking Methods (Heartbeat Optimization)
	// ==========================================================================

	// UpdateOfflineTimestamp marks an agent as offline with the current timestamp.
	// Called when a health monitor detects heartbeat timeout.
	UpdateOfflineTimestamp(ctx context.Context, id shared.ID) error

	// MarkStaleAgentsOffline finds agents that haven't sent heartbeat within timeout and marks them offline.
	// Returns the list of agent IDs that were marked offline (for audit logging).
	MarkStaleAgentsOffline(ctx context.Context, timeout time.Duration) ([]shared.ID, error)

	// GetAgentsOfflineSince returns agents that went offline after the given timestamp.
	// Used for historical queries like "which agents went offline in the last hour?"
	GetAgentsOfflineSince(ctx context.Context, since time.Time) ([]*Agent, error)

	// ==========================================================================
	// Tool Availability Methods
	// ==========================================================================

	// GetAvailableToolsForTenant returns all unique tool names that have at least one available agent.
	// Used to determine which tools can actually be executed.
	GetAvailableToolsForTenant(ctx context.Context, tenantID shared.ID) ([]string, error)

	// HasAgentForTool checks if there's at least one agent that supports the given tool.
	HasAgentForTool(ctx context.Context, tenantID shared.ID, tool string) (bool, error)

	// GetAvailableCapabilitiesForTenant returns all unique capability names from all agents accessible to the tenant.
	// Used to determine what capabilities a tenant can use based on their available agents.
	GetAvailableCapabilitiesForTenant(ctx context.Context, tenantID shared.ID) ([]string, error)

	// HasAgentForCapability checks if there's at least one agent that supports the given capability.
	HasAgentForCapability(ctx context.Context, tenantID shared.ID, capability string) (bool, error)
}

// APIKeyFilter represents filter options for listing API keys.
type APIKeyFilter struct {
	AgentID  *shared.ID
	IsActive *bool
}

// APIKeyRepository defines the interface for API key persistence.
type APIKeyRepository interface {
	// Create creates a new API key.
	Create(ctx context.Context, key *APIKey) error

	// GetByID retrieves an API key by ID.
	GetByID(ctx context.Context, id shared.ID) (*APIKey, error)

	// GetByHash retrieves an API key by hash.
	GetByHash(ctx context.Context, hash string) (*APIKey, error)

	// GetByAgentID retrieves all API keys for an agent.
	GetByAgentID(ctx context.Context, agentID shared.ID) ([]*APIKey, error)

	// List lists API keys with filters.
	List(ctx context.Context, filter APIKeyFilter) ([]*APIKey, error)

	// Update updates an API key.
	Update(ctx context.Context, key *APIKey) error

	// Delete deletes an API key.
	Delete(ctx context.Context, id shared.ID) error

	// RecordUsage records API key usage.
	RecordUsage(ctx context.Context, id shared.ID, ip string) error

	// Revoke revokes an API key.
	Revoke(ctx context.Context, id shared.ID, reason string) error

	// CountActiveByAgentID counts active keys for an agent.
	CountActiveByAgentID(ctx context.Context, agentID shared.ID) (int, error)
}

// RegistrationTokenFilter represents filter options for listing tokens.
type RegistrationTokenFilter struct {
	TenantID *shared.ID
	IsActive *bool
}

// RegistrationTokenRepository defines the interface for registration token persistence.
type RegistrationTokenRepository interface {
	// Create creates a new registration token.
	Create(ctx context.Context, token *RegistrationToken) error

	// GetByID retrieves a token by ID.
	GetByID(ctx context.Context, id shared.ID) (*RegistrationToken, error)

	// GetByTenantAndID retrieves a token by tenant and ID.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*RegistrationToken, error)

	// GetByHash retrieves a token by hash.
	GetByHash(ctx context.Context, hash string) (*RegistrationToken, error)

	// List lists tokens with filters and pagination.
	List(ctx context.Context, filter RegistrationTokenFilter, page pagination.Pagination) (pagination.Result[*RegistrationToken], error)

	// Update updates a token.
	Update(ctx context.Context, token *RegistrationToken) error

	// Delete deletes a token.
	Delete(ctx context.Context, id shared.ID) error

	// IncrementUsage increments the usage counter.
	IncrementUsage(ctx context.Context, id shared.ID) error

	// Deactivate deactivates a token.
	Deactivate(ctx context.Context, id shared.ID) error
}
