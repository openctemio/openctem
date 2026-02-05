package command

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// Filter represents filter options for listing commands.
type Filter struct {
	TenantID        *shared.ID
	AgentID         *shared.ID
	Type            *CommandType
	Status          *CommandStatus
	Priority        *CommandPriority
	IsPlatformJob   *bool      // Filter by platform job status (v3.2)
	PlatformAgentID *shared.ID // Filter by assigned platform agent (v3.2)
}

// Repository defines the interface for command persistence.
type Repository interface {
	// Create creates a new command.
	Create(ctx context.Context, cmd *Command) error

	// GetByID retrieves a command by ID.
	GetByID(ctx context.Context, id shared.ID) (*Command, error)

	// GetByTenantAndID retrieves a command by tenant and ID.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*Command, error)

	// GetPendingForAgent retrieves pending commands for an agent.
	GetPendingForAgent(ctx context.Context, tenantID shared.ID, agentID *shared.ID, limit int) ([]*Command, error)

	// List lists commands with filters and pagination.
	List(ctx context.Context, filter Filter, page pagination.Pagination) (pagination.Result[*Command], error)

	// Update updates a command.
	Update(ctx context.Context, cmd *Command) error

	// Delete deletes a command.
	Delete(ctx context.Context, id shared.ID) error

	// ExpireOldCommands expires commands that have passed their expiration time.
	ExpireOldCommands(ctx context.Context) (int64, error)

	// FindExpired finds commands that have expired but not yet marked as expired.
	FindExpired(ctx context.Context) ([]*Command, error)

	// ==========================================================================
	// Platform Job Queue Methods (v3.2)
	// ==========================================================================

	// GetByAuthTokenHash retrieves a command by auth token hash.
	GetByAuthTokenHash(ctx context.Context, hash string) (*Command, error)

	// CountActivePlatformJobsByTenant counts active platform jobs for a tenant.
	// Active = pending, acknowledged, or running.
	CountActivePlatformJobsByTenant(ctx context.Context, tenantID shared.ID) (int, error)

	// CountQueuedPlatformJobsByTenant counts queued (pending, not dispatched) platform jobs for a tenant.
	CountQueuedPlatformJobsByTenant(ctx context.Context, tenantID shared.ID) (int, error)

	// CountQueuedPlatformJobs counts all queued platform jobs across all tenants.
	CountQueuedPlatformJobs(ctx context.Context) (int, error)

	// GetQueuedPlatformJobs retrieves queued platform jobs ordered by priority.
	// Returns jobs that are pending and not yet assigned to an agent.
	GetQueuedPlatformJobs(ctx context.Context, limit int) ([]*Command, error)

	// GetNextPlatformJob atomically claims the next job from the queue for an agent.
	// Uses FOR UPDATE SKIP LOCKED for concurrent safety.
	// Returns nil if no suitable job is available.
	GetNextPlatformJob(ctx context.Context, agentID shared.ID, capabilities []string, tools []string) (*Command, error)

	// UpdateQueuePriorities recalculates queue priorities for all pending platform jobs.
	// Returns the number of jobs updated.
	UpdateQueuePriorities(ctx context.Context) (int64, error)

	// RecoverStuckJobs returns stuck jobs to the queue.
	// A job is stuck if it's assigned but the agent is offline or hasn't progressed.
	// Returns the number of jobs recovered.
	RecoverStuckJobs(ctx context.Context, stuckThresholdMinutes int, maxRetries int) (int64, error)

	// ExpireOldPlatformJobs expires platform jobs that have been in queue too long.
	// Returns the number of jobs expired.
	ExpireOldPlatformJobs(ctx context.Context, maxQueueMinutes int) (int64, error)

	// GetQueuePosition gets the queue position for a specific command.
	GetQueuePosition(ctx context.Context, commandID shared.ID) (*QueuePosition, error)

	// ListPlatformJobsByTenant lists platform jobs for a tenant.
	ListPlatformJobsByTenant(ctx context.Context, tenantID shared.ID, page pagination.Pagination) (pagination.Result[*Command], error)

	// ListPlatformJobsAdmin lists platform jobs across all tenants (admin only).
	// Optional filters: agentID, tenantID, status.
	ListPlatformJobsAdmin(ctx context.Context, agentID, tenantID *shared.ID, status *CommandStatus, page pagination.Pagination) (pagination.Result[*Command], error)

	// GetPlatformJobsByAgent lists platform jobs assigned to an agent.
	GetPlatformJobsByAgent(ctx context.Context, agentID shared.ID, status *CommandStatus) ([]*Command, error)

	// ==========================================================================
	// Tenant Command Recovery Methods
	// ==========================================================================

	// RecoverStuckTenantCommands returns stuck tenant commands to the pool.
	// A command is stuck if it's assigned to an offline agent or hasn't been picked up.
	// Returns the number of commands recovered.
	RecoverStuckTenantCommands(ctx context.Context, stuckThresholdMinutes int, maxRetries int) (int64, error)

	// FailExhaustedCommands marks commands that exceeded max retries as failed.
	// Returns the number of commands failed.
	FailExhaustedCommands(ctx context.Context, maxRetries int) (int64, error)

	// GetStatsByTenant returns aggregated command statistics for a tenant in a single query.
	// This is optimized to avoid N queries when fetching stats.
	GetStatsByTenant(ctx context.Context, tenantID shared.ID) (CommandStats, error)
}

// CommandStats represents aggregated command statistics.
type CommandStats struct {
	Total     int64
	Pending   int64
	Running   int64
	Completed int64
	Failed    int64
	Canceled  int64
}
