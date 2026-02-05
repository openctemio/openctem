package pipeline

import (
	"context"
	"database/sql"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// TemplateFilter represents filter options for listing templates.
type TemplateFilter struct {
	TenantID              *shared.ID
	IsActive              *bool
	IsSystemTemplate      *bool
	Tags                  []string
	Search                string
	IncludeSystemTemplate bool // Include system templates in results (for tenant views)
}

// TemplateRepository defines the interface for pipeline template persistence.
type TemplateRepository interface {
	// Create creates a new pipeline template.
	Create(ctx context.Context, template *Template) error

	// GetByID retrieves a template by ID.
	GetByID(ctx context.Context, id shared.ID) (*Template, error)

	// GetByTenantAndID retrieves a template by tenant and ID.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*Template, error)

	// GetByName retrieves a template by name and version.
	GetByName(ctx context.Context, tenantID shared.ID, name string, version int) (*Template, error)

	// List lists templates with filters and pagination.
	List(ctx context.Context, filter TemplateFilter, page pagination.Pagination) (pagination.Result[*Template], error)

	// Update updates a template.
	Update(ctx context.Context, template *Template) error

	// Delete deletes a template.
	Delete(ctx context.Context, id shared.ID) error

	// DeleteInTx deletes a template within a transaction.
	DeleteInTx(ctx context.Context, tx *sql.Tx, id shared.ID) error

	// GetWithSteps retrieves a template with its steps.
	GetWithSteps(ctx context.Context, id shared.ID) (*Template, error)

	// GetSystemTemplateByID retrieves a system template by ID (for copy-on-use).
	GetSystemTemplateByID(ctx context.Context, id shared.ID) (*Template, error)

	// ListWithSystemTemplates lists tenant templates + system templates.
	// System templates are returned with is_system_template=true flag.
	ListWithSystemTemplates(ctx context.Context, tenantID shared.ID, filter TemplateFilter, page pagination.Pagination) (pagination.Result[*Template], error)
}

// StepRepository defines the interface for pipeline step persistence.
type StepRepository interface {
	// Create creates a new step.
	Create(ctx context.Context, step *Step) error

	// CreateBatch creates multiple steps.
	CreateBatch(ctx context.Context, steps []*Step) error

	// GetByID retrieves a step by ID.
	GetByID(ctx context.Context, id shared.ID) (*Step, error)

	// GetByPipelineID retrieves all steps for a pipeline.
	GetByPipelineID(ctx context.Context, pipelineID shared.ID) ([]*Step, error)

	// GetByKey retrieves a step by pipeline ID and step key.
	GetByKey(ctx context.Context, pipelineID shared.ID, stepKey string) (*Step, error)

	// Update updates a step.
	Update(ctx context.Context, step *Step) error

	// Delete deletes a step.
	Delete(ctx context.Context, id shared.ID) error

	// DeleteByPipelineID deletes all steps for a pipeline.
	DeleteByPipelineID(ctx context.Context, pipelineID shared.ID) error

	// DeleteByPipelineIDInTx deletes all steps for a pipeline within a transaction.
	DeleteByPipelineIDInTx(ctx context.Context, tx *sql.Tx, pipelineID shared.ID) error

	// Reorder updates the order of steps.
	Reorder(ctx context.Context, pipelineID shared.ID, stepOrders map[string]int) error

	// FindPipelineIDsByToolName finds all active pipeline IDs that use a specific tool.
	// Used for cascade deactivation when a tool is deactivated or deleted.
	FindPipelineIDsByToolName(ctx context.Context, toolName string) ([]shared.ID, error)
}

// RunFilter represents filter options for listing runs.
type RunFilter struct {
	TenantID    *shared.ID
	PipelineID  *shared.ID
	AssetID     *shared.ID
	Status      *RunStatus
	TriggerType *TriggerType
	TriggeredBy string
	StartedFrom *time.Time
	StartedTo   *time.Time
}

// RunRepository defines the interface for pipeline run persistence.
type RunRepository interface {
	// Create creates a new run.
	Create(ctx context.Context, run *Run) error

	// GetByID retrieves a run by ID.
	GetByID(ctx context.Context, id shared.ID) (*Run, error)

	// GetByTenantAndID retrieves a run by tenant and ID.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*Run, error)

	// List lists runs with filters and pagination.
	List(ctx context.Context, filter RunFilter, page pagination.Pagination) (pagination.Result[*Run], error)

	// ListByScanID lists runs for a specific scan with pagination.
	ListByScanID(ctx context.Context, scanID shared.ID, page, perPage int) ([]*Run, int64, error)

	// Update updates a run.
	Update(ctx context.Context, run *Run) error

	// Delete deletes a run.
	Delete(ctx context.Context, id shared.ID) error

	// GetWithStepRuns retrieves a run with its step runs.
	GetWithStepRuns(ctx context.Context, id shared.ID) (*Run, error)

	// GetActiveByPipelineID retrieves active runs for a pipeline.
	GetActiveByPipelineID(ctx context.Context, pipelineID shared.ID) ([]*Run, error)

	// GetActiveByAssetID retrieves active runs for an asset.
	GetActiveByAssetID(ctx context.Context, assetID shared.ID) ([]*Run, error)

	// CountActiveByPipelineID counts active runs (pending/running) for a pipeline.
	CountActiveByPipelineID(ctx context.Context, pipelineID shared.ID) (int, error)

	// CountActiveByTenantID counts active runs (pending/running) for a tenant.
	CountActiveByTenantID(ctx context.Context, tenantID shared.ID) (int, error)

	// CountActiveByScanID counts active runs (pending/running) for a scan config.
	CountActiveByScanID(ctx context.Context, scanID shared.ID) (int, error)

	// CreateRunIfUnderLimit atomically checks concurrent run limits and creates run if under limit.
	// Returns ErrConcurrentLimitExceeded if scan or tenant limit is exceeded.
	// This prevents race conditions where multiple triggers bypass the limit.
	CreateRunIfUnderLimit(ctx context.Context, run *Run, maxPerScan, maxPerTenant int) error

	// UpdateStats updates run statistics.
	UpdateStats(ctx context.Context, id shared.ID, completed, failed, skipped, findings int) error

	// UpdateStatus updates run status.
	UpdateStatus(ctx context.Context, id shared.ID, status RunStatus, errorMessage string) error

	// GetStatsByTenant returns aggregated run statistics for a tenant in a single query.
	// This is optimized to avoid N+1 queries when fetching stats.
	GetStatsByTenant(ctx context.Context, tenantID shared.ID) (RunStats, error)
}

// RunStats represents aggregated run statistics.
type RunStats struct {
	Total     int64
	Pending   int64
	Running   int64
	Completed int64
	Failed    int64
	Canceled  int64
}

// StepRunFilter represents filter options for listing step runs.
type StepRunFilter struct {
	PipelineRunID *shared.ID
	StepID        *shared.ID
	AgentID       *shared.ID
	Status        *StepRunStatus
}

// StepRunRepository defines the interface for step run persistence.
type StepRunRepository interface {
	// Create creates a new step run.
	Create(ctx context.Context, stepRun *StepRun) error

	// CreateBatch creates multiple step runs.
	CreateBatch(ctx context.Context, stepRuns []*StepRun) error

	// GetByID retrieves a step run by ID.
	GetByID(ctx context.Context, id shared.ID) (*StepRun, error)

	// GetByPipelineRunID retrieves all step runs for a pipeline run.
	GetByPipelineRunID(ctx context.Context, pipelineRunID shared.ID) ([]*StepRun, error)

	// GetByStepKey retrieves a step run by pipeline run ID and step key.
	GetByStepKey(ctx context.Context, pipelineRunID shared.ID, stepKey string) (*StepRun, error)

	// List lists step runs with filters.
	List(ctx context.Context, filter StepRunFilter) ([]*StepRun, error)

	// Update updates a step run.
	Update(ctx context.Context, stepRun *StepRun) error

	// Delete deletes a step run.
	Delete(ctx context.Context, id shared.ID) error

	// UpdateStatus updates step run status.
	UpdateStatus(ctx context.Context, id shared.ID, status StepRunStatus, errorMessage, errorCode string) error

	// AssignAgent assigns an agent and command to a step run.
	AssignAgent(ctx context.Context, id shared.ID, agentID, commandID shared.ID) error

	// Complete marks a step run as completed.
	Complete(ctx context.Context, id shared.ID, findingsCount int, output map[string]any) error

	// GetPendingByDependencies gets step runs that are pending and have their dependencies completed.
	GetPendingByDependencies(ctx context.Context, pipelineRunID shared.ID, completedStepKeys []string) ([]*StepRun, error)

	// GetStatsByTenant returns aggregated step run statistics for a tenant in a single query.
	// This is optimized to avoid N+1 queries when fetching stats.
	GetStatsByTenant(ctx context.Context, tenantID shared.ID) (RunStats, error)
}
