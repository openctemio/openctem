package scanworkflow

import (
	"context"
	"database/sql"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Filter represents filter options for listing templates.
type Filter struct {
	TenantID              *shared.ID
	IsActive              *bool
	IsSystemTemplate      *bool
	Tags                  []string
	Search                string
	IncludeSystemTemplate bool // Include system templates in results (for tenant views)
}

// Repository defines the interface for scan workflow persistence.
type Repository interface {
	// Create creates a new scan workflow.
	Create(ctx context.Context, template *Workflow) error

	// GetByID retrieves a template by ID.
	GetByID(ctx context.Context, id shared.ID) (*Workflow, error)

	// GetByTenantAndID retrieves a template by tenant and ID.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*Workflow, error)

	// GetByName retrieves a template by name and version.
	GetByName(ctx context.Context, tenantID shared.ID, name string, version int) (*Workflow, error)

	// List lists templates with filters and pagination.
	List(ctx context.Context, filter Filter, page pagination.Pagination) (pagination.Result[*Workflow], error)

	// Update updates a template.
	Update(ctx context.Context, template *Workflow) error

	// Delete deletes a template.
	Delete(ctx context.Context, id shared.ID) error

	// Remove deletes the tenant's workflow, or retires it when it has runs
	// (their history is kept). It refuses with ErrScanWorkflowRunActive while
	// a run is pending or running; a workflow outside the tenant is
	// ErrNotFound. retired reports which of the two happened.
	Remove(ctx context.Context, tenantID, id shared.ID) (retired bool, err error)

	// DeleteInTx deletes a template within a transaction.
	DeleteInTx(ctx context.Context, tx *sql.Tx, id shared.ID) error

	// GetWithSteps retrieves a template with its steps.
	GetWithSteps(ctx context.Context, id shared.ID) (*Workflow, error)

	// GetSystemTemplateByID retrieves a system template by ID (for copy-on-use).
	GetSystemTemplateByID(ctx context.Context, id shared.ID) (*Workflow, error)

	// ListWithSystemTemplates lists tenant templates + system templates.
	// System templates are returned with is_system_template=true flag.
	ListWithSystemTemplates(ctx context.Context, tenantID shared.ID, filter Filter, page pagination.Pagination) (pagination.Result[*Workflow], error)
}

// StepRepository defines the interface for workflow step persistence.
type StepRepository interface {
	// Create creates a new step.
	Create(ctx context.Context, step *Step) error

	// CreateBatch creates multiple steps.
	CreateBatch(ctx context.Context, steps []*Step) error

	// GetByID retrieves a step by ID.
	GetByID(ctx context.Context, id shared.ID) (*Step, error)

	// GetByScanWorkflowID retrieves all steps for a scan workflow.
	GetByScanWorkflowID(ctx context.Context, scanWorkflowID shared.ID) ([]*Step, error)

	// GetByKey retrieves a step by scan workflow ID and step key.
	GetByKey(ctx context.Context, scanWorkflowID shared.ID, stepKey string) (*Step, error)

	// Update updates a step.
	Update(ctx context.Context, step *Step) error

	// Delete deletes a step.
	Delete(ctx context.Context, id shared.ID) error

	// DeleteByScanWorkflowID deletes all steps for a scan workflow.
	DeleteByScanWorkflowID(ctx context.Context, scanWorkflowID shared.ID) error

	// DeleteByScanWorkflowIDInTx deletes all steps for a scan workflow within a transaction.
	DeleteByScanWorkflowIDInTx(ctx context.Context, tx *sql.Tx, scanWorkflowID shared.ID) error

	// Reorder updates the order of steps.
	Reorder(ctx context.Context, scanWorkflowID shared.ID, stepOrders map[string]int) error

	// FindScanWorkflowIDsByToolName finds all active scan workflow IDs that use a specific tool.
	// Used for cascade deactivation when a tool is deactivated or deleted.
	FindScanWorkflowIDsByToolName(ctx context.Context, tenantID shared.ID, toolName string) ([]shared.ID, error)

	// MutateSteps changes the steps of the tenant's scan workflow in one
	// transaction. It locks the scan workflow, refuses with ErrScanWorkflowRunActive
	// while a run of it is pending or running, reads the current steps and
	// passes them to mutate, then stores what mutate returns: a step whose
	// ID is already one of the scan workflow's steps is updated in place (its ID,
	// and so its run history, stays), a new ID is inserted, and the
	// scan workflow's other steps are deleted. Deleting a step keeps its step runs
	// (scan_run_steps.step_id becomes NULL). A scan workflow outside the tenant is
	// ErrNotFound.
	MutateSteps(ctx context.Context, tenantID, scanWorkflowID shared.ID, mutate func(current []*Step) ([]*Step, error)) ([]*Step, error)
}

// ErrScanWorkflowRetired refuses a change to, or a run of, a retired workflow.
var ErrScanWorkflowRetired = shared.NewDomainError("WORKFLOW_RETIRED",
	"this scan workflow was deleted; its runs are kept for history, but it cannot be changed or run", shared.ErrConflict)

// ErrScanWorkflowRunActive refuses a change to a scan workflow's steps while a run of
// the scan workflow is pending or running. A running run reads the step
// definitions as it advances, so editing them mid-run would change what the
// rest of that run does.
var ErrScanWorkflowRunActive = shared.NewDomainError("PIPELINE_RUN_ACTIVE",
	"this pipeline has a run in progress; wait for it to finish or cancel it, then save the steps", shared.ErrConflict)
