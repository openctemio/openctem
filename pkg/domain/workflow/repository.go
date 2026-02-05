package workflow

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// WorkflowFilter represents filter options for listing workflows.
type WorkflowFilter struct {
	TenantID *shared.ID
	IsActive *bool
	Tags     []string
	Search   string
}

// WorkflowRepository defines the interface for workflow persistence.
type WorkflowRepository interface {
	// Create creates a new workflow.
	Create(ctx context.Context, workflow *Workflow) error

	// GetByID retrieves a workflow by ID.
	GetByID(ctx context.Context, id shared.ID) (*Workflow, error)

	// GetByTenantAndID retrieves a workflow by tenant and ID.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*Workflow, error)

	// GetByName retrieves a workflow by name.
	GetByName(ctx context.Context, tenantID shared.ID, name string) (*Workflow, error)

	// List lists workflows with filters and pagination.
	List(ctx context.Context, filter WorkflowFilter, page pagination.Pagination) (pagination.Result[*Workflow], error)

	// Update updates a workflow.
	Update(ctx context.Context, workflow *Workflow) error

	// Delete deletes a workflow.
	Delete(ctx context.Context, id shared.ID) error

	// GetWithGraph retrieves a workflow with its nodes and edges.
	GetWithGraph(ctx context.Context, id shared.ID) (*Workflow, error)

	// ListActiveWithTriggerType lists active workflows that have a trigger node
	// with the specified trigger type. Returns workflows with their full graph
	// (nodes and edges) in a single efficient query.
	// This method is optimized to avoid N+1 query issues when processing events.
	ListActiveWithTriggerType(ctx context.Context, tenantID shared.ID, triggerType TriggerType) ([]*Workflow, error)
}

// NodeRepository defines the interface for workflow node persistence.
type NodeRepository interface {
	// Create creates a new node.
	Create(ctx context.Context, node *Node) error

	// CreateBatch creates multiple nodes.
	CreateBatch(ctx context.Context, nodes []*Node) error

	// GetByID retrieves a node by ID.
	GetByID(ctx context.Context, id shared.ID) (*Node, error)

	// GetByWorkflowID retrieves all nodes for a workflow.
	GetByWorkflowID(ctx context.Context, workflowID shared.ID) ([]*Node, error)

	// GetByKey retrieves a node by workflow ID and node key.
	GetByKey(ctx context.Context, workflowID shared.ID, nodeKey string) (*Node, error)

	// Update updates a node.
	Update(ctx context.Context, node *Node) error

	// Delete deletes a node.
	Delete(ctx context.Context, id shared.ID) error

	// DeleteByWorkflowID deletes all nodes for a workflow.
	DeleteByWorkflowID(ctx context.Context, workflowID shared.ID) error
}

// EdgeRepository defines the interface for workflow edge persistence.
type EdgeRepository interface {
	// Create creates a new edge.
	Create(ctx context.Context, edge *Edge) error

	// CreateBatch creates multiple edges.
	CreateBatch(ctx context.Context, edges []*Edge) error

	// GetByID retrieves an edge by ID.
	GetByID(ctx context.Context, id shared.ID) (*Edge, error)

	// GetByWorkflowID retrieves all edges for a workflow.
	GetByWorkflowID(ctx context.Context, workflowID shared.ID) ([]*Edge, error)

	// Delete deletes an edge.
	Delete(ctx context.Context, id shared.ID) error

	// DeleteByWorkflowID deletes all edges for a workflow.
	DeleteByWorkflowID(ctx context.Context, workflowID shared.ID) error
}

// RunFilter represents filter options for listing runs.
type RunFilter struct {
	TenantID    *shared.ID
	WorkflowID  *shared.ID
	Status      *RunStatus
	TriggerType *TriggerType
	TriggeredBy *shared.ID
	StartedFrom *time.Time
	StartedTo   *time.Time
}

// RunRepository defines the interface for workflow run persistence.
type RunRepository interface {
	// Create creates a new run.
	Create(ctx context.Context, run *Run) error

	// GetByID retrieves a run by ID.
	GetByID(ctx context.Context, id shared.ID) (*Run, error)

	// GetByTenantAndID retrieves a run by tenant and ID.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*Run, error)

	// List lists runs with filters and pagination.
	List(ctx context.Context, filter RunFilter, page pagination.Pagination) (pagination.Result[*Run], error)

	// ListByWorkflowID lists runs for a specific workflow with pagination.
	ListByWorkflowID(ctx context.Context, workflowID shared.ID, page, perPage int) ([]*Run, int64, error)

	// Update updates a run.
	Update(ctx context.Context, run *Run) error

	// Delete deletes a run.
	Delete(ctx context.Context, id shared.ID) error

	// GetWithNodeRuns retrieves a run with its node runs.
	GetWithNodeRuns(ctx context.Context, id shared.ID) (*Run, error)

	// GetActiveByWorkflowID retrieves active runs for a workflow.
	GetActiveByWorkflowID(ctx context.Context, workflowID shared.ID) ([]*Run, error)

	// CountActiveByWorkflowID counts active runs (pending/running) for a workflow.
	CountActiveByWorkflowID(ctx context.Context, workflowID shared.ID) (int, error)

	// CountActiveByTenantID counts active runs (pending/running) for a tenant.
	CountActiveByTenantID(ctx context.Context, tenantID shared.ID) (int, error)

	// UpdateStats updates run statistics.
	UpdateStats(ctx context.Context, id shared.ID, completed, failed int) error

	// UpdateStatus updates run status.
	UpdateStatus(ctx context.Context, id shared.ID, status RunStatus, errorMessage string) error

	// CreateRunIfUnderLimit atomically checks concurrent run limits and creates run if under limit.
	// Uses a transaction with row-level locking to prevent race conditions.
	// This prevents TOCTOU (time-of-check-time-of-use) vulnerabilities where multiple concurrent
	// triggers could bypass the limits.
	CreateRunIfUnderLimit(ctx context.Context, run *Run, maxPerWorkflow, maxPerTenant int) error
}

// NodeRunFilter represents filter options for listing node runs.
type NodeRunFilter struct {
	WorkflowRunID *shared.ID
	NodeID        *shared.ID
	Status        *NodeRunStatus
}

// NodeRunRepository defines the interface for node run persistence.
type NodeRunRepository interface {
	// Create creates a new node run.
	Create(ctx context.Context, nodeRun *NodeRun) error

	// CreateBatch creates multiple node runs.
	CreateBatch(ctx context.Context, nodeRuns []*NodeRun) error

	// GetByID retrieves a node run by ID.
	GetByID(ctx context.Context, id shared.ID) (*NodeRun, error)

	// GetByWorkflowRunID retrieves all node runs for a workflow run.
	GetByWorkflowRunID(ctx context.Context, workflowRunID shared.ID) ([]*NodeRun, error)

	// GetByNodeKey retrieves a node run by workflow run ID and node key.
	GetByNodeKey(ctx context.Context, workflowRunID shared.ID, nodeKey string) (*NodeRun, error)

	// List lists node runs with filters.
	List(ctx context.Context, filter NodeRunFilter) ([]*NodeRun, error)

	// Update updates a node run.
	Update(ctx context.Context, nodeRun *NodeRun) error

	// Delete deletes a node run.
	Delete(ctx context.Context, id shared.ID) error

	// UpdateStatus updates node run status.
	UpdateStatus(ctx context.Context, id shared.ID, status NodeRunStatus, errorMessage, errorCode string) error

	// Complete marks a node run as completed.
	Complete(ctx context.Context, id shared.ID, output map[string]any) error

	// GetPendingByDependencies gets node runs that are pending and have their dependencies completed.
	GetPendingByDependencies(ctx context.Context, workflowRunID shared.ID, completedNodeKeys []string) ([]*NodeRun, error)
}
