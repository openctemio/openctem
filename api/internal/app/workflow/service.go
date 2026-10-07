// Package workflow implements the application service for the workflow bounded context — orchestrates pkg/domain/workflow entities and cross-cutting concerns (audit, notifications, RBAC).
package workflow

import (
	"context"
	"errors"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	workflowdom "github.com/openctemio/openctem/api/pkg/domain/workflow"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Run limits: how many runs may wait or run at once (the executor runs a
// bounded number per tenant and queues the rest). The hourly quotas are in
// workflowdom (run_limits.go).
const (
	// MaxConcurrentWorkflowRunsPerWorkflow caps the waiting and running runs
	// of one workflow.
	MaxConcurrentWorkflowRunsPerWorkflow = workflowdom.MaxActiveRunsPerWorkflow

	// MaxConcurrentWorkflowRunsPerTenant caps the waiting and running runs
	// of one tenant.
	MaxConcurrentWorkflowRunsPerTenant = workflowdom.MaxActiveRunsPerTenant
)

// WorkflowService handles workflow-related business operations.
type WorkflowService struct {
	workflowRepo workflowdom.WorkflowRepository
	nodeRepo     workflowdom.NodeRepository
	edgeRepo     workflowdom.EdgeRepository
	runRepo      workflowdom.RunRepository
	nodeRunRepo  workflowdom.NodeRunRepository
	executor     *WorkflowExecutor
	auditService *auditapp.AuditService
	logger       *logger.Logger
}

// WorkflowServiceOption is a functional option for WorkflowService.
type WorkflowServiceOption func(*WorkflowService)

// WithWorkflowAuditService sets the audit service for WorkflowService.
func WithWorkflowAuditService(auditService *auditapp.AuditService) WorkflowServiceOption {
	return func(s *WorkflowService) {
		s.auditService = auditService
	}
}

// WithWorkflowExecutor sets the workflow executor for WorkflowService.
func WithWorkflowExecutor(executor *WorkflowExecutor) WorkflowServiceOption {
	return func(s *WorkflowService) {
		s.executor = executor
	}
}

// NewWorkflowService creates a new WorkflowService.
func NewWorkflowService(
	workflowRepo workflowdom.WorkflowRepository,
	nodeRepo workflowdom.NodeRepository,
	edgeRepo workflowdom.EdgeRepository,
	runRepo workflowdom.RunRepository,
	nodeRunRepo workflowdom.NodeRunRepository,
	log *logger.Logger,
	opts ...WorkflowServiceOption,
) *WorkflowService {
	s := &WorkflowService{
		workflowRepo: workflowRepo,
		nodeRepo:     nodeRepo,
		edgeRepo:     edgeRepo,
		runRepo:      runRepo,
		nodeRunRepo:  nodeRunRepo,
		logger:       log.With("service", "workflow"),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// logAudit logs an audit event if audit service is configured.
func (s *WorkflowService) logAudit(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) {
	if s.auditService == nil {
		return
	}
	if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
		s.logger.Error("failed to log audit event", "error", err, "action", event.Action)
	}
}

// --------------------------------------------------------------------------
// Workflow CRUD
// --------------------------------------------------------------------------

// CreateWorkflowInput represents input for creating a workflow.
type CreateWorkflowInput struct {
	TenantID    shared.ID
	UserID      shared.ID
	Name        string
	Description string
	Tags        []string
	Nodes       []CreateNodeInput
	Edges       []CreateEdgeInput
}

// CreateNodeInput represents input for creating a workflow node.
type CreateNodeInput struct {
	NodeKey     string
	NodeType    workflowdom.NodeType
	Name        string
	Description string
	UIPositionX float64
	UIPositionY float64
	Config      workflowdom.NodeConfig
}

// CreateEdgeInput represents input for creating a workflow edge.
type CreateEdgeInput struct {
	SourceNodeKey string
	TargetNodeKey string
	SourceHandle  string
	Label         string
}

// CreateWorkflow creates a new workflow with its nodes and edges.
func (s *WorkflowService) CreateWorkflow(ctx context.Context, input CreateWorkflowInput) (*workflowdom.Workflow, error) {
	// Create workflow entity
	w, err := workflowdom.NewWorkflow(input.TenantID, input.Name, input.Description)
	if err != nil {
		return nil, err
	}

	if !input.UserID.IsZero() {
		w.SetCreatedBy(input.UserID)
	}

	if input.Tags != nil {
		w.Tags = input.Tags
	}

	// Refuse trigger/action types the platform does not execute and an
	// invalid graph (cycle, unreachable node, edge into a trigger), before
	// any write.
	if err := validateSupportedNodeInputs(input.Nodes); err != nil {
		return nil, err
	}
	if err := validateGraphInputs(input.Nodes, input.Edges); err != nil {
		return nil, err
	}

	// Create workflow
	if err := s.workflowRepo.Create(ctx, w); err != nil {
		return nil, fmt.Errorf("failed to create workflow: %w", err)
	}

	// Create nodes
	for _, nodeInput := range input.Nodes {
		node, err := workflowdom.NewNode(w.ID, nodeInput.NodeKey, nodeInput.NodeType, nodeInput.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to create node %s: %w", nodeInput.NodeKey, err)
		}
		node.SetDescription(nodeInput.Description)
		node.SetUIPosition(nodeInput.UIPositionX, nodeInput.UIPositionY)
		node.Config = nodeInput.Config

		if err := s.nodeRepo.Create(ctx, node); err != nil {
			return nil, fmt.Errorf("failed to save node %s: %w", nodeInput.NodeKey, err)
		}
		w.Nodes = append(w.Nodes, node)
	}

	// Create edges
	for _, edgeInput := range input.Edges {
		edge, err := workflowdom.NewEdge(w.ID, edgeInput.SourceNodeKey, edgeInput.TargetNodeKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create edge: %w", err)
		}
		edge.SetSourceHandle(edgeInput.SourceHandle)
		edge.SetLabel(edgeInput.Label)

		if err := s.edgeRepo.Create(ctx, edge); err != nil {
			return nil, fmt.Errorf("failed to save edge: %w", err)
		}
		w.Edges = append(w.Edges, edge)
	}

	// Validate graph
	if err := w.ValidateGraph(); err != nil {
		// Rollback: delete the workflow (cascades to nodes/edges)
		_ = s.workflowRepo.Delete(ctx, w.ID)
		return nil, err
	}

	// Audit log
	s.logAudit(ctx, auditapp.AuditContext{TenantID: input.TenantID.String(), ActorID: input.UserID.String()},
		auditapp.NewSuccessEvent(audit.ActionWorkflowCreated, audit.ResourceTypeWorkflow, w.ID.String()).
			WithResourceName(w.Name).
			WithMessage(fmt.Sprintf("Workflow '%s' created with %d nodes", w.Name, len(w.Nodes))))

	return w, nil
}

// GetWorkflow retrieves a workflow by ID with its graph.
func (s *WorkflowService) GetWorkflow(ctx context.Context, tenantID, workflowID shared.ID) (*workflowdom.Workflow, error) {
	// Verify workflow belongs to tenant
	_, err := s.workflowRepo.GetByTenantAndID(ctx, tenantID, workflowID)
	if err != nil {
		return nil, err
	}

	// Load graph
	return s.workflowRepo.GetWithGraph(ctx, workflowID)
}

// ListWorkflowsInput represents input for listing workflows.
type ListWorkflowsInput struct {
	TenantID shared.ID
	IsActive *bool
	Tags     []string
	Search   string
	Page     int
	PerPage  int
}

// ListWorkflows lists workflows with filters.
func (s *WorkflowService) ListWorkflows(ctx context.Context, input ListWorkflowsInput) (pagination.Result[*workflowdom.Workflow], error) {
	filter := workflowdom.WorkflowFilter{
		TenantID: &input.TenantID,
		IsActive: input.IsActive,
		Tags:     input.Tags,
		Search:   input.Search,
	}

	page := pagination.Pagination{
		Page:    input.Page,
		PerPage: input.PerPage,
	}
	if page.Page < 1 {
		page.Page = 1
	}
	if page.PerPage < 1 {
		page.PerPage = 20
	}

	return s.workflowRepo.List(ctx, filter, page)
}

// UpdateWorkflowInput represents input for updating a workflow.
type UpdateWorkflowInput struct {
	TenantID    shared.ID
	UserID      shared.ID
	WorkflowID  shared.ID
	Name        *string
	Description *string
	Tags        []string
	IsActive    *bool
}

// UpdateWorkflow updates a workflow.
func (s *WorkflowService) UpdateWorkflow(ctx context.Context, input UpdateWorkflowInput) (*workflowdom.Workflow, error) {
	w, err := s.workflowRepo.GetByTenantAndID(ctx, input.TenantID, input.WorkflowID)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		w.Name = *input.Name
	}
	if input.Description != nil {
		w.Description = *input.Description
	}
	if input.Tags != nil {
		w.Tags = input.Tags
	}

	// Track activation changes for audit
	var activationChange string
	if input.IsActive != nil {
		if *input.IsActive && !w.IsActive {
			// A workflow that uses a trigger or action the platform does not
			// execute stays readable, but cannot be switched on.
			full, err := s.workflowRepo.GetWithGraph(ctx, w.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to load workflow graph: %w", err)
			}
			if err := full.ValidateSupported(); err != nil {
				return nil, err
			}
			// Nor can a graph with a cycle or a node no trigger reaches
			// (possible when it was built one node and edge at a time).
			if err := full.ValidateTopology(); err != nil {
				return nil, err
			}
			w.Activate()
			activationChange = "activated"
		} else if !*input.IsActive && w.IsActive {
			w.Deactivate()
			activationChange = "deactivated"
		}
	}

	if err := s.workflowRepo.Update(ctx, w); err != nil {
		return nil, fmt.Errorf("failed to update workflow: %w", err)
	}

	// Audit log
	if activationChange != "" {
		action := audit.ActionWorkflowActivated
		if activationChange == "deactivated" {
			action = audit.ActionWorkflowDeactivated
		}
		s.logAudit(ctx, auditapp.AuditContext{TenantID: input.TenantID.String(), ActorID: input.UserID.String()},
			auditapp.NewSuccessEvent(action, audit.ResourceTypeWorkflow, w.ID.String()).
				WithResourceName(w.Name).
				WithMessage(fmt.Sprintf("Workflow '%s' %s", w.Name, activationChange)))
	} else {
		s.logAudit(ctx, auditapp.AuditContext{TenantID: input.TenantID.String(), ActorID: input.UserID.String()},
			auditapp.NewSuccessEvent(audit.ActionWorkflowUpdated, audit.ResourceTypeWorkflow, w.ID.String()).
				WithResourceName(w.Name).
				WithMessage(fmt.Sprintf("Workflow '%s' updated", w.Name)))
	}

	return w, nil
}

// UpdateWorkflowGraphInput represents input for updating a workflow's graph (nodes and edges).
type UpdateWorkflowGraphInput struct {
	TenantID    shared.ID
	UserID      shared.ID
	WorkflowID  shared.ID
	Name        *string           // Optional: update name
	Description *string           // Optional: update description
	Tags        []string          // Optional: update tags (nil = no change)
	Nodes       []CreateNodeInput // Required: new nodes (replaces all existing)
	Edges       []CreateEdgeInput // Required: new edges (replaces all existing)
}

// UpdateWorkflowGraph atomically replaces a workflow's graph (nodes and edges).
// This is a complete replacement operation - all existing nodes/edges are deleted
// and new ones are created in a single atomic operation.
func (s *WorkflowService) UpdateWorkflowGraph(ctx context.Context, input UpdateWorkflowGraphInput) (*workflowdom.Workflow, error) {
	// Verify workflow exists and belongs to tenant
	w, err := s.workflowRepo.GetByTenantAndID(ctx, input.TenantID, input.WorkflowID)
	if err != nil {
		return nil, err
	}

	// Check for active runs - cannot modify graph while runs are in progress
	activeCount, err := s.runRepo.CountActiveByWorkflowID(ctx, input.WorkflowID)
	if err != nil {
		return nil, fmt.Errorf("failed to check active runs: %w", err)
	}
	if activeCount > 0 {
		return nil, shared.NewDomainError("ACTIVE_RUNS_EXIST", "cannot update workflow graph with active runs", shared.ErrValidation)
	}

	// Refuse trigger/action types the platform does not execute and an
	// invalid graph, before the existing graph is deleted.
	if err := validateSupportedNodeInputs(input.Nodes); err != nil {
		return nil, err
	}
	if err := validateGraphInputs(input.Nodes, input.Edges); err != nil {
		return nil, err
	}

	// Update metadata if provided
	if input.Name != nil {
		w.Name = *input.Name
	}
	if input.Description != nil {
		w.Description = *input.Description
	}
	if input.Tags != nil {
		w.Tags = input.Tags
	}

	// Delete existing edges first (FK constraint)
	if err := s.edgeRepo.DeleteByWorkflowID(ctx, input.WorkflowID); err != nil {
		return nil, fmt.Errorf("failed to delete existing edges: %w", err)
	}

	// Delete existing nodes
	if err := s.nodeRepo.DeleteByWorkflowID(ctx, input.WorkflowID); err != nil {
		return nil, fmt.Errorf("failed to delete existing nodes: %w", err)
	}

	// Clear the in-memory slices
	w.Nodes = nil
	w.Edges = nil

	// Create new nodes
	for _, nodeInput := range input.Nodes {
		node, err := workflowdom.NewNode(w.ID, nodeInput.NodeKey, nodeInput.NodeType, nodeInput.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to create node %s: %w", nodeInput.NodeKey, err)
		}
		node.SetDescription(nodeInput.Description)
		node.SetUIPosition(nodeInput.UIPositionX, nodeInput.UIPositionY)
		node.Config = nodeInput.Config

		if err := s.nodeRepo.Create(ctx, node); err != nil {
			return nil, fmt.Errorf("failed to save node %s: %w", nodeInput.NodeKey, err)
		}
		w.Nodes = append(w.Nodes, node)
	}

	// Create new edges
	for _, edgeInput := range input.Edges {
		edge, err := workflowdom.NewEdge(w.ID, edgeInput.SourceNodeKey, edgeInput.TargetNodeKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create edge: %w", err)
		}
		edge.SetSourceHandle(edgeInput.SourceHandle)
		edge.SetLabel(edgeInput.Label)

		if err := s.edgeRepo.Create(ctx, edge); err != nil {
			return nil, fmt.Errorf("failed to save edge: %w", err)
		}
		w.Edges = append(w.Edges, edge)
	}

	// Validate the new graph
	if err := w.ValidateGraph(); err != nil {
		// Known limitation: graph deletion and re-creation are not wrapped in a single
		// transaction. If validation fails here, the workflow may be in an inconsistent state.
		// Acceptable risk for MVP — the admin can re-save the workflow to fix it.
		return nil, fmt.Errorf("graph validation failed: %w", err)
	}

	// Update workflow metadata
	if err := s.workflowRepo.Update(ctx, w); err != nil {
		return nil, fmt.Errorf("failed to update workflow: %w", err)
	}

	// Audit log
	s.logAudit(ctx, auditapp.AuditContext{TenantID: input.TenantID.String(), ActorID: input.UserID.String()},
		auditapp.NewSuccessEvent(audit.ActionWorkflowUpdated, audit.ResourceTypeWorkflow, w.ID.String()).
			WithResourceName(w.Name).
			WithMessage(fmt.Sprintf("Workflow '%s' graph updated with %d nodes and %d edges", w.Name, len(w.Nodes), len(w.Edges))))

	return w, nil
}

// DeleteWorkflow deletes a workflow and all its nodes/edges.
func (s *WorkflowService) DeleteWorkflow(ctx context.Context, tenantID, userID, workflowID shared.ID) error {
	w, err := s.workflowRepo.GetByTenantAndID(ctx, tenantID, workflowID)
	if err != nil {
		return err
	}

	workflowName := w.Name

	// Check for active runs
	activeCount, err := s.runRepo.CountActiveByWorkflowID(ctx, workflowID)
	if err != nil {
		return fmt.Errorf("failed to check active runs: %w", err)
	}
	if activeCount > 0 {
		return shared.NewDomainError("ACTIVE_RUNS_EXIST", "cannot delete workflow with active runs", shared.ErrValidation)
	}

	// Delete edges first (FK constraint)
	if err := s.edgeRepo.DeleteByWorkflowID(ctx, workflowID); err != nil {
		return fmt.Errorf("failed to delete edges: %w", err)
	}

	// Delete nodes
	if err := s.nodeRepo.DeleteByWorkflowID(ctx, workflowID); err != nil {
		return fmt.Errorf("failed to delete nodes: %w", err)
	}

	// Delete workflow
	if err := s.workflowRepo.Delete(ctx, workflowID); err != nil {
		return fmt.Errorf("failed to delete workflow: %w", err)
	}

	// Audit log
	s.logAudit(ctx, auditapp.AuditContext{TenantID: tenantID.String(), ActorID: userID.String()},
		auditapp.NewSuccessEvent(audit.ActionWorkflowDeleted, audit.ResourceTypeWorkflow, workflowID.String()).
			WithResourceName(workflowName).
			WithMessage(fmt.Sprintf("Workflow '%s' deleted", workflowName)))

	return nil
}

// --------------------------------------------------------------------------
// Node Management
// --------------------------------------------------------------------------

// AddNodeInput represents input for adding a node.
type AddNodeInput struct {
	TenantID    shared.ID
	UserID      shared.ID
	WorkflowID  shared.ID
	NodeKey     string
	NodeType    workflowdom.NodeType
	Name        string
	Description string
	UIPositionX float64
	UIPositionY float64
	Config      workflowdom.NodeConfig
}

// AddNode adds a node to a workflow.
func (s *WorkflowService) AddNode(ctx context.Context, input AddNodeInput) (*workflowdom.Node, error) {
	// Verify workflow exists and belongs to tenant
	w, err := s.workflowRepo.GetByTenantAndID(ctx, input.TenantID, input.WorkflowID)
	if err != nil {
		return nil, err
	}

	if err := workflowdom.ValidateSupported(input.Config); err != nil {
		return nil, err
	}

	node, err := workflowdom.NewNode(w.ID, input.NodeKey, input.NodeType, input.Name)
	if err != nil {
		return nil, err
	}
	node.SetDescription(input.Description)
	node.SetUIPosition(input.UIPositionX, input.UIPositionY)
	node.Config = input.Config

	if err := s.nodeRepo.Create(ctx, node); err != nil {
		return nil, fmt.Errorf("failed to create node: %w", err)
	}

	return node, nil
}

// UpdateNodeInput represents input for updating a node.
type UpdateNodeInput struct {
	TenantID    shared.ID
	UserID      shared.ID
	WorkflowID  shared.ID
	NodeID      shared.ID
	Name        *string
	Description *string
	UIPositionX *float64
	UIPositionY *float64
	Config      *workflowdom.NodeConfig
}

// UpdateNode updates a workflow node.
func (s *WorkflowService) UpdateNode(ctx context.Context, input UpdateNodeInput) (*workflowdom.Node, error) {
	// Verify workflow belongs to tenant
	_, err := s.workflowRepo.GetByTenantAndID(ctx, input.TenantID, input.WorkflowID)
	if err != nil {
		return nil, err
	}

	node, err := s.nodeRepo.GetByID(ctx, input.NodeID)
	if err != nil {
		return nil, err
	}

	// Verify node belongs to workflow
	if node.WorkflowID != input.WorkflowID {
		return nil, shared.ErrNotFound
	}

	if input.Name != nil {
		node.Name = *input.Name
	}
	if input.Description != nil {
		node.Description = *input.Description
	}
	if input.UIPositionX != nil && input.UIPositionY != nil {
		node.SetUIPosition(*input.UIPositionX, *input.UIPositionY)
	}
	if input.Config != nil {
		if err := workflowdom.ValidateSupported(*input.Config); err != nil {
			return nil, err
		}
		node.Config = *input.Config
	}

	if err := s.nodeRepo.Update(ctx, node); err != nil {
		return nil, fmt.Errorf("failed to update node: %w", err)
	}

	return node, nil
}

// DeleteNode deletes a node from a workflow.
func (s *WorkflowService) DeleteNode(ctx context.Context, tenantID, workflowID, nodeID shared.ID) error {
	// Verify workflow belongs to tenant
	_, err := s.workflowRepo.GetByTenantAndID(ctx, tenantID, workflowID)
	if err != nil {
		return err
	}

	node, err := s.nodeRepo.GetByID(ctx, nodeID)
	if err != nil {
		return err
	}

	// Verify node belongs to workflow
	if node.WorkflowID != workflowID {
		return shared.ErrNotFound
	}

	return s.nodeRepo.Delete(ctx, nodeID)
}

// --------------------------------------------------------------------------
// Edge Management
// --------------------------------------------------------------------------

// AddEdgeInput represents input for adding an edge.
type AddEdgeInput struct {
	TenantID      shared.ID
	UserID        shared.ID
	WorkflowID    shared.ID
	SourceNodeKey string
	TargetNodeKey string
	SourceHandle  string
	Label         string
}

// AddEdge adds an edge to a workflow.
func (s *WorkflowService) AddEdge(ctx context.Context, input AddEdgeInput) (*workflowdom.Edge, error) {
	// Verify workflow belongs to tenant
	w, err := s.workflowRepo.GetByTenantAndID(ctx, input.TenantID, input.WorkflowID)
	if err != nil {
		return nil, err
	}

	// Verify nodes exist
	_, err = s.nodeRepo.GetByKey(ctx, w.ID, input.SourceNodeKey)
	if err != nil {
		return nil, shared.NewDomainError("INVALID_SOURCE_NODE", "source node not found", shared.ErrValidation)
	}

	_, err = s.nodeRepo.GetByKey(ctx, w.ID, input.TargetNodeKey)
	if err != nil {
		return nil, shared.NewDomainError("INVALID_TARGET_NODE", "target node not found", shared.ErrValidation)
	}

	edge, err := workflowdom.NewEdge(w.ID, input.SourceNodeKey, input.TargetNodeKey)
	if err != nil {
		return nil, err
	}
	edge.SetSourceHandle(input.SourceHandle)
	edge.SetLabel(input.Label)

	// The new edge must not end at a trigger, leave a condition without a
	// yes/no handle, or close a cycle (a run would never end).
	full, err := s.workflowRepo.GetWithGraph(ctx, w.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to load workflow graph: %w", err)
	}
	if err := full.ValidateNewEdge(edge); err != nil {
		return nil, err
	}

	if err := s.edgeRepo.Create(ctx, edge); err != nil {
		return nil, fmt.Errorf("failed to create edge: %w", err)
	}

	return edge, nil
}

// DeleteEdge deletes an edge from a workflow.
func (s *WorkflowService) DeleteEdge(ctx context.Context, tenantID, workflowID, edgeID shared.ID) error {
	// Verify workflow belongs to tenant
	_, err := s.workflowRepo.GetByTenantAndID(ctx, tenantID, workflowID)
	if err != nil {
		return err
	}

	edge, err := s.edgeRepo.GetByID(ctx, edgeID)
	if err != nil {
		return err
	}

	// Verify edge belongs to workflow
	if edge.WorkflowID != workflowID {
		return shared.ErrNotFound
	}

	return s.edgeRepo.Delete(ctx, edgeID)
}

// --------------------------------------------------------------------------
// Workflow Execution
// --------------------------------------------------------------------------

// TriggerWorkflowInput represents input for triggering a workflow.
type TriggerWorkflowInput struct {
	TenantID    shared.ID
	UserID      shared.ID
	WorkflowID  shared.ID
	TriggerType workflowdom.TriggerType
	TriggerData map[string]any
	// SubjectID is the finding or asset the run is about (nil for none).
	SubjectID *shared.ID
	// IdempotencyKey identifies the event: a second trigger with the same
	// key for the same workflow returns workflowdom.ErrRunDuplicate.
	IdempotencyKey string
}

// TriggerWorkflow triggers a workflow execution.
func (s *WorkflowService) TriggerWorkflow(ctx context.Context, input TriggerWorkflowInput) (*workflowdom.Run, error) {
	// Load workflow with graph
	w, err := s.workflowRepo.GetWithGraph(ctx, input.WorkflowID)
	if err != nil {
		return nil, err
	}

	// Verify tenant
	if w.TenantID != input.TenantID {
		return nil, shared.ErrNotFound
	}

	// Check if workflow is active
	if !w.IsActive {
		return nil, shared.NewDomainError("WORKFLOW_INACTIVE", "workflow is not active", shared.ErrValidation)
	}

	// Create run
	run, err := workflowdom.NewRun(input.WorkflowID, input.TenantID, input.TriggerType, input.TriggerData)
	if err != nil {
		return nil, err
	}

	if !input.UserID.IsZero() {
		run.SetTriggeredBy(input.UserID)
	}
	run.SetSubject(input.SubjectID, input.IdempotencyKey)

	run.TotalNodes = len(w.Nodes)

	// FIXED: Use atomic CreateRunIfUnderLimit to prevent race conditions
	// This atomically checks concurrent run limits AND creates the run in a single transaction.
	// Previously, the check-then-create pattern allowed race conditions where multiple
	// concurrent triggers could bypass the limits (TOCTOU vulnerability).
	if err := s.runRepo.CreateRunIfUnderLimit(ctx, run, MaxConcurrentWorkflowRunsPerWorkflow, MaxConcurrentWorkflowRunsPerTenant); err != nil {
		return nil, err
	}

	// Create node runs for all nodes
	for _, node := range w.Nodes {
		nodeRun, err := workflowdom.NewNodeRun(run.ID, node.ID, node.NodeKey, node.NodeType)
		if err != nil {
			return nil, fmt.Errorf("failed to create node run for %s: %w", node.NodeKey, err)
		}

		if err := s.nodeRunRepo.Create(ctx, nodeRun); err != nil {
			return nil, fmt.Errorf("failed to save node run for %s: %w", node.NodeKey, err)
		}

		run.NodeRuns = append(run.NodeRuns, nodeRun)
	}

	// Audit log
	s.logAudit(ctx, auditapp.AuditContext{TenantID: input.TenantID.String(), ActorID: input.UserID.String()},
		auditapp.NewSuccessEvent(audit.ActionWorkflowRunTriggered, audit.ResourceTypeWorkflowRun, run.ID.String()).
			WithResourceName(w.Name).
			WithMessage(fmt.Sprintf("Workflow '%s' triggered", w.Name)).
			WithMetadata("trigger_type", string(input.TriggerType)).
			WithMetadata("workflow_id", w.ID.String()))

	// Execute workflow asynchronously with tenant context for isolation
	if s.executor != nil {
		s.executor.ExecuteAsyncWithTenant(run.ID, input.TenantID)
	}

	return run, nil
}

// GetRun retrieves a workflow run with its node runs.
func (s *WorkflowService) GetRun(ctx context.Context, tenantID, runID shared.ID) (*workflowdom.Run, error) {
	run, err := s.runRepo.GetByTenantAndID(ctx, tenantID, runID)
	if err != nil {
		return nil, err
	}

	return s.runRepo.GetWithNodeRuns(ctx, run.ID)
}

// ListWorkflowRunsInput represents input for listing workflow runs.
type ListWorkflowRunsInput struct {
	TenantID   shared.ID
	WorkflowID *shared.ID
	Status     *workflowdom.RunStatus
	Page       int
	PerPage    int
}

// ListRuns lists workflow runs.
func (s *WorkflowService) ListRuns(ctx context.Context, input ListWorkflowRunsInput) (pagination.Result[*workflowdom.Run], error) {
	filter := workflowdom.RunFilter{
		TenantID:   &input.TenantID,
		WorkflowID: input.WorkflowID,
		Status:     input.Status,
	}

	page := pagination.Pagination{
		Page:    input.Page,
		PerPage: input.PerPage,
	}
	if page.Page < 1 {
		page.Page = 1
	}
	if page.PerPage < 1 {
		page.PerPage = 20
	}

	return s.runRepo.List(ctx, filter, page)
}

// CancelRun cancels a running workflow.
func (s *WorkflowService) CancelRun(ctx context.Context, tenantID, userID, runID shared.ID) error {
	run, err := s.runRepo.GetByTenantAndID(ctx, tenantID, runID)
	if err != nil {
		return err
	}

	if run.Status == workflowdom.RunStatusCanceled {
		// Canceling again is the same cancel: close anything left open.
		s.skipOpenNodeRuns(ctx, tenantID, runID)
		return nil
	}
	if run.Status.IsTerminal() {
		return shared.NewDomainError("INVALID_STATUS", "run is already in terminal state", shared.ErrValidation)
	}

	run.Cancel()

	// The update refuses a run that finished meanwhile, so a cancel never
	// turns a completed run into a canceled one.
	if err := s.runRepo.Update(ctx, run); err != nil {
		if errors.Is(err, workflowdom.ErrRunAlreadyFinished) {
			return shared.NewDomainError("INVALID_STATUS", "run is already in terminal state", shared.ErrValidation)
		}
		return fmt.Errorf("failed to cancel run: %w", err)
	}

	// Its pending and running steps end now. The executor sees the run
	// canceled before its next step and stops; a step it then tries to
	// start or finish is refused (a finished node run never changes).
	skipped := s.skipOpenNodeRuns(ctx, tenantID, runID)

	// Audit log
	s.logAudit(ctx, auditapp.AuditContext{TenantID: tenantID.String(), ActorID: userID.String()},
		auditapp.NewSuccessEvent(audit.ActionWorkflowRunCanceled, audit.ResourceTypeWorkflowRun, runID.String()).
			WithMessage("Workflow run canceled").
			WithMetadata("workflow_id", run.WorkflowID.String()).
			WithMetadata("skipped_steps", skipped))

	return nil
}

// skipOpenNodeRuns ends the open steps of a canceled run (best effort: the
// run is canceled either way, and canceling again retries this).
func (s *WorkflowService) skipOpenNodeRuns(ctx context.Context, tenantID, runID shared.ID) int64 {
	c, ok := s.nodeRunRepo.(workflowdom.NodeRunCanceler)
	if !ok {
		return 0
	}
	n, err := c.SkipOpenNodeRuns(ctx, tenantID, runID)
	if err != nil {
		s.logger.Warn("failed to close the canceled run's steps", "run_id", runID.String(), "error", err)
		return 0
	}
	return n
}

// validateGraphInputs builds the graph from the inputs in memory and runs
// the domain graph checks (unique keys, known edge ends, a trigger, no
// edge into a trigger, condition handles, no cycle, every node reached
// from a trigger), so an invalid graph is refused before anything is written.
func validateGraphInputs(nodes []CreateNodeInput, edges []CreateEdgeInput) error {
	trial := &workflowdom.Workflow{}
	for _, n := range nodes {
		node, err := workflowdom.NewNode(shared.ID{}, n.NodeKey, n.NodeType, n.Name)
		if err != nil {
			return fmt.Errorf("node %s: %w", n.NodeKey, err)
		}
		trial.Nodes = append(trial.Nodes, node)
	}
	for _, e := range edges {
		edge, err := workflowdom.NewEdge(shared.ID{}, e.SourceNodeKey, e.TargetNodeKey)
		if err != nil {
			return err
		}
		edge.SetSourceHandle(e.SourceHandle)
		trial.Edges = append(trial.Edges, edge)
	}
	return trial.ValidateGraph()
}

// validateSupportedNodeInputs refuses node inputs that use a trigger or action
// type the platform does not execute (see workflowdom.ValidateSupported).
func validateSupportedNodeInputs(nodes []CreateNodeInput) error {
	configs := make([]workflowdom.NodeConfig, 0, len(nodes))
	for _, n := range nodes {
		configs = append(configs, n.Config)
	}
	return workflowdom.ValidateSupported(configs...)
}
