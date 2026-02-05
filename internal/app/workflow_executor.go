package app

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/workflow"
	"github.com/openctemio/api/pkg/logger"
)

// WorkflowExecutor handles the execution of workflow runs.
// It processes nodes in topological order, handling conditions,
// actions, and notifications.
//
// SECURITY: Includes tenant isolation, execution timeout, and rate limiting.
type WorkflowExecutor struct {
	db           *sql.DB
	workflowRepo workflow.WorkflowRepository
	runRepo      workflow.RunRepository
	nodeRunRepo  workflow.NodeRunRepository

	// Action handlers
	actionHandlers      map[workflow.ActionType]ActionHandler
	notificationHandler NotificationHandler
	conditionEvaluator  ConditionEvaluator

	// Services for actions
	notificationService *NotificationService
	integrationService  *IntegrationService
	auditService        *AuditService

	logger *logger.Logger
	mu     sync.RWMutex

	// SEC-WF04: Execution control
	maxConcurrentRuns int           // Max concurrent async executions
	runSemaphore      chan struct{} // Semaphore for limiting concurrent runs
	maxExecutionTime  time.Duration // Max time for entire workflow execution
	maxNodeTime       time.Duration // Max time for single node execution

	// SEC-WF10: Per-tenant rate limiting
	maxConcurrentPerTenant int            // Max concurrent runs per tenant
	tenantRunCounts        map[string]int // Current run count per tenant
	tenantMu               sync.Mutex     // Mutex for tenant counts
}

// WorkflowExecutorConfig holds configuration for the executor.
type WorkflowExecutorConfig struct {
	// MaxNodeExecutionTime is the maximum time allowed for a single node execution.
	MaxNodeExecutionTime time.Duration

	// MaxConcurrentNodes is the maximum nodes that can execute concurrently.
	MaxConcurrentNodes int
}

// DefaultWorkflowExecutorConfig returns default configuration.
func DefaultWorkflowExecutorConfig() WorkflowExecutorConfig {
	return WorkflowExecutorConfig{
		MaxNodeExecutionTime: 30 * time.Second,
		MaxConcurrentNodes:   10,
	}
}

// SEC-WF04: Default security limits
const (
	defaultMaxConcurrentRuns      = 50               // Max concurrent workflow executions (global)
	defaultMaxConcurrentPerTenant = 10               // Max concurrent per tenant (SEC-WF10)
	defaultMaxExecutionTime       = 5 * time.Minute  // Max time for entire workflow
	defaultMaxNodeTime            = 30 * time.Second // Max time for single node
)

// WorkflowExecutorOption is a functional option for WorkflowExecutor.
type WorkflowExecutorOption func(*WorkflowExecutor)

// WithExecutorNotificationService sets the notification service.
func WithExecutorNotificationService(svc *NotificationService) WorkflowExecutorOption {
	return func(e *WorkflowExecutor) {
		e.notificationService = svc
	}
}

// WithExecutorIntegrationService sets the integration service.
func WithExecutorIntegrationService(svc *IntegrationService) WorkflowExecutorOption {
	return func(e *WorkflowExecutor) {
		e.integrationService = svc
	}
}

// WithExecutorAuditService sets the audit service.
func WithExecutorAuditService(svc *AuditService) WorkflowExecutorOption {
	return func(e *WorkflowExecutor) {
		e.auditService = svc
	}
}

// WithExecutorDB sets the database connection for transactions.
func WithExecutorDB(db *sql.DB) WorkflowExecutorOption {
	return func(e *WorkflowExecutor) {
		e.db = db
	}
}

// NewWorkflowExecutor creates a new WorkflowExecutor.
func NewWorkflowExecutor(
	workflowRepo workflow.WorkflowRepository,
	runRepo workflow.RunRepository,
	nodeRunRepo workflow.NodeRunRepository,
	log *logger.Logger,
	opts ...WorkflowExecutorOption,
) *WorkflowExecutor {
	e := &WorkflowExecutor{
		workflowRepo:       workflowRepo,
		runRepo:            runRepo,
		nodeRunRepo:        nodeRunRepo,
		actionHandlers:     make(map[workflow.ActionType]ActionHandler),
		conditionEvaluator: &DefaultConditionEvaluator{},
		logger:             log.With("component", "workflow_executor"),
		// SEC-WF04: Default security limits
		maxConcurrentRuns: defaultMaxConcurrentRuns,
		maxExecutionTime:  defaultMaxExecutionTime,
		maxNodeTime:       defaultMaxNodeTime,
		// SEC-WF10: Per-tenant rate limiting
		maxConcurrentPerTenant: defaultMaxConcurrentPerTenant,
		tenantRunCounts:        make(map[string]int),
	}

	// Initialize semaphore for concurrency control
	e.runSemaphore = make(chan struct{}, e.maxConcurrentRuns)

	for _, opt := range opts {
		opt(e)
	}

	// Register default action handlers
	e.registerDefaultHandlers()

	return e
}

// registerDefaultHandlers registers the built-in action handlers.
func (e *WorkflowExecutor) registerDefaultHandlers() {
	// HTTP Request handler (with SSRF protection)
	e.RegisterActionHandler(workflow.ActionTypeHTTPRequest, NewHTTPRequestHandler(e.logger))

	// Notification-based actions will use the notification service
	if e.notificationService != nil {
		e.notificationHandler = &DefaultNotificationHandler{
			notificationService: e.notificationService,
			integrationService:  e.integrationService,
			logger:              e.logger,
		}
	}
}

// RegisterActionHandler registers a custom action handler.
func (e *WorkflowExecutor) RegisterActionHandler(actionType workflow.ActionType, handler ActionHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.actionHandlers[actionType] = handler
}

// Execute executes a workflow run.
// This is the main entry point for workflow execution.
// SEC-WF05: Includes tenant isolation check.
func (e *WorkflowExecutor) Execute(ctx context.Context, runID shared.ID) error {
	return e.ExecuteWithTenant(ctx, runID, shared.ID{})
}

// ExecuteWithTenant executes a workflow run with explicit tenant verification.
// SEC-WF05: If expectedTenantID is provided, verifies the run belongs to that tenant.
func (e *WorkflowExecutor) ExecuteWithTenant(ctx context.Context, runID shared.ID, expectedTenantID shared.ID) error {
	e.logger.Info("starting workflow execution", "run_id", runID)

	// SEC-WF06: Apply execution timeout
	execCtx, cancel := context.WithTimeout(ctx, e.maxExecutionTime)
	defer cancel()

	// Load run with node runs
	run, err := e.runRepo.GetWithNodeRuns(execCtx, runID)
	if err != nil {
		return fmt.Errorf("failed to load run: %w", err)
	}

	// SEC-WF05: Tenant isolation check
	if !expectedTenantID.IsZero() && run.TenantID != expectedTenantID {
		e.logger.Warn("tenant isolation violation attempt",
			"run_id", runID,
			"expected_tenant", expectedTenantID,
			"actual_tenant", run.TenantID,
		)
		return fmt.Errorf("access denied: run does not belong to tenant")
	}

	// Check if already running or completed
	if run.Status != workflow.RunStatusPending {
		return fmt.Errorf("run is not in pending state: %s", run.Status)
	}

	// Load workflow with graph
	wf, err := e.workflowRepo.GetWithGraph(execCtx, run.WorkflowID)
	if err != nil {
		return fmt.Errorf("failed to load workflow: %w", err)
	}

	// SEC-WF05: Verify workflow belongs to same tenant
	if wf.TenantID != run.TenantID {
		e.logger.Error("workflow/run tenant mismatch",
			"run_id", runID,
			"run_tenant", run.TenantID,
			"workflow_tenant", wf.TenantID,
		)
		return fmt.Errorf("integrity error: workflow and run tenant mismatch")
	}

	// Start the run
	run.Start()
	if err := e.runRepo.Update(execCtx, run); err != nil {
		return fmt.Errorf("failed to start run: %w", err)
	}

	// Create execution context
	workflowExecCtx := &ExecutionContext{
		Run:               run,
		Workflow:          wf,
		TriggerData:       run.TriggerData,
		Context:           make(map[string]any),
		CompletedNodeKeys: make(map[string]bool),
		NodeRunsByKey:     make(map[string]*workflow.NodeRun),
	}

	// Index node runs by key
	for _, nr := range run.NodeRuns {
		workflowExecCtx.NodeRunsByKey[nr.NodeKey] = nr
	}

	// Execute the workflow graph
	err = e.executeGraph(execCtx, workflowExecCtx)

	// Finalize the run
	e.finalizeRun(context.Background(), workflowExecCtx, err) // Use background ctx for finalization

	return err
}

// ExecutionContext holds the state during workflow execution.
type ExecutionContext struct {
	Run               *workflow.Run
	Workflow          *workflow.Workflow
	TriggerData       map[string]any
	Context           map[string]any // Shared context across nodes
	CompletedNodeKeys map[string]bool
	NodeRunsByKey     map[string]*workflow.NodeRun
	mu                sync.RWMutex
}

// SetContextValue sets a value in the execution context.
func (ec *ExecutionContext) SetContextValue(key string, value any) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.Context[key] = value
}

// GetContextValue gets a value from the execution context.
func (ec *ExecutionContext) GetContextValue(key string) (any, bool) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	v, ok := ec.Context[key]
	return v, ok
}

// MarkNodeCompleted marks a node as completed.
func (ec *ExecutionContext) MarkNodeCompleted(nodeKey string) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.CompletedNodeKeys[nodeKey] = true
}

// IsNodeCompleted checks if a node is completed.
func (ec *ExecutionContext) IsNodeCompleted(nodeKey string) bool {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	return ec.CompletedNodeKeys[nodeKey]
}

// executeGraph executes the workflow graph starting from trigger nodes.
func (e *WorkflowExecutor) executeGraph(ctx context.Context, execCtx *ExecutionContext) error {
	wf := execCtx.Workflow

	// Find trigger nodes - these are the starting points
	triggerNodes := wf.GetTriggerNodes()
	if len(triggerNodes) == 0 {
		return fmt.Errorf("workflow has no trigger nodes")
	}

	// Execute trigger nodes first
	for _, trigger := range triggerNodes {
		if err := e.executeNode(ctx, execCtx, trigger); err != nil {
			// Trigger failures are fatal
			return fmt.Errorf("trigger node %s failed: %w", trigger.NodeKey, err)
		}
	}

	// Execute remaining nodes in topological order
	return e.executeDownstream(ctx, execCtx)
}

// executeDownstream executes nodes that have all dependencies satisfied.
func (e *WorkflowExecutor) executeDownstream(ctx context.Context, execCtx *ExecutionContext) error {
	wf := execCtx.Workflow

	// Keep executing until no more nodes can be executed
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Find nodes ready to execute (all upstream dependencies completed)
		readyNodes := e.findReadyNodes(execCtx)
		if len(readyNodes) == 0 {
			// No more nodes to execute
			break
		}

		// Execute ready nodes
		for _, node := range readyNodes {
			// Check if we should skip based on condition results
			if e.shouldSkipNode(execCtx, node) {
				if err := e.skipNode(ctx, execCtx, node, "condition not met"); err != nil {
					e.logger.Error("failed to skip node", "node_key", node.NodeKey, "error", err)
				}
				continue
			}

			if err := e.executeNode(ctx, execCtx, node); err != nil {
				e.logger.Error("node execution failed", "node_key", node.NodeKey, "error", err)
				// Continue with other nodes - don't fail the entire workflow for one node
				// The node is already marked as failed
			}
		}

		// Check for completion
		allDone := true
		for _, nr := range execCtx.Run.NodeRuns {
			if !nr.Status.IsTerminal() {
				allDone = false
				break
			}
		}
		if allDone {
			break
		}
	}

	// Skip any remaining unreachable nodes
	for _, node := range wf.Nodes {
		nr := execCtx.NodeRunsByKey[node.NodeKey]
		if nr != nil && nr.Status == workflow.NodeRunStatusPending {
			_ = e.skipNode(ctx, execCtx, node, "unreachable due to workflow path")
		}
	}

	return nil
}

// findReadyNodes finds nodes that are ready to execute.
// A node is ready if all its upstream dependencies are completed.
func (e *WorkflowExecutor) findReadyNodes(execCtx *ExecutionContext) []*workflow.Node {
	var ready []*workflow.Node
	wf := execCtx.Workflow

	for _, node := range wf.Nodes {
		nr := execCtx.NodeRunsByKey[node.NodeKey]
		if nr == nil || nr.Status != workflow.NodeRunStatusPending {
			continue
		}

		// Skip trigger nodes (already executed)
		if node.NodeType == workflow.NodeTypeTrigger {
			continue
		}

		// Check if all upstream nodes are completed
		allUpstreamDone := true
		for _, edge := range wf.Edges {
			if edge.TargetNodeKey == node.NodeKey {
				if !execCtx.IsNodeCompleted(edge.SourceNodeKey) {
					allUpstreamDone = false
					break
				}
			}
		}

		if allUpstreamDone {
			ready = append(ready, node)
		}
	}

	return ready
}

// shouldSkipNode checks if a node should be skipped based on condition results.
func (e *WorkflowExecutor) shouldSkipNode(execCtx *ExecutionContext, node *workflow.Node) bool {
	wf := execCtx.Workflow

	// Check incoming edges from condition nodes
	for _, edge := range wf.Edges {
		if edge.TargetNodeKey != node.NodeKey {
			continue
		}

		sourceNode := wf.GetNodeByKey(edge.SourceNodeKey)
		if sourceNode == nil || sourceNode.NodeType != workflow.NodeTypeCondition {
			continue
		}

		// Get the condition result
		sourceNR := execCtx.NodeRunsByKey[edge.SourceNodeKey]
		if sourceNR == nil || sourceNR.ConditionResult == nil {
			continue
		}

		conditionResult := *sourceNR.ConditionResult

		// Check if the edge matches the condition result
		if edge.SourceHandle == "yes" && !conditionResult {
			return true // Skip: condition was false but this is the "yes" branch
		}
		if edge.SourceHandle == "no" && conditionResult {
			return true // Skip: condition was true but this is the "no" branch
		}
	}

	return false
}

// executeNode executes a single node.
func (e *WorkflowExecutor) executeNode(ctx context.Context, execCtx *ExecutionContext, node *workflow.Node) error {
	nodeRun := execCtx.NodeRunsByKey[node.NodeKey]
	if nodeRun == nil {
		return fmt.Errorf("node run not found for %s", node.NodeKey)
	}

	e.logger.Info("executing node", "node_key", node.NodeKey, "node_type", node.NodeType)

	// Mark as running
	nodeRun.Start()
	nodeRun.SetInput(e.buildNodeInput(execCtx, node))
	if err := e.nodeRunRepo.Update(ctx, nodeRun); err != nil {
		return fmt.Errorf("failed to update node run status: %w", err)
	}

	// Execute based on node type
	var output map[string]any
	var execErr error

	switch node.NodeType {
	case workflow.NodeTypeTrigger:
		output, execErr = e.executeTriggerNode(ctx, execCtx, node)
	case workflow.NodeTypeCondition:
		output, execErr = e.executeConditionNode(ctx, execCtx, node, nodeRun)
	case workflow.NodeTypeAction:
		output, execErr = e.executeActionNode(ctx, execCtx, node)
	case workflow.NodeTypeNotification:
		output, execErr = e.executeNotificationNode(ctx, execCtx, node)
	default:
		execErr = fmt.Errorf("unknown node type: %s", node.NodeType)
	}

	// Update node run result
	if execErr != nil {
		nodeRun.Fail(execErr.Error(), "EXECUTION_ERROR")
		e.updateRunStats(execCtx, false)
	} else {
		nodeRun.Complete(output)
		execCtx.MarkNodeCompleted(node.NodeKey)
		e.updateRunStats(execCtx, true)

		// Store output in context for downstream nodes
		if output != nil {
			execCtx.SetContextValue(fmt.Sprintf("node.%s.output", node.NodeKey), output)
		}
	}

	if err := e.nodeRunRepo.Update(ctx, nodeRun); err != nil {
		e.logger.Error("failed to save node run result", "error", err)
	}

	return execErr
}

// skipNode marks a node as skipped.
func (e *WorkflowExecutor) skipNode(ctx context.Context, execCtx *ExecutionContext, node *workflow.Node, reason string) error {
	nodeRun := execCtx.NodeRunsByKey[node.NodeKey]
	if nodeRun == nil {
		return nil
	}

	nodeRun.Skip(reason)
	execCtx.MarkNodeCompleted(node.NodeKey)

	return e.nodeRunRepo.Update(ctx, nodeRun)
}

// buildNodeInput builds the input for a node based on context and trigger data.
func (e *WorkflowExecutor) buildNodeInput(execCtx *ExecutionContext, node *workflow.Node) map[string]any {
	input := make(map[string]any)

	// Include trigger data
	input["trigger"] = execCtx.TriggerData

	// Include workflow context
	input["context"] = execCtx.Context

	// Include outputs from upstream nodes
	upstreamOutputs := make(map[string]any)
	for _, edge := range execCtx.Workflow.Edges {
		if edge.TargetNodeKey == node.NodeKey {
			if output, ok := execCtx.GetContextValue(fmt.Sprintf("node.%s.output", edge.SourceNodeKey)); ok {
				upstreamOutputs[edge.SourceNodeKey] = output
			}
		}
	}
	input["upstream"] = upstreamOutputs

	return input
}

// executeTriggerNode executes a trigger node.
func (e *WorkflowExecutor) executeTriggerNode(ctx context.Context, execCtx *ExecutionContext, node *workflow.Node) (map[string]any, error) {
	// Trigger nodes simply pass through the trigger data
	output := map[string]any{
		"trigger_type": string(node.Config.TriggerType),
		"trigger_data": execCtx.TriggerData,
		"timestamp":    time.Now().Format(time.RFC3339),
	}
	return output, nil
}

// executeConditionNode executes a condition node.
func (e *WorkflowExecutor) executeConditionNode(ctx context.Context, execCtx *ExecutionContext, node *workflow.Node, nodeRun *workflow.NodeRun) (map[string]any, error) {
	expr := node.Config.ConditionExpr
	if expr == "" {
		// No condition expression - default to true
		nodeRun.SetConditionResult(true)
		return map[string]any{"result": true, "expression": ""}, nil
	}

	// Evaluate the condition
	input := e.buildNodeInput(execCtx, node)
	result, err := e.conditionEvaluator.Evaluate(ctx, expr, input)
	if err != nil {
		return nil, fmt.Errorf("condition evaluation failed: %w", err)
	}

	nodeRun.SetConditionResult(result)

	return map[string]any{
		"result":     result,
		"expression": expr,
	}, nil
}

// executeActionNode executes an action node.
func (e *WorkflowExecutor) executeActionNode(ctx context.Context, execCtx *ExecutionContext, node *workflow.Node) (map[string]any, error) {
	actionType := node.Config.ActionType

	// Look up the action handler
	e.mu.RLock()
	handler, ok := e.actionHandlers[actionType]
	e.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no handler registered for action type: %s", actionType)
	}

	// Build action input
	input := &ActionInput{
		TenantID:     execCtx.Run.TenantID,
		WorkflowID:   execCtx.Workflow.ID,
		RunID:        execCtx.Run.ID,
		NodeKey:      node.NodeKey,
		ActionType:   actionType,
		ActionConfig: node.Config.ActionConfig,
		TriggerData:  execCtx.TriggerData,
		Context:      e.buildNodeInput(execCtx, node),
	}

	// Execute the action
	return handler.Execute(ctx, input)
}

// executeNotificationNode executes a notification node.
func (e *WorkflowExecutor) executeNotificationNode(ctx context.Context, execCtx *ExecutionContext, node *workflow.Node) (map[string]any, error) {
	if e.notificationHandler == nil {
		return nil, fmt.Errorf("notification handler not configured")
	}

	// Build notification input
	input := &NotificationInput{
		TenantID:           execCtx.Run.TenantID,
		WorkflowID:         execCtx.Workflow.ID,
		RunID:              execCtx.Run.ID,
		NodeKey:            node.NodeKey,
		NotificationType:   node.Config.NotificationType,
		NotificationConfig: node.Config.NotificationConfig,
		TriggerData:        execCtx.TriggerData,
		Context:            e.buildNodeInput(execCtx, node),
	}

	return e.notificationHandler.Send(ctx, input)
}

// updateRunStats updates the run statistics.
func (e *WorkflowExecutor) updateRunStats(execCtx *ExecutionContext, success bool) {
	if success {
		execCtx.Run.CompletedNodes++
	} else {
		execCtx.Run.FailedNodes++
	}
}

// finalizeRun finalizes the workflow run.
func (e *WorkflowExecutor) finalizeRun(ctx context.Context, execCtx *ExecutionContext, execErr error) {
	run := execCtx.Run

	// Determine final status
	switch {
	case execErr != nil:
		run.Fail(execErr.Error())
	case run.FailedNodes > 0:
		run.Fail(fmt.Sprintf("%d node(s) failed", run.FailedNodes))
	default:
		run.Complete()
	}

	// Update run
	if err := e.runRepo.Update(ctx, run); err != nil {
		e.logger.Error("failed to finalize run", "error", err)
	}

	// Update workflow statistics
	wf := execCtx.Workflow
	status := string(run.Status)
	wf.RecordRun(run.ID, status)
	if err := e.workflowRepo.Update(ctx, wf); err != nil {
		e.logger.Error("failed to update workflow stats", "error", err)
	}

	// Audit log
	if e.auditService != nil {
		action := audit.ActionWorkflowRunCompleted
		if run.Status == workflow.RunStatusFailed {
			action = audit.ActionWorkflowRunFailed
		}
		actx := AuditContext{
			TenantID: run.TenantID.String(),
		}
		if run.TriggeredBy != nil {
			actx.ActorID = run.TriggeredBy.String()
		}
		event := NewSuccessEvent(action, audit.ResourceTypeWorkflowRun, run.ID.String()).
			WithResourceName(wf.Name).
			WithMessage(fmt.Sprintf("Workflow '%s' run %s: %d/%d nodes completed",
				wf.Name, run.Status, run.CompletedNodes, run.TotalNodes)).
			WithMetadata("status", status).
			WithMetadata("workflow_id", wf.ID.String())

		if err := e.auditService.LogEvent(ctx, actx, event); err != nil {
			e.logger.Error("failed to log audit event", "error", err)
		}
	}

	e.logger.Info("workflow run finalized",
		"run_id", run.ID,
		"status", run.Status,
		"completed_nodes", run.CompletedNodes,
		"failed_nodes", run.FailedNodes,
	)
}

// ExecuteAsync executes a workflow run asynchronously with rate limiting.
// SEC-WF07: Uses semaphore to limit concurrent executions.
func (e *WorkflowExecutor) ExecuteAsync(runID shared.ID) {
	e.ExecuteAsyncWithTenant(runID, shared.ID{})
}

// ExecuteAsyncWithTenant executes a workflow run asynchronously with tenant context.
// SEC-WF07: Uses semaphore to limit concurrent executions and passes tenant for isolation.
// SEC-WF10: Also enforces per-tenant rate limiting.
// SEC-WF12: Includes panic recovery to prevent resource leaks.
func (e *WorkflowExecutor) ExecuteAsyncWithTenant(runID shared.ID, tenantID shared.ID) {
	tenantKey := tenantID.String()

	go func() {
		// SEC-WF12: Track acquired resources for cleanup
		var tenantSlotAcquired bool
		var globalSlotAcquired bool

		// SEC-WF12: Panic recovery - ensure resources are always released
		defer func() {
			if r := recover(); r != nil {
				e.logger.Error("panic recovered in workflow execution",
					"run_id", runID,
					"tenant_id", tenantKey,
					"panic", r,
				)
				// Try to mark run as failed
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if run, err := e.runRepo.GetByID(ctx, runID); err == nil {
					run.Fail(fmt.Sprintf("execution failed: internal error"))
					_ = e.runRepo.Update(ctx, run)
				}
			}

			// SEC-WF12: Always release global semaphore if acquired
			if globalSlotAcquired {
				<-e.runSemaphore
			}

			// SEC-WF12: Always release tenant slot if acquired
			if tenantSlotAcquired {
				e.tenantMu.Lock()
				if e.tenantRunCounts[tenantKey] > 0 {
					e.tenantRunCounts[tenantKey]--
				}
				if e.tenantRunCounts[tenantKey] <= 0 {
					delete(e.tenantRunCounts, tenantKey)
				}
				e.tenantMu.Unlock()
			}
		}()

		// SEC-WF10: Check per-tenant limit first
		if !tenantID.IsZero() {
			e.tenantMu.Lock()
			currentCount := e.tenantRunCounts[tenantKey]
			if currentCount >= e.maxConcurrentPerTenant {
				e.tenantMu.Unlock()
				e.logger.Warn("workflow execution rejected: per-tenant limit reached",
					"run_id", runID,
					"tenant_id", tenantKey,
					"current_count", currentCount,
					"max_per_tenant", e.maxConcurrentPerTenant,
				)
				// Mark the run as failed due to tenant capacity
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if run, err := e.runRepo.GetByID(ctx, runID); err == nil {
					run.Fail("execution rejected: tenant at capacity")
					_ = e.runRepo.Update(ctx, run)
				}
				return
			}
			e.tenantRunCounts[tenantKey]++
			tenantSlotAcquired = true
			e.tenantMu.Unlock()
		}

		// SEC-WF07: Try to acquire global semaphore (non-blocking check first)
		select {
		case e.runSemaphore <- struct{}{}:
			globalSlotAcquired = true
		default:
			// Semaphore full - too many concurrent executions
			e.logger.Warn("workflow execution rejected: max concurrent runs reached",
				"run_id", runID,
				"max_concurrent", e.maxConcurrentRuns,
			)
			// Mark the run as failed due to capacity
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if run, err := e.runRepo.GetByID(ctx, runID); err == nil {
				run.Fail("execution rejected: system at capacity")
				_ = e.runRepo.Update(ctx, run)
			}
			return
		}

		ctx := context.Background()
		if err := e.ExecuteWithTenant(ctx, runID, tenantID); err != nil {
			e.logger.Error("async workflow execution failed", "run_id", runID, "error", err)
		}
	}()
}
