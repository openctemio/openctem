package automation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/metrics"

	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// WorkflowExecutor handles the execution of workflow runs.
// It processes nodes in topological order, handling conditions,
// actions, and notifications.
//
// SECURITY: Includes tenant isolation, execution timeout, and rate limiting.
type WorkflowExecutor struct {
	db           *sql.DB
	workflowRepo automationdom.WorkflowRepository
	runRepo      automationdom.RunRepository
	nodeRunRepo  automationdom.NodeRunRepository
	versions     automationdom.VersionRepository
	// deliveries records what egress steps sent or would have sent.
	deliveries automationdom.DeliveryRepository
	// evaluator is the only thing a simulate run's action and notification
	// steps reach (evaluate.go).
	evaluator StepEvaluator

	// Action handlers
	actionHandlers      map[automationdom.ActionType]ActionHandler
	notificationHandler NotificationHandler
	conditionEvaluator  ConditionEvaluator

	// Services for actions
	notificationService *outbox.Service
	integrationService  *integration.IntegrationService
	auditService        *auditapp.AuditService

	// authorizer checks, before every action and notification step, that
	// the person the run acts as may run it (see authz.go). Nil refuses
	// every such step (fail closed).
	authorizer StepAuthorizer

	logger *logger.Logger
	mu     sync.RWMutex

	// SEC-WF04: Execution control
	maxConcurrentRuns int           // Max concurrent async executions
	runSemaphore      chan struct{} // Semaphore for limiting concurrent runs
	maxExecutionTime  time.Duration // Max time for entire workflow execution
	maxNodeTime       time.Duration // Max time for single node execution

	// SEC-WF10: Per-tenant rate limiting
	maxConcurrentPerTenant int                      // Max concurrent runs per tenant
	tenantSlots            map[string]chan struct{} // Per-tenant run slots
	tenantMu               sync.Mutex               // Guards tenantSlots
	maxQueueWait           time.Duration            // How long a run waits for a slot
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
	// A run waits this long for a free slot before it fails. Runs are
	// bounded where they are created (hourly quotas, active caps), so
	// waiting replaces refusing: a batch of 40 findings runs 10 at a time
	// per tenant instead of failing 30 of them.
	defaultMaxQueueWait = 30 * time.Minute
)

// WorkflowExecutorOption is a functional option for WorkflowExecutor.
type WorkflowExecutorOption func(*WorkflowExecutor)

// WithExecutorOutboxService sets the notification service.
func WithExecutorOutboxService(svc *outbox.Service) WorkflowExecutorOption {
	return func(e *WorkflowExecutor) {
		e.notificationService = svc
	}
}

// WithExecutorIntegrationService sets the integration service.
func WithExecutorIntegrationService(svc *integration.IntegrationService) WorkflowExecutorOption {
	return func(e *WorkflowExecutor) {
		e.integrationService = svc
	}
}

// WithExecutorAuditService sets the audit service.
func WithExecutorAuditService(svc *auditapp.AuditService) WorkflowExecutorOption {
	return func(e *WorkflowExecutor) {
		e.auditService = svc
	}
}

// WithExecutorStepAuthorizer sets the per-step principal check.
func WithExecutorStepAuthorizer(a StepAuthorizer) WorkflowExecutorOption {
	return func(e *WorkflowExecutor) {
		e.authorizer = a
	}
}

// WithExecutorNotificationHandler sets the handler live notification steps
// send through (the default is built from the outbox service).
func WithExecutorNotificationHandler(h NotificationHandler) WorkflowExecutorOption {
	return func(e *WorkflowExecutor) {
		e.notificationHandler = h
	}
}

// WithExecutorDeliveries sets where egress steps record what they sent or
// would have sent.
func WithExecutorDeliveries(r automationdom.DeliveryRepository) WorkflowExecutorOption {
	return func(e *WorkflowExecutor) {
		e.deliveries = r
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
	workflowRepo automationdom.WorkflowRepository,
	runRepo automationdom.RunRepository,
	nodeRunRepo automationdom.NodeRunRepository,
	log *logger.Logger,
	opts ...WorkflowExecutorOption,
) *WorkflowExecutor {
	e := &WorkflowExecutor{
		workflowRepo:       workflowRepo,
		runRepo:            runRepo,
		nodeRunRepo:        nodeRunRepo,
		actionHandlers:     make(map[automationdom.ActionType]ActionHandler),
		conditionEvaluator: &DefaultConditionEvaluator{},
		logger:             log.With("component", "workflow_executor"),
		// SEC-WF04: Default security limits
		maxConcurrentRuns: defaultMaxConcurrentRuns,
		maxExecutionTime:  defaultMaxExecutionTime,
		maxNodeTime:       defaultMaxNodeTime,
		// SEC-WF10: Per-tenant rate limiting
		maxConcurrentPerTenant: defaultMaxConcurrentPerTenant,
		tenantSlots:            make(map[string]chan struct{}),
		maxQueueWait:           defaultMaxQueueWait,
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
func (e *WorkflowExecutor) RegisterActionHandler(actionType automationdom.ActionType, handler ActionHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.actionHandlers[actionType] = handler
}

// HasActionHandler reports whether a handler is registered for the action type.
func (e *WorkflowExecutor) HasActionHandler(actionType automationdom.ActionType) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.actionHandlers[actionType]
	return ok
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

	// Check if already running or completed (a resumed run is pending again)
	if run.Status != automationdom.RunStatusPending {
		return fmt.Errorf("run is not in pending state: %s", run.Status)
	}

	// Load workflow with graph
	wf, err := e.workflowRepo.GetWithGraph(execCtx, run.WorkflowID)
	if err != nil {
		return fmt.Errorf("failed to load workflow: %w", err)
	}

	// A live run executes the version it pinned when it was created, not
	// the draft as it is now (versions.go). A live run without a pinned
	// version would act on the unpublished draft, past the go-live gate: it
	// is refused once versions are configured.
	if run.Mode == automationdom.ModeLive && run.VersionID == nil && e.versions != nil {
		return fmt.Errorf("integrity error: live run %s has no pinned version", run.ID)
	}
	if run.VersionID != nil {
		if e.versions == nil {
			return fmt.Errorf("load run version: versions are not configured")
		}
		v, err := e.versions.GetByTenantAndID(execCtx, run.TenantID, *run.VersionID)
		if err != nil {
			return fmt.Errorf("failed to load run version: %w", err)
		}
		if v.AutomationID != wf.ID {
			return fmt.Errorf("integrity error: run version belongs to another automation")
		}
		wf = v.Definition.Materialize(wf)
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
		PrincipalID:       runPrincipal(run, wf),
		TriggerData:       run.TriggerData,
		Context:           make(map[string]any),
		CompletedNodeKeys: make(map[string]bool),
		NodeRunsByKey:     make(map[string]*automationdom.NodeRun),
		maxChanges:        automationdom.EffectiveMaxChanges(wf.MaxChangesPerRun),
	}
	if confirmed, _ := run.Context["change_cap_confirmed"].(bool); confirmed {
		workflowExecCtx.capConfirmed = true
	}

	// Index node runs by key. A resumed run keeps the steps it already
	// finished: they are not run again and their outputs feed what follows.
	for _, nr := range run.NodeRuns {
		workflowExecCtx.NodeRunsByKey[nr.NodeKey] = nr
		if nr.Status == automationdom.NodeRunStatusCompleted || nr.Status == automationdom.NodeRunStatusSkipped {
			workflowExecCtx.CompletedNodeKeys[nr.NodeKey] = true
			if nr.Output != nil {
				workflowExecCtx.Context[fmt.Sprintf("node.%s.output", nr.NodeKey)] = nr.Output
			}
		}
	}

	// Execute the workflow graph
	err = e.executeGraph(execCtx, workflowExecCtx)

	// Finalize the run
	e.finalizeRun(context.Background(), workflowExecCtx, err) // Use background ctx for finalization

	if errors.Is(err, errRunPaused) {
		return nil // waiting for a publisher, not a failure
	}
	return err
}

// errRunCanceled stops an execution whose run was canceled.
var errRunCanceled = errors.New("workflow run canceled")

// errRunPaused stops an execution at its change cap (guardrails).
var errRunPaused = errors.New("workflow run paused at its change cap")

// runCanceled reports whether run was canceled since the executor loaded it,
// reading it again by its own tenant. A read error does not stop the run.
func (e *WorkflowExecutor) runCanceled(ctx context.Context, run *automationdom.Run) bool {
	cur, err := e.runRepo.GetByTenantAndID(ctx, run.TenantID, run.ID)
	if err != nil {
		return false
	}
	return cur.Status == automationdom.RunStatusCanceled
}

// ExecutionContext holds the state during workflow execution.
type ExecutionContext struct {
	Run      *automationdom.Run
	Workflow *automationdom.Workflow
	// PrincipalID is the person the run acts as (authz.go): the member who
	// started a manual run, otherwise the automation's owner.
	PrincipalID       shared.ID
	TriggerData       map[string]any
	Context           map[string]any // Shared context across nodes
	CompletedNodeKeys map[string]bool
	NodeRunsByKey     map[string]*automationdom.NodeRun
	// traces holds the trace a step set while it ran (keyed by node key).
	traces map[string]automationdom.StepTrace
	// changes counts the side effects of a live run; maxChanges is its cap
	// and capConfirmed says a publisher let it go past the cap.
	changes      int
	maxChanges   int
	capConfirmed bool
	mu           sync.RWMutex
}

// setTrace records the trace of the step nodeKey.
func (ec *ExecutionContext) setTrace(nodeKey string, t automationdom.StepTrace) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	if ec.traces == nil {
		ec.traces = map[string]automationdom.StepTrace{}
	}
	ec.traces[nodeKey] = t
}

// takeTrace returns and forgets the trace of the step nodeKey.
func (ec *ExecutionContext) takeTrace(nodeKey string) (automationdom.StepTrace, bool) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	t, ok := ec.traces[nodeKey]
	delete(ec.traces, nodeKey)
	return t, ok
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

	// Execute trigger nodes first (a resumed run already did)
	for _, trigger := range triggerNodes {
		if execCtx.IsNodeCompleted(trigger.NodeKey) {
			continue
		}
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
					e.logger.Error("failed to skip node", "node_key", logger.SanitizeValue(node.NodeKey), "error", logger.SanitizeError(err))
				}
				continue
			}

			if err := e.executeNode(ctx, execCtx, node); err != nil {
				if errors.Is(err, errRunCanceled) || errors.Is(err, errRunPaused) {
					return err
				}
				e.logger.Error("node execution failed", "node_key", logger.SanitizeValue(node.NodeKey), "error", logger.SanitizeError(err))
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
		if nr != nil && nr.Status == automationdom.NodeRunStatusPending {
			_ = e.skipNode(ctx, execCtx, node, "unreachable due to workflow path")
		}
	}

	return nil
}

// findReadyNodes finds nodes that are ready to execute.
// A node is ready if all its upstream dependencies are completed.
func (e *WorkflowExecutor) findReadyNodes(execCtx *ExecutionContext) []*automationdom.Node {
	var ready []*automationdom.Node
	wf := execCtx.Workflow

	for _, node := range wf.Nodes {
		nr := execCtx.NodeRunsByKey[node.NodeKey]
		if nr == nil || nr.Status != automationdom.NodeRunStatusPending {
			continue
		}

		// Skip trigger nodes (already executed)
		if node.NodeType == automationdom.NodeTypeTrigger {
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
func (e *WorkflowExecutor) shouldSkipNode(execCtx *ExecutionContext, node *automationdom.Node) bool {
	wf := execCtx.Workflow

	// Check incoming edges from condition nodes
	for _, edge := range wf.Edges {
		if edge.TargetNodeKey != node.NodeKey {
			continue
		}

		sourceNode := wf.GetNodeByKey(edge.SourceNodeKey)
		if sourceNode == nil || sourceNode.NodeType != automationdom.NodeTypeCondition {
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
func (e *WorkflowExecutor) executeNode(ctx context.Context, execCtx *ExecutionContext, node *automationdom.Node) error {
	nodeRun := execCtx.NodeRunsByKey[node.NodeKey]
	if nodeRun == nil {
		return fmt.Errorf("node run not found for %s", node.NodeKey)
	}
	// A canceled run starts no further step (RFC-046 §8).
	if e.runCanceled(ctx, execCtx.Run) {
		return errRunCanceled
	}
	// A live run stops before the change past its cap, until a publisher
	// lets it continue; the step stays pending.
	sideEffect := node.NodeType == automationdom.NodeTypeAction || node.NodeType == automationdom.NodeTypeNotification
	if sideEffect && execCtx.Run.Mode == automationdom.ModeLive && !execCtx.capConfirmed && execCtx.changes >= execCtx.maxChanges {
		return errRunPaused
	}

	e.logger.Info("executing node", "node_key", node.NodeKey, "node_type", node.NodeType)

	// Mark as running. A step a cancel already ended is refused here and
	// never runs.
	nodeRun.Start()
	nodeRun.SetInput(e.buildNodeInput(execCtx, node))
	if err := e.nodeRunRepo.Update(ctx, nodeRun); err != nil {
		if errors.Is(err, automationdom.ErrNodeRunAlreadyFinished) {
			return errRunCanceled
		}
		return fmt.Errorf("failed to update node run status: %w", err)
	}

	// Execute based on node type
	var output map[string]any
	var execErr error

	// A step runs for at most maxNodeTime (declared and, until now, never
	// applied): a hung call fails its step instead of the whole run.
	stepCtx, cancelStep := context.WithTimeout(ctx, e.maxNodeTime)
	switch node.NodeType {
	case automationdom.NodeTypeTrigger:
		output, execErr = e.executeTriggerNode(stepCtx, execCtx, node)
	case automationdom.NodeTypeCondition:
		output, execErr = e.executeConditionNode(stepCtx, execCtx, node, nodeRun)
	case automationdom.NodeTypeAction:
		output, execErr = e.executeActionNode(stepCtx, execCtx, node)
	case automationdom.NodeTypeNotification:
		output, execErr = e.executeNotificationNode(stepCtx, execCtx, node)
	default:
		execErr = fmt.Errorf("unknown node type: %s", node.NodeType)
	}
	if execErr != nil && errors.Is(stepCtx.Err(), context.DeadlineExceeded) {
		execErr = fmt.Errorf("step timed out after %s: %w", e.maxNodeTime, execErr)
	}
	cancelStep()

	// Update node run result
	trace, traced := execCtx.takeTrace(node.NodeKey)
	if execErr != nil {
		code := "EXECUTION_ERROR"
		if IsRunNotAuthorized(execErr) {
			code = ErrCodeRunNotAuthorized
		}
		if !traced {
			trace = automationdom.StepTrace{In: 1}
			if code == ErrCodeRunNotAuthorized {
				trace.Skip(automationdom.SkipNotAuthorized, 1)
			}
		}
		nodeRun.SetTrace(trace)
		nodeRun.Fail(execErr.Error(), code)
		e.updateRunStats(execCtx, false)
	} else {
		if !traced {
			trace = automationdom.StepTrace{In: 1, Out: 1}
		}
		nodeRun.SetTrace(trace)
		if sideEffect && execCtx.Run.Mode == automationdom.ModeLive {
			execCtx.changes++
		}
		nodeRun.Complete(output)
		execCtx.MarkNodeCompleted(node.NodeKey)
		e.updateRunStats(execCtx, true)

		// Store output in context for downstream nodes
		if output != nil {
			execCtx.SetContextValue(fmt.Sprintf("node.%s.output", node.NodeKey), output)
		}
	}

	if err := e.nodeRunRepo.Update(ctx, nodeRun); err != nil {
		if errors.Is(err, automationdom.ErrNodeRunAlreadyFinished) {
			// The run was canceled while this step ran: the cancel ended it.
			e.logger.Info("step ended by a cancel while it ran; result not recorded", "node_key", node.NodeKey)
			return errRunCanceled
		}
		e.logger.Error("failed to save node run result", "error", err)
	}

	return execErr
}

// skipNode marks a node as skipped.
func (e *WorkflowExecutor) skipNode(ctx context.Context, execCtx *ExecutionContext, node *automationdom.Node, reason string) error {
	nodeRun := execCtx.NodeRunsByKey[node.NodeKey]
	if nodeRun == nil {
		return nil
	}

	var t automationdom.StepTrace
	t.Skip(automationdom.SkipBranchNotTaken, 1)
	nodeRun.SetTrace(t)
	nodeRun.Skip(reason)
	execCtx.MarkNodeCompleted(node.NodeKey)

	return e.nodeRunRepo.Update(ctx, nodeRun)
}

// buildNodeInput builds the input for a node based on context and trigger data.
func (e *WorkflowExecutor) buildNodeInput(execCtx *ExecutionContext, node *automationdom.Node) map[string]any {
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
func (e *WorkflowExecutor) executeTriggerNode(ctx context.Context, execCtx *ExecutionContext, node *automationdom.Node) (map[string]any, error) {
	// Trigger nodes simply pass through the trigger data
	output := map[string]any{
		"trigger_type": string(node.Config.TriggerType),
		"trigger_data": execCtx.TriggerData,
		"timestamp":    time.Now().Format(time.RFC3339),
	}
	return output, nil
}

// executeConditionNode executes a condition node.
func (e *WorkflowExecutor) executeConditionNode(ctx context.Context, execCtx *ExecutionContext, node *automationdom.Node, nodeRun *automationdom.NodeRun) (map[string]any, error) {
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
	t := automationdom.StepTrace{In: 1}
	if result {
		t.Out = 1
	} else {
		t.Skip(automationdom.SkipConditionFalse, 1)
	}
	execCtx.setTrace(node.NodeKey, t)

	return map[string]any{
		"result":     result,
		"expression": expr,
	}, nil
}

// executeActionNode executes an action node.
func (e *WorkflowExecutor) executeActionNode(ctx context.Context, execCtx *ExecutionContext, node *automationdom.Node) (map[string]any, error) {
	actionType := node.Config.ActionType

	// A stored workflow may still hold a removed action type
	// (automationdom.ValidateSupported). Such a node never runs.
	if !actionType.IsValid() {
		return nil, fmt.Errorf("action type %s is not supported; edit the automation to remove it", actionType)
	}

	stepCtx, err := e.authorizeStep(ctx, execCtx, node.Config, node.Config.ActionConfig)
	if err != nil {
		return nil, err
	}

	// Only a live run calls an action handler; any other run (simulate, or
	// a mode this build does not know) records what the step would do.
	if execCtx.Run.Mode != automationdom.ModeLive {
		return e.simulateStep(stepCtx, execCtx, node)
	}

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
		Principal:    execCtx.PrincipalID,
	}

	// Execute the action as the run principal. The events the step causes
	// (a status change, a scan) carry the run as their cause, so they cannot
	// start a loop (loop_guard.go).
	out, err := handler.Execute(WithAutomationCause(stepCtx, stepCause(execCtx.Run, node.NodeKey)), input)
	if actionType == automationdom.ActionTypeCreateTicket || actionType == automationdom.ActionTypeUpdateTicket {
		e.recordLiveTicket(ctx, execCtx, node, out, err)
	}
	return out, err
}

// authorizeStep checks that the run's principal may run a step with this
// config on the run's subject, and returns the context to run it with.
func (e *WorkflowExecutor) authorizeStep(ctx context.Context, execCtx *ExecutionContext, cfg automationdom.NodeConfig, actionConfig map[string]any) (context.Context, error) {
	if e.authorizer == nil {
		return ctx, errNotAuthorized(shared.ErrForbidden, "automation run authorization is not configured")
	}
	perm, _ := NodePermission(cfg)
	findings, assets := stepSubjects(actionConfig, execCtx.TriggerData)
	stepCtx, err := e.authorizer.AuthorizeStep(ctx, StepAuthorization{
		TenantID:    execCtx.Run.TenantID,
		PrincipalID: execCtx.PrincipalID,
		Permission:  perm,
		FindingIDs:  findings,
		AssetIDs:    assets,
	})
	if err != nil {
		e.logger.Warn("automation step refused: the run's principal may not run it",
			"run_id", execCtx.Run.ID, "workflow_id", execCtx.Workflow.ID,
			"principal_id", execCtx.PrincipalID, "required_permission", string(perm), "error", err)
		return ctx, err
	}
	return stepCtx, nil
}

// executeNotificationNode executes a notification node.
func (e *WorkflowExecutor) executeNotificationNode(ctx context.Context, execCtx *ExecutionContext, node *automationdom.Node) (map[string]any, error) {
	stepCtx, err := e.authorizeStep(ctx, execCtx, node.Config, nil)
	if err != nil {
		return nil, err
	}

	// Only a live run sends; any other run records what the step would send.
	if execCtx.Run.Mode != automationdom.ModeLive {
		return e.simulateStep(stepCtx, execCtx, node)
	}
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

	out, sendErr := e.notificationHandler.Send(WithAutomationCause(stepCtx, stepCause(execCtx.Run, node.NodeKey)), input)
	d := notificationDelivery(input)
	d.Status, d.Attempts = automationdom.DeliverySent, 1
	if sendErr != nil {
		d.Status, d.Error = automationdom.DeliveryFailed, sendErr.Error()
	}
	e.recordDelivery(ctx, execCtx, node, d)
	return out, sendErr
}

// simulateStep evaluates a step of a simulate run: it records what the
// step would do (its trace and any delivery, mode simulate), and never calls
// a handler.
func (e *WorkflowExecutor) simulateStep(ctx context.Context, execCtx *ExecutionContext, node *automationdom.Node) (map[string]any, error) {
	if e.evaluator == nil {
		return simulatedOutput(node), nil
	}
	eff, err := e.evaluator.Evaluate(ctx, &EvalInput{
		TenantID: execCtx.Run.TenantID, WorkflowID: execCtx.Workflow.ID, RunID: execCtx.Run.ID,
		NodeKey: node.NodeKey, Config: node.Config, TriggerData: execCtx.TriggerData,
	})
	if err != nil {
		return nil, err
	}
	execCtx.setTrace(node.NodeKey, eff.Trace)
	if eff.Delivery != nil {
		eff.Delivery.Status = automationdom.DeliverySimulated
		e.recordDelivery(ctx, execCtx, node, eff.Delivery)
	}
	return eff.Output, nil
}

// recordLiveTicket records the delivery of a live ticket step.
func (e *WorkflowExecutor) recordLiveTicket(ctx context.Context, execCtx *ExecutionContext, node *automationdom.Node, out map[string]any, err error) {
	provider, _ := out["provider"].(string)
	if provider == "" {
		provider, _ = node.Config.ActionConfig["provider"].(string)
	}
	if provider == "" {
		provider = "jira"
	}
	findingID, _ := out["finding_id"].(string)
	d := &automationdom.Delivery{Channel: strings.ToLower(provider), Attempts: 1, Status: automationdom.DeliverySent,
		Payload: map[string]any{"provider": provider, "finding_id": findingID}}
	if project, ok := node.Config.ActionConfig["project_key"].(string); ok {
		d.Target = project
	}
	switch {
	case err != nil:
		d.Status, d.Error = automationdom.DeliveryFailed, err.Error()
	case out["held"] == true:
		d.Status = automationdom.DeliveryHeld
		d.Payload["held_reason"], _ = out["held_reason"].(string)
	default:
		d.ExternalRef, _ = out["ticket_key"].(string)
	}
	e.recordDelivery(ctx, execCtx, node, d)
}

// recordDelivery stores d for the step (best effort: a lost record never
// changes the step's outcome).
func (e *WorkflowExecutor) recordDelivery(ctx context.Context, execCtx *ExecutionContext, node *automationdom.Node, d *automationdom.Delivery) {
	if e.deliveries == nil || d == nil {
		return
	}
	d.TenantID, d.RunID, d.NodeKey, d.Mode = execCtx.Run.TenantID, execCtx.Run.ID, node.NodeKey, execCtx.Run.Mode
	d.IdempotencyKey = execCtx.Run.ID.String() + ":" + node.NodeKey
	if err := e.deliveries.Record(context.WithoutCancel(ctx), d); err != nil {
		e.logger.Warn("failed to record an automation delivery", "run_id", execCtx.Run.ID, "node_key", node.NodeKey, "error", err)
	}
}

// simulatedOutput is the output of an action or notification step of a
// simulate run when no evaluator is configured: what it would have done,
// nothing done.
func simulatedOutput(node *automationdom.Node) map[string]any {
	out := map[string]any{"simulated": true}
	if node.Config.ActionType != "" {
		out["would"] = string(node.Config.ActionType)
	}
	if node.Config.NotificationType != "" {
		out["would"] = "notify:" + string(node.Config.NotificationType)
	}
	return out
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

	// Canceled while it ran: the cancel already recorded the outcome and
	// closed the steps; the executor writes nothing over it.
	if errors.Is(execErr, errRunCanceled) {
		e.logger.Info("workflow run canceled; stopped before its next step", "run_id", run.ID)
		return
	}

	// At the change cap: the run waits for a publisher (POST
	// /workflow-runs/{id}/approve); nothing is counted as finished.
	if errors.Is(execErr, errRunPaused) {
		run.Pause(automationdom.PauseReasonBlastRadius)
		if err := e.runRepo.Update(ctx, run); err != nil {
			e.logger.Error("failed to pause run", "run_id", run.ID, "error", err)
			return
		}
		e.logger.Warn("automation run paused at its change cap", "run_id", run.ID, "changes", execCtx.changes, "cap", execCtx.maxChanges)
		if e.auditService != nil {
			auditapp.RecordOrWarn(ctx, e.logger, e.auditService, auditapp.AuditContext{TenantID: run.TenantID.String()},
				auditapp.NewSuccessEvent(audit.ActionWorkflowRunPaused, audit.ResourceTypeWorkflowRun, run.ID.String()).
					WithResourceName(execCtx.Workflow.Name).
					WithMessage(fmt.Sprintf("Automation run paused after %d changes (its cap); a publisher may let it continue", execCtx.changes)).
					WithMetadata("workflow_id", execCtx.Workflow.ID.String()).
					WithMetadata("cap", execCtx.maxChanges))
		}
		return
	}

	// Determine final status
	switch {
	case execErr != nil:
		run.Fail(execErr.Error())
	case run.FailedNodes > 0:
		run.Fail(fmt.Sprintf("%d node(s) failed", run.FailedNodes))
	default:
		run.Complete()
	}

	// Update run. A run canceled meanwhile is refused (a finished run never
	// changes), and then nothing else is recorded for it.
	if err := e.runRepo.Update(ctx, run); err != nil {
		if errors.Is(err, automationdom.ErrRunAlreadyFinished) {
			e.logger.Info("workflow run finished elsewhere (canceled); not recording an outcome", "run_id", run.ID)
			return
		}
		e.logger.Error("failed to finalize run", "error", err)
	}

	// Update workflow statistics on the workflow as it is now: the copy
	// loaded when the run started would write back a switch-off (or an edit)
	// made while the run was executing.
	wf := execCtx.Workflow
	if fresh, err := e.workflowRepo.GetByTenantAndID(ctx, run.TenantID, wf.ID); err == nil {
		wf = fresh
	}
	status := string(run.Status)
	metrics.AutomationRunsTotal.WithLabelValues(status).Inc()
	wf.RecordRun(run.ID, status)
	paused := run.Status == automationdom.RunStatusFailed && e.keepsFailing(ctx, wf)
	if paused {
		wf.Deactivate()
	}
	if err := e.workflowRepo.Update(ctx, wf); err != nil {
		e.logger.Error("failed to update workflow stats", "error", err)
		paused = false
	}
	if paused {
		metrics.AutomationsAutoPausedTotal.Inc()
		e.logger.Warn("automation paused: its latest runs all failed",
			"workflow_id", wf.ID, "workflow_name", wf.Name, "failed_runs", maxConsecutiveFailures)
		if e.auditService != nil {
			auditapp.RecordOrWarn(ctx, e.logger, e.auditService, auditapp.AuditContext{TenantID: run.TenantID.String()},
				auditapp.NewSuccessEvent(audit.ActionWorkflowDeactivated, audit.ResourceTypeWorkflow, wf.ID.String()).
					WithResourceName(wf.Name).
					WithMessage(fmt.Sprintf("Automation '%s' paused by the platform: its last %d runs failed", wf.Name, maxConsecutiveFailures)).
					WithMetadata("reason", "consecutive_failures"))
		}
	}

	// Audit log
	if e.auditService != nil {
		action := audit.ActionWorkflowRunCompleted
		if run.Status == automationdom.RunStatusFailed {
			action = audit.ActionWorkflowRunFailed
		}
		actx := auditapp.AuditContext{
			TenantID: run.TenantID.String(),
		}
		if run.TriggeredBy != nil {
			actx.ActorID = run.TriggeredBy.String()
		}
		event := auditapp.NewSuccessEvent(action, audit.ResourceTypeWorkflowRun, run.ID.String()).
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
// SEC-WF07/SEC-WF10: at most maxConcurrentRuns runs execute at once, and
// at most maxConcurrentPerTenant per tenant; a run waits (up to
// maxQueueWait) for a free slot instead of being
// failed. A run still waiting when it times out fails with that reason.
// SEC-WF12: Includes panic recovery to prevent resource leaks.
func (e *WorkflowExecutor) ExecuteAsyncWithTenant(runID shared.ID, tenantID shared.ID) {
	tenantKey := tenantID.String()

	go func() {
		// SEC-WF12: Track acquired resources for cleanup
		var tenantSlot chan struct{}
		var globalSlotAcquired bool

		// SEC-WF12: Panic recovery - ensure resources are always released
		defer func() {
			if r := recover(); r != nil {
				metrics.RecordPanic("workflow_run")
				e.logger.Error("panic recovered in workflow execution",
					"run_id", runID,
					"tenant_id", tenantKey,
					"panic", r,
				)
				e.failRun(runID, "execution failed: internal error")
			}
			if globalSlotAcquired {
				<-e.runSemaphore
			}
			if tenantSlot != nil {
				<-tenantSlot
			}
		}()

		deadline := time.NewTimer(e.maxQueueWait)
		defer deadline.Stop()

		// SEC-WF10: per-tenant slot first, so one tenant's backlog never
		// holds global slots while it waits.
		if !tenantID.IsZero() {
			slot := e.tenantSlot(tenantKey)
			select {
			case slot <- struct{}{}:
				tenantSlot = slot
			case <-deadline.C:
				e.logger.Warn("workflow run not started: no free tenant slot in time",
					"run_id", runID, "tenant_id", tenantKey, "max_per_tenant", e.maxConcurrentPerTenant)
				e.failRun(runID, fmt.Sprintf("not started: waited %s for a free slot (at most %d runs at once per organization)",
					e.maxQueueWait, e.maxConcurrentPerTenant))
				return
			}
		}

		// SEC-WF07: global slot.
		select {
		case e.runSemaphore <- struct{}{}:
			globalSlotAcquired = true
		case <-deadline.C:
			e.logger.Warn("workflow run not started: no free slot in time",
				"run_id", runID, "max_concurrent", e.maxConcurrentRuns)
			e.failRun(runID, fmt.Sprintf("not started: waited %s for a free slot", e.maxQueueWait))
			return
		}

		ctx := context.Background()
		if err := e.ExecuteWithTenant(ctx, runID, tenantID); err != nil {
			e.logger.Error("async workflow execution failed", "run_id", runID, "error", logger.SanitizeError(err))
		}
	}()
}

// tenantSlot returns the run-slot channel of a tenant (created on first use).
func (e *WorkflowExecutor) tenantSlot(tenantKey string) chan struct{} {
	e.tenantMu.Lock()
	defer e.tenantMu.Unlock()
	slot, ok := e.tenantSlots[tenantKey]
	if !ok {
		slot = make(chan struct{}, e.maxConcurrentPerTenant)
		e.tenantSlots[tenantKey] = slot
	}
	return slot
}

// failRun marks a run that never started as failed (best effort).
func (e *WorkflowExecutor) failRun(runID shared.ID, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if run, err := e.runRepo.GetByID(ctx, runID); err == nil && !run.Status.IsTerminal() {
		run.Fail(reason)
		_ = e.runRepo.Update(ctx, run)
	}
}

// maxConsecutiveFailures failed runs in a row pause an automation
// (is_active = false, audited): an automation that cannot succeed (its
// integration is gone, its owner lost access) stops acting until someone
// fixes and switches it on again.
const maxConsecutiveFailures = 20

// keepsFailing reports whether the workflow's latest maxConsecutiveFailures
// finished runs all failed. A read error never pauses.
func (e *WorkflowExecutor) keepsFailing(ctx context.Context, wf *automationdom.Workflow) bool {
	reader, ok := e.runRepo.(automationdom.RunOutcomeReader)
	if !ok {
		return false
	}
	outcomes, err := reader.LatestOutcomes(ctx, wf.TenantID, wf.ID, maxConsecutiveFailures)
	if err != nil {
		e.logger.Warn("failed to read the latest run outcomes", "workflow_id", wf.ID, "error", err)
		return false
	}
	if len(outcomes) < maxConsecutiveFailures {
		return false
	}
	for _, o := range outcomes {
		if o != automationdom.RunStatusFailed {
			return false
		}
	}
	return true
}
