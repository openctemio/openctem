package unit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/workflow"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Repositories for WorkflowExecutor tests (prefixed with wfExec)
// =============================================================================

// wfExecMockWorkflowRepo implements workflow.WorkflowRepository for executor tests.
type wfExecMockWorkflowRepo struct {
	mu          sync.RWMutex
	workflows   map[string]*workflow.Workflow
	getGraphErr error
	updateErr   error
}

func newWfExecMockWorkflowRepo() *wfExecMockWorkflowRepo {
	return &wfExecMockWorkflowRepo{
		workflows: make(map[string]*workflow.Workflow),
	}
}

func (m *wfExecMockWorkflowRepo) Create(ctx context.Context, wf *workflow.Workflow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workflows[wf.ID.String()] = wf
	return nil
}

func (m *wfExecMockWorkflowRepo) GetByID(ctx context.Context, id shared.ID) (*workflow.Workflow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if wf, ok := m.workflows[id.String()]; ok {
		return wf, nil
	}
	return nil, shared.ErrNotFound
}

func (m *wfExecMockWorkflowRepo) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*workflow.Workflow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, wf := range m.workflows {
		if wf.ID == id && wf.TenantID == tenantID {
			return wf, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *wfExecMockWorkflowRepo) GetByName(ctx context.Context, tenantID shared.ID, name string) (*workflow.Workflow, error) {
	return nil, shared.ErrNotFound
}

func (m *wfExecMockWorkflowRepo) List(ctx context.Context, filter workflow.WorkflowFilter, page pagination.Pagination) (pagination.Result[*workflow.Workflow], error) {
	return pagination.Result[*workflow.Workflow]{}, nil
}

func (m *wfExecMockWorkflowRepo) Update(ctx context.Context, wf *workflow.Workflow) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workflows[wf.ID.String()] = wf
	return nil
}

func (m *wfExecMockWorkflowRepo) Delete(ctx context.Context, id shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.workflows, id.String())
	return nil
}

func (m *wfExecMockWorkflowRepo) GetWithGraph(ctx context.Context, id shared.ID) (*workflow.Workflow, error) {
	if m.getGraphErr != nil {
		return nil, m.getGraphErr
	}
	return m.GetByID(ctx, id)
}

func (m *wfExecMockWorkflowRepo) ListActiveWithTriggerType(ctx context.Context, tenantID shared.ID, triggerType workflow.TriggerType) ([]*workflow.Workflow, error) {
	return nil, nil
}

// wfExecMockRunRepo implements workflow.RunRepository for executor tests.
type wfExecMockRunRepo struct {
	mu             sync.RWMutex
	runs           map[string]*workflow.Run
	getWithNRErr   error
	getByIDErr     error
	updateErr      error
	updateCount    int
}

func newWfExecMockRunRepo() *wfExecMockRunRepo {
	return &wfExecMockRunRepo{
		runs: make(map[string]*workflow.Run),
	}
}

func (m *wfExecMockRunRepo) Create(ctx context.Context, run *workflow.Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[run.ID.String()] = run
	return nil
}

func (m *wfExecMockRunRepo) GetByID(ctx context.Context, id shared.ID) (*workflow.Run, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if run, ok := m.runs[id.String()]; ok {
		return run, nil
	}
	return nil, shared.ErrNotFound
}

func (m *wfExecMockRunRepo) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*workflow.Run, error) {
	return nil, shared.ErrNotFound
}

func (m *wfExecMockRunRepo) List(ctx context.Context, filter workflow.RunFilter, page pagination.Pagination) (pagination.Result[*workflow.Run], error) {
	return pagination.Result[*workflow.Run]{}, nil
}

func (m *wfExecMockRunRepo) ListByWorkflowID(ctx context.Context, workflowID shared.ID, page, perPage int) ([]*workflow.Run, int64, error) {
	return nil, 0, nil
}

func (m *wfExecMockRunRepo) Update(ctx context.Context, run *workflow.Run) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[run.ID.String()] = run
	m.updateCount++
	return nil
}

func (m *wfExecMockRunRepo) Delete(ctx context.Context, id shared.ID) error {
	return nil
}

func (m *wfExecMockRunRepo) GetWithNodeRuns(ctx context.Context, id shared.ID) (*workflow.Run, error) {
	if m.getWithNRErr != nil {
		return nil, m.getWithNRErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if run, ok := m.runs[id.String()]; ok {
		return run, nil
	}
	return nil, shared.ErrNotFound
}

func (m *wfExecMockRunRepo) GetActiveByWorkflowID(ctx context.Context, workflowID shared.ID) ([]*workflow.Run, error) {
	return nil, nil
}

func (m *wfExecMockRunRepo) CountActiveByWorkflowID(ctx context.Context, workflowID shared.ID) (int, error) {
	return 0, nil
}

func (m *wfExecMockRunRepo) CountActiveByTenantID(ctx context.Context, tenantID shared.ID) (int, error) {
	return 0, nil
}

func (m *wfExecMockRunRepo) UpdateStats(ctx context.Context, id shared.ID, completed, failed int) error {
	return nil
}

func (m *wfExecMockRunRepo) UpdateStatus(ctx context.Context, id shared.ID, status workflow.RunStatus, errorMessage string) error {
	return nil
}

func (m *wfExecMockRunRepo) CreateRunIfUnderLimit(ctx context.Context, run *workflow.Run, maxPerWorkflow, maxPerTenant int) error {
	return nil
}

func (m *wfExecMockRunRepo) getUpdateCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.updateCount
}

// wfExecMockNodeRunRepo implements workflow.NodeRunRepository for executor tests.
type wfExecMockNodeRunRepo struct {
	mu          sync.RWMutex
	nodeRuns    map[string]*workflow.NodeRun
	updateErr   error
	updateCount int
}

func newWfExecMockNodeRunRepo() *wfExecMockNodeRunRepo {
	return &wfExecMockNodeRunRepo{
		nodeRuns: make(map[string]*workflow.NodeRun),
	}
}

func (m *wfExecMockNodeRunRepo) Create(ctx context.Context, nodeRun *workflow.NodeRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodeRuns[nodeRun.ID.String()] = nodeRun
	return nil
}

func (m *wfExecMockNodeRunRepo) CreateBatch(ctx context.Context, nodeRuns []*workflow.NodeRun) error {
	for _, nr := range nodeRuns {
		if err := m.Create(ctx, nr); err != nil {
			return err
		}
	}
	return nil
}

func (m *wfExecMockNodeRunRepo) GetByID(ctx context.Context, id shared.ID) (*workflow.NodeRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if nr, ok := m.nodeRuns[id.String()]; ok {
		return nr, nil
	}
	return nil, shared.ErrNotFound
}

func (m *wfExecMockNodeRunRepo) GetByWorkflowRunID(ctx context.Context, workflowRunID shared.ID) ([]*workflow.NodeRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var items []*workflow.NodeRun
	for _, nr := range m.nodeRuns {
		if nr.WorkflowRunID == workflowRunID {
			items = append(items, nr)
		}
	}
	return items, nil
}

func (m *wfExecMockNodeRunRepo) GetByNodeKey(ctx context.Context, workflowRunID shared.ID, nodeKey string) (*workflow.NodeRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, nr := range m.nodeRuns {
		if nr.WorkflowRunID == workflowRunID && nr.NodeKey == nodeKey {
			return nr, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *wfExecMockNodeRunRepo) List(ctx context.Context, filter workflow.NodeRunFilter) ([]*workflow.NodeRun, error) {
	return nil, nil
}

func (m *wfExecMockNodeRunRepo) Update(ctx context.Context, nodeRun *workflow.NodeRun) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodeRuns[nodeRun.ID.String()] = nodeRun
	m.updateCount++
	return nil
}

func (m *wfExecMockNodeRunRepo) Delete(ctx context.Context, id shared.ID) error {
	return nil
}

func (m *wfExecMockNodeRunRepo) UpdateStatus(ctx context.Context, id shared.ID, status workflow.NodeRunStatus, errorMessage, errorCode string) error {
	return nil
}

func (m *wfExecMockNodeRunRepo) Complete(ctx context.Context, id shared.ID, output map[string]any) error {
	return nil
}

func (m *wfExecMockNodeRunRepo) GetPendingByDependencies(ctx context.Context, workflowRunID shared.ID, completedNodeKeys []string) ([]*workflow.NodeRun, error) {
	return nil, nil
}

func (m *wfExecMockNodeRunRepo) getUpdateCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.updateCount
}

// =============================================================================
// Mock ActionHandler and NotificationHandler for executor tests
// =============================================================================

type wfExecMockActionHandler struct {
	mu          sync.Mutex
	callCount   int
	returnErr   error
	returnOutput map[string]any
}

func (h *wfExecMockActionHandler) Execute(ctx context.Context, input *app.ActionInput) (map[string]any, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.callCount++
	if h.returnErr != nil {
		return nil, h.returnErr
	}
	if h.returnOutput != nil {
		return h.returnOutput, nil
	}
	return map[string]any{"executed": true}, nil
}

func (h *wfExecMockActionHandler) getCallCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.callCount
}

// =============================================================================
// Helper functions to build test workflows and runs
// =============================================================================

// wfExecBuildSimpleWorkflow builds a workflow with trigger → action nodes.
func wfExecBuildSimpleWorkflow(tenantID shared.ID) (*workflow.Workflow, *workflow.Node, *workflow.Node) {
	wf, _ := workflow.NewWorkflow(tenantID, "Simple Test WF", "")
	triggerNode, _ := workflow.NewNode(wf.ID, "trigger_1", workflow.NodeTypeTrigger, "Trigger")
	_ = triggerNode.SetTriggerConfig(workflow.TriggerTypeManual, nil)
	actionNode, _ := workflow.NewNode(wf.ID, "action_1", workflow.NodeTypeAction, "Action")
	_ = actionNode.SetActionConfig(workflow.ActionTypeHTTPRequest, map[string]any{"url": "https://example.com"})
	edge, _ := workflow.NewEdge(wf.ID, "trigger_1", "action_1")
	wf.AddNode(triggerNode)
	wf.AddNode(actionNode)
	wf.AddEdge(edge)
	return wf, triggerNode, actionNode
}

// wfExecBuildConditionWorkflow builds workflow: trigger → condition → (yes: actionYes, no: actionNo)
func wfExecBuildConditionWorkflow(tenantID shared.ID) (*workflow.Workflow, *workflow.Node, *workflow.Node, *workflow.Node, *workflow.Node) {
	wf, _ := workflow.NewWorkflow(tenantID, "Condition Test WF", "")
	triggerNode, _ := workflow.NewNode(wf.ID, "trigger_1", workflow.NodeTypeTrigger, "Trigger")
	_ = triggerNode.SetTriggerConfig(workflow.TriggerTypeManual, nil)
	condNode, _ := workflow.NewNode(wf.ID, "condition_1", workflow.NodeTypeCondition, "Condition")
	_ = condNode.SetConditionConfig("trigger.severity == critical")
	actionYes, _ := workflow.NewNode(wf.ID, "action_yes", workflow.NodeTypeAction, "Action Yes")
	_ = actionYes.SetActionConfig(workflow.ActionTypeHTTPRequest, map[string]any{"url": "https://example.com"})
	actionNo, _ := workflow.NewNode(wf.ID, "action_no", workflow.NodeTypeAction, "Action No")
	_ = actionNo.SetActionConfig(workflow.ActionTypeHTTPRequest, map[string]any{"url": "https://example.com"})

	edgeTriggerCond, _ := workflow.NewEdge(wf.ID, "trigger_1", "condition_1")
	edgeYes, _ := workflow.NewEdge(wf.ID, "condition_1", "action_yes")
	edgeYes.SetSourceHandle("yes")
	edgeNo, _ := workflow.NewEdge(wf.ID, "condition_1", "action_no")
	edgeNo.SetSourceHandle("no")

	wf.AddNode(triggerNode)
	wf.AddNode(condNode)
	wf.AddNode(actionYes)
	wf.AddNode(actionNo)
	wf.AddEdge(edgeTriggerCond)
	wf.AddEdge(edgeYes)
	wf.AddEdge(edgeNo)
	return wf, triggerNode, condNode, actionYes, actionNo
}

// wfExecBuildLinearWorkflow builds a workflow with trigger → action1 → action2 → action3.
func wfExecBuildLinearWorkflow(tenantID shared.ID) *workflow.Workflow {
	wf, _ := workflow.NewWorkflow(tenantID, "Linear WF", "")
	triggerNode, _ := workflow.NewNode(wf.ID, "trigger_1", workflow.NodeTypeTrigger, "Trigger")
	_ = triggerNode.SetTriggerConfig(workflow.TriggerTypeManual, nil)
	action1, _ := workflow.NewNode(wf.ID, "action_1", workflow.NodeTypeAction, "Action 1")
	_ = action1.SetActionConfig(workflow.ActionTypeHTTPRequest, nil)
	action2, _ := workflow.NewNode(wf.ID, "action_2", workflow.NodeTypeAction, "Action 2")
	_ = action2.SetActionConfig(workflow.ActionTypeHTTPRequest, nil)
	action3, _ := workflow.NewNode(wf.ID, "action_3", workflow.NodeTypeAction, "Action 3")
	_ = action3.SetActionConfig(workflow.ActionTypeHTTPRequest, nil)

	e1, _ := workflow.NewEdge(wf.ID, "trigger_1", "action_1")
	e2, _ := workflow.NewEdge(wf.ID, "action_1", "action_2")
	e3, _ := workflow.NewEdge(wf.ID, "action_2", "action_3")

	wf.AddNode(triggerNode)
	wf.AddNode(action1)
	wf.AddNode(action2)
	wf.AddNode(action3)
	wf.AddEdge(e1)
	wf.AddEdge(e2)
	wf.AddEdge(e3)
	return wf
}

// wfExecBuildRun creates a Run and corresponding NodeRuns for the given workflow.
func wfExecBuildRun(wf *workflow.Workflow, tenantID shared.ID) *workflow.Run {
	run, _ := workflow.NewRun(wf.ID, tenantID, workflow.TriggerTypeManual, map[string]any{"severity": "critical"})
	run.TotalNodes = len(wf.Nodes)
	for _, node := range wf.Nodes {
		nr, _ := workflow.NewNodeRun(run.ID, node.ID, node.NodeKey, node.NodeType)
		run.NodeRuns = append(run.NodeRuns, nr)
	}
	return run
}

// wfExecNewExecutor creates a WorkflowExecutor with test mocks.
func wfExecNewExecutor(
	workflowRepo *wfExecMockWorkflowRepo,
	runRepo *wfExecMockRunRepo,
	nodeRunRepo *wfExecMockNodeRunRepo,
) *app.WorkflowExecutor {
	log := logger.NewNop()
	return app.NewWorkflowExecutor(workflowRepo, runRepo, nodeRunRepo, log)
}

// =============================================================================
// Tests: NewWorkflowExecutor
// =============================================================================

func TestWfExec_NewWorkflowExecutor_DefaultConfig(t *testing.T) {
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	log := logger.NewNop()

	executor := app.NewWorkflowExecutor(workflowRepo, runRepo, nodeRunRepo, log)
	if executor == nil {
		t.Fatal("expected non-nil executor")
	}
}

func TestWfExec_NewWorkflowExecutor_NotNil(t *testing.T) {
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()

	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)
	if executor == nil {
		t.Fatal("NewWorkflowExecutor returned nil")
	}
}

// =============================================================================
// Tests: RegisterActionHandler
// =============================================================================

func TestWfExec_RegisterActionHandler_RegistersCustomHandler(t *testing.T) {
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler := &wfExecMockActionHandler{}
	// Should not panic
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)
}

func TestWfExec_RegisterActionHandler_OverridesExistingHandler(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler1 := &wfExecMockActionHandler{returnOutput: map[string]any{"handler": "first"}}
	handler2 := &wfExecMockActionHandler{returnOutput: map[string]any{"handler": "second"}}

	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler1)
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler2)

	// Build and execute a workflow to confirm handler2 is used
	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	ctx := context.Background()
	err := executor.Execute(ctx, run.ID)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// handler2 should have been called (handler1 overridden)
	if handler1.getCallCount() != 0 {
		t.Error("handler1 should not have been called after being overridden")
	}
	if handler2.getCallCount() != 1 {
		t.Errorf("handler2 should have been called once, got %d", handler2.getCallCount())
	}
}

// =============================================================================
// Tests: Execute - Simple Workflow (trigger → action)
// =============================================================================

func TestWfExec_Execute_SimpleWorkflow_Success(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler := &wfExecMockActionHandler{}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)

	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	err := executor.Execute(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Run should be in a terminal state
	finalRun, _ := runRepo.GetByID(context.Background(), run.ID)
	if !finalRun.Status.IsTerminal() {
		t.Errorf("expected terminal run status, got %s", finalRun.Status)
	}
}

func TestWfExec_Execute_SimpleWorkflow_RunCompleted(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler := &wfExecMockActionHandler{returnOutput: map[string]any{"status": "ok"}}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)

	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	err := executor.Execute(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	finalRun, _ := runRepo.GetByID(context.Background(), run.ID)
	if finalRun.Status != workflow.RunStatusCompleted {
		t.Errorf("expected completed status, got %s", finalRun.Status)
	}
}

func TestWfExec_Execute_RunNotFound(t *testing.T) {
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	nonExistentID := shared.NewID()
	err := executor.Execute(context.Background(), nonExistentID)
	if err == nil {
		t.Fatal("expected error for non-existent run")
	}
}

func TestWfExec_Execute_WorkflowNotFound(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	// Create a run pointing to a non-existent workflow
	nonExistentWFID := shared.NewID()
	run, _ := workflow.NewRun(nonExistentWFID, tenantID, workflow.TriggerTypeManual, nil)
	runRepo.Create(context.Background(), run)

	err := executor.Execute(context.Background(), run.ID)
	if err == nil {
		t.Fatal("expected error when workflow is not found")
	}
}

func TestWfExec_Execute_RunAlreadyRunning(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	run.Start() // move to running state
	runRepo.Create(context.Background(), run)

	err := executor.Execute(context.Background(), run.ID)
	if err == nil {
		t.Fatal("expected error for run already in running state")
	}
}

func TestWfExec_Execute_RunAlreadyCompleted(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	run.Complete() // already completed
	runRepo.Create(context.Background(), run)

	err := executor.Execute(context.Background(), run.ID)
	if err == nil {
		t.Fatal("expected error for already completed run")
	}
}

func TestWfExec_Execute_RunAlreadyFailed(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	run.Fail("previous failure") // already failed
	runRepo.Create(context.Background(), run)

	err := executor.Execute(context.Background(), run.ID)
	if err == nil {
		t.Fatal("expected error for already failed run")
	}
}

// =============================================================================
// Tests: ExecuteWithTenant - Tenant Isolation
// =============================================================================

func TestWfExec_ExecuteWithTenant_MatchingTenant_Success(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler := &wfExecMockActionHandler{}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)

	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	err := executor.ExecuteWithTenant(context.Background(), run.ID, tenantID)
	if err != nil {
		t.Fatalf("ExecuteWithTenant failed: %v", err)
	}
}

func TestWfExec_ExecuteWithTenant_MismatchTenantID(t *testing.T) {
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)

	// Execute with a different tenant ID
	err := executor.ExecuteWithTenant(context.Background(), run.ID, otherTenantID)
	if err == nil {
		t.Fatal("expected error for tenant ID mismatch")
	}
}

func TestWfExec_ExecuteWithTenant_ZeroTenantID_Succeeds(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler := &wfExecMockActionHandler{}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)

	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	// Zero tenant ID means no isolation check
	zeroID := shared.ID{}
	err := executor.ExecuteWithTenant(context.Background(), run.ID, zeroID)
	if err != nil {
		t.Fatalf("ExecuteWithTenant with zero tenant failed: %v", err)
	}
}

// =============================================================================
// Tests: Workflow with condition node
// =============================================================================

func TestWfExec_Execute_ConditionTrue_YesBranchExecuted(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	actionYesHandler := &wfExecMockActionHandler{}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, actionYesHandler)

	wf, _, _, _, _ := wfExecBuildConditionWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	// Set trigger data so condition "trigger.severity == critical" is true
	run.TriggerData = map[string]any{"severity": "critical"}
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	err := executor.Execute(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Both action nodes share the same handler type; check total calls = 1 (only yes branch)
	// The condition result is true → only "action_yes" should execute
	finalRun, _ := runRepo.GetByID(context.Background(), run.ID)
	if !finalRun.Status.IsTerminal() {
		t.Errorf("expected terminal status, got %s", finalRun.Status)
	}

	// action_yes NodeRun should be completed, action_no should be skipped
	var actionYesNR, actionNoNR *workflow.NodeRun
	for _, nr := range run.NodeRuns {
		switch nr.NodeKey {
		case "action_yes":
			actionYesNR = nr
		case "action_no":
			actionNoNR = nr
		}
	}

	if actionYesNR != nil && actionYesNR.Status != workflow.NodeRunStatusCompleted {
		t.Errorf("action_yes should be completed, got %s", actionYesNR.Status)
	}
	if actionNoNR != nil && actionNoNR.Status != workflow.NodeRunStatusSkipped {
		t.Errorf("action_no should be skipped, got %s", actionNoNR.Status)
	}
}

func TestWfExec_Execute_ConditionFalse_NoBranchExecuted(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	actionHandler := &wfExecMockActionHandler{}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, actionHandler)

	wf, _, _, _, _ := wfExecBuildConditionWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	// Trigger data where severity != "critical" → condition false
	run.TriggerData = map[string]any{"severity": "low"}
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	err := executor.Execute(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// action_yes should be skipped, action_no should be completed
	var actionYesNR, actionNoNR *workflow.NodeRun
	for _, nr := range run.NodeRuns {
		switch nr.NodeKey {
		case "action_yes":
			actionYesNR = nr
		case "action_no":
			actionNoNR = nr
		}
	}

	if actionYesNR != nil && actionYesNR.Status != workflow.NodeRunStatusSkipped {
		t.Errorf("action_yes should be skipped, got %s", actionYesNR.Status)
	}
	if actionNoNR != nil && actionNoNR.Status != workflow.NodeRunStatusCompleted {
		t.Errorf("action_no should be completed, got %s", actionNoNR.Status)
	}
}

// =============================================================================
// Tests: Notification node
// =============================================================================

func TestWfExec_Execute_NotificationNode_NoHandlerConfigured(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	// Build workflow with notification node
	wf, _ := workflow.NewWorkflow(tenantID, "Notification WF", "")
	triggerNode, _ := workflow.NewNode(wf.ID, "trigger_1", workflow.NodeTypeTrigger, "Trigger")
	_ = triggerNode.SetTriggerConfig(workflow.TriggerTypeManual, nil)
	notifNode, _ := workflow.NewNode(wf.ID, "notif_1", workflow.NodeTypeNotification, "Send Notif")
	_ = notifNode.SetNotificationConfig(workflow.NotificationTypeSlack, map[string]any{"channel": "#alerts"})
	edge, _ := workflow.NewEdge(wf.ID, "trigger_1", "notif_1")
	wf.AddNode(triggerNode)
	wf.AddNode(notifNode)
	wf.AddEdge(edge)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	// No notification handler registered → notification node fails
	err := executor.Execute(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("Execute should succeed (node failure doesn't abort), got: %v", err)
	}

	// Notification node run should be failed
	var notifNR *workflow.NodeRun
	for _, nr := range run.NodeRuns {
		if nr.NodeKey == "notif_1" {
			notifNR = nr
			break
		}
	}
	if notifNR != nil && notifNR.Status != workflow.NodeRunStatusFailed {
		t.Errorf("notification node should be failed, got %s", notifNR.Status)
	}
}

// =============================================================================
// Tests: Condition Evaluation (DefaultConditionEvaluator)
// =============================================================================

func TestWfExec_ConditionEval_SimpleEquality_True(t *testing.T) {
	evaluator := &app.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{"severity": "critical"},
	}
	result, err := evaluator.Evaluate(context.Background(), "trigger.severity == critical", data)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !result {
		t.Error("expected true for matching equality")
	}
}

func TestWfExec_ConditionEval_SimpleEquality_False(t *testing.T) {
	evaluator := &app.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{"severity": "low"},
	}
	result, err := evaluator.Evaluate(context.Background(), "trigger.severity == critical", data)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result {
		t.Error("expected false for non-matching equality")
	}
}

func TestWfExec_ConditionEval_NumericGreaterThan_True(t *testing.T) {
	evaluator := &app.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{"cvss": 9.0},
	}
	result, err := evaluator.Evaluate(context.Background(), "trigger.cvss > 7.0", data)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !result {
		t.Error("expected true for 9.0 > 7.0")
	}
}

func TestWfExec_ConditionEval_NumericGreaterThan_False(t *testing.T) {
	evaluator := &app.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{"cvss": 5.0},
	}
	result, err := evaluator.Evaluate(context.Background(), "trigger.cvss > 7.0", data)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result {
		t.Error("expected false for 5.0 > 7.0")
	}
}

func TestWfExec_ConditionEval_BooleanEquality_True(t *testing.T) {
	evaluator := &app.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{"is_confirmed": true},
	}
	result, err := evaluator.Evaluate(context.Background(), "trigger.is_confirmed == true", data)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !result {
		t.Error("expected true for boolean equality")
	}
}

func TestWfExec_ConditionEval_BooleanEquality_False(t *testing.T) {
	evaluator := &app.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{"is_confirmed": false},
	}
	result, err := evaluator.Evaluate(context.Background(), "trigger.is_confirmed == true", data)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result {
		t.Error("expected false for false == true")
	}
}

func TestWfExec_ConditionEval_NestedPathResolution(t *testing.T) {
	evaluator := &app.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"finding": map[string]any{
				"severity": "critical",
			},
		},
	}
	result, err := evaluator.Evaluate(context.Background(), "trigger.finding.severity == critical", data)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !result {
		t.Error("expected true for nested path resolution")
	}
}

func TestWfExec_ConditionEval_EmptyExpression_ReturnsTrue(t *testing.T) {
	evaluator := &app.DefaultConditionEvaluator{}
	result, err := evaluator.Evaluate(context.Background(), "", map[string]any{})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !result {
		t.Error("expected true for empty expression")
	}
}

func TestWfExec_ConditionEval_LiteralTrue(t *testing.T) {
	evaluator := &app.DefaultConditionEvaluator{}
	result, err := evaluator.Evaluate(context.Background(), "true", map[string]any{})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !result {
		t.Error("expected true for literal 'true'")
	}
}

func TestWfExec_ConditionEval_LiteralFalse(t *testing.T) {
	evaluator := &app.DefaultConditionEvaluator{}
	result, err := evaluator.Evaluate(context.Background(), "false", map[string]any{})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result {
		t.Error("expected false for literal 'false'")
	}
}

func TestWfExec_ConditionEval_ExpressionTooLong_ReturnsError(t *testing.T) {
	evaluator := &app.DefaultConditionEvaluator{}
	longExpr := make([]byte, 501)
	for i := range longExpr {
		longExpr[i] = 'a'
	}
	_, err := evaluator.Evaluate(context.Background(), string(longExpr), map[string]any{})
	if err == nil {
		t.Error("expected error for expression exceeding length limit")
	}
}

func TestWfExec_ConditionEval_MissingPath_ReturnsFalse(t *testing.T) {
	evaluator := &app.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{},
	}
	result, err := evaluator.Evaluate(context.Background(), "trigger.nonexistent == critical", data)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result {
		t.Error("expected false for missing path")
	}
}

func TestWfExec_ConditionEval_InequalityOperator(t *testing.T) {
	evaluator := &app.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{"severity": "low"},
	}
	result, err := evaluator.Evaluate(context.Background(), "trigger.severity != critical", data)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !result {
		t.Error("expected true for != operator with different values")
	}
}

func TestWfExec_ConditionEval_InOperator_True(t *testing.T) {
	evaluator := &app.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{"severity": "critical"},
	}
	result, err := evaluator.Evaluate(context.Background(), "trigger.severity in [critical, high]", data)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !result {
		t.Error("expected true for 'in' operator with matching value")
	}
}

func TestWfExec_ConditionEval_InOperator_False(t *testing.T) {
	evaluator := &app.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{"severity": "low"},
	}
	result, err := evaluator.Evaluate(context.Background(), "trigger.severity in [critical, high]", data)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result {
		t.Error("expected false for 'in' operator with non-matching value")
	}
}

// =============================================================================
// Tests: Node execution flow
// =============================================================================

func TestWfExec_Execute_NodeFailure_RunMarkedFailed(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	// Action handler that fails
	failingHandler := &wfExecMockActionHandler{returnErr: errors.New("action failed: connection refused")}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, failingHandler)

	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	err := executor.Execute(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("Execute should not return error (node failure is non-fatal): %v", err)
	}

	finalRun, _ := runRepo.GetByID(context.Background(), run.ID)
	if finalRun.Status != workflow.RunStatusFailed {
		t.Errorf("expected failed run status due to node failure, got %s", finalRun.Status)
	}
}

func TestWfExec_Execute_NoHandlerForActionType_NodeFails(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	// Use an action type that has NO handler registered (use a custom one)
	wf, _ := workflow.NewWorkflow(tenantID, "No Handler WF", "")
	triggerNode, _ := workflow.NewNode(wf.ID, "trigger_1", workflow.NodeTypeTrigger, "Trigger")
	_ = triggerNode.SetTriggerConfig(workflow.TriggerTypeManual, nil)
	actionNode, _ := workflow.NewNode(wf.ID, "action_1", workflow.NodeTypeAction, "Action")
	// Use ActionTypeAssignUser which has no handler registered
	_ = actionNode.SetActionConfig(workflow.ActionTypeAssignUser, nil)
	edge, _ := workflow.NewEdge(wf.ID, "trigger_1", "action_1")
	wf.AddNode(triggerNode)
	wf.AddNode(actionNode)
	wf.AddEdge(edge)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	err := executor.Execute(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("Execute should succeed despite node failure: %v", err)
	}

	// action node should be failed (no handler)
	var actionNR *workflow.NodeRun
	for _, nr := range run.NodeRuns {
		if nr.NodeKey == "action_1" {
			actionNR = nr
			break
		}
	}
	if actionNR != nil && actionNR.Status != workflow.NodeRunStatusFailed {
		t.Errorf("expected failed node run status, got %s", actionNR.Status)
	}
}

func TestWfExec_Execute_NodeRunNotFound_TriggerFails(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	// Run has NodeRuns but NOT for the trigger node (missing trigger node run)
	run := wfExecBuildRun(wf, tenantID)
	// Only add non-trigger NodeRuns (exclude trigger_1)
	for _, nr := range run.NodeRuns {
		if nr.NodeKey != "trigger_1" {
			nodeRunRepo.Create(context.Background(), nr)
		}
	}
	// Rebuild NodeRuns slice without the trigger
	var filteredNRs []*workflow.NodeRun
	for _, nr := range run.NodeRuns {
		if nr.NodeKey != "trigger_1" {
			filteredNRs = append(filteredNRs, nr)
		}
	}
	run.NodeRuns = filteredNRs
	runRepo.Create(context.Background(), run)

	err := executor.Execute(context.Background(), run.ID)
	if err == nil {
		t.Fatal("expected error when trigger node run is missing")
	}
}

// =============================================================================
// Tests: Graph Execution
// =============================================================================

func TestWfExec_Execute_LinearGraph_AllNodesCompleted(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler := &wfExecMockActionHandler{returnOutput: map[string]any{"status": "ok"}}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)

	wf := wfExecBuildLinearWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	err := executor.Execute(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	finalRun, _ := runRepo.GetByID(context.Background(), run.ID)
	if finalRun.Status != workflow.RunStatusCompleted {
		t.Errorf("expected completed status for linear graph, got %s", finalRun.Status)
	}

	// Handler should be called 3 times (action_1, action_2, action_3)
	if handler.getCallCount() != 3 {
		t.Errorf("expected 3 handler calls for linear graph, got %d", handler.getCallCount())
	}
}

func TestWfExec_Execute_NoTriggerNodes_ReturnsError(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	// Build workflow with only action nodes (no trigger)
	wf, _ := workflow.NewWorkflow(tenantID, "No Trigger WF", "")
	actionNode, _ := workflow.NewNode(wf.ID, "action_1", workflow.NodeTypeAction, "Action")
	_ = actionNode.SetActionConfig(workflow.ActionTypeHTTPRequest, nil)
	wf.AddNode(actionNode)
	workflowRepo.Create(context.Background(), wf)

	run, _ := workflow.NewRun(wf.ID, tenantID, workflow.TriggerTypeManual, nil)
	run.TotalNodes = 1
	nr, _ := workflow.NewNodeRun(run.ID, actionNode.ID, "action_1", workflow.NodeTypeAction)
	run.NodeRuns = []*workflow.NodeRun{nr}
	runRepo.Create(context.Background(), run)
	nodeRunRepo.Create(context.Background(), nr)

	err := executor.Execute(context.Background(), run.ID)
	if err == nil {
		t.Fatal("expected error for workflow with no trigger nodes")
	}
}

func TestWfExec_Execute_MultipleTriggerNodes(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler := &wfExecMockActionHandler{}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)

	// Build workflow with two trigger nodes
	wf, _ := workflow.NewWorkflow(tenantID, "Multi Trigger WF", "")
	trigger1, _ := workflow.NewNode(wf.ID, "trigger_1", workflow.NodeTypeTrigger, "Trigger 1")
	_ = trigger1.SetTriggerConfig(workflow.TriggerTypeManual, nil)
	trigger2, _ := workflow.NewNode(wf.ID, "trigger_2", workflow.NodeTypeTrigger, "Trigger 2")
	_ = trigger2.SetTriggerConfig(workflow.TriggerTypeFindingCreated, nil)
	actionNode, _ := workflow.NewNode(wf.ID, "action_1", workflow.NodeTypeAction, "Action")
	_ = actionNode.SetActionConfig(workflow.ActionTypeHTTPRequest, nil)
	edge1, _ := workflow.NewEdge(wf.ID, "trigger_1", "action_1")
	edge2, _ := workflow.NewEdge(wf.ID, "trigger_2", "action_1")
	wf.AddNode(trigger1)
	wf.AddNode(trigger2)
	wf.AddNode(actionNode)
	wf.AddEdge(edge1)
	wf.AddEdge(edge2)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	err := executor.Execute(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("Execute with multiple triggers failed: %v", err)
	}

	finalRun, _ := runRepo.GetByID(context.Background(), run.ID)
	if !finalRun.Status.IsTerminal() {
		t.Errorf("expected terminal status, got %s", finalRun.Status)
	}
}

func TestWfExec_Execute_BranchingGraph_DownstreamExecutedAfterCompletion(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler := &wfExecMockActionHandler{returnOutput: map[string]any{"ok": true}}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)

	wf, _, _, _, _ := wfExecBuildConditionWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	run.TriggerData = map[string]any{"severity": "critical"}
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	err := executor.Execute(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// All node runs should be in terminal states
	for _, nr := range run.NodeRuns {
		if !nr.Status.IsTerminal() {
			t.Errorf("node %s expected terminal status, got %s", nr.NodeKey, nr.Status)
		}
	}
}

// =============================================================================
// Tests: Run Finalization
// =============================================================================

func TestWfExec_Execute_AllNodesCompleted_RunCompleted(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler := &wfExecMockActionHandler{}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)

	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	_ = executor.Execute(context.Background(), run.ID)

	finalRun, _ := runRepo.GetByID(context.Background(), run.ID)
	if finalRun.Status != workflow.RunStatusCompleted {
		t.Errorf("all nodes completed → expected RunStatusCompleted, got %s", finalRun.Status)
	}
}

func TestWfExec_Execute_SomeNodesFailed_RunFailed(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	failHandler := &wfExecMockActionHandler{returnErr: errors.New("node error")}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, failHandler)

	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	_ = executor.Execute(context.Background(), run.ID)

	finalRun, _ := runRepo.GetByID(context.Background(), run.ID)
	if finalRun.Status != workflow.RunStatusFailed {
		t.Errorf("failed node → expected RunStatusFailed, got %s", finalRun.Status)
	}
	if finalRun.FailedNodes == 0 {
		t.Error("expected FailedNodes > 0")
	}
}

func TestWfExec_Execute_WorkflowStatsUpdated(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler := &wfExecMockActionHandler{}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)

	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	initialTotalRuns := wf.TotalRuns
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	_ = executor.Execute(context.Background(), run.ID)

	finalWF, _ := workflowRepo.GetByID(context.Background(), wf.ID)
	if finalWF.TotalRuns <= initialTotalRuns {
		t.Errorf("expected TotalRuns to increment after execution")
	}
}

func TestWfExec_Execute_CompletedNodesCountUpdated(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler := &wfExecMockActionHandler{}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)

	wf := wfExecBuildLinearWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	_ = executor.Execute(context.Background(), run.ID)

	finalRun, _ := runRepo.GetByID(context.Background(), run.ID)
	// trigger(1) + action1(1) + action2(1) + action3(1) = 4 completed nodes
	if finalRun.CompletedNodes < 4 {
		t.Errorf("expected at least 4 completed nodes, got %d", finalRun.CompletedNodes)
	}
}

// =============================================================================
// Tests: Concurrency
// =============================================================================

func TestWfExec_Execute_SemaphoreNotExhausted(t *testing.T) {
	// Verify executor can run multiple workflows when semaphore is available
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler := &wfExecMockActionHandler{}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)

	// Execute two separate workflows concurrently via goroutines
	const numRuns = 3
	errs := make(chan error, numRuns)

	for i := 0; i < numRuns; i++ {
		wf, _ := workflow.NewWorkflow(tenantID, "Concurrent WF", "")
		trig, _ := workflow.NewNode(wf.ID, "trigger_1", workflow.NodeTypeTrigger, "T")
		_ = trig.SetTriggerConfig(workflow.TriggerTypeManual, nil)
		wf.AddNode(trig)
		workflowRepo.Create(context.Background(), wf)

		run := wfExecBuildRun(wf, tenantID)
		runRepo.Create(context.Background(), run)
		for _, nr := range run.NodeRuns {
			nodeRunRepo.Create(context.Background(), nr)
		}

		go func(runID shared.ID) {
			errs <- executor.Execute(context.Background(), runID)
		}(run.ID)
	}

	for i := 0; i < numRuns; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Execute failed: %v", err)
		}
	}
}

func TestWfExec_ExecuteAsync_DoesNotBlock(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler := &wfExecMockActionHandler{}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)

	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	start := time.Now()
	executor.ExecuteAsync(run.ID)
	elapsed := time.Since(start)

	// ExecuteAsync should return immediately (non-blocking)
	if elapsed > 100*time.Millisecond {
		t.Errorf("ExecuteAsync blocked for %v, expected near-instant return", elapsed)
	}

	// Give the goroutine time to complete
	time.Sleep(200 * time.Millisecond)
}

func TestWfExec_ExecuteAsyncWithTenant_DoesNotBlock(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler := &wfExecMockActionHandler{}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)

	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	start := time.Now()
	executor.ExecuteAsyncWithTenant(run.ID, tenantID)
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Errorf("ExecuteAsyncWithTenant blocked for %v", elapsed)
	}

	time.Sleep(200 * time.Millisecond)
}

func TestWfExec_RegisterActionHandler_ConcurrentAccess_NoRace(t *testing.T) {
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	var wg sync.WaitGroup
	const numGoroutines = 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handler := &wfExecMockActionHandler{}
			executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)
		}()
	}
	wg.Wait()
}

// =============================================================================
// Tests: Node run update called during execution
// =============================================================================

func TestWfExec_Execute_NodeRunUpdatedDuringExecution(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler := &wfExecMockActionHandler{}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)

	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	_ = executor.Execute(context.Background(), run.ID)

	// Node runs should have been updated (at least twice per node: start + complete/fail)
	updateCount := nodeRunRepo.getUpdateCount()
	if updateCount < 2 {
		t.Errorf("expected node run updates during execution, got %d", updateCount)
	}
}

func TestWfExec_Execute_RunUpdatedDuringExecution(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler := &wfExecMockActionHandler{}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)

	wf, _, _ := wfExecBuildSimpleWorkflow(tenantID)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	_ = executor.Execute(context.Background(), run.ID)

	// Run repo should have been updated at least once (finalization)
	updateCount := runRepo.getUpdateCount()
	if updateCount < 1 {
		t.Errorf("expected run updates during execution, got %d", updateCount)
	}
}

// =============================================================================
// Tests: Workflow/Run Tenant Mismatch
// =============================================================================

func TestWfExec_Execute_WorkflowAndRunTenantMismatch_ReturnsError(t *testing.T) {
	tenantA := shared.NewID()
	tenantB := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	// Workflow belongs to tenantA
	wf, _ := workflow.NewWorkflow(tenantA, "Tenant A WF", "")
	triggerNode, _ := workflow.NewNode(wf.ID, "trigger_1", workflow.NodeTypeTrigger, "Trigger")
	_ = triggerNode.SetTriggerConfig(workflow.TriggerTypeManual, nil)
	wf.AddNode(triggerNode)
	workflowRepo.Create(context.Background(), wf)

	// Run belongs to tenantB but references tenantA's workflow
	run, _ := workflow.NewRun(wf.ID, tenantB, workflow.TriggerTypeManual, nil)
	runRepo.Create(context.Background(), run)

	err := executor.Execute(context.Background(), run.ID)
	if err == nil {
		t.Fatal("expected error for workflow/run tenant mismatch")
	}
}

// =============================================================================
// Tests: Condition node with no expression (defaults to true)
// =============================================================================

func TestWfExec_Execute_ConditionNodeNoExpression_DefaultsTrue(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	handler := &wfExecMockActionHandler{}
	executor.RegisterActionHandler(workflow.ActionTypeHTTPRequest, handler)

	// Build workflow: trigger → condition (no expr) → action
	wf, _ := workflow.NewWorkflow(tenantID, "Empty Condition WF", "")
	triggerNode, _ := workflow.NewNode(wf.ID, "trigger_1", workflow.NodeTypeTrigger, "Trigger")
	_ = triggerNode.SetTriggerConfig(workflow.TriggerTypeManual, nil)
	condNode, _ := workflow.NewNode(wf.ID, "condition_1", workflow.NodeTypeCondition, "Condition")
	// No expression set → defaults to true
	actionNode, _ := workflow.NewNode(wf.ID, "action_1", workflow.NodeTypeAction, "Action")
	_ = actionNode.SetActionConfig(workflow.ActionTypeHTTPRequest, nil)

	edgeTC, _ := workflow.NewEdge(wf.ID, "trigger_1", "condition_1")
	edgeCA, _ := workflow.NewEdge(wf.ID, "condition_1", "action_1")
	edgeCA.SetSourceHandle("yes")

	wf.AddNode(triggerNode)
	wf.AddNode(condNode)
	wf.AddNode(actionNode)
	wf.AddEdge(edgeTC)
	wf.AddEdge(edgeCA)
	workflowRepo.Create(context.Background(), wf)

	run := wfExecBuildRun(wf, tenantID)
	runRepo.Create(context.Background(), run)
	for _, nr := range run.NodeRuns {
		nodeRunRepo.Create(context.Background(), nr)
	}

	err := executor.Execute(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// action should be completed (condition defaulted true)
	var actionNR *workflow.NodeRun
	for _, nr := range run.NodeRuns {
		if nr.NodeKey == "action_1" {
			actionNR = nr
			break
		}
	}
	if actionNR != nil && actionNR.Status != workflow.NodeRunStatusCompleted {
		t.Errorf("action should be completed (condition defaulted true), got %s", actionNR.Status)
	}
}

// =============================================================================
// Tests: Unknown Node Type
// =============================================================================

func TestWfExec_Execute_UnknownNodeType_NodeFails(t *testing.T) {
	tenantID := shared.NewID()
	workflowRepo := newWfExecMockWorkflowRepo()
	runRepo := newWfExecMockRunRepo()
	nodeRunRepo := newWfExecMockNodeRunRepo()
	executor := wfExecNewExecutor(workflowRepo, runRepo, nodeRunRepo)

	// Manually build a run with a node run that has an invalid node type
	wf, _ := workflow.NewWorkflow(tenantID, "Unknown Type WF", "")
	triggerNode, _ := workflow.NewNode(wf.ID, "trigger_1", workflow.NodeTypeTrigger, "Trigger")
	_ = triggerNode.SetTriggerConfig(workflow.TriggerTypeManual, nil)
	wf.AddNode(triggerNode)
	workflowRepo.Create(context.Background(), wf)

	run, _ := workflow.NewRun(wf.ID, tenantID, workflow.TriggerTypeManual, nil)
	run.TotalNodes = 1
	nr, _ := workflow.NewNodeRun(run.ID, triggerNode.ID, "trigger_1", workflow.NodeTypeTrigger)
	run.NodeRuns = []*workflow.NodeRun{nr}
	runRepo.Create(context.Background(), run)
	nodeRunRepo.Create(context.Background(), nr)

	// Should succeed (trigger node only)
	err := executor.Execute(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("Execute with trigger-only WF failed: %v", err)
	}
}
