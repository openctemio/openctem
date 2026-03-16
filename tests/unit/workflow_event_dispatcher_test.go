package unit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/findingsource"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/domain/workflow"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// wfDispatchMockWorkflowRepo
// =============================================================================

type wfDispatchMockWorkflowRepo struct {
	mu               sync.RWMutex
	workflows        map[string]*workflow.Workflow
	listActiveResult []*workflow.Workflow
	listActiveErr    error
	getWithGraphErr  error
	listActiveCalls  int
}

func newWfDispatchMockWorkflowRepo() *wfDispatchMockWorkflowRepo {
	return &wfDispatchMockWorkflowRepo{
		workflows: make(map[string]*workflow.Workflow),
	}
}

func (m *wfDispatchMockWorkflowRepo) Create(_ context.Context, wf *workflow.Workflow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workflows[wf.ID.String()] = wf
	return nil
}

func (m *wfDispatchMockWorkflowRepo) GetByID(_ context.Context, id shared.ID) (*workflow.Workflow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if wf, ok := m.workflows[id.String()]; ok {
		return wf, nil
	}
	return nil, shared.ErrNotFound
}

func (m *wfDispatchMockWorkflowRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*workflow.Workflow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, wf := range m.workflows {
		if wf.ID == id && wf.TenantID == tenantID {
			return wf, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *wfDispatchMockWorkflowRepo) GetByName(_ context.Context, tenantID shared.ID, name string) (*workflow.Workflow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, wf := range m.workflows {
		if wf.TenantID == tenantID && wf.Name == name {
			return wf, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *wfDispatchMockWorkflowRepo) List(_ context.Context, filter workflow.WorkflowFilter, page pagination.Pagination) (pagination.Result[*workflow.Workflow], error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var items []*workflow.Workflow
	for _, wf := range m.workflows {
		if filter.TenantID != nil && wf.TenantID != *filter.TenantID {
			continue
		}
		items = append(items, wf)
	}
	return pagination.Result[*workflow.Workflow]{
		Data:       items,
		Total:      int64(len(items)),
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: 1,
	}, nil
}

func (m *wfDispatchMockWorkflowRepo) Update(_ context.Context, wf *workflow.Workflow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workflows[wf.ID.String()] = wf
	return nil
}

func (m *wfDispatchMockWorkflowRepo) Delete(_ context.Context, id shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.workflows, id.String())
	return nil
}

func (m *wfDispatchMockWorkflowRepo) GetWithGraph(_ context.Context, id shared.ID) (*workflow.Workflow, error) {
	if m.getWithGraphErr != nil {
		return nil, m.getWithGraphErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if wf, ok := m.workflows[id.String()]; ok {
		return wf, nil
	}
	return nil, shared.ErrNotFound
}

func (m *wfDispatchMockWorkflowRepo) ListActiveWithTriggerType(_ context.Context, tenantID shared.ID, triggerType workflow.TriggerType) ([]*workflow.Workflow, error) {
	m.mu.Lock()
	m.listActiveCalls++
	m.mu.Unlock()

	if m.listActiveErr != nil {
		return nil, m.listActiveErr
	}

	if m.listActiveResult != nil {
		return m.listActiveResult, nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*workflow.Workflow
	for _, wf := range m.workflows {
		if wf.TenantID != tenantID || !wf.IsActive {
			continue
		}
		for _, node := range wf.Nodes {
			if node.NodeType == workflow.NodeTypeTrigger && node.Config.TriggerType == triggerType {
				result = append(result, wf)
				break
			}
		}
	}
	return result, nil
}

// =============================================================================
// wfDispatchMockNodeRepo
// =============================================================================

type wfDispatchMockNodeRepo struct {
	nodes     map[string]*workflow.Node
	createErr error
	mu        sync.RWMutex
}

func newWfDispatchMockNodeRepo() *wfDispatchMockNodeRepo {
	return &wfDispatchMockNodeRepo{
		nodes: make(map[string]*workflow.Node),
	}
}

func (m *wfDispatchMockNodeRepo) Create(_ context.Context, node *workflow.Node) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes[node.ID.String()] = node
	return nil
}

func (m *wfDispatchMockNodeRepo) CreateBatch(_ context.Context, nodes []*workflow.Node) error {
	for _, n := range nodes {
		if err := m.Create(context.Background(), n); err != nil {
			return err
		}
	}
	return nil
}

func (m *wfDispatchMockNodeRepo) GetByID(_ context.Context, id shared.ID) (*workflow.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if n, ok := m.nodes[id.String()]; ok {
		return n, nil
	}
	return nil, shared.ErrNotFound
}

func (m *wfDispatchMockNodeRepo) GetByWorkflowID(_ context.Context, workflowID shared.ID) ([]*workflow.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*workflow.Node
	for _, n := range m.nodes {
		if n.WorkflowID == workflowID {
			result = append(result, n)
		}
	}
	return result, nil
}

func (m *wfDispatchMockNodeRepo) GetByKey(_ context.Context, workflowID shared.ID, nodeKey string) (*workflow.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, n := range m.nodes {
		if n.WorkflowID == workflowID && n.NodeKey == nodeKey {
			return n, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *wfDispatchMockNodeRepo) Update(_ context.Context, node *workflow.Node) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes[node.ID.String()] = node
	return nil
}

func (m *wfDispatchMockNodeRepo) Delete(_ context.Context, id shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.nodes, id.String())
	return nil
}

func (m *wfDispatchMockNodeRepo) DeleteByWorkflowID(_ context.Context, workflowID shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, n := range m.nodes {
		if n.WorkflowID == workflowID {
			delete(m.nodes, id)
		}
	}
	return nil
}

// =============================================================================
// wfDispatchMockRunRepo
// =============================================================================

type wfDispatchMockRunRepo struct {
	mu           sync.Mutex
	createdRuns  []*workflow.Run
	createRunErr error
}

func newWfDispatchMockRunRepo() *wfDispatchMockRunRepo {
	return &wfDispatchMockRunRepo{}
}

func (m *wfDispatchMockRunRepo) Create(_ context.Context, run *workflow.Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createdRuns = append(m.createdRuns, run)
	return nil
}

func (m *wfDispatchMockRunRepo) GetByID(_ context.Context, _ shared.ID) (*workflow.Run, error) {
	return nil, shared.ErrNotFound
}

func (m *wfDispatchMockRunRepo) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*workflow.Run, error) {
	return nil, shared.ErrNotFound
}

func (m *wfDispatchMockRunRepo) List(_ context.Context, _ workflow.RunFilter, _ pagination.Pagination) (pagination.Result[*workflow.Run], error) {
	return pagination.Result[*workflow.Run]{}, nil
}

func (m *wfDispatchMockRunRepo) ListByWorkflowID(_ context.Context, _ shared.ID, _, _ int) ([]*workflow.Run, int64, error) {
	return nil, 0, nil
}

func (m *wfDispatchMockRunRepo) Update(_ context.Context, _ *workflow.Run) error {
	return nil
}

func (m *wfDispatchMockRunRepo) Delete(_ context.Context, _ shared.ID) error {
	return nil
}

func (m *wfDispatchMockRunRepo) GetWithNodeRuns(_ context.Context, _ shared.ID) (*workflow.Run, error) {
	return nil, shared.ErrNotFound
}

func (m *wfDispatchMockRunRepo) GetActiveByWorkflowID(_ context.Context, _ shared.ID) ([]*workflow.Run, error) {
	return nil, nil
}

func (m *wfDispatchMockRunRepo) CountActiveByWorkflowID(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}

func (m *wfDispatchMockRunRepo) CountActiveByTenantID(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}

func (m *wfDispatchMockRunRepo) UpdateStats(_ context.Context, _ shared.ID, _, _ int) error {
	return nil
}

func (m *wfDispatchMockRunRepo) UpdateStatus(_ context.Context, _ shared.ID, _ workflow.RunStatus, _ string) error {
	return nil
}

func (m *wfDispatchMockRunRepo) CreateRunIfUnderLimit(_ context.Context, run *workflow.Run, _, _ int) error {
	if m.createRunErr != nil {
		return m.createRunErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createdRuns = append(m.createdRuns, run)
	return nil
}

func (m *wfDispatchMockRunRepo) TriggeredCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.createdRuns)
}

// =============================================================================
// wfDispatchStubFindingSourceRepo
// =============================================================================

// wfDispatchStubFindingSourceRepo implements findingsource.Repository for use in
// ValidateSourceFilter tests. Only IsValidCode is meaningful; everything else is a stub.
type wfDispatchStubFindingSourceRepo struct {
	validCodes map[string]bool
}

func (r *wfDispatchStubFindingSourceRepo) GetByID(_ context.Context, _ shared.ID) (*findingsource.FindingSource, error) {
	return nil, shared.ErrNotFound
}

func (r *wfDispatchStubFindingSourceRepo) GetByCode(_ context.Context, _ string) (*findingsource.FindingSource, error) {
	return nil, shared.ErrNotFound
}

func (r *wfDispatchStubFindingSourceRepo) List(_ context.Context, _ findingsource.Filter, _ findingsource.ListOptions, _ pagination.Pagination) (pagination.Result[*findingsource.FindingSource], error) {
	return pagination.Result[*findingsource.FindingSource]{}, nil
}

func (r *wfDispatchStubFindingSourceRepo) ListWithCategory(_ context.Context, _ findingsource.Filter, _ findingsource.ListOptions, _ pagination.Pagination) (pagination.Result[*findingsource.FindingSourceWithCategory], error) {
	return pagination.Result[*findingsource.FindingSourceWithCategory]{}, nil
}

func (r *wfDispatchStubFindingSourceRepo) ListActive(_ context.Context) ([]*findingsource.FindingSource, error) {
	return nil, nil
}

func (r *wfDispatchStubFindingSourceRepo) ListActiveWithCategory(_ context.Context) ([]*findingsource.FindingSourceWithCategory, error) {
	result := make([]*findingsource.FindingSourceWithCategory, 0, len(r.validCodes))
	for code := range r.validCodes {
		fs, err := findingsource.NewFindingSource(code, code)
		if err != nil {
			return nil, err
		}
		result = append(result, &findingsource.FindingSourceWithCategory{
			FindingSource: fs,
			Category:      nil,
		})
	}
	return result, nil
}

func (r *wfDispatchStubFindingSourceRepo) ListActiveByCategory(_ context.Context, _ shared.ID) ([]*findingsource.FindingSource, error) {
	return nil, nil
}

func (r *wfDispatchStubFindingSourceRepo) ExistsByCode(_ context.Context, code string) (bool, error) {
	return r.validCodes[code], nil
}

func (r *wfDispatchStubFindingSourceRepo) IsValidCode(_ context.Context, code string) (bool, error) {
	return r.validCodes[code], nil
}

// =============================================================================
// Test harness
// =============================================================================

type wfDispatchTestHarness struct {
	wfRepo   *wfDispatchMockWorkflowRepo
	nodeRepo *wfDispatchMockNodeRepo
	runRepo  *wfDispatchMockRunRepo
	service  *app.WorkflowService
	dispatch *app.WorkflowEventDispatcher
}

func newWfDispatchTestHarness() *wfDispatchTestHarness {
	log := logger.NewNop()
	wfRepo := newWfDispatchMockWorkflowRepo()
	nodeRepo := newWfDispatchMockNodeRepo()
	edgeRepo := NewMockEdgeRepository()
	runRepo := newWfDispatchMockRunRepo()
	nodeRunRepo := NewMockNodeRunRepository()

	svc := app.NewWorkflowService(
		wfRepo,
		nodeRepo,
		edgeRepo,
		runRepo,
		nodeRunRepo,
		log,
	)

	dispatcher := app.NewWorkflowEventDispatcher(wfRepo, nodeRepo, svc, log)

	return &wfDispatchTestHarness{
		wfRepo:   wfRepo,
		nodeRepo: nodeRepo,
		runRepo:  runRepo,
		service:  svc,
		dispatch: dispatcher,
	}
}

// wfDispatchMakeFinding creates a minimal Finding for dispatcher tests.
func wfDispatchMakeFinding(
	t *testing.T,
	tenantID shared.ID,
	assetID shared.ID,
	source vulnerability.FindingSource,
	toolName string,
	severity vulnerability.Severity,
) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(tenantID, assetID, source, toolName, severity, "test finding")
	if err != nil {
		t.Fatalf("failed to create test finding: %v", err)
	}
	return f
}

// wfDispatchMakeWorkflow creates a workflow with one trigger node of the given type.
func wfDispatchMakeWorkflow(
	t *testing.T,
	tenantID shared.ID,
	triggerType workflow.TriggerType,
	triggerConfig map[string]any,
) *workflow.Workflow {
	t.Helper()
	wf, err := workflow.NewWorkflow(tenantID, "test-workflow", "test")
	if err != nil {
		t.Fatalf("failed to create workflow: %v", err)
	}
	wf.IsActive = true

	node, err := workflow.NewNode(wf.ID, "trigger_1", workflow.NodeTypeTrigger, "Trigger")
	if err != nil {
		t.Fatalf("failed to create trigger node: %v", err)
	}
	if err := node.SetTriggerConfig(triggerType, triggerConfig); err != nil {
		t.Fatalf("failed to set trigger config: %v", err)
	}
	wf.Nodes = append(wf.Nodes, node)
	return wf
}

// newWfDispatchFindingSourceCacheService builds a FindingSourceCacheService backed
// by a stub repo with the given valid codes (nil Redis = graceful degradation path).
func newWfDispatchFindingSourceCacheService(t *testing.T, log *logger.Logger, validCodes map[string]bool) *app.FindingSourceCacheService {
	t.Helper()
	repo := &wfDispatchStubFindingSourceRepo{validCodes: validCodes}
	svc, err := app.NewFindingSourceCacheService(nil, repo, log)
	if err != nil {
		t.Fatalf("failed to create FindingSourceCacheService: %v", err)
	}
	return svc
}

// =============================================================================
// TestWfDispatch_DispatchFindingEvent
// =============================================================================

func TestWfDispatch_DispatchFindingEvent_Success(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, nil)
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	err := h.dispatch.DispatchFindingEvent(ctx, event)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if h.runRepo.TriggeredCount() != 1 {
		t.Errorf("expected 1 workflow triggered, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_DispatchFindingEvent_NoMatchingWorkflows(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	err := h.dispatch.DispatchFindingEvent(ctx, event)

	if err != nil {
		t.Fatalf("expected no error when no workflows found, got %v", err)
	}
	if h.runRepo.TriggeredCount() != 0 {
		t.Errorf("expected 0 workflows triggered, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_DispatchFindingEvent_WorkflowRepoError(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	expectedErr := errors.New("database unavailable")
	h.wfRepo.listActiveErr = expectedErr

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	err := h.dispatch.DispatchFindingEvent(ctx, event)

	if err == nil {
		t.Fatal("expected error when repo fails, got nil")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected wrapped database error, got %v", err)
	}
}

func TestWfDispatch_DispatchFindingEvent_InactiveWorkflowNotMatched(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, nil)
	wf.IsActive = false
	h.wfRepo.workflows[wf.ID.String()] = wf
	// Simulate repo-level filtering: active=false workflows are not returned
	h.wfRepo.listActiveResult = []*workflow.Workflow{}

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	err := h.dispatch.DispatchFindingEvent(ctx, event)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if h.runRepo.TriggeredCount() != 0 {
		t.Errorf("expected 0 workflows triggered for inactive workflow, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_DispatchFindingEvent_MultipleWorkflowsAllTriggered(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf1 := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, nil)
	wf2 := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, nil)
	wf2.Name = "test-workflow-2"
	h.wfRepo.workflows[wf1.ID.String()] = wf1
	h.wfRepo.workflows[wf2.ID.String()] = wf2

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	err := h.dispatch.DispatchFindingEvent(ctx, event)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if h.runRepo.TriggeredCount() != 2 {
		t.Errorf("expected 2 workflows triggered, got %d", h.runRepo.TriggeredCount())
	}
}

// =============================================================================
// TestWfDispatch_DispatchFindingsCreated (batch)
// =============================================================================

func TestWfDispatch_DispatchFindingsCreated_DispatchesForEachFinding(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, nil)
	h.wfRepo.workflows[wf.ID.String()] = wf

	f1 := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)
	f2 := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityLow)

	h.dispatch.DispatchFindingsCreated(ctx, tenantID, []*vulnerability.Finding{f1, f2})

	// Wait for async goroutine
	time.Sleep(200 * time.Millisecond)

	// Deduplication: same workflow triggered only once per batch
	if h.runRepo.TriggeredCount() != 1 {
		t.Errorf("expected 1 trigger (deduplicated per batch), got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_DispatchFindingsCreated_EmptyFindingsNoOp(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()

	h.dispatch.DispatchFindingsCreated(ctx, tenantID, []*vulnerability.Finding{})

	// No goroutine spawned for empty slice; repo should not have been called
	if h.wfRepo.listActiveCalls != 0 {
		t.Errorf("expected 0 repo calls for empty findings, got %d", h.wfRepo.listActiveCalls)
	}
}

func TestWfDispatch_DispatchFindingsCreated_RespectsMaxLimit(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	// 600 findings exceeds the 500 maxFindingsPerDispatch limit
	var findings []*vulnerability.Finding
	for i := 0; i < 600; i++ {
		f := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)
		findings = append(findings, f)
	}

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, nil)
	h.wfRepo.workflows[wf.ID.String()] = wf

	h.dispatch.DispatchFindingsCreated(ctx, tenantID, findings)
	time.Sleep(200 * time.Millisecond)

	// Deduplication: at most triggered once
	if h.runRepo.TriggeredCount() > 1 {
		t.Errorf("expected at most 1 trigger (dedup across truncated batch), got %d", h.runRepo.TriggeredCount())
	}
}

// =============================================================================
// TestWfDispatch_matchesTriggerFilters
// =============================================================================

func TestWfDispatch_MatchesTriggerFilters_NoFiltersMatchAll(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, nil)
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	err := h.dispatch.DispatchFindingEvent(ctx, event)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.runRepo.TriggeredCount() != 1 {
		t.Errorf("expected 1 trigger with no filters, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_MatchesTriggerFilters_SeverityFilterMatch(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, map[string]any{
		"severity_filter": []interface{}{"high", "critical"},
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	_ = h.dispatch.DispatchFindingEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 1 {
		t.Errorf("expected 1 trigger for matching severity, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_MatchesTriggerFilters_SeverityFilterMismatch(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, map[string]any{
		"severity_filter": []interface{}{"critical"},
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityLow)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	_ = h.dispatch.DispatchFindingEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 0 {
		t.Errorf("expected 0 triggers for severity mismatch, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_MatchesTriggerFilters_ToolFilterMatch(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, map[string]any{
		"tool_filter": []interface{}{"semgrep", "codeql"},
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	_ = h.dispatch.DispatchFindingEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 1 {
		t.Errorf("expected 1 trigger for matching tool, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_MatchesTriggerFilters_ToolFilterMismatch(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, map[string]any{
		"tool_filter": []interface{}{"snyk"},
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	_ = h.dispatch.DispatchFindingEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 0 {
		t.Errorf("expected 0 triggers for tool mismatch, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_MatchesTriggerFilters_SourceFilterMatch(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, map[string]any{
		"source_filter": []interface{}{"sast", "dast"},
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	_ = h.dispatch.DispatchFindingEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 1 {
		t.Errorf("expected 1 trigger for matching source, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_MatchesTriggerFilters_SourceFilterMismatch(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, map[string]any{
		"source_filter": []interface{}{"container"},
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	_ = h.dispatch.DispatchFindingEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 0 {
		t.Errorf("expected 0 triggers for source mismatch, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_MatchesTriggerFilters_MultipleFiltersANDLogic(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	// Both severity AND tool must match
	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, map[string]any{
		"severity_filter": []interface{}{"high", "critical"},
		"tool_filter":     []interface{}{"semgrep"},
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	// Matches severity but NOT tool
	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "snyk", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	_ = h.dispatch.DispatchFindingEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 0 {
		t.Errorf("expected 0 triggers when tool filter fails (AND logic), got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_MatchesTriggerFilters_MultipleFiltersAllMatch(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, map[string]any{
		"severity_filter": []interface{}{"high", "critical"},
		"tool_filter":     []interface{}{"semgrep"},
		"source_filter":   []interface{}{"sast"},
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	_ = h.dispatch.DispatchFindingEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 1 {
		t.Errorf("expected 1 trigger when all filters match, got %d", h.runRepo.TriggeredCount())
	}
}

// =============================================================================
// TestWfDispatch_matchesSeverityFilter
// =============================================================================

func TestWfDispatch_MatchesSeverityFilter_SeverityInList(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, map[string]any{
		"severity_filter": []interface{}{"low", "medium"},
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityLow)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	_ = h.dispatch.DispatchFindingEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 1 {
		t.Errorf("expected severity 'low' in ['low','medium'] to match, got %d triggers", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_MatchesSeverityFilter_SeverityNotInList(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, map[string]any{
		"severity_filter": []interface{}{"low", "medium"},
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityCritical)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	_ = h.dispatch.DispatchFindingEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 0 {
		t.Errorf("expected 0 triggers when severity not in filter list, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_MatchesSeverityFilter_EmptySeverityListMatchAll(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, map[string]any{
		"severity_filter": []interface{}{},
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityInfo)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	_ = h.dispatch.DispatchFindingEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 1 {
		t.Errorf("expected empty severity list to match all, got %d triggers", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_MatchesSeverityFilter_CaseSensitiveMatch(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	// Filter uses lowercase which matches what finding.Severity() returns
	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, map[string]any{
		"severity_filter": []interface{}{"high"},
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	_ = h.dispatch.DispatchFindingEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 1 {
		t.Errorf("expected lowercase severity to match, got %d triggers", h.runRepo.TriggeredCount())
	}
}

// =============================================================================
// TestWfDispatch_matchesToolFilter
// =============================================================================

func TestWfDispatch_MatchesToolFilter_ToolInList(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, map[string]any{
		"tool_filter": []interface{}{"trivy", "grype"},
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	_ = h.dispatch.DispatchFindingEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 1 {
		t.Errorf("expected 1 trigger for tool in list, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_MatchesToolFilter_ToolNotInList(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, map[string]any{
		"tool_filter": []interface{}{"trivy"},
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSCA, "grype", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	_ = h.dispatch.DispatchFindingEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 0 {
		t.Errorf("expected 0 triggers for tool not in list, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_MatchesToolFilter_EmptyToolListMatchAll(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, map[string]any{
		"tool_filter": []interface{}{},
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "any-tool", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	_ = h.dispatch.DispatchFindingEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 1 {
		t.Errorf("expected empty tool list to match all, got %d triggers", h.runRepo.TriggeredCount())
	}
}

// =============================================================================
// TestWfDispatch_DispatchAITriageEvent
// =============================================================================

func TestWfDispatch_DispatchAITriageEvent_SuccessWithMatchingWorkflows(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeAITriageCompleted, nil)
	h.wfRepo.workflows[wf.ID.String()] = wf

	event := app.AITriageEvent{
		TenantID:  tenantID,
		FindingID: shared.NewID(),
		TriageID:  shared.NewID(),
		EventType: workflow.TriggerTypeAITriageCompleted,
		TriageData: map[string]any{
			"severity_assessment": "high",
			"risk_score":          float64(8.5),
		},
	}

	err := h.dispatch.DispatchAITriageEvent(ctx, event)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if h.runRepo.TriggeredCount() != 1 {
		t.Errorf("expected 1 workflow triggered, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_DispatchAITriageEvent_NoMatchingWorkflows(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()

	event := app.AITriageEvent{
		TenantID:  tenantID,
		FindingID: shared.NewID(),
		TriageID:  shared.NewID(),
		EventType: workflow.TriggerTypeAITriageCompleted,
	}

	err := h.dispatch.DispatchAITriageEvent(ctx, event)

	if err != nil {
		t.Fatalf("expected no error with no workflows, got %v", err)
	}
	if h.runRepo.TriggeredCount() != 0 {
		t.Errorf("expected 0 triggers, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_DispatchAITriageEvent_WrongTriggerTypeNotMatched(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeAITriageCompleted, nil)
	h.wfRepo.workflows[wf.ID.String()] = wf
	// Repo returns none for ai_triage_failed
	h.wfRepo.listActiveResult = []*workflow.Workflow{}

	event := app.AITriageEvent{
		TenantID:  tenantID,
		FindingID: shared.NewID(),
		TriageID:  shared.NewID(),
		EventType: workflow.TriggerTypeAITriageFailed,
	}

	err := h.dispatch.DispatchAITriageEvent(ctx, event)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.runRepo.TriggeredCount() != 0 {
		t.Errorf("expected 0 triggers for wrong trigger type, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_DispatchAITriageEvent_FailedEventMatchesFailedWorkflow(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeAITriageFailed, nil)
	h.wfRepo.workflows[wf.ID.String()] = wf

	event := app.AITriageEvent{
		TenantID:  tenantID,
		FindingID: shared.NewID(),
		TriageID:  shared.NewID(),
		EventType: workflow.TriggerTypeAITriageFailed,
		TriageData: map[string]any{
			"error_message": "LLM timeout",
		},
	}

	err := h.dispatch.DispatchAITriageEvent(ctx, event)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.runRepo.TriggeredCount() != 1 {
		t.Errorf("expected 1 trigger for ai_triage_failed matching workflow, got %d", h.runRepo.TriggeredCount())
	}
}

// =============================================================================
// TestWfDispatch_matchesAITriageTriggerFilters
// =============================================================================

func TestWfDispatch_MatchesAITriageTriggerFilters_NoFiltersMatchAll(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeAITriageCompleted, nil)
	h.wfRepo.workflows[wf.ID.String()] = wf

	event := app.AITriageEvent{
		TenantID:  tenantID,
		FindingID: shared.NewID(),
		TriageID:  shared.NewID(),
		EventType: workflow.TriggerTypeAITriageCompleted,
		TriageData: map[string]any{
			"severity_assessment": "medium",
			"risk_score":          float64(5.0),
		},
	}

	err := h.dispatch.DispatchAITriageEvent(ctx, event)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.runRepo.TriggeredCount() != 1 {
		t.Errorf("expected 1 trigger with no filters, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_MatchesAITriageTriggerFilters_SeverityFilterMatch(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeAITriageCompleted, map[string]any{
		"severity_filter": []interface{}{"high", "critical"},
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	event := app.AITriageEvent{
		TenantID:  tenantID,
		FindingID: shared.NewID(),
		TriageID:  shared.NewID(),
		EventType: workflow.TriggerTypeAITriageCompleted,
		TriageData: map[string]any{"severity_assessment": "high"},
	}

	_ = h.dispatch.DispatchAITriageEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 1 {
		t.Errorf("expected 1 trigger when triage severity matches filter, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_MatchesAITriageTriggerFilters_SeverityFilterMismatch(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeAITriageCompleted, map[string]any{
		"severity_filter": []interface{}{"critical"},
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	event := app.AITriageEvent{
		TenantID:  tenantID,
		FindingID: shared.NewID(),
		TriageID:  shared.NewID(),
		EventType: workflow.TriggerTypeAITriageCompleted,
		TriageData: map[string]any{"severity_assessment": "low"},
	}

	_ = h.dispatch.DispatchAITriageEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 0 {
		t.Errorf("expected 0 triggers when triage severity mismatches filter, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_MatchesAITriageTriggerFilters_RiskScoreAboveMin(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeAITriageCompleted, map[string]any{
		"risk_score_min": float64(7.0),
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	event := app.AITriageEvent{
		TenantID:  tenantID,
		FindingID: shared.NewID(),
		TriageID:  shared.NewID(),
		EventType: workflow.TriggerTypeAITriageCompleted,
		TriageData: map[string]any{
			"severity_assessment": "critical",
			"risk_score":          float64(9.0),
		},
	}

	_ = h.dispatch.DispatchAITriageEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 1 {
		t.Errorf("expected 1 trigger when risk_score above minimum, got %d", h.runRepo.TriggeredCount())
	}
}

func TestWfDispatch_MatchesAITriageTriggerFilters_RiskScoreBelowMin(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeAITriageCompleted, map[string]any{
		"risk_score_min": float64(8.0),
	})
	h.wfRepo.workflows[wf.ID.String()] = wf

	event := app.AITriageEvent{
		TenantID:  tenantID,
		FindingID: shared.NewID(),
		TriageID:  shared.NewID(),
		EventType: workflow.TriggerTypeAITriageCompleted,
		TriageData: map[string]any{
			"severity_assessment": "medium",
			"risk_score":          float64(5.0),
		},
	}

	_ = h.dispatch.DispatchAITriageEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 0 {
		t.Errorf("expected 0 triggers when risk_score below minimum, got %d", h.runRepo.TriggeredCount())
	}
}

// =============================================================================
// TestWfDispatch_buildFindingTriggerData
// =============================================================================

func TestWfDispatch_BuildFindingTriggerData_CorrectDataMap(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, nil)
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)

	event := app.FindingEvent{
		TenantID:  tenantID,
		Finding:   finding,
		EventType: workflow.TriggerTypeFindingCreated,
		Changes:   map[string]any{"status": "new"},
	}

	err := h.dispatch.DispatchFindingEvent(ctx, event)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.runRepo.TriggeredCount() != 1 {
		t.Fatalf("expected 1 run to be created")
	}

	run := h.runRepo.createdRuns[0]
	if run.TriggerData == nil {
		t.Fatal("expected TriggerData to be non-nil")
	}

	if run.TriggerData["event_type"] != string(workflow.TriggerTypeFindingCreated) {
		t.Errorf("expected event_type %q, got %v", workflow.TriggerTypeFindingCreated, run.TriggerData["event_type"])
	}

	findingMap, ok := run.TriggerData["finding"].(map[string]any)
	if !ok {
		t.Fatal("expected 'finding' map in trigger data")
	}
	if findingMap["id"] != finding.ID().String() {
		t.Errorf("expected finding id %q, got %v", finding.ID().String(), findingMap["id"])
	}
	if findingMap["severity"] != string(vulnerability.SeverityHigh) {
		t.Errorf("expected severity 'high', got %v", findingMap["severity"])
	}
	if findingMap["tool_name"] != "semgrep" {
		t.Errorf("expected tool_name 'semgrep', got %v", findingMap["tool_name"])
	}
	if findingMap["source"] != string(vulnerability.FindingSourceSAST) {
		t.Errorf("expected source 'sast', got %v", findingMap["source"])
	}
	if findingMap["asset_id"] != assetID.String() {
		t.Errorf("expected asset_id %q, got %v", assetID.String(), findingMap["asset_id"])
	}

	changesMap, ok := run.TriggerData["changes"].(map[string]any)
	if !ok {
		t.Fatal("expected 'changes' map in trigger data when event has changes")
	}
	if changesMap["status"] != "new" {
		t.Errorf("expected changes.status = 'new', got %v", changesMap["status"])
	}
}

func TestWfDispatch_BuildFindingTriggerData_NoChangesOmitted(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, nil)
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	err := h.dispatch.DispatchFindingEvent(ctx, event)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.runRepo.TriggeredCount() != 1 {
		t.Fatalf("expected 1 run created")
	}
	if _, ok := h.runRepo.createdRuns[0].TriggerData["changes"]; ok {
		t.Error("expected 'changes' key to be absent when event.Changes is nil")
	}
}

func TestWfDispatch_BuildFindingTriggerData_IncludesAllFindingFields(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeFindingCreated, nil)
	h.wfRepo.workflows[wf.ID.String()] = wf

	finding := wfDispatchMakeFinding(t, tenantID, assetID, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh)
	event := app.FindingEvent{TenantID: tenantID, Finding: finding, EventType: workflow.TriggerTypeFindingCreated}

	_ = h.dispatch.DispatchFindingEvent(ctx, event)

	if h.runRepo.TriggeredCount() != 1 {
		t.Fatalf("expected 1 run")
	}
	findingMap, ok := h.runRepo.createdRuns[0].TriggerData["finding"].(map[string]any)
	if !ok {
		t.Fatal("expected finding map")
	}

	requiredFields := []string{"id", "title", "severity", "status", "source", "tool_name", "asset_id"}
	for _, field := range requiredFields {
		if _, ok := findingMap[field]; !ok {
			t.Errorf("expected field %q in finding trigger data", field)
		}
	}
}

// =============================================================================
// TestWfDispatch_buildAITriageTriggerData
// =============================================================================

func TestWfDispatch_BuildAITriageTriggerData_CorrectDataMap(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	findingID := shared.NewID()
	triageID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeAITriageCompleted, nil)
	h.wfRepo.workflows[wf.ID.String()] = wf

	event := app.AITriageEvent{
		TenantID:  tenantID,
		FindingID: findingID,
		TriageID:  triageID,
		EventType: workflow.TriggerTypeAITriageCompleted,
		TriageData: map[string]any{
			"severity_assessment": "high",
			"risk_score":          float64(8.5),
			"recommendation":      "Apply patch immediately",
		},
	}

	err := h.dispatch.DispatchAITriageEvent(ctx, event)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.runRepo.TriggeredCount() != 1 {
		t.Fatalf("expected 1 run created")
	}

	td := h.runRepo.createdRuns[0].TriggerData

	if td["event_type"] != string(workflow.TriggerTypeAITriageCompleted) {
		t.Errorf("expected event_type 'ai_triage_completed', got %v", td["event_type"])
	}
	if td["triage_id"] != triageID.String() {
		t.Errorf("expected triage_id %q, got %v", triageID.String(), td["triage_id"])
	}
	if td["finding_id"] != findingID.String() {
		t.Errorf("expected finding_id %q, got %v", findingID.String(), td["finding_id"])
	}
	if td["severity_assessment"] != "high" {
		t.Errorf("expected severity_assessment 'high', got %v", td["severity_assessment"])
	}
	if td["risk_score"] != float64(8.5) {
		t.Errorf("expected risk_score 8.5, got %v", td["risk_score"])
	}
	if td["recommendation"] != "Apply patch immediately" {
		t.Errorf("expected recommendation to be set, got %v", td["recommendation"])
	}

	findingData, ok := td["finding"].(map[string]any)
	if !ok {
		t.Fatal("expected 'finding' map in AI triage trigger data")
	}
	if findingData["id"] != findingID.String() {
		t.Errorf("expected finding.id = %q, got %v", findingID.String(), findingData["id"])
	}
}

func TestWfDispatch_BuildAITriageTriggerData_PreservesExistingFindingFromTriageData(t *testing.T) {
	h := newWfDispatchTestHarness()
	ctx := context.Background()
	tenantID := shared.NewID()
	findingID := shared.NewID()
	triageID := shared.NewID()

	wf := wfDispatchMakeWorkflow(t, tenantID, workflow.TriggerTypeAITriageCompleted, nil)
	h.wfRepo.workflows[wf.ID.String()] = wf

	event := app.AITriageEvent{
		TenantID:  tenantID,
		FindingID: findingID,
		TriageID:  triageID,
		EventType: workflow.TriggerTypeAITriageCompleted,
		TriageData: map[string]any{
			"finding": map[string]any{
				"id":       findingID.String(),
				"title":    "SQL Injection",
				"severity": "critical",
			},
			"risk_score": float64(9.5),
		},
	}

	err := h.dispatch.DispatchAITriageEvent(ctx, event)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	td := h.runRepo.createdRuns[0].TriggerData
	findingData, ok := td["finding"].(map[string]any)
	if !ok {
		t.Fatal("expected finding to be a map")
	}
	if findingData["title"] != "SQL Injection" {
		t.Errorf("expected finding.title 'SQL Injection', got %v", findingData["title"])
	}
}

// =============================================================================
// TestWfDispatch_ValidateSourceFilter
// =============================================================================

func TestWfDispatch_ValidateSourceFilter_ValidSourceCode(t *testing.T) {
	ctx := context.Background()
	log := logger.NewNop()
	fsSvc := newWfDispatchFindingSourceCacheService(t, log, map[string]bool{"sast": true, "dast": true})

	err := app.ValidateSourceFilter(ctx, map[string]any{"source_filter": []interface{}{"sast"}}, fsSvc)

	if err != nil {
		t.Errorf("expected nil error for valid source code, got %v", err)
	}
}

func TestWfDispatch_ValidateSourceFilter_InvalidSourceCode(t *testing.T) {
	ctx := context.Background()
	log := logger.NewNop()
	fsSvc := newWfDispatchFindingSourceCacheService(t, log, map[string]bool{"sast": true})

	err := app.ValidateSourceFilter(ctx, map[string]any{"source_filter": []interface{}{"nonexistent_source"}}, fsSvc)

	if err == nil {
		t.Error("expected error for invalid source code, got nil")
	}
}

func TestWfDispatch_ValidateSourceFilter_NoSourceFilter(t *testing.T) {
	ctx := context.Background()
	log := logger.NewNop()
	fsSvc := newWfDispatchFindingSourceCacheService(t, log, map[string]bool{"sast": true})

	err := app.ValidateSourceFilter(ctx, map[string]any{"severity_filter": []interface{}{"high"}}, fsSvc)

	if err != nil {
		t.Errorf("expected nil error when no source_filter key, got %v", err)
	}
}

func TestWfDispatch_ValidateSourceFilter_MultipleCodesAllValid(t *testing.T) {
	ctx := context.Background()
	log := logger.NewNop()
	fsSvc := newWfDispatchFindingSourceCacheService(t, log, map[string]bool{"sast": true, "dast": true, "container": true})

	err := app.ValidateSourceFilter(ctx, map[string]any{"source_filter": []interface{}{"sast", "dast", "container"}}, fsSvc)

	if err != nil {
		t.Errorf("expected nil error when all source codes are valid, got %v", err)
	}
}

func TestWfDispatch_ValidateSourceFilter_OneInvalidCodeFails(t *testing.T) {
	ctx := context.Background()
	log := logger.NewNop()
	fsSvc := newWfDispatchFindingSourceCacheService(t, log, map[string]bool{"sast": true})

	err := app.ValidateSourceFilter(ctx, map[string]any{"source_filter": []interface{}{"sast", "bogus"}}, fsSvc)

	if err == nil {
		t.Error("expected error when one source code is invalid, got nil")
	}
}
