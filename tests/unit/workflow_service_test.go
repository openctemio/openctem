package unit

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/workflow"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Repositories
// =============================================================================

// MockWorkflowRepository implements workflow.WorkflowRepository for testing.
type MockWorkflowRepository struct {
	mu          sync.RWMutex
	workflows   map[string]*workflow.Workflow
	createErr   error
	getErr      error
	updateErr   error
	deleteErr   error
	getGraphErr error
}

func NewMockWorkflowRepository() *MockWorkflowRepository {
	return &MockWorkflowRepository{
		workflows: make(map[string]*workflow.Workflow),
	}
}

func (m *MockWorkflowRepository) Create(ctx context.Context, wf *workflow.Workflow) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workflows[wf.ID.String()] = wf
	return nil
}

func (m *MockWorkflowRepository) GetByID(ctx context.Context, id shared.ID) (*workflow.Workflow, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if wf, ok := m.workflows[id.String()]; ok {
		return wf, nil
	}
	return nil, shared.ErrNotFound
}

func (m *MockWorkflowRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*workflow.Workflow, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, wf := range m.workflows {
		if wf.ID == id && wf.TenantID == tenantID {
			return wf, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *MockWorkflowRepository) GetByName(ctx context.Context, tenantID shared.ID, name string) (*workflow.Workflow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, wf := range m.workflows {
		if wf.Name == name && wf.TenantID == tenantID {
			return wf, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *MockWorkflowRepository) List(ctx context.Context, filter workflow.WorkflowFilter, page pagination.Pagination) (pagination.Result[*workflow.Workflow], error) {
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

func (m *MockWorkflowRepository) Update(ctx context.Context, wf *workflow.Workflow) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workflows[wf.ID.String()] = wf
	return nil
}

func (m *MockWorkflowRepository) Delete(ctx context.Context, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.workflows, id.String())
	return nil
}

func (m *MockWorkflowRepository) GetWithGraph(ctx context.Context, id shared.ID) (*workflow.Workflow, error) {
	if m.getGraphErr != nil {
		return nil, m.getGraphErr
	}
	return m.GetByID(ctx, id)
}

func (m *MockWorkflowRepository) ListActiveWithTriggerType(ctx context.Context, tenantID shared.ID, triggerType workflow.TriggerType) ([]*workflow.Workflow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var items []*workflow.Workflow
	for _, wf := range m.workflows {
		if wf.TenantID == tenantID && wf.IsActive {
			items = append(items, wf)
		}
	}
	return items, nil
}

// MockNodeRepository implements workflow.NodeRepository for testing.
type MockNodeRepository struct {
	mu        sync.RWMutex
	nodes     map[string]*workflow.Node
	createErr error
	deleteErr error
}

func NewMockNodeRepository() *MockNodeRepository {
	return &MockNodeRepository{
		nodes: make(map[string]*workflow.Node),
	}
}

func (m *MockNodeRepository) Create(ctx context.Context, node *workflow.Node) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes[node.ID.String()] = node
	return nil
}

func (m *MockNodeRepository) CreateBatch(ctx context.Context, nodes []*workflow.Node) error {
	for _, node := range nodes {
		if err := m.Create(ctx, node); err != nil {
			return err
		}
	}
	return nil
}

func (m *MockNodeRepository) GetByID(ctx context.Context, id shared.ID) (*workflow.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if node, ok := m.nodes[id.String()]; ok {
		return node, nil
	}
	return nil, shared.ErrNotFound
}

func (m *MockNodeRepository) GetByWorkflowID(ctx context.Context, workflowID shared.ID) ([]*workflow.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var items []*workflow.Node
	for _, node := range m.nodes {
		if node.WorkflowID == workflowID {
			items = append(items, node)
		}
	}
	return items, nil
}

func (m *MockNodeRepository) GetByKey(ctx context.Context, workflowID shared.ID, nodeKey string) (*workflow.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, node := range m.nodes {
		if node.WorkflowID == workflowID && node.NodeKey == nodeKey {
			return node, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *MockNodeRepository) Update(ctx context.Context, node *workflow.Node) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes[node.ID.String()] = node
	return nil
}

func (m *MockNodeRepository) Delete(ctx context.Context, id shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.nodes, id.String())
	return nil
}

func (m *MockNodeRepository) DeleteByWorkflowID(ctx context.Context, workflowID shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, node := range m.nodes {
		if node.WorkflowID == workflowID {
			delete(m.nodes, id)
		}
	}
	return nil
}

func (m *MockNodeRepository) GetNodeCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.nodes)
}

// MockEdgeRepository implements workflow.EdgeRepository for testing.
type MockEdgeRepository struct {
	mu        sync.RWMutex
	edges     map[string]*workflow.Edge
	createErr error
	deleteErr error
}

func NewMockEdgeRepository() *MockEdgeRepository {
	return &MockEdgeRepository{
		edges: make(map[string]*workflow.Edge),
	}
}

func (m *MockEdgeRepository) Create(ctx context.Context, edge *workflow.Edge) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.edges[edge.ID.String()] = edge
	return nil
}

func (m *MockEdgeRepository) CreateBatch(ctx context.Context, edges []*workflow.Edge) error {
	for _, edge := range edges {
		if err := m.Create(ctx, edge); err != nil {
			return err
		}
	}
	return nil
}

func (m *MockEdgeRepository) GetByID(ctx context.Context, id shared.ID) (*workflow.Edge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if edge, ok := m.edges[id.String()]; ok {
		return edge, nil
	}
	return nil, shared.ErrNotFound
}

func (m *MockEdgeRepository) GetByWorkflowID(ctx context.Context, workflowID shared.ID) ([]*workflow.Edge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var items []*workflow.Edge
	for _, edge := range m.edges {
		if edge.WorkflowID == workflowID {
			items = append(items, edge)
		}
	}
	return items, nil
}

func (m *MockEdgeRepository) Delete(ctx context.Context, id shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.edges, id.String())
	return nil
}

func (m *MockEdgeRepository) DeleteByWorkflowID(ctx context.Context, workflowID shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, edge := range m.edges {
		if edge.WorkflowID == workflowID {
			delete(m.edges, id)
		}
	}
	return nil
}

func (m *MockEdgeRepository) GetEdgeCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.edges)
}

// MockRunRepository implements workflow.RunRepository for testing.
type MockRunRepository struct {
	activeCount    int
	activeCountErr error
}

func NewMockRunRepository() *MockRunRepository {
	return &MockRunRepository{}
}

func (m *MockRunRepository) Create(ctx context.Context, run *workflow.Run) error {
	return nil
}

func (m *MockRunRepository) GetByID(ctx context.Context, id shared.ID) (*workflow.Run, error) {
	return nil, shared.ErrNotFound
}

func (m *MockRunRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*workflow.Run, error) {
	return nil, shared.ErrNotFound
}

func (m *MockRunRepository) List(ctx context.Context, filter workflow.RunFilter, page pagination.Pagination) (pagination.Result[*workflow.Run], error) {
	return pagination.Result[*workflow.Run]{}, nil
}

func (m *MockRunRepository) ListByWorkflowID(ctx context.Context, workflowID shared.ID, page, perPage int) ([]*workflow.Run, int64, error) {
	return nil, 0, nil
}

func (m *MockRunRepository) Update(ctx context.Context, run *workflow.Run) error {
	return nil
}

func (m *MockRunRepository) Delete(ctx context.Context, id shared.ID) error {
	return nil
}

func (m *MockRunRepository) GetWithNodeRuns(ctx context.Context, id shared.ID) (*workflow.Run, error) {
	return nil, shared.ErrNotFound
}

func (m *MockRunRepository) GetActiveByWorkflowID(ctx context.Context, workflowID shared.ID) ([]*workflow.Run, error) {
	return nil, nil
}

func (m *MockRunRepository) CountActiveByWorkflowID(ctx context.Context, workflowID shared.ID) (int, error) {
	if m.activeCountErr != nil {
		return 0, m.activeCountErr
	}
	return m.activeCount, nil
}

func (m *MockRunRepository) CountActiveByTenantID(ctx context.Context, tenantID shared.ID) (int, error) {
	return 0, nil
}

func (m *MockRunRepository) UpdateStats(ctx context.Context, id shared.ID, completed, failed int) error {
	return nil
}

func (m *MockRunRepository) UpdateStatus(ctx context.Context, id shared.ID, status workflow.RunStatus, errorMessage string) error {
	return nil
}

func (m *MockRunRepository) CreateRunIfUnderLimit(ctx context.Context, run *workflow.Run, maxPerWorkflow, maxPerTenant int) error {
	return nil
}

func (m *MockRunRepository) SetActiveCount(count int) {
	m.activeCount = count
}

// MockNodeRunRepository implements workflow.NodeRunRepository for testing.
type MockNodeRunRepository struct{}

func NewMockNodeRunRepository() *MockNodeRunRepository {
	return &MockNodeRunRepository{}
}

func (m *MockNodeRunRepository) Create(ctx context.Context, nodeRun *workflow.NodeRun) error {
	return nil
}

func (m *MockNodeRunRepository) CreateBatch(ctx context.Context, nodeRuns []*workflow.NodeRun) error {
	return nil
}

func (m *MockNodeRunRepository) GetByID(ctx context.Context, id shared.ID) (*workflow.NodeRun, error) {
	return nil, shared.ErrNotFound
}

func (m *MockNodeRunRepository) GetByWorkflowRunID(ctx context.Context, workflowRunID shared.ID) ([]*workflow.NodeRun, error) {
	return nil, nil
}

func (m *MockNodeRunRepository) GetByNodeKey(ctx context.Context, workflowRunID shared.ID, nodeKey string) (*workflow.NodeRun, error) {
	return nil, shared.ErrNotFound
}

func (m *MockNodeRunRepository) List(ctx context.Context, filter workflow.NodeRunFilter) ([]*workflow.NodeRun, error) {
	return nil, nil
}

func (m *MockNodeRunRepository) Update(ctx context.Context, nodeRun *workflow.NodeRun) error {
	return nil
}

func (m *MockNodeRunRepository) Delete(ctx context.Context, id shared.ID) error {
	return nil
}

func (m *MockNodeRunRepository) UpdateStatus(ctx context.Context, id shared.ID, status workflow.NodeRunStatus, errorMessage, errorCode string) error {
	return nil
}

func (m *MockNodeRunRepository) Complete(ctx context.Context, id shared.ID, output map[string]any) error {
	return nil
}

func (m *MockNodeRunRepository) GetPendingByDependencies(ctx context.Context, workflowRunID shared.ID, completedNodeKeys []string) ([]*workflow.NodeRun, error) {
	return nil, nil
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func newTestWorkflowService() (*app.WorkflowService, *MockWorkflowRepository, *MockNodeRepository, *MockEdgeRepository, *MockRunRepository) {
	workflowRepo := NewMockWorkflowRepository()
	nodeRepo := NewMockNodeRepository()
	edgeRepo := NewMockEdgeRepository()
	runRepo := NewMockRunRepository()
	nodeRunRepo := NewMockNodeRunRepository()
	log := logger.NewNop()

	service := app.NewWorkflowService(
		workflowRepo,
		nodeRepo,
		edgeRepo,
		runRepo,
		nodeRunRepo,
		log,
	)

	return service, workflowRepo, nodeRepo, edgeRepo, runRepo
}

func createTestWorkflow(tenantID shared.ID, name string) *workflow.Workflow {
	wf, _ := workflow.NewWorkflow(tenantID, name, "Test description")
	return wf
}

// =============================================================================
// Tests for CreateWorkflow
// =============================================================================

func TestCreateWorkflow_Success(t *testing.T) {
	service, workflowRepo, nodeRepo, edgeRepo, _ := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	input := app.CreateWorkflowInput{
		TenantID:    tenantID,
		UserID:      userID,
		Name:        "Test Workflow",
		Description: "A test workflow",
		Tags:        []string{"test", "automation"},
		Nodes: []app.CreateNodeInput{
			{
				NodeKey:  "trigger_1",
				NodeType: workflow.NodeTypeTrigger,
				Name:     "Manual Trigger",
				Config: workflow.NodeConfig{
					TriggerType: workflow.TriggerTypeManual,
				},
			},
			{
				NodeKey:  "action_1",
				NodeType: workflow.NodeTypeAction,
				Name:     "Send Notification",
			},
		},
		Edges: []app.CreateEdgeInput{
			{
				SourceNodeKey: "trigger_1",
				TargetNodeKey: "action_1",
			},
		},
	}

	wf, err := service.CreateWorkflow(ctx, input)
	if err != nil {
		t.Fatalf("CreateWorkflow failed: %v", err)
	}

	if wf == nil {
		t.Fatal("CreateWorkflow returned nil workflow")
	}

	if wf.Name != "Test Workflow" {
		t.Errorf("Expected name 'Test Workflow', got '%s'", wf.Name)
	}

	if len(wf.Nodes) != 2 {
		t.Errorf("Expected 2 nodes, got %d", len(wf.Nodes))
	}

	if len(wf.Edges) != 1 {
		t.Errorf("Expected 1 edge, got %d", len(wf.Edges))
	}

	// Verify repositories were called
	if len(workflowRepo.workflows) != 1 {
		t.Errorf("Expected 1 workflow in repo, got %d", len(workflowRepo.workflows))
	}

	if nodeRepo.GetNodeCount() != 2 {
		t.Errorf("Expected 2 nodes in repo, got %d", nodeRepo.GetNodeCount())
	}

	if edgeRepo.GetEdgeCount() != 1 {
		t.Errorf("Expected 1 edge in repo, got %d", edgeRepo.GetEdgeCount())
	}
}

func TestCreateWorkflow_EmptyName(t *testing.T) {
	service, _, _, _, _ := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()

	input := app.CreateWorkflowInput{
		TenantID: tenantID,
		Name:     "",
		Nodes: []app.CreateNodeInput{
			{
				NodeKey:  "trigger_1",
				NodeType: workflow.NodeTypeTrigger,
				Name:     "Manual Trigger",
			},
		},
	}

	_, err := service.CreateWorkflow(ctx, input)
	if err == nil {
		t.Fatal("Expected error for empty name, got nil")
	}
}

// =============================================================================
// Tests for UpdateWorkflowGraph
// =============================================================================

func TestUpdateWorkflowGraph_Success(t *testing.T) {
	service, workflowRepo, nodeRepo, edgeRepo, runRepo := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Create initial workflow
	initialWf := createTestWorkflow(tenantID, "Original Workflow")
	workflowRepo.Create(ctx, initialWf)

	// Create initial nodes
	triggerNode, _ := workflow.NewNode(initialWf.ID, "trigger_old", workflow.NodeTypeTrigger, "Old Trigger")
	actionNode, _ := workflow.NewNode(initialWf.ID, "action_old", workflow.NodeTypeAction, "Old Action")
	nodeRepo.Create(ctx, triggerNode)
	nodeRepo.Create(ctx, actionNode)

	// Create initial edge
	oldEdge, _ := workflow.NewEdge(initialWf.ID, "trigger_old", "action_old")
	edgeRepo.Create(ctx, oldEdge)

	// No active runs
	runRepo.SetActiveCount(0)

	// Update with new graph
	newName := "Updated Workflow"
	input := app.UpdateWorkflowGraphInput{
		TenantID:   tenantID,
		UserID:     userID,
		WorkflowID: initialWf.ID,
		Name:       &newName,
		Nodes: []app.CreateNodeInput{
			{
				NodeKey:  "trigger_new",
				NodeType: workflow.NodeTypeTrigger,
				Name:     "New Trigger",
				Config: workflow.NodeConfig{
					TriggerType: workflow.TriggerTypeManual,
				},
			},
			{
				NodeKey:  "condition_1",
				NodeType: workflow.NodeTypeCondition,
				Name:     "Check Severity",
			},
			{
				NodeKey:  "action_new",
				NodeType: workflow.NodeTypeAction,
				Name:     "New Action",
			},
		},
		Edges: []app.CreateEdgeInput{
			{
				SourceNodeKey: "trigger_new",
				TargetNodeKey: "condition_1",
			},
			{
				SourceNodeKey: "condition_1",
				TargetNodeKey: "action_new",
				SourceHandle:  "yes",
			},
		},
	}

	wf, err := service.UpdateWorkflowGraph(ctx, input)
	if err != nil {
		t.Fatalf("UpdateWorkflowGraph failed: %v", err)
	}

	if wf.Name != "Updated Workflow" {
		t.Errorf("Expected name 'Updated Workflow', got '%s'", wf.Name)
	}

	if len(wf.Nodes) != 3 {
		t.Errorf("Expected 3 nodes, got %d", len(wf.Nodes))
	}

	if len(wf.Edges) != 2 {
		t.Errorf("Expected 2 edges, got %d", len(wf.Edges))
	}

	// Verify old nodes were deleted and new ones created
	if nodeRepo.GetNodeCount() != 3 {
		t.Errorf("Expected 3 nodes in repo (old deleted, new created), got %d", nodeRepo.GetNodeCount())
	}

	if edgeRepo.GetEdgeCount() != 2 {
		t.Errorf("Expected 2 edges in repo (old deleted, new created), got %d", edgeRepo.GetEdgeCount())
	}
}

func TestUpdateWorkflowGraph_WithActiveRuns(t *testing.T) {
	service, workflowRepo, _, _, runRepo := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Create workflow
	wf := createTestWorkflow(tenantID, "Workflow with active runs")
	workflowRepo.Create(ctx, wf)

	// Set active runs
	runRepo.SetActiveCount(2)

	input := app.UpdateWorkflowGraphInput{
		TenantID:   tenantID,
		UserID:     userID,
		WorkflowID: wf.ID,
		Nodes: []app.CreateNodeInput{
			{
				NodeKey:  "trigger_1",
				NodeType: workflow.NodeTypeTrigger,
				Name:     "Trigger",
			},
		},
	}

	_, err := service.UpdateWorkflowGraph(ctx, input)
	if err == nil {
		t.Fatal("Expected error when updating workflow with active runs")
	}

	// Verify error is about active runs
	var domainErr *shared.DomainError
	if !errors.As(err, &domainErr) {
		t.Fatalf("Expected DomainError, got %T", err)
	}

	if domainErr.Code != "ACTIVE_RUNS_EXIST" {
		t.Errorf("Expected error code 'ACTIVE_RUNS_EXIST', got '%s'", domainErr.Code)
	}
}

func TestUpdateWorkflowGraph_WorkflowNotFound(t *testing.T) {
	service, _, _, _, _ := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()
	nonExistentID := shared.NewID()

	input := app.UpdateWorkflowGraphInput{
		TenantID:   tenantID,
		UserID:     userID,
		WorkflowID: nonExistentID,
		Nodes: []app.CreateNodeInput{
			{
				NodeKey:  "trigger_1",
				NodeType: workflow.NodeTypeTrigger,
				Name:     "Trigger",
			},
		},
	}

	_, err := service.UpdateWorkflowGraph(ctx, input)
	if err == nil {
		t.Fatal("Expected error when updating non-existent workflow")
	}

	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestUpdateWorkflowGraph_PreservesMetadataWhenNotProvided(t *testing.T) {
	service, workflowRepo, _, _, runRepo := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Create workflow with specific metadata
	wf := createTestWorkflow(tenantID, "Original Name")
	wf.Description = "Original Description"
	wf.Tags = []string{"tag1", "tag2"}
	workflowRepo.Create(ctx, wf)

	runRepo.SetActiveCount(0)

	// Update only graph, not metadata
	input := app.UpdateWorkflowGraphInput{
		TenantID:   tenantID,
		UserID:     userID,
		WorkflowID: wf.ID,
		// Name, Description, Tags not provided
		Nodes: []app.CreateNodeInput{
			{
				NodeKey:  "trigger_1",
				NodeType: workflow.NodeTypeTrigger,
				Name:     "Trigger",
				Config: workflow.NodeConfig{
					TriggerType: workflow.TriggerTypeManual,
				},
			},
		},
	}

	result, err := service.UpdateWorkflowGraph(ctx, input)
	if err != nil {
		t.Fatalf("UpdateWorkflowGraph failed: %v", err)
	}

	// Verify metadata was preserved
	if result.Name != "Original Name" {
		t.Errorf("Expected name 'Original Name', got '%s'", result.Name)
	}

	if result.Description != "Original Description" {
		t.Errorf("Expected description 'Original Description', got '%s'", result.Description)
	}

	if len(result.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(result.Tags))
	}
}

// =============================================================================
// Tests for DeleteWorkflow
// =============================================================================

func TestDeleteWorkflow_Success(t *testing.T) {
	service, workflowRepo, nodeRepo, edgeRepo, runRepo := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Create workflow
	wf := createTestWorkflow(tenantID, "To Delete")
	workflowRepo.Create(ctx, wf)

	// Create nodes
	node, _ := workflow.NewNode(wf.ID, "trigger_1", workflow.NodeTypeTrigger, "Trigger")
	nodeRepo.Create(ctx, node)

	// Create edge
	edge, _ := workflow.NewEdge(wf.ID, "trigger_1", "action_1")
	edgeRepo.Create(ctx, edge)

	runRepo.SetActiveCount(0)

	err := service.DeleteWorkflow(ctx, tenantID, userID, wf.ID)
	if err != nil {
		t.Fatalf("DeleteWorkflow failed: %v", err)
	}

	// Verify workflow was deleted
	if len(workflowRepo.workflows) != 0 {
		t.Errorf("Expected 0 workflows, got %d", len(workflowRepo.workflows))
	}
}

func TestDeleteWorkflow_WithActiveRuns(t *testing.T) {
	service, workflowRepo, _, _, runRepo := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Create workflow
	wf := createTestWorkflow(tenantID, "Cannot Delete")
	workflowRepo.Create(ctx, wf)

	// Set active runs
	runRepo.SetActiveCount(1)

	err := service.DeleteWorkflow(ctx, tenantID, userID, wf.ID)
	if err == nil {
		t.Fatal("Expected error when deleting workflow with active runs")
	}

	// Verify workflow was NOT deleted
	if len(workflowRepo.workflows) != 1 {
		t.Errorf("Expected workflow to still exist")
	}
}

// =============================================================================
// Tests for UpdateWorkflow (metadata only)
// =============================================================================

func TestUpdateWorkflow_Success(t *testing.T) {
	service, workflowRepo, _, _, _ := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Create workflow
	wf := createTestWorkflow(tenantID, "Original")
	workflowRepo.Create(ctx, wf)

	newName := "Updated Name"
	newDesc := "Updated Description"
	input := app.UpdateWorkflowInput{
		TenantID:    tenantID,
		UserID:      userID,
		WorkflowID:  wf.ID,
		Name:        &newName,
		Description: &newDesc,
		Tags:        []string{"new-tag"},
	}

	result, err := service.UpdateWorkflow(ctx, input)
	if err != nil {
		t.Fatalf("UpdateWorkflow failed: %v", err)
	}

	if result.Name != "Updated Name" {
		t.Errorf("Expected name 'Updated Name', got '%s'", result.Name)
	}

	if result.Description != "Updated Description" {
		t.Errorf("Expected description 'Updated Description', got '%s'", result.Description)
	}

	if len(result.Tags) != 1 || result.Tags[0] != "new-tag" {
		t.Errorf("Expected tags ['new-tag'], got %v", result.Tags)
	}
}

func TestUpdateWorkflow_ActivateDeactivate(t *testing.T) {
	service, workflowRepo, _, _, _ := newTestWorkflowService()
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Create workflow (active by default)
	wf := createTestWorkflow(tenantID, "Toggle Active")
	workflowRepo.Create(ctx, wf)

	// Deactivate
	inactive := false
	input := app.UpdateWorkflowInput{
		TenantID:   tenantID,
		UserID:     userID,
		WorkflowID: wf.ID,
		IsActive:   &inactive,
	}

	result, err := service.UpdateWorkflow(ctx, input)
	if err != nil {
		t.Fatalf("UpdateWorkflow (deactivate) failed: %v", err)
	}

	if result.IsActive {
		t.Error("Expected workflow to be inactive")
	}

	// Reactivate
	active := true
	input.IsActive = &active

	result, err = service.UpdateWorkflow(ctx, input)
	if err != nil {
		t.Fatalf("UpdateWorkflow (activate) failed: %v", err)
	}

	if !result.IsActive {
		t.Error("Expected workflow to be active")
	}
}
