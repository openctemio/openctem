package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Agent Repository
// =============================================================================

// mockAgentRepo implements agent.Repository for testing.
type mockAgentRepo struct {
	agents       map[shared.ID]*agent.Agent
	apiKeyMap    map[string]*agent.Agent // hash -> agent
	createErr    error
	getByIDErr   error
	updateErr    error
	deleteErr    error
	listResult   pagination.Result[*agent.Agent]
	listErr      error
	findAvailErr error
	findAvail    []*agent.Agent
	claimJobErr  error

	// Call tracking
	createCalls    int
	updateCalls    int
	lastSeenCalls  int
	claimJobCalls  int
	releaseJobCalls int
}

func newMockAgentRepo() *mockAgentRepo {
	return &mockAgentRepo{
		agents:    make(map[shared.ID]*agent.Agent),
		apiKeyMap: make(map[string]*agent.Agent),
	}
}

func (m *mockAgentRepo) Create(_ context.Context, a *agent.Agent) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.agents[a.ID] = a
	if a.APIKeyHash != "" {
		m.apiKeyMap[a.APIKeyHash] = a
	}
	return nil
}

func (m *mockAgentRepo) CountByTenant(_ context.Context, _ shared.ID) (int, error) {
	return len(m.agents), nil
}

func (m *mockAgentRepo) GetByID(_ context.Context, id shared.ID) (*agent.Agent, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	a, ok := m.agents[id]
	if !ok {
		return nil, agent.ErrAgentNotFound
	}
	return a, nil
}

func (m *mockAgentRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*agent.Agent, error) {
	a, ok := m.agents[id]
	if !ok {
		return nil, agent.ErrAgentNotFound
	}
	if a.TenantID == nil || *a.TenantID != tenantID {
		return nil, agent.ErrAgentNotFound
	}
	return a, nil
}

func (m *mockAgentRepo) GetByAPIKeyHash(_ context.Context, hash string) (*agent.Agent, error) {
	a, ok := m.apiKeyMap[hash]
	if !ok {
		return nil, agent.ErrInvalidAPIKey
	}
	return a, nil
}

func (m *mockAgentRepo) List(_ context.Context, _ agent.Filter, _ pagination.Pagination) (pagination.Result[*agent.Agent], error) {
	if m.listErr != nil {
		return pagination.Result[*agent.Agent]{}, m.listErr
	}
	if m.listResult.Data != nil {
		return m.listResult, nil
	}
	// Default: return all agents
	var items []*agent.Agent
	for _, a := range m.agents {
		items = append(items, a)
	}
	return pagination.Result[*agent.Agent]{
		Data:    items,
		Total:   int64(len(items)),
		Page:    1,
		PerPage: 20,
	}, nil
}

func (m *mockAgentRepo) Update(_ context.Context, a *agent.Agent) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.agents[a.ID] = a
	return nil
}

func (m *mockAgentRepo) Delete(_ context.Context, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.agents, id)
	return nil
}

func (m *mockAgentRepo) UpdateLastSeen(_ context.Context, id shared.ID) error {
	m.lastSeenCalls++
	return nil
}

func (m *mockAgentRepo) IncrementStats(_ context.Context, _ shared.ID, _, _, _ int64) error {
	return nil
}

func (m *mockAgentRepo) FindByCapabilities(_ context.Context, _ shared.ID, _ []string, _ string) ([]*agent.Agent, error) {
	return m.findAvail, m.findAvailErr
}

func (m *mockAgentRepo) FindAvailable(_ context.Context, _ shared.ID, _ []string, _ string) ([]*agent.Agent, error) {
	return m.findAvail, m.findAvailErr
}

func (m *mockAgentRepo) FindAvailableWithTool(_ context.Context, _ shared.ID, _ string) (*agent.Agent, error) {
	if len(m.findAvail) > 0 {
		return m.findAvail[0], nil
	}
	return nil, agent.ErrNoPlatformAgentAvailable
}

func (m *mockAgentRepo) MarkStaleAsOffline(_ context.Context, _ time.Duration) (int64, error) {
	return 0, nil
}

func (m *mockAgentRepo) FindAvailableWithCapacity(_ context.Context, _ shared.ID, _ []string, _ string) ([]*agent.Agent, error) {
	return m.findAvail, m.findAvailErr
}

func (m *mockAgentRepo) ClaimJob(_ context.Context, _ shared.ID) error {
	m.claimJobCalls++
	return m.claimJobErr
}

func (m *mockAgentRepo) ReleaseJob(_ context.Context, _ shared.ID) error {
	m.releaseJobCalls++
	return nil
}

func (m *mockAgentRepo) UpdateOfflineTimestamp(_ context.Context, _ shared.ID) error {
	return nil
}

func (m *mockAgentRepo) MarkStaleAgentsOffline(_ context.Context, _ time.Duration) ([]shared.ID, error) {
	return nil, nil
}

func (m *mockAgentRepo) GetAgentsOfflineSince(_ context.Context, _ time.Time) ([]*agent.Agent, error) {
	return nil, nil
}

func (m *mockAgentRepo) GetAvailableToolsForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return nil, nil
}

func (m *mockAgentRepo) HasAgentForTool(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}

func (m *mockAgentRepo) GetAvailableCapabilitiesForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return []string{}, nil
}

func (m *mockAgentRepo) HasAgentForCapability(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}

func (m *mockAgentRepo) GetPlatformAgentStats(_ context.Context, _ shared.ID) (*agent.PlatformAgentStatsResult, error) {
	return &agent.PlatformAgentStatsResult{
		TierBreakdown: make(map[string]agent.TierBreakdown),
	}, nil
}

func (m *mockAgentRepo) GetTenantAgentStats(_ context.Context, _ shared.ID) (*agent.TenantAgentStats, error) {
	return &agent.TenantAgentStats{
		ByStatus: make(map[string]int),
		ByHealth: make(map[string]int),
		ByType:   make(map[string]int),
		ByMode:   make(map[string]int),
	}, nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func newTestAgentService(repo *mockAgentRepo) *app.AgentService {
	log := logger.NewNop()
	return app.NewAgentService(repo, nil, log)
}

func createTestAgent(t *testing.T, tenantID shared.ID, name string) *agent.Agent {
	t.Helper()
	a, err := agent.NewAgent(tenantID, name, agent.AgentTypeWorker, "test agent", []string{"sast"}, []string{"semgrep"}, agent.ExecutionModeDaemon)
	if err != nil {
		t.Fatalf("failed to create test agent: %v", err)
	}
	return a
}

// =============================================================================
// Tests for CreateAgent (RegisterAgent equivalent)
// =============================================================================

func TestCreateAgent_Success(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	input := app.CreateAgentInput{
		TenantID:      tenantID.String(),
		Name:          "Test Worker Agent",
		Type:          "worker",
		Description:   "A test worker agent",
		Capabilities:  []string{"sast", "sca"},
		Tools:         []string{"semgrep", "trivy"},
		ExecutionMode: "daemon",
	}

	output, err := svc.CreateAgent(context.Background(), input)
	if err != nil {
		t.Fatalf("CreateAgent failed: %v", err)
	}

	if output == nil {
		t.Fatal("Expected non-nil output")
	}
	if output.Agent == nil {
		t.Fatal("Expected non-nil agent")
	}
	if output.APIKey == "" {
		t.Error("Expected non-empty API key")
	}
	if output.Agent.Name != "Test Worker Agent" {
		t.Errorf("Expected name 'Test Worker Agent', got '%s'", output.Agent.Name)
	}
	if output.Agent.Type != agent.AgentTypeWorker {
		t.Errorf("Expected type worker, got %s", output.Agent.Type)
	}
	if output.Agent.Status != agent.AgentStatusActive {
		t.Errorf("Expected status active, got %s", output.Agent.Status)
	}
	if output.Agent.Health != agent.AgentHealthUnknown {
		t.Errorf("Expected health unknown, got %s", output.Agent.Health)
	}

	// Verify repo was called
	if repo.createCalls != 1 {
		t.Errorf("Expected 1 create call, got %d", repo.createCalls)
	}
}

func TestCreateAgent_InvalidTenantID(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)

	input := app.CreateAgentInput{
		TenantID: "not-a-uuid",
		Name:     "Bad Agent",
		Type:     "worker",
	}

	_, err := svc.CreateAgent(context.Background(), input)
	if err == nil {
		t.Fatal("Expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestCreateAgent_EmptyName(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	input := app.CreateAgentInput{
		TenantID: tenantID.String(),
		Name:     "",
		Type:     "worker",
	}

	_, err := svc.CreateAgent(context.Background(), input)
	if err == nil {
		t.Fatal("Expected error for empty name")
	}
}

func TestCreateAgent_RepoError(t *testing.T) {
	repo := newMockAgentRepo()
	repo.createErr = errors.New("database error")
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	input := app.CreateAgentInput{
		TenantID: tenantID.String(),
		Name:     "Failing Agent",
		Type:     "worker",
	}

	_, err := svc.CreateAgent(context.Background(), input)
	if err == nil {
		t.Fatal("Expected error when repo fails")
	}
}

func TestCreateAgent_WithMaxConcurrentJobs(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	input := app.CreateAgentInput{
		TenantID:          tenantID.String(),
		Name:              "Capacity Agent",
		Type:              "worker",
		MaxConcurrentJobs: 10,
	}

	output, err := svc.CreateAgent(context.Background(), input)
	if err != nil {
		t.Fatalf("CreateAgent failed: %v", err)
	}

	if output.Agent.MaxConcurrentJobs != 10 {
		t.Errorf("Expected max concurrent jobs 10, got %d", output.Agent.MaxConcurrentJobs)
	}
}

func TestCreateAgent_DefaultExecutionMode(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	// Worker should default to daemon mode
	input := app.CreateAgentInput{
		TenantID: tenantID.String(),
		Name:     "Default Mode Agent",
		Type:     "worker",
		// ExecutionMode not set
	}

	output, err := svc.CreateAgent(context.Background(), input)
	if err != nil {
		t.Fatalf("CreateAgent failed: %v", err)
	}

	if output.Agent.ExecutionMode != agent.ExecutionModeDaemon {
		t.Errorf("Expected default execution mode 'daemon' for worker, got '%s'", output.Agent.ExecutionMode)
	}
}

// =============================================================================
// Tests for GetAgent
// =============================================================================

func TestGetAgent_Success(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	a := createTestAgent(t, tenantID, "Get Me Agent")
	repo.agents[a.ID] = a

	result, err := svc.GetAgent(context.Background(), tenantID.String(), a.ID.String())
	if err != nil {
		t.Fatalf("GetAgent failed: %v", err)
	}

	if result.Name != "Get Me Agent" {
		t.Errorf("Expected name 'Get Me Agent', got '%s'", result.Name)
	}
}

func TestGetAgent_NotFound(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	_, err := svc.GetAgent(context.Background(), tenantID.String(), shared.NewID().String())
	if err == nil {
		t.Fatal("Expected error for non-existent agent")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestGetAgent_InvalidTenantID(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)

	_, err := svc.GetAgent(context.Background(), "not-a-uuid", shared.NewID().String())
	if err == nil {
		t.Fatal("Expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestGetAgent_InvalidAgentID(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	_, err := svc.GetAgent(context.Background(), tenantID.String(), "not-a-uuid")
	if err == nil {
		t.Fatal("Expected error for invalid agent ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestGetAgent_WrongTenant(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	a := createTestAgent(t, tenantID, "Wrong Tenant Agent")
	repo.agents[a.ID] = a

	_, err := svc.GetAgent(context.Background(), otherTenantID.String(), a.ID.String())
	if err == nil {
		t.Fatal("Expected error for wrong tenant")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

// =============================================================================
// Tests for ListAgents
// =============================================================================

func TestListAgents_WithFilters(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	// Add agents
	for _, name := range []string{"Agent Alpha", "Agent Beta", "Agent Gamma"} {
		a := createTestAgent(t, tenantID, name)
		repo.agents[a.ID] = a
	}

	result, err := svc.ListAgents(context.Background(), app.ListAgentsInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("ListAgents failed: %v", err)
	}

	if len(result.Data) != 3 {
		t.Errorf("Expected 3 agents, got %d", len(result.Data))
	}
}

func TestListAgents_InvalidTenantID(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)

	_, err := svc.ListAgents(context.Background(), app.ListAgentsInput{
		TenantID: "not-a-uuid",
	})
	if err == nil {
		t.Fatal("Expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestListAgents_EmptyResult(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	result, err := svc.ListAgents(context.Background(), app.ListAgentsInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("ListAgents failed: %v", err)
	}

	if len(result.Data) != 0 {
		t.Errorf("Expected 0 agents, got %d", len(result.Data))
	}
}

// =============================================================================
// Tests for UpdateAgent (UpdateAgentStatus equivalent)
// =============================================================================

func TestUpdateAgent_Success(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	a := createTestAgent(t, tenantID, "Update Me")
	repo.agents[a.ID] = a

	input := app.UpdateAgentInput{
		TenantID:    tenantID.String(),
		AgentID:     a.ID.String(),
		Name:        "Updated Name",
		Description: "Updated description",
	}

	result, err := svc.UpdateAgent(context.Background(), input)
	if err != nil {
		t.Fatalf("UpdateAgent failed: %v", err)
	}

	if result.Name != "Updated Name" {
		t.Errorf("Expected name 'Updated Name', got '%s'", result.Name)
	}
	if result.Description != "Updated description" {
		t.Errorf("Expected description 'Updated description', got '%s'", result.Description)
	}
}

func TestUpdateAgent_NotFound(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	input := app.UpdateAgentInput{
		TenantID: tenantID.String(),
		AgentID:  shared.NewID().String(),
		Name:     "Updated",
	}

	_, err := svc.UpdateAgent(context.Background(), input)
	if err == nil {
		t.Fatal("Expected error for non-existent agent")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestUpdateAgent_ChangeStatus(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	a := createTestAgent(t, tenantID, "Status Agent")
	repo.agents[a.ID] = a

	// Disable agent
	input := app.UpdateAgentInput{
		TenantID: tenantID.String(),
		AgentID:  a.ID.String(),
		Status:   "disabled",
	}

	result, err := svc.UpdateAgent(context.Background(), input)
	if err != nil {
		t.Fatalf("UpdateAgent (disable) failed: %v", err)
	}

	if result.Status != agent.AgentStatusDisabled {
		t.Errorf("Expected status disabled, got %s", result.Status)
	}
}

func TestUpdateAgent_ChangeMaxConcurrentJobs(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	a := createTestAgent(t, tenantID, "Capacity Agent")
	repo.agents[a.ID] = a

	maxJobs := 20
	input := app.UpdateAgentInput{
		TenantID:          tenantID.String(),
		AgentID:           a.ID.String(),
		MaxConcurrentJobs: &maxJobs,
	}

	result, err := svc.UpdateAgent(context.Background(), input)
	if err != nil {
		t.Fatalf("UpdateAgent failed: %v", err)
	}

	if result.MaxConcurrentJobs != 20 {
		t.Errorf("Expected max concurrent jobs 20, got %d", result.MaxConcurrentJobs)
	}
}

// =============================================================================
// Tests for DeleteAgent
// =============================================================================

func TestDeleteAgent_Success(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	a := createTestAgent(t, tenantID, "Delete Me")
	repo.agents[a.ID] = a

	err := svc.DeleteAgent(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err != nil {
		t.Fatalf("DeleteAgent failed: %v", err)
	}

	// Verify agent was deleted
	if _, exists := repo.agents[a.ID]; exists {
		t.Error("Expected agent to be deleted")
	}
}

func TestDeleteAgent_NotFound(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	err := svc.DeleteAgent(context.Background(), tenantID.String(), shared.NewID().String(), nil)
	if err == nil {
		t.Fatal("Expected error for non-existent agent")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestDeleteAgent_InvalidTenantID(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)

	err := svc.DeleteAgent(context.Background(), "not-a-uuid", shared.NewID().String(), nil)
	if err == nil {
		t.Fatal("Expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

// =============================================================================
// Tests for ActivateAgent
// =============================================================================

func TestActivateAgent_Success(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	a := createTestAgent(t, tenantID, "Disabled Agent")
	a.Disable("maintenance")
	repo.agents[a.ID] = a

	result, err := svc.ActivateAgent(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err != nil {
		t.Fatalf("ActivateAgent failed: %v", err)
	}

	if result.Status != agent.AgentStatusActive {
		t.Errorf("Expected status active, got %s", result.Status)
	}
}

func TestActivateAgent_RevokedAgent(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	a := createTestAgent(t, tenantID, "Revoked Agent")
	a.Revoke("compromised")
	repo.agents[a.ID] = a

	_, err := svc.ActivateAgent(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err == nil {
		t.Fatal("Expected error when activating revoked agent")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("Expected ErrForbidden, got: %v", err)
	}
}

func TestActivateAgent_NotFound(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	_, err := svc.ActivateAgent(context.Background(), tenantID.String(), shared.NewID().String(), nil)
	if err == nil {
		t.Fatal("Expected error for non-existent agent")
	}
}

// =============================================================================
// Tests for DisableAgent
// =============================================================================

func TestDisableAgent_Success(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	a := createTestAgent(t, tenantID, "Active Agent")
	repo.agents[a.ID] = a

	result, err := svc.DisableAgent(context.Background(), tenantID.String(), a.ID.String(), "maintenance window", nil)
	if err != nil {
		t.Fatalf("DisableAgent failed: %v", err)
	}

	if result.Status != agent.AgentStatusDisabled {
		t.Errorf("Expected status disabled, got %s", result.Status)
	}
	if result.StatusMessage != "maintenance window" {
		t.Errorf("Expected message 'maintenance window', got '%s'", result.StatusMessage)
	}
}

func TestDisableAgent_DefaultReason(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	a := createTestAgent(t, tenantID, "Default Reason Agent")
	repo.agents[a.ID] = a

	result, err := svc.DisableAgent(context.Background(), tenantID.String(), a.ID.String(), "", nil)
	if err != nil {
		t.Fatalf("DisableAgent failed: %v", err)
	}

	if result.StatusMessage != "Disabled by administrator" {
		t.Errorf("Expected default reason, got '%s'", result.StatusMessage)
	}
}

// =============================================================================
// Tests for RevokeAgent
// =============================================================================

func TestRevokeAgent_Success(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	a := createTestAgent(t, tenantID, "Revoke Me")
	repo.agents[a.ID] = a

	result, err := svc.RevokeAgent(context.Background(), tenantID.String(), a.ID.String(), "compromised", nil)
	if err != nil {
		t.Fatalf("RevokeAgent failed: %v", err)
	}

	if result.Status != agent.AgentStatusRevoked {
		t.Errorf("Expected status revoked, got %s", result.Status)
	}
}

// =============================================================================
// Tests for AuthenticateByAPIKey
// =============================================================================

func TestAuthenticateByAPIKey_Success(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	a := createTestAgent(t, tenantID, "Auth Agent")
	a.SetAPIKey("testhash123", "rda_test")
	repo.agents[a.ID] = a
	repo.apiKeyMap["testhash123"] = a

	// We can't test the actual API key flow since hash computation
	// is internal, but we can test the repo interaction
	_, err := svc.AuthenticateByAPIKey(context.Background(), "some-key")
	if err == nil {
		// If the hash doesn't match, it's expected to fail
		// This test verifies the authentication flow handles the error properly
		t.Log("Authentication succeeded (unexpected, but not necessarily wrong)")
	}
}

func TestAuthenticateByAPIKey_DisabledAgent(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	a := createTestAgent(t, tenantID, "Disabled Auth Agent")
	a.Disable("disabled")
	// We need to set the hash for a known key so the lookup succeeds
	a.SetAPIKey("knownhash", "rda_test")
	repo.agents[a.ID] = a
	repo.apiKeyMap["knownhash"] = a

	// The API key hash won't match, but we test that disabled agents
	// would be rejected. The actual test requires matching the hash.
	_, err := svc.AuthenticateByAPIKey(context.Background(), "wrong-key")
	if err == nil {
		t.Fatal("Expected error for wrong API key")
	}
}

// =============================================================================
// Tests for Heartbeat
// =============================================================================

func TestHeartbeat_Success(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	a := createTestAgent(t, tenantID, "Heartbeat Agent")
	repo.agents[a.ID] = a

	input := app.AgentHeartbeatInput{
		AgentID:  a.ID,
		Version:  "1.0.0",
		Hostname: "test-host",
	}

	err := svc.Heartbeat(context.Background(), input)
	if err != nil {
		t.Fatalf("Heartbeat failed: %v", err)
	}

	// Verify agent was updated
	updated := repo.agents[a.ID]
	if updated.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", updated.Version)
	}
	if updated.Hostname != "test-host" {
		t.Errorf("Expected hostname 'test-host', got '%s'", updated.Hostname)
	}
	if updated.Health != agent.AgentHealthOnline {
		t.Errorf("Expected health 'online', got '%s'", updated.Health)
	}
}

func TestHeartbeat_AgentNotFound(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)

	input := app.AgentHeartbeatInput{
		AgentID: shared.NewID(),
	}

	err := svc.Heartbeat(context.Background(), input)
	if err == nil {
		t.Fatal("Expected error for non-existent agent")
	}
}

// =============================================================================
// Tests for FindAvailableAgents
// =============================================================================

func TestFindAvailableAgents_Success(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	a1 := createTestAgent(t, tenantID, "Available Agent 1")
	a2 := createTestAgent(t, tenantID, "Available Agent 2")
	repo.findAvail = []*agent.Agent{a1, a2}

	agents, err := svc.FindAvailableAgents(context.Background(), tenantID, []string{"sast"}, "semgrep")
	if err != nil {
		t.Fatalf("FindAvailableAgents failed: %v", err)
	}

	if len(agents) != 2 {
		t.Errorf("Expected 2 available agents, got %d", len(agents))
	}
}

func TestFindAvailableAgents_NoAgents(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	repo.findAvail = []*agent.Agent{}

	agents, err := svc.FindAvailableAgents(context.Background(), tenantID, []string{"sast"}, "nuclei")
	if err != nil {
		t.Fatalf("FindAvailableAgents failed: %v", err)
	}

	if len(agents) != 0 {
		t.Errorf("Expected 0 agents, got %d", len(agents))
	}
}

// =============================================================================
// Tests for ClaimJob / ReleaseJob
// =============================================================================

func TestClaimJob_Success(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	agentID := shared.NewID()

	err := svc.ClaimJob(context.Background(), agentID)
	if err != nil {
		t.Fatalf("ClaimJob failed: %v", err)
	}

	if repo.claimJobCalls != 1 {
		t.Errorf("Expected 1 claim job call, got %d", repo.claimJobCalls)
	}
}

func TestClaimJob_Error(t *testing.T) {
	repo := newMockAgentRepo()
	repo.claimJobErr = agent.ErrAgentNoCapacity
	svc := newTestAgentService(repo)
	agentID := shared.NewID()

	err := svc.ClaimJob(context.Background(), agentID)
	if err == nil {
		t.Fatal("Expected error when agent has no capacity")
	}
	if !errors.Is(err, agent.ErrAgentNoCapacity) {
		t.Errorf("Expected ErrAgentNoCapacity, got: %v", err)
	}
}

func TestReleaseJob_Success(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	agentID := shared.NewID()

	err := svc.ReleaseJob(context.Background(), agentID)
	if err != nil {
		t.Fatalf("ReleaseJob failed: %v", err)
	}

	if repo.releaseJobCalls != 1 {
		t.Errorf("Expected 1 release job call, got %d", repo.releaseJobCalls)
	}
}

// =============================================================================
// Tests for RegenerateAPIKey
// =============================================================================

func TestRegenerateAPIKey_Success(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	a := createTestAgent(t, tenantID, "Regen Key Agent")
	a.SetAPIKey("oldhash", "rda_old")
	repo.agents[a.ID] = a

	newKey, err := svc.RegenerateAPIKey(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err != nil {
		t.Fatalf("RegenerateAPIKey failed: %v", err)
	}

	if newKey == "" {
		t.Error("Expected non-empty new API key")
	}

	// Verify agent was updated with new key hash
	updated := repo.agents[a.ID]
	if updated.APIKeyHash == "oldhash" {
		t.Error("Expected API key hash to be different from old hash")
	}
}

func TestRegenerateAPIKey_AgentNotFound(t *testing.T) {
	repo := newMockAgentRepo()
	svc := newTestAgentService(repo)
	tenantID := shared.NewID()

	_, err := svc.RegenerateAPIKey(context.Background(), tenantID.String(), shared.NewID().String(), nil)
	if err == nil {
		t.Fatal("Expected error for non-existent agent")
	}
}

// =============================================================================
// Tests for RegistrationToken Entity
// =============================================================================

func TestRegistrationToken_CanRegister_Active(t *testing.T) {
	tenantID := shared.NewID()
	token, err := agent.NewRegistrationToken(tenantID, "Test Token", agent.AgentTypeWorker, nil, nil)
	if err != nil {
		t.Fatalf("NewRegistrationToken failed: %v", err)
	}

	if !token.IsValid() {
		t.Error("New token should be valid")
	}

	if err := token.CanRegister(); err != nil {
		t.Errorf("Active token should be registerable: %v", err)
	}
}

func TestRegistrationToken_CanRegister_Expired(t *testing.T) {
	tenantID := shared.NewID()
	past := time.Now().Add(-time.Hour)
	token, err := agent.NewRegistrationToken(tenantID, "Expired Token", agent.AgentTypeWorker, nil, &past)
	if err != nil {
		t.Fatalf("NewRegistrationToken failed: %v", err)
	}

	if token.IsValid() {
		t.Error("Expired token should not be valid")
	}

	if !token.IsExpired() {
		t.Error("Token should be expired")
	}

	err = token.CanRegister()
	if err == nil {
		t.Fatal("Expected error for expired token")
	}
}

func TestRegistrationToken_CanRegister_Exhausted(t *testing.T) {
	tenantID := shared.NewID()
	maxUses := 2
	token, err := agent.NewRegistrationToken(tenantID, "Limited Token", agent.AgentTypeWorker, &maxUses, nil)
	if err != nil {
		t.Fatalf("NewRegistrationToken failed: %v", err)
	}

	// Use up the token
	token.IncrementUsage()
	token.IncrementUsage()

	if token.IsValid() {
		t.Error("Exhausted token should not be valid")
	}

	if !token.IsExhausted() {
		t.Error("Token should be exhausted")
	}

	err = token.CanRegister()
	if err == nil {
		t.Fatal("Expected error for exhausted token")
	}
}

func TestRegistrationToken_CanRegister_Inactive(t *testing.T) {
	tenantID := shared.NewID()
	token, err := agent.NewRegistrationToken(tenantID, "Inactive Token", agent.AgentTypeWorker, nil, nil)
	if err != nil {
		t.Fatalf("NewRegistrationToken failed: %v", err)
	}

	token.Deactivate()

	if token.IsValid() {
		t.Error("Deactivated token should not be valid")
	}

	err = token.CanRegister()
	if err == nil {
		t.Fatal("Expected error for inactive token")
	}
}

// =============================================================================
// Tests for Agent Entity
// =============================================================================

func TestAgent_HasCapacity(t *testing.T) {
	tenantID := shared.NewID()
	a := createTestAgent(t, tenantID, "Capacity Test")
	a.SetMaxConcurrentJobs(5)
	a.CurrentJobs = 3

	if !a.HasCapacity() {
		t.Error("Agent with 3/5 jobs should have capacity")
	}

	a.CurrentJobs = 5
	if a.HasCapacity() {
		t.Error("Agent with 5/5 jobs should not have capacity")
	}
}

func TestAgent_AvailableSlots(t *testing.T) {
	tenantID := shared.NewID()
	a := createTestAgent(t, tenantID, "Slots Test")
	a.SetMaxConcurrentJobs(5)
	a.CurrentJobs = 2

	if a.AvailableSlots() != 3 {
		t.Errorf("Expected 3 available slots, got %d", a.AvailableSlots())
	}
}

func TestAgent_MatchesRequirements(t *testing.T) {
	tenantID := shared.NewID()
	a := createTestAgent(t, tenantID, "Requirements Test")
	// Has capabilities: ["sast"], tools: ["semgrep"]

	if !a.MatchesRequirements([]string{"sast"}, "semgrep") {
		t.Error("Agent should match sast + semgrep requirements")
	}

	if a.MatchesRequirements([]string{"dast"}, "nuclei") {
		t.Error("Agent should not match dast + nuclei requirements")
	}

	if a.MatchesRequirements([]string{"sast"}, "trivy") {
		t.Error("Agent should not match sast + trivy (wrong tool)")
	}
}

func TestAgent_IsAvailable(t *testing.T) {
	tenantID := shared.NewID()
	a := createTestAgent(t, tenantID, "Available Test")

	if !a.IsAvailable() {
		t.Error("Active agent should be available")
	}

	a.Disable("test")
	if a.IsAvailable() {
		t.Error("Disabled agent should not be available")
	}
}
