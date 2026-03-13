package unit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ============================================================================
// Mock Repository
// ============================================================================

// agentSvcMockRepo implements agent.Repository for testing.
type agentSvcMockRepo struct {
	mu     sync.Mutex
	agents map[string]*agent.Agent // keyed by agent ID string

	// Error injection
	createErr                  error
	getByIDErr                 error
	getByTenantAndIDErr        error
	getByAPIKeyHashErr         error
	listErr                    error
	updateErr                  error
	deleteErr                  error
	updateLastSeenErr          error
	incrementStatsErr          error
	findAvailableErr           error
	findAvailableWithCapErr    error
	claimJobErr                error
	releaseJobErr              error
	getAvailableCapabilitiesErr error
	hasAgentForCapabilityErr   error
	getPlatformAgentStatsErr   error

	// Return overrides
	availableAgents     []*agent.Agent
	availableCapAgents  []*agent.Agent
	capabilities        []string
	hasCapability       bool
	platformStats       *agent.PlatformAgentStatsResult

	// Call tracking
	createCalls              int
	getByIDCalls             int
	getByTenantAndIDCalls    int
	getByAPIKeyHashCalls     int
	listCalls                int
	updateCalls              int
	deleteCalls              int
	updateLastSeenCalls      int
	incrementStatsCalls      int
	findAvailableCalls       int
	findAvailableCapCalls    int
	claimJobCalls            int
	releaseJobCalls          int
	getAvailCapCalls         int
	hasAgentCapCalls         int
	getPlatformStatsCalls    int

	// Last args
	lastFilter     agent.Filter
	lastPagination pagination.Pagination
	lastAPIKeyHash string
	lastStatsArgs  struct {
		findings, scans, errors int64
	}
}

func newAgentSvcMockRepo() *agentSvcMockRepo {
	return &agentSvcMockRepo{
		agents: make(map[string]*agent.Agent),
	}
}

func (m *agentSvcMockRepo) Create(_ context.Context, a *agent.Agent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.agents[a.ID.String()] = a
	return nil
}

func (m *agentSvcMockRepo) CountByTenant(_ context.Context, _ shared.ID) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, a := range m.agents {
		count++
		_ = a
	}
	return count, nil
}

func (m *agentSvcMockRepo) GetByID(_ context.Context, id shared.ID) (*agent.Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getByIDCalls++
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	a, ok := m.agents[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return a, nil
}

func (m *agentSvcMockRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*agent.Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getByTenantAndIDCalls++
	if m.getByTenantAndIDErr != nil {
		return nil, m.getByTenantAndIDErr
	}
	a, ok := m.agents[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	// IDOR check
	if a.TenantID == nil || *a.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return a, nil
}

func (m *agentSvcMockRepo) GetByAPIKeyHash(_ context.Context, hash string) (*agent.Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getByAPIKeyHashCalls++
	m.lastAPIKeyHash = hash
	if m.getByAPIKeyHashErr != nil {
		return nil, m.getByAPIKeyHashErr
	}
	for _, a := range m.agents {
		if a.APIKeyHash == hash {
			return a, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *agentSvcMockRepo) List(_ context.Context, filter agent.Filter, page pagination.Pagination) (pagination.Result[*agent.Agent], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listCalls++
	m.lastFilter = filter
	m.lastPagination = page
	if m.listErr != nil {
		return pagination.Result[*agent.Agent]{}, m.listErr
	}
	var results []*agent.Agent
	for _, a := range m.agents {
		if filter.TenantID != nil && (a.TenantID == nil || *a.TenantID != *filter.TenantID) {
			continue
		}
		results = append(results, a)
	}
	total := int64(len(results))
	return pagination.Result[*agent.Agent]{
		Data:       results,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: 1,
	}, nil
}

func (m *agentSvcMockRepo) Update(_ context.Context, a *agent.Agent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.agents[a.ID.String()] = a
	return nil
}

func (m *agentSvcMockRepo) Delete(_ context.Context, id shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.agents, id.String())
	return nil
}

func (m *agentSvcMockRepo) UpdateLastSeen(_ context.Context, _ shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateLastSeenCalls++
	return m.updateLastSeenErr
}

func (m *agentSvcMockRepo) IncrementStats(_ context.Context, _ shared.ID, findings, scans, errs int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.incrementStatsCalls++
	m.lastStatsArgs.findings = findings
	m.lastStatsArgs.scans = scans
	m.lastStatsArgs.errors = errs
	return m.incrementStatsErr
}

func (m *agentSvcMockRepo) FindByCapabilities(_ context.Context, _ shared.ID, _ []string, _ string) ([]*agent.Agent, error) {
	return nil, nil
}

func (m *agentSvcMockRepo) FindAvailable(_ context.Context, _ shared.ID, _ []string, _ string) ([]*agent.Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findAvailableCalls++
	if m.findAvailableErr != nil {
		return nil, m.findAvailableErr
	}
	return m.availableAgents, nil
}

func (m *agentSvcMockRepo) FindAvailableWithTool(_ context.Context, _ shared.ID, _ string) (*agent.Agent, error) {
	return nil, nil
}

func (m *agentSvcMockRepo) MarkStaleAsOffline(_ context.Context, _ time.Duration) (int64, error) {
	return 0, nil
}

func (m *agentSvcMockRepo) FindAvailableWithCapacity(_ context.Context, _ shared.ID, _ []string, _ string) ([]*agent.Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findAvailableCapCalls++
	if m.findAvailableWithCapErr != nil {
		return nil, m.findAvailableWithCapErr
	}
	return m.availableCapAgents, nil
}

func (m *agentSvcMockRepo) ClaimJob(_ context.Context, _ shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.claimJobCalls++
	return m.claimJobErr
}

func (m *agentSvcMockRepo) ReleaseJob(_ context.Context, _ shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releaseJobCalls++
	return m.releaseJobErr
}

func (m *agentSvcMockRepo) UpdateOfflineTimestamp(_ context.Context, _ shared.ID) error {
	return nil
}

func (m *agentSvcMockRepo) MarkStaleAgentsOffline(_ context.Context, _ time.Duration) ([]shared.ID, error) {
	return nil, nil
}

func (m *agentSvcMockRepo) GetAgentsOfflineSince(_ context.Context, _ time.Time) ([]*agent.Agent, error) {
	return nil, nil
}

func (m *agentSvcMockRepo) GetAvailableToolsForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return nil, nil
}

func (m *agentSvcMockRepo) HasAgentForTool(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}

func (m *agentSvcMockRepo) GetAvailableCapabilitiesForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getAvailCapCalls++
	if m.getAvailableCapabilitiesErr != nil {
		return nil, m.getAvailableCapabilitiesErr
	}
	return m.capabilities, nil
}

func (m *agentSvcMockRepo) HasAgentForCapability(_ context.Context, _ shared.ID, _ string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hasAgentCapCalls++
	if m.hasAgentForCapabilityErr != nil {
		return false, m.hasAgentForCapabilityErr
	}
	return m.hasCapability, nil
}

func (m *agentSvcMockRepo) GetPlatformAgentStats(_ context.Context, _ shared.ID) (*agent.PlatformAgentStatsResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getPlatformStatsCalls++
	if m.getPlatformAgentStatsErr != nil {
		return nil, m.getPlatformAgentStatsErr
	}
	if m.platformStats != nil {
		return m.platformStats, nil
	}
	return &agent.PlatformAgentStatsResult{
		TierBreakdown: make(map[string]agent.TierBreakdown),
	}, nil
}

// seedAgent creates and stores an agent in the mock repo.
func (m *agentSvcMockRepo) seedAgent(tenantID shared.ID, name string, agentType agent.AgentType) *agent.Agent {
	a, _ := agent.NewAgent(tenantID, name, agentType, "test agent", []string{"sast"}, []string{"semgrep"}, agent.ExecutionModeStandalone)
	m.agents[a.ID.String()] = a
	return a
}

// ============================================================================
// Helper functions
// ============================================================================

func newAgentSvcTestService(repo *agentSvcMockRepo) *app.AgentService {
	log := logger.NewNop()
	return app.NewAgentService(repo, nil, log)
}

func agentSvcValidTenantID() string {
	return shared.NewID().String()
}

// ============================================================================
// Tests: CreateAgent
// ============================================================================

func TestAgentService_CreateAgent_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	input := app.CreateAgentInput{
		TenantID:     agentSvcValidTenantID(),
		Name:         "test-runner",
		Type:         "runner",
		Description:  "A test runner agent",
		Capabilities: []string{"sast", "sca"},
		Tools:        []string{"semgrep", "trivy"},
	}

	out, err := svc.CreateAgent(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if out.Agent == nil {
		t.Fatal("expected agent to be non-nil")
	}

	if out.Agent.Name != "test-runner" {
		t.Errorf("expected name 'test-runner', got %q", out.Agent.Name)
	}

	if out.Agent.Type != agent.AgentTypeRunner {
		t.Errorf("expected type 'runner', got %q", out.Agent.Type)
	}

	if out.Agent.Status != agent.AgentStatusActive {
		t.Errorf("expected status 'active', got %q", out.Agent.Status)
	}

	if out.Agent.Health != agent.AgentHealthUnknown {
		t.Errorf("expected health 'unknown', got %q", out.Agent.Health)
	}

	// API key must start with "rda_"
	if !strings.HasPrefix(out.APIKey, "rda_") {
		t.Errorf("expected API key to start with 'rda_', got %q", out.APIKey)
	}

	// API key length: "rda_" + 64 hex chars = 68
	if len(out.APIKey) != 68 {
		t.Errorf("expected API key length 68, got %d", len(out.APIKey))
	}

	if out.Agent.APIKeyHash == "" {
		t.Error("expected API key hash to be set")
	}

	if out.Agent.APIKeyPrefix == "" {
		t.Error("expected API key prefix to be set")
	}

	if repo.createCalls != 1 {
		t.Errorf("expected 1 Create call, got %d", repo.createCalls)
	}
}

func TestAgentService_CreateAgent_DefaultExecutionMode(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	tests := []struct {
		agentType    string
		expectedMode agent.ExecutionMode
	}{
		{"runner", agent.ExecutionModeStandalone},
		{"worker", agent.ExecutionModeDaemon},
		{"collector", agent.ExecutionModeDaemon},
		{"sensor", agent.ExecutionModeDaemon},
	}

	for _, tc := range tests {
		t.Run(tc.agentType, func(t *testing.T) {
			input := app.CreateAgentInput{
				TenantID: agentSvcValidTenantID(),
				Name:     "test-" + tc.agentType,
				Type:     tc.agentType,
			}
			out, err := svc.CreateAgent(context.Background(), input)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if out.Agent.ExecutionMode != tc.expectedMode {
				t.Errorf("expected execution mode %q for type %q, got %q", tc.expectedMode, tc.agentType, out.Agent.ExecutionMode)
			}
		})
	}
}

func TestAgentService_CreateAgent_MaxConcurrentJobs(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	input := app.CreateAgentInput{
		TenantID:          agentSvcValidTenantID(),
		Name:              "worker-1",
		Type:              "worker",
		MaxConcurrentJobs: 10,
	}

	out, err := svc.CreateAgent(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if out.Agent.MaxConcurrentJobs != 10 {
		t.Errorf("expected max concurrent jobs 10, got %d", out.Agent.MaxConcurrentJobs)
	}
}

func TestAgentService_CreateAgent_InvalidTenantID(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	input := app.CreateAgentInput{
		TenantID: "not-a-uuid",
		Name:     "test-agent",
		Type:     "runner",
	}

	_, err := svc.CreateAgent(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAgentService_CreateAgent_RepoError(t *testing.T) {
	repo := newAgentSvcMockRepo()
	repo.createErr = errors.New("db connection failed")
	svc := newAgentSvcTestService(repo)

	input := app.CreateAgentInput{
		TenantID: agentSvcValidTenantID(),
		Name:     "test-agent",
		Type:     "runner",
	}

	_, err := svc.CreateAgent(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when repo.Create fails")
	}
}

func TestAgentService_CreateAgent_EmptyName(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	input := app.CreateAgentInput{
		TenantID: agentSvcValidTenantID(),
		Name:     "",
		Type:     "runner",
	}

	_, err := svc.CreateAgent(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAgentService_CreateAgent_InvalidType(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	input := app.CreateAgentInput{
		TenantID: agentSvcValidTenantID(),
		Name:     "test-agent",
		Type:     "invalid-type",
	}

	_, err := svc.CreateAgent(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid agent type")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// ============================================================================
// Tests: GetAgent
// ============================================================================

func TestAgentService_GetAgent_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "my-runner", agent.AgentTypeRunner)

	got, err := svc.GetAgent(context.Background(), tenantID.String(), a.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got.ID != a.ID {
		t.Errorf("expected agent ID %s, got %s", a.ID, got.ID)
	}
}

func TestAgentService_GetAgent_InvalidTenantID(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	_, err := svc.GetAgent(context.Background(), "bad-id", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAgentService_GetAgent_InvalidAgentID(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	_, err := svc.GetAgent(context.Background(), agentSvcValidTenantID(), "bad-id")
	if err == nil {
		t.Fatal("expected error for invalid agent ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAgentService_GetAgent_NotFound(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	_, err := svc.GetAgent(context.Background(), agentSvcValidTenantID(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent agent")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAgentService_GetAgent_IDORPrevention(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	tenantA := shared.NewID()
	tenantB := shared.NewID()
	a := repo.seedAgent(tenantA, "agent-a", agent.AgentTypeRunner)

	// Try to access tenant A's agent using tenant B's ID
	_, err := svc.GetAgent(context.Background(), tenantB.String(), a.ID.String())
	if err == nil {
		t.Fatal("expected error when accessing another tenant's agent (IDOR)")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound for IDOR prevention, got %v", err)
	}
}

// ============================================================================
// Tests: ListAgents
// ============================================================================

func TestAgentService_ListAgents_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	repo.seedAgent(tenantID, "runner-1", agent.AgentTypeRunner)
	repo.seedAgent(tenantID, "worker-1", agent.AgentTypeWorker)

	result, err := svc.ListAgents(context.Background(), app.ListAgentsInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected 2 agents, got %d", result.Total)
	}
}

func TestAgentService_ListAgents_WithTypeFilter(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	repo.seedAgent(tenantID, "runner-1", agent.AgentTypeRunner)

	_, err := svc.ListAgents(context.Background(), app.ListAgentsInput{
		TenantID: tenantID.String(),
		Type:     "runner",
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.lastFilter.Type == nil || *repo.lastFilter.Type != agent.AgentTypeRunner {
		t.Error("expected type filter to be set to runner")
	}
}

func TestAgentService_ListAgents_WithStatusFilter(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	_, err := svc.ListAgents(context.Background(), app.ListAgentsInput{
		TenantID: agentSvcValidTenantID(),
		Status:   "active",
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.lastFilter.Status == nil || *repo.lastFilter.Status != agent.AgentStatusActive {
		t.Error("expected status filter to be set to active")
	}
}

func TestAgentService_ListAgents_WithHealthFilter(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	_, err := svc.ListAgents(context.Background(), app.ListAgentsInput{
		TenantID: agentSvcValidTenantID(),
		Health:   "online",
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.lastFilter.Health == nil || *repo.lastFilter.Health != agent.AgentHealthOnline {
		t.Error("expected health filter to be set to online")
	}
}

func TestAgentService_ListAgents_WithExecutionModeFilter(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	_, err := svc.ListAgents(context.Background(), app.ListAgentsInput{
		TenantID:      agentSvcValidTenantID(),
		ExecutionMode: "daemon",
		Page:          1,
		PerPage:       10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.lastFilter.ExecutionMode == nil || *repo.lastFilter.ExecutionMode != agent.ExecutionModeDaemon {
		t.Error("expected execution mode filter to be set to daemon")
	}
}

func TestAgentService_ListAgents_InvalidTenantID(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	_, err := svc.ListAgents(context.Background(), app.ListAgentsInput{
		TenantID: "not-a-uuid",
	})
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAgentService_ListAgents_RepoError(t *testing.T) {
	repo := newAgentSvcMockRepo()
	repo.listErr = errors.New("db error")
	svc := newAgentSvcTestService(repo)

	_, err := svc.ListAgents(context.Background(), app.ListAgentsInput{
		TenantID: agentSvcValidTenantID(),
		Page:     1,
		PerPage:  10,
	})
	if err == nil {
		t.Fatal("expected error when repo.List fails")
	}
}

// ============================================================================
// Tests: UpdateAgent
// ============================================================================

func TestAgentService_UpdateAgent_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "old-name", agent.AgentTypeRunner)

	updated, err := svc.UpdateAgent(context.Background(), app.UpdateAgentInput{
		TenantID:    tenantID.String(),
		AgentID:     a.ID.String(),
		Name:        "new-name",
		Description: "updated description",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.Name != "new-name" {
		t.Errorf("expected name 'new-name', got %q", updated.Name)
	}
	if updated.Description != "updated description" {
		t.Errorf("expected description 'updated description', got %q", updated.Description)
	}
}

func TestAgentService_UpdateAgent_Capabilities(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)

	updated, err := svc.UpdateAgent(context.Background(), app.UpdateAgentInput{
		TenantID:     tenantID.String(),
		AgentID:      a.ID.String(),
		Capabilities: []string{"dast", "api"},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(updated.Capabilities) != 2 || updated.Capabilities[0] != "dast" {
		t.Errorf("expected capabilities [dast, api], got %v", updated.Capabilities)
	}
}

func TestAgentService_UpdateAgent_Tools(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)

	updated, err := svc.UpdateAgent(context.Background(), app.UpdateAgentInput{
		TenantID: tenantID.String(),
		AgentID:  a.ID.String(),
		Tools:    []string{"nuclei", "nmap"},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(updated.Tools) != 2 || updated.Tools[0] != "nuclei" {
		t.Errorf("expected tools [nuclei, nmap], got %v", updated.Tools)
	}
}

func TestAgentService_UpdateAgent_Status(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)

	updated, err := svc.UpdateAgent(context.Background(), app.UpdateAgentInput{
		TenantID: tenantID.String(),
		AgentID:  a.ID.String(),
		Status:   "disabled",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.Status != agent.AgentStatusDisabled {
		t.Errorf("expected status 'disabled', got %q", updated.Status)
	}
}

func TestAgentService_UpdateAgent_MaxConcurrentJobs(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeWorker)

	maxJobs := 20
	updated, err := svc.UpdateAgent(context.Background(), app.UpdateAgentInput{
		TenantID:          tenantID.String(),
		AgentID:           a.ID.String(),
		MaxConcurrentJobs: &maxJobs,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.MaxConcurrentJobs != 20 {
		t.Errorf("expected max concurrent jobs 20, got %d", updated.MaxConcurrentJobs)
	}
}

func TestAgentService_UpdateAgent_NotFound(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	_, err := svc.UpdateAgent(context.Background(), app.UpdateAgentInput{
		TenantID: agentSvcValidTenantID(),
		AgentID:  shared.NewID().String(),
		Name:     "new-name",
	})
	if err == nil {
		t.Fatal("expected error for non-existent agent")
	}
}

func TestAgentService_UpdateAgent_RepoError(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)
	repo.updateErr = errors.New("update failed")

	_, err := svc.UpdateAgent(context.Background(), app.UpdateAgentInput{
		TenantID: tenantID.String(),
		AgentID:  a.ID.String(),
		Name:     "new-name",
	})
	if err == nil {
		t.Fatal("expected error when repo.Update fails")
	}
}

func TestAgentService_UpdateAgent_NoChanges(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)

	// Update with same name and empty fields
	updated, err := svc.UpdateAgent(context.Background(), app.UpdateAgentInput{
		TenantID: tenantID.String(),
		AgentID:  a.ID.String(),
		Name:     "agent-1", // same name
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.Name != "agent-1" {
		t.Errorf("expected name unchanged")
	}
}

// ============================================================================
// Tests: UpdateHeartbeat
// ============================================================================

func TestAgentService_UpdateHeartbeat_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeWorker)

	err := svc.UpdateHeartbeat(context.Background(), a.ID, app.AgentHeartbeatData{
		Version:       "1.2.0",
		Hostname:      "worker-node-1",
		CPUPercent:    45.5,
		MemoryPercent: 62.3,
		CurrentJobs:   3,
		Region:        "us-east-1",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	updated := repo.agents[a.ID.String()]
	if updated.Version != "1.2.0" {
		t.Errorf("expected version '1.2.0', got %q", updated.Version)
	}
	if updated.Hostname != "worker-node-1" {
		t.Errorf("expected hostname 'worker-node-1', got %q", updated.Hostname)
	}
	if updated.Health != agent.AgentHealthOnline {
		t.Errorf("expected health 'online' after heartbeat, got %q", updated.Health)
	}
	if updated.LastSeenAt == nil {
		t.Error("expected LastSeenAt to be set after heartbeat")
	}
}

func TestAgentService_UpdateHeartbeat_NotFound(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	err := svc.UpdateHeartbeat(context.Background(), shared.NewID(), app.AgentHeartbeatData{})
	if err == nil {
		t.Fatal("expected error for non-existent agent")
	}
}

func TestAgentService_UpdateHeartbeat_UpdateError(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeWorker)
	repo.updateErr = errors.New("update failed")

	err := svc.UpdateHeartbeat(context.Background(), a.ID, app.AgentHeartbeatData{
		Version: "1.0.0",
	})
	if err == nil {
		t.Fatal("expected error when repo.Update fails")
	}
}

// ============================================================================
// Tests: DeleteAgent
// ============================================================================

func TestAgentService_DeleteAgent_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-to-delete", agent.AgentTypeRunner)

	err := svc.DeleteAgent(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.deleteCalls != 1 {
		t.Errorf("expected 1 Delete call, got %d", repo.deleteCalls)
	}

	// Agent should be gone
	if _, exists := repo.agents[a.ID.String()]; exists {
		t.Error("expected agent to be removed from repo")
	}
}

func TestAgentService_DeleteAgent_InvalidTenantID(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	err := svc.DeleteAgent(context.Background(), "bad-id", shared.NewID().String(), nil)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAgentService_DeleteAgent_InvalidAgentID(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	err := svc.DeleteAgent(context.Background(), agentSvcValidTenantID(), "bad-id", nil)
	if err == nil {
		t.Fatal("expected error for invalid agent ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAgentService_DeleteAgent_NotFound(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	err := svc.DeleteAgent(context.Background(), agentSvcValidTenantID(), shared.NewID().String(), nil)
	if err == nil {
		t.Fatal("expected error for non-existent agent")
	}
}

func TestAgentService_DeleteAgent_IDORPrevention(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantA := shared.NewID()
	tenantB := shared.NewID()
	a := repo.seedAgent(tenantA, "agent-a", agent.AgentTypeRunner)

	err := svc.DeleteAgent(context.Background(), tenantB.String(), a.ID.String(), nil)
	if err == nil {
		t.Fatal("expected error when deleting another tenant's agent (IDOR)")
	}
}

func TestAgentService_DeleteAgent_RepoError(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)
	repo.deleteErr = errors.New("delete failed")

	err := svc.DeleteAgent(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err == nil {
		t.Fatal("expected error when repo.Delete fails")
	}
}

// ============================================================================
// Tests: RegenerateAPIKey
// ============================================================================

func TestAgentService_RegenerateAPIKey_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)
	oldHash := a.APIKeyHash

	newKey, err := svc.RegenerateAPIKey(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !strings.HasPrefix(newKey, "rda_") {
		t.Errorf("expected regenerated key to start with 'rda_', got %q", newKey)
	}

	updated := repo.agents[a.ID.String()]
	if updated.APIKeyHash == oldHash {
		t.Error("expected API key hash to change after regeneration")
	}
}

func TestAgentService_RegenerateAPIKey_NotFound(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	_, err := svc.RegenerateAPIKey(context.Background(), agentSvcValidTenantID(), shared.NewID().String(), nil)
	if err == nil {
		t.Fatal("expected error for non-existent agent")
	}
}

func TestAgentService_RegenerateAPIKey_UpdateError(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)
	repo.updateErr = errors.New("update failed")

	_, err := svc.RegenerateAPIKey(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err == nil {
		t.Fatal("expected error when repo.Update fails")
	}
}

// ============================================================================
// Tests: AuthenticateByAPIKey
// ============================================================================

func TestAgentService_AuthenticateByAPIKey_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()

	// Create an agent via service to get a valid API key
	out, err := svc.CreateAgent(context.Background(), app.CreateAgentInput{
		TenantID: tenantID.String(),
		Name:     "auth-agent",
		Type:     "runner",
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	// Authenticate with the key
	authenticated, err := svc.AuthenticateByAPIKey(context.Background(), out.APIKey)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if authenticated.ID != out.Agent.ID {
		t.Errorf("expected agent ID %s, got %s", out.Agent.ID, authenticated.ID)
	}
}

func TestAgentService_AuthenticateByAPIKey_InvalidKey(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	_, err := svc.AuthenticateByAPIKey(context.Background(), "rda_invalid_key_here")
	if err == nil {
		t.Fatal("expected error for invalid API key")
	}
	if !errors.Is(err, shared.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized, got %v", err)
	}
}

func TestAgentService_AuthenticateByAPIKey_DisabledAgent(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()

	out, err := svc.CreateAgent(context.Background(), app.CreateAgentInput{
		TenantID: tenantID.String(),
		Name:     "disabled-agent",
		Type:     "runner",
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	// Disable the agent
	out.Agent.Disable("test disable")
	repo.agents[out.Agent.ID.String()] = out.Agent

	_, err = svc.AuthenticateByAPIKey(context.Background(), out.APIKey)
	if err == nil {
		t.Fatal("expected error for disabled agent")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

func TestAgentService_AuthenticateByAPIKey_RevokedAgent(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()

	out, err := svc.CreateAgent(context.Background(), app.CreateAgentInput{
		TenantID: tenantID.String(),
		Name:     "revoked-agent",
		Type:     "runner",
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	// Revoke the agent
	out.Agent.Revoke("compromised")
	repo.agents[out.Agent.ID.String()] = out.Agent

	_, err = svc.AuthenticateByAPIKey(context.Background(), out.APIKey)
	if err == nil {
		t.Fatal("expected error for revoked agent")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("expected error message to mention 'revoked', got %q", err.Error())
	}
}

// ============================================================================
// Tests: ActivateAgent
// ============================================================================

func TestAgentService_ActivateAgent_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)
	a.Disable("maintenance")

	activated, err := svc.ActivateAgent(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if activated.Status != agent.AgentStatusActive {
		t.Errorf("expected status 'active', got %q", activated.Status)
	}
}

func TestAgentService_ActivateAgent_RevokedCannotReactivate(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)
	a.Revoke("compromised")

	_, err := svc.ActivateAgent(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err == nil {
		t.Fatal("expected error when activating revoked agent")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("expected error message to mention 'revoked', got %q", err.Error())
	}
}

func TestAgentService_ActivateAgent_NotFound(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	_, err := svc.ActivateAgent(context.Background(), agentSvcValidTenantID(), shared.NewID().String(), nil)
	if err == nil {
		t.Fatal("expected error for non-existent agent")
	}
}

func TestAgentService_ActivateAgent_RepoError(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)
	a.Disable("test")
	repo.updateErr = errors.New("update failed")

	_, err := svc.ActivateAgent(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err == nil {
		t.Fatal("expected error when repo.Update fails")
	}
}

// ============================================================================
// Tests: DisableAgent
// ============================================================================

func TestAgentService_DisableAgent_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)

	disabled, err := svc.DisableAgent(context.Background(), tenantID.String(), a.ID.String(), "maintenance window", nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if disabled.Status != agent.AgentStatusDisabled {
		t.Errorf("expected status 'disabled', got %q", disabled.Status)
	}
	if disabled.StatusMessage != "maintenance window" {
		t.Errorf("expected status message 'maintenance window', got %q", disabled.StatusMessage)
	}
}

func TestAgentService_DisableAgent_DefaultReason(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)

	disabled, err := svc.DisableAgent(context.Background(), tenantID.String(), a.ID.String(), "", nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if disabled.StatusMessage != "Disabled by administrator" {
		t.Errorf("expected default reason 'Disabled by administrator', got %q", disabled.StatusMessage)
	}
}

func TestAgentService_DisableAgent_NotFound(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	_, err := svc.DisableAgent(context.Background(), agentSvcValidTenantID(), shared.NewID().String(), "test", nil)
	if err == nil {
		t.Fatal("expected error for non-existent agent")
	}
}

// ============================================================================
// Tests: RevokeAgent
// ============================================================================

func TestAgentService_RevokeAgent_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)

	revoked, err := svc.RevokeAgent(context.Background(), tenantID.String(), a.ID.String(), "compromised key", nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if revoked.Status != agent.AgentStatusRevoked {
		t.Errorf("expected status 'revoked', got %q", revoked.Status)
	}
	if revoked.StatusMessage != "compromised key" {
		t.Errorf("expected status message 'compromised key', got %q", revoked.StatusMessage)
	}
}

func TestAgentService_RevokeAgent_DefaultReason(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)

	revoked, err := svc.RevokeAgent(context.Background(), tenantID.String(), a.ID.String(), "", nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if revoked.StatusMessage != "Revoked by administrator" {
		t.Errorf("expected default reason 'Revoked by administrator', got %q", revoked.StatusMessage)
	}
}

func TestAgentService_RevokeAgent_NotFound(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	_, err := svc.RevokeAgent(context.Background(), agentSvcValidTenantID(), shared.NewID().String(), "test", nil)
	if err == nil {
		t.Fatal("expected error for non-existent agent")
	}
}

func TestAgentService_RevokeAgent_RepoError(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)
	repo.updateErr = errors.New("update failed")

	_, err := svc.RevokeAgent(context.Background(), tenantID.String(), a.ID.String(), "test", nil)
	if err == nil {
		t.Fatal("expected error when repo.Update fails")
	}
}

// ============================================================================
// Tests: Heartbeat
// ============================================================================

func TestAgentService_Heartbeat_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeWorker)

	err := svc.Heartbeat(context.Background(), app.AgentHeartbeatInput{
		AgentID:   a.ID,
		Status:    "online",
		Message:   "all good",
		Version:   "2.0.0",
		Hostname:  "node-42",
		IPAddress: "192.168.1.100",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	updated := repo.agents[a.ID.String()]
	if updated.Health != agent.AgentHealthOnline {
		t.Errorf("expected health 'online', got %q", updated.Health)
	}
	if updated.Version != "2.0.0" {
		t.Errorf("expected version '2.0.0', got %q", updated.Version)
	}
	if updated.Hostname != "node-42" {
		t.Errorf("expected hostname 'node-42', got %q", updated.Hostname)
	}
	if updated.IPAddress.String() != "192.168.1.100" {
		t.Errorf("expected IP '192.168.1.100', got %q", updated.IPAddress)
	}
	if updated.StatusMessage != "all good" {
		t.Errorf("expected status message 'all good', got %q", updated.StatusMessage)
	}
	if updated.LastSeenAt == nil {
		t.Error("expected LastSeenAt to be set")
	}
}

func TestAgentService_Heartbeat_MinimalInput(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeWorker)

	err := svc.Heartbeat(context.Background(), app.AgentHeartbeatInput{
		AgentID: a.ID,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	updated := repo.agents[a.ID.String()]
	if updated.Health != agent.AgentHealthOnline {
		t.Errorf("expected health 'online' after heartbeat, got %q", updated.Health)
	}
}

func TestAgentService_Heartbeat_NotFound(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	err := svc.Heartbeat(context.Background(), app.AgentHeartbeatInput{
		AgentID: shared.NewID(),
	})
	if err == nil {
		t.Fatal("expected error for non-existent agent")
	}
}

func TestAgentService_Heartbeat_UpdateError(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeWorker)
	repo.updateErr = errors.New("update failed")

	err := svc.Heartbeat(context.Background(), app.AgentHeartbeatInput{
		AgentID: a.ID,
		Version: "1.0.0",
	})
	if err == nil {
		t.Fatal("expected error when repo.Update fails")
	}
}

// ============================================================================
// Tests: FindAvailableAgents
// ============================================================================

func TestAgentService_FindAvailableAgents_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)
	repo.availableAgents = []*agent.Agent{a}

	agents, err := svc.FindAvailableAgents(context.Background(), tenantID, []string{"sast"}, "semgrep")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(agents) != 1 {
		t.Errorf("expected 1 available agent, got %d", len(agents))
	}
}

func TestAgentService_FindAvailableAgents_Empty(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	repo.availableAgents = []*agent.Agent{}

	agents, err := svc.FindAvailableAgents(context.Background(), shared.NewID(), []string{"sast"}, "semgrep")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(agents) != 0 {
		t.Errorf("expected 0 available agents, got %d", len(agents))
	}
}

func TestAgentService_FindAvailableAgents_RepoError(t *testing.T) {
	repo := newAgentSvcMockRepo()
	repo.findAvailableErr = errors.New("db error")
	svc := newAgentSvcTestService(repo)

	_, err := svc.FindAvailableAgents(context.Background(), shared.NewID(), []string{"sast"}, "semgrep")
	if err == nil {
		t.Fatal("expected error when repo.FindAvailable fails")
	}
}

// ============================================================================
// Tests: FindAvailableWithCapacity
// ============================================================================

func TestAgentService_FindAvailableWithCapacity_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeWorker)
	repo.availableCapAgents = []*agent.Agent{a}

	agents, err := svc.FindAvailableWithCapacity(context.Background(), tenantID, []string{"sast"}, "semgrep")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(agents) != 1 {
		t.Errorf("expected 1 agent with capacity, got %d", len(agents))
	}
}

func TestAgentService_FindAvailableWithCapacity_RepoError(t *testing.T) {
	repo := newAgentSvcMockRepo()
	repo.findAvailableWithCapErr = errors.New("db error")
	svc := newAgentSvcTestService(repo)

	_, err := svc.FindAvailableWithCapacity(context.Background(), shared.NewID(), []string{"sast"}, "semgrep")
	if err == nil {
		t.Fatal("expected error when repo.FindAvailableWithCapacity fails")
	}
}

// ============================================================================
// Tests: ClaimJob
// ============================================================================

func TestAgentService_ClaimJob_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	err := svc.ClaimJob(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.claimJobCalls != 1 {
		t.Errorf("expected 1 ClaimJob call, got %d", repo.claimJobCalls)
	}
}

func TestAgentService_ClaimJob_RepoError(t *testing.T) {
	repo := newAgentSvcMockRepo()
	repo.claimJobErr = errors.New("no capacity")
	svc := newAgentSvcTestService(repo)

	err := svc.ClaimJob(context.Background(), shared.NewID())
	if err == nil {
		t.Fatal("expected error when repo.ClaimJob fails")
	}
}

// ============================================================================
// Tests: ReleaseJob
// ============================================================================

func TestAgentService_ReleaseJob_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	err := svc.ReleaseJob(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.releaseJobCalls != 1 {
		t.Errorf("expected 1 ReleaseJob call, got %d", repo.releaseJobCalls)
	}
}

func TestAgentService_ReleaseJob_RepoError(t *testing.T) {
	repo := newAgentSvcMockRepo()
	repo.releaseJobErr = errors.New("not claimed")
	svc := newAgentSvcTestService(repo)

	err := svc.ReleaseJob(context.Background(), shared.NewID())
	if err == nil {
		t.Fatal("expected error when repo.ReleaseJob fails")
	}
}

// ============================================================================
// Tests: IncrementStats
// ============================================================================

func TestAgentService_IncrementStats_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	err := svc.IncrementStats(context.Background(), shared.NewID(), 10, 5, 2)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.incrementStatsCalls != 1 {
		t.Errorf("expected 1 IncrementStats call, got %d", repo.incrementStatsCalls)
	}
	if repo.lastStatsArgs.findings != 10 {
		t.Errorf("expected findings=10, got %d", repo.lastStatsArgs.findings)
	}
	if repo.lastStatsArgs.scans != 5 {
		t.Errorf("expected scans=5, got %d", repo.lastStatsArgs.scans)
	}
	if repo.lastStatsArgs.errors != 2 {
		t.Errorf("expected errors=2, got %d", repo.lastStatsArgs.errors)
	}
}

func TestAgentService_IncrementStats_RepoError(t *testing.T) {
	repo := newAgentSvcMockRepo()
	repo.incrementStatsErr = errors.New("db error")
	svc := newAgentSvcTestService(repo)

	err := svc.IncrementStats(context.Background(), shared.NewID(), 1, 1, 0)
	if err == nil {
		t.Fatal("expected error when repo.IncrementStats fails")
	}
}

// ============================================================================
// Tests: GetAvailableCapabilitiesForTenant
// ============================================================================

func TestAgentService_GetAvailableCapabilitiesForTenant_Success(t *testing.T) {
	repo := newAgentSvcMockRepo()
	repo.capabilities = []string{"sast", "sca", "dast"}
	svc := newAgentSvcTestService(repo)

	out, err := svc.GetAvailableCapabilitiesForTenant(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(out.Capabilities) != 3 {
		t.Errorf("expected 3 capabilities, got %d", len(out.Capabilities))
	}
	if out.TotalAgents != 3 {
		t.Errorf("expected TotalAgents=3 (len of capabilities), got %d", out.TotalAgents)
	}
}

func TestAgentService_GetAvailableCapabilitiesForTenant_Empty(t *testing.T) {
	repo := newAgentSvcMockRepo()
	repo.capabilities = nil // nil from repo
	svc := newAgentSvcTestService(repo)

	out, err := svc.GetAvailableCapabilitiesForTenant(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Should return empty array, not nil
	if out.Capabilities == nil {
		t.Error("expected non-nil capabilities slice (empty array)")
	}
	if len(out.Capabilities) != 0 {
		t.Errorf("expected 0 capabilities, got %d", len(out.Capabilities))
	}
}

func TestAgentService_GetAvailableCapabilitiesForTenant_RepoError(t *testing.T) {
	repo := newAgentSvcMockRepo()
	repo.getAvailableCapabilitiesErr = errors.New("db error")
	svc := newAgentSvcTestService(repo)

	_, err := svc.GetAvailableCapabilitiesForTenant(context.Background(), shared.NewID())
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// ============================================================================
// Tests: HasCapability
// ============================================================================

func TestAgentService_HasCapability_True(t *testing.T) {
	repo := newAgentSvcMockRepo()
	repo.hasCapability = true
	svc := newAgentSvcTestService(repo)

	has, err := svc.HasCapability(context.Background(), shared.NewID(), "sast")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !has {
		t.Error("expected HasCapability to return true")
	}
}

func TestAgentService_HasCapability_False(t *testing.T) {
	repo := newAgentSvcMockRepo()
	repo.hasCapability = false
	svc := newAgentSvcTestService(repo)

	has, err := svc.HasCapability(context.Background(), shared.NewID(), "sast")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if has {
		t.Error("expected HasCapability to return false")
	}
}

func TestAgentService_HasCapability_RepoError(t *testing.T) {
	repo := newAgentSvcMockRepo()
	repo.hasAgentForCapabilityErr = errors.New("db error")
	svc := newAgentSvcTestService(repo)

	_, err := svc.HasCapability(context.Background(), shared.NewID(), "sast")
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// ============================================================================
// Tests: GetPlatformStats
// ============================================================================

func TestAgentService_GetPlatformStats_NoPlatformAgents(t *testing.T) {
	repo := newAgentSvcMockRepo()
	repo.platformStats = &agent.PlatformAgentStatsResult{
		TotalAgents:   0,
		TierBreakdown: make(map[string]agent.TierBreakdown),
	}
	svc := newAgentSvcTestService(repo)

	out, err := svc.GetPlatformStats(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if out.Enabled {
		t.Error("expected Enabled=false when no platform agents")
	}
	if out.MaxTier != "shared" {
		t.Errorf("expected MaxTier='shared', got %q", out.MaxTier)
	}
	if len(out.AccessibleTiers) != 1 || out.AccessibleTiers[0] != "shared" {
		t.Errorf("expected AccessibleTiers=[shared], got %v", out.AccessibleTiers)
	}
}

func TestAgentService_GetPlatformStats_WithAgents(t *testing.T) {
	repo := newAgentSvcMockRepo()
	repo.platformStats = &agent.PlatformAgentStatsResult{
		TotalAgents:       5,
		OnlineAgents:      3,
		TotalCapacity:     25,
		CurrentActiveJobs: 10,
		CurrentQueuedJobs: 2,
		TierBreakdown: map[string]agent.TierBreakdown{
			"shared": {
				TotalAgents:   3,
				OnlineAgents:  2,
				TotalCapacity: 15,
				CurrentLoad:   6,
			},
			"dedicated": {
				TotalAgents:   2,
				OnlineAgents:  1,
				TotalCapacity: 10,
				CurrentLoad:   4,
			},
		},
	}
	svc := newAgentSvcTestService(repo)

	out, err := svc.GetPlatformStats(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !out.Enabled {
		t.Error("expected Enabled=true when platform agents exist")
	}
	if out.MaxTier != "dedicated" {
		t.Errorf("expected MaxTier='dedicated', got %q", out.MaxTier)
	}
	if out.MaxConcurrent != 25 {
		t.Errorf("expected MaxConcurrent=25, got %d", out.MaxConcurrent)
	}
	if out.MaxQueued != 75 {
		t.Errorf("expected MaxQueued=75 (3x capacity), got %d", out.MaxQueued)
	}
	if out.CurrentActive != 10 {
		t.Errorf("expected CurrentActive=10, got %d", out.CurrentActive)
	}
	if out.CurrentQueued != 2 {
		t.Errorf("expected CurrentQueued=2, got %d", out.CurrentQueued)
	}
	if out.AvailableSlots != 15 {
		t.Errorf("expected AvailableSlots=15, got %d", out.AvailableSlots)
	}

	// Check tier stats
	sharedTier, ok := out.TierStats["shared"]
	if !ok {
		t.Fatal("expected 'shared' tier in TierStats")
	}
	if sharedTier.TotalAgents != 3 {
		t.Errorf("expected shared TotalAgents=3, got %d", sharedTier.TotalAgents)
	}
	if sharedTier.OnlineAgents != 2 {
		t.Errorf("expected shared OnlineAgents=2, got %d", sharedTier.OnlineAgents)
	}
	if sharedTier.OfflineAgents != 1 {
		t.Errorf("expected shared OfflineAgents=1, got %d", sharedTier.OfflineAgents)
	}
	if sharedTier.AvailableSlots != 9 {
		t.Errorf("expected shared AvailableSlots=9, got %d", sharedTier.AvailableSlots)
	}
}

func TestAgentService_GetPlatformStats_WithPremiumTier(t *testing.T) {
	repo := newAgentSvcMockRepo()
	repo.platformStats = &agent.PlatformAgentStatsResult{
		TotalAgents:   2,
		TotalCapacity: 10,
		TierBreakdown: map[string]agent.TierBreakdown{
			"shared": {TotalAgents: 1, TotalCapacity: 5},
			"premium": {TotalAgents: 1, TotalCapacity: 5},
		},
	}
	svc := newAgentSvcTestService(repo)

	out, err := svc.GetPlatformStats(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if out.MaxTier != "premium" {
		t.Errorf("expected MaxTier='premium', got %q", out.MaxTier)
	}
	// Should have shared + premium
	foundShared := false
	foundPremium := false
	for _, tier := range out.AccessibleTiers {
		if tier == "shared" {
			foundShared = true
		}
		if tier == "premium" {
			foundPremium = true
		}
	}
	if !foundShared || !foundPremium {
		t.Errorf("expected AccessibleTiers to contain shared and premium, got %v", out.AccessibleTiers)
	}
}

func TestAgentService_GetPlatformStats_RepoError(t *testing.T) {
	repo := newAgentSvcMockRepo()
	repo.getPlatformAgentStatsErr = errors.New("db error")
	svc := newAgentSvcTestService(repo)

	_, err := svc.GetPlatformStats(context.Background(), shared.NewID())
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// ============================================================================
// Tests: API Key Format
// ============================================================================

func TestAgentService_APIKeyFormat(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	out, err := svc.CreateAgent(context.Background(), app.CreateAgentInput{
		TenantID: agentSvcValidTenantID(),
		Name:     "format-test",
		Type:     "runner",
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	// Verify prefix format: "rda_" + first 8 hex chars
	expectedPrefix := out.APIKey[:12]
	if out.Agent.APIKeyPrefix != expectedPrefix {
		t.Errorf("expected prefix %q, got %q", expectedPrefix, out.Agent.APIKeyPrefix)
	}
}

func TestAgentService_APIKeyUniqueness(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)

	keys := make(map[string]bool)
	for i := 0; i < 10; i++ {
		out, err := svc.CreateAgent(context.Background(), app.CreateAgentInput{
			TenantID: agentSvcValidTenantID(),
			Name:     "agent-" + strings.Repeat("x", i+1),
			Type:     "runner",
		})
		if err != nil {
			t.Fatalf("failed to create agent %d: %v", i, err)
		}
		if keys[out.APIKey] {
			t.Fatalf("duplicate API key generated at iteration %d", i)
		}
		keys[out.APIKey] = true
	}
}

// ============================================================================
// Tests: Status Transitions
// ============================================================================

func TestAgentService_StatusTransitions(t *testing.T) {
	repo := newAgentSvcMockRepo()
	svc := newAgentSvcTestService(repo)
	tenantID := shared.NewID()

	// Create agent (active by default)
	out, err := svc.CreateAgent(context.Background(), app.CreateAgentInput{
		TenantID: tenantID.String(),
		Name:     "transition-agent",
		Type:     "runner",
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}
	if out.Agent.Status != agent.AgentStatusActive {
		t.Fatalf("expected initial status 'active', got %q", out.Agent.Status)
	}

	agentID := out.Agent.ID.String()

	// Active -> Disabled
	disabled, err := svc.DisableAgent(context.Background(), tenantID.String(), agentID, "test", nil)
	if err != nil {
		t.Fatalf("failed to disable: %v", err)
	}
	if disabled.Status != agent.AgentStatusDisabled {
		t.Errorf("expected 'disabled', got %q", disabled.Status)
	}

	// Disabled -> Active
	activated, err := svc.ActivateAgent(context.Background(), tenantID.String(), agentID, nil)
	if err != nil {
		t.Fatalf("failed to activate: %v", err)
	}
	if activated.Status != agent.AgentStatusActive {
		t.Errorf("expected 'active', got %q", activated.Status)
	}

	// Active -> Revoked
	revoked, err := svc.RevokeAgent(context.Background(), tenantID.String(), agentID, "bye", nil)
	if err != nil {
		t.Fatalf("failed to revoke: %v", err)
	}
	if revoked.Status != agent.AgentStatusRevoked {
		t.Errorf("expected 'revoked', got %q", revoked.Status)
	}

	// Revoked -> Active (should fail)
	_, err = svc.ActivateAgent(context.Background(), tenantID.String(), agentID, nil)
	if err == nil {
		t.Fatal("expected error when activating revoked agent")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

// ============================================================================
// Tests: Nil AuditService (optional dependency)
// ============================================================================

func TestAgentService_NilAuditService_DoesNotPanic(t *testing.T) {
	repo := newAgentSvcMockRepo()
	// Pass nil audit service
	log := logger.NewNop()
	svc := app.NewAgentService(repo, nil, log)
	tenantID := shared.NewID()

	// CreateAgent with audit context should not panic
	out, err := svc.CreateAgent(context.Background(), app.CreateAgentInput{
		TenantID: tenantID.String(),
		Name:     "no-panic-agent",
		Type:     "runner",
		AuditContext: &app.AuditContext{
			TenantID: tenantID.String(),
			ActorID:  shared.NewID().String(),
		},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	agentID := out.Agent.ID.String()

	// UpdateAgent with audit context
	_, err = svc.UpdateAgent(context.Background(), app.UpdateAgentInput{
		TenantID:     tenantID.String(),
		AgentID:      agentID,
		Name:         "updated",
		AuditContext: &app.AuditContext{TenantID: tenantID.String()},
	})
	if err != nil {
		t.Fatalf("UpdateAgent should not panic with nil audit service: %v", err)
	}

	// DeleteAgent with audit context
	auditCtx := &app.AuditContext{TenantID: tenantID.String()}
	err = svc.DeleteAgent(context.Background(), tenantID.String(), agentID, auditCtx)
	if err != nil {
		t.Fatalf("DeleteAgent should not panic with nil audit service: %v", err)
	}
}
