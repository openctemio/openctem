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
// Mock: agent.Repository (prefixed with agentSel)
// =============================================================================

// agentSelMockAgentRepo implements agent.Repository for AgentSelector tests.
type agentSelMockAgentRepo struct {
	// Return values for FindAvailableWithCapacity
	availableAgents []*agent.Agent
	availableErr    error

	// Capture args from FindAvailableWithCapacity calls
	lastTenantID     shared.ID
	lastCapabilities []string
	lastTool         string
	callCount        int
}

func newAgentSelMockAgentRepo() *agentSelMockAgentRepo {
	return &agentSelMockAgentRepo{}
}

func (m *agentSelMockAgentRepo) FindAvailableWithCapacity(_ context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*agent.Agent, error) {
	m.lastTenantID = tenantID
	m.lastCapabilities = capabilities
	m.lastTool = tool
	m.callCount++
	return m.availableAgents, m.availableErr
}

// Stub all other Repository methods to satisfy the interface.

func (m *agentSelMockAgentRepo) Create(_ context.Context, _ *agent.Agent) error { return nil }
func (m *agentSelMockAgentRepo) CountByTenant(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}
func (m *agentSelMockAgentRepo) GetByID(_ context.Context, _ shared.ID) (*agent.Agent, error) {
	return nil, nil
}
func (m *agentSelMockAgentRepo) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*agent.Agent, error) {
	return nil, nil
}
func (m *agentSelMockAgentRepo) GetByAPIKeyHash(_ context.Context, _ string) (*agent.Agent, error) {
	return nil, nil
}
func (m *agentSelMockAgentRepo) List(_ context.Context, _ agent.Filter, _ pagination.Pagination) (pagination.Result[*agent.Agent], error) {
	return pagination.Result[*agent.Agent]{}, nil
}
func (m *agentSelMockAgentRepo) Update(_ context.Context, _ *agent.Agent) error { return nil }
func (m *agentSelMockAgentRepo) UpdateKeyExpiry(_ context.Context, _ shared.ID, _ *time.Time) error {
	return nil
}
func (m *agentSelMockAgentRepo) Delete(_ context.Context, _ shared.ID) error { return nil }
func (m *agentSelMockAgentRepo) UpdateLastSeen(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *agentSelMockAgentRepo) IncrementStats(_ context.Context, _ shared.ID, _, _, _ int64) error {
	return nil
}
func (m *agentSelMockAgentRepo) FindByCapabilities(_ context.Context, _ shared.ID, _ []string, _ string) ([]*agent.Agent, error) {
	return nil, nil
}
func (m *agentSelMockAgentRepo) FindAvailable(_ context.Context, _ shared.ID, _ []string, _ string) ([]*agent.Agent, error) {
	return nil, nil
}
func (m *agentSelMockAgentRepo) FindAvailableWithTool(_ context.Context, _ shared.ID, _ string) (*agent.Agent, error) {
	return nil, nil
}
func (m *agentSelMockAgentRepo) MarkStaleAsOffline(_ context.Context, _ time.Duration) (int64, error) {
	return 0, nil
}
func (m *agentSelMockAgentRepo) ClaimJob(_ context.Context, _ shared.ID) error   { return nil }
func (m *agentSelMockAgentRepo) ReleaseJob(_ context.Context, _ shared.ID) error { return nil }
func (m *agentSelMockAgentRepo) UpdateOfflineTimestamp(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *agentSelMockAgentRepo) MarkStaleAgentsOffline(_ context.Context, _ time.Duration) ([]shared.ID, error) {
	return nil, nil
}
func (m *agentSelMockAgentRepo) GetAgentsOfflineSince(_ context.Context, _ time.Time) ([]*agent.Agent, error) {
	return nil, nil
}
func (m *agentSelMockAgentRepo) GetAvailableToolsForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return nil, nil
}
func (m *agentSelMockAgentRepo) HasAgentForTool(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}
func (m *agentSelMockAgentRepo) GetAvailableCapabilitiesForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return nil, nil
}
func (m *agentSelMockAgentRepo) HasAgentForCapability(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}
func (m *agentSelMockAgentRepo) GetPlatformAgentStats(_ context.Context, _ shared.ID) (*agent.PlatformAgentStatsResult, error) {
	return nil, nil
}
func (m *agentSelMockAgentRepo) GetTenantAgentStats(_ context.Context, _ shared.ID) (*agent.TenantAgentStats, error) {
	return nil, nil
}

// =============================================================================
// Helpers
// =============================================================================

// makeAgentSelAgent builds a minimal *agent.Agent with the given load values.
func makeAgentSelAgent(name string, currentJobs, maxJobs int) *agent.Agent {
	tenantID := shared.NewID()
	return &agent.Agent{
		ID:                shared.NewID(),
		TenantID:          &tenantID,
		Name:              name,
		Type:              agent.AgentTypeWorker,
		Status:            agent.AgentStatusActive,
		Health:            agent.AgentHealthOnline,
		CurrentJobs:       currentJobs,
		MaxConcurrentJobs: maxJobs,
		Capabilities:      []string{},
		Tools:             []string{},
	}
}

// newAgentSelector creates an AgentSelector wired to the mock repo.
// commandRepo and agentState are nil because the current implementation does
// not use them in SelectAgent / CheckAgentAvailability.
func newAgentSelSelector(repo *agentSelMockAgentRepo) *app.AgentSelector {
	log := logger.NewNop()
	return app.NewAgentSelector(repo, nil, nil, log)
}

// =============================================================================
// Tests: SelectAgent
// =============================================================================

// TestAgentSelSelectAgent_SingleAgent verifies that the only available agent
// is returned when exactly one is present.
func TestAgentSelSelectAgent_SingleAgent(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()
	a := makeAgentSelAgent("alpha", 1, 5)
	repo.availableAgents = []*agent.Agent{a}

	sel := newAgentSelSelector(repo)

	tenantID := shared.NewID()
	result, err := sel.SelectAgent(context.Background(), app.SelectAgentRequest{
		TenantID: tenantID,
		Mode:     app.SelectTenantOnly,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Agent == nil {
		t.Fatal("expected agent to be set")
	}
	if result.Agent.ID != a.ID {
		t.Errorf("expected agent %s, got %s", a.ID, result.Agent.ID)
	}
	if result.Queued {
		t.Error("expected Queued=false")
	}
}

// TestAgentSelSelectAgent_MultipleAgents_LeastLoaded verifies that among
// multiple agents the one with the lowest load ratio is chosen.
func TestAgentSelSelectAgent_MultipleAgents_LeastLoaded(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()

	// high: 4/5 = 80% load
	high := makeAgentSelAgent("high-load", 4, 5)
	// low: 1/5 = 20% load — should be selected
	low := makeAgentSelAgent("low-load", 1, 5)
	// mid: 3/5 = 60% load
	mid := makeAgentSelAgent("mid-load", 3, 5)

	repo.availableAgents = []*agent.Agent{high, low, mid}

	sel := newAgentSelSelector(repo)

	result, err := sel.SelectAgent(context.Background(), app.SelectAgentRequest{
		TenantID: shared.NewID(),
		Mode:     app.SelectTenantOnly,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Agent == nil {
		t.Fatal("expected agent to be set")
	}
	if result.Agent.ID != low.ID {
		t.Errorf("expected least-loaded agent %q, got %q", low.Name, result.Agent.Name)
	}
}

// TestAgentSelSelectAgent_NoAgents_Error verifies that ErrNoAgentAvailable is
// returned when no agents are available and AllowQueue is false.
func TestAgentSelSelectAgent_NoAgents_Error(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()
	repo.availableAgents = []*agent.Agent{} // none

	sel := newAgentSelSelector(repo)

	result, err := sel.SelectAgent(context.Background(), app.SelectAgentRequest{
		TenantID:   shared.NewID(),
		Mode:       app.SelectTenantOnly,
		AllowQueue: false,
	})

	if result != nil {
		t.Error("expected nil result")
	}
	if !errors.Is(err, app.ErrNoAgentAvailable) {
		t.Errorf("expected ErrNoAgentAvailable, got %v", err)
	}
}

// TestAgentSelSelectAgent_NoAgents_AllowQueue verifies that when AllowQueue is
// true and no agents are available, a queued result is returned without error.
func TestAgentSelSelectAgent_NoAgents_AllowQueue(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()
	repo.availableAgents = []*agent.Agent{}

	sel := newAgentSelSelector(repo)

	result, err := sel.SelectAgent(context.Background(), app.SelectAgentRequest{
		TenantID:   shared.NewID(),
		Mode:       app.SelectTenantOnly,
		AllowQueue: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.Queued {
		t.Error("expected Queued=true")
	}
	if result.Agent != nil {
		t.Error("expected Agent to be nil when queued")
	}
	if result.Message == "" {
		t.Error("expected a non-empty message in queued result")
	}
}

// TestAgentSelSelectAgent_RepoError verifies that repository errors are
// propagated back to the caller.
func TestAgentSelSelectAgent_RepoError(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()
	repoErr := errors.New("db connection lost")
	repo.availableErr = repoErr

	sel := newAgentSelSelector(repo)

	result, err := sel.SelectAgent(context.Background(), app.SelectAgentRequest{
		TenantID: shared.NewID(),
	})

	if result != nil {
		t.Error("expected nil result on error")
	}
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, repoErr) {
		t.Errorf("expected wrapped repo error, got %v", err)
	}
}

// TestAgentSelSelectAgent_PassesToolAndCapabilities verifies that the
// Capabilities and Tool fields are forwarded to the repository.
func TestAgentSelSelectAgent_PassesToolAndCapabilities(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()
	a := makeAgentSelAgent("agent-with-tool", 0, 5)
	repo.availableAgents = []*agent.Agent{a}

	sel := newAgentSelSelector(repo)

	wantCaps := []string{"sast", "sca"}
	wantTool := "semgrep"

	_, _ = sel.SelectAgent(context.Background(), app.SelectAgentRequest{
		TenantID:     shared.NewID(),
		Capabilities: wantCaps,
		Tool:         wantTool,
		Mode:         app.SelectTenantOnly,
	})

	if repo.lastTool != wantTool {
		t.Errorf("expected tool=%q forwarded to repo, got %q", wantTool, repo.lastTool)
	}
	if len(repo.lastCapabilities) != len(wantCaps) {
		t.Errorf("expected %d capabilities, got %d", len(wantCaps), len(repo.lastCapabilities))
	}
	for i, c := range wantCaps {
		if repo.lastCapabilities[i] != c {
			t.Errorf("capability[%d]: want %q, got %q", i, c, repo.lastCapabilities[i])
		}
	}
}

// TestAgentSelSelectAgent_CorrectTenantID verifies the TenantID is forwarded
// to the repository unchanged.
func TestAgentSelSelectAgent_CorrectTenantID(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()
	a := makeAgentSelAgent("worker", 0, 5)
	repo.availableAgents = []*agent.Agent{a}

	sel := newAgentSelSelector(repo)

	tenantID := shared.NewID()
	_, _ = sel.SelectAgent(context.Background(), app.SelectAgentRequest{
		TenantID: tenantID,
	})

	if repo.lastTenantID != tenantID {
		t.Errorf("expected tenantID=%s, got %s", tenantID, repo.lastTenantID)
	}
}

// TestAgentSelSelectAgent_EqualLoad verifies that when two agents have the
// same load the first encountered is returned (stable selection).
func TestAgentSelSelectAgent_EqualLoad(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()

	first := makeAgentSelAgent("first", 2, 4)   // 50% load
	second := makeAgentSelAgent("second", 2, 4) // 50% load

	repo.availableAgents = []*agent.Agent{first, second}

	sel := newAgentSelSelector(repo)

	result, err := sel.SelectAgent(context.Background(), app.SelectAgentRequest{
		TenantID: shared.NewID(),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With equal loads, the first agent in the slice should be selected
	// because the implementation starts bestLoad at 1.0 (100%) and the first
	// agent with load < 1.0 wins; subsequent equal-load agents do not replace.
	if result.Agent.ID != first.ID {
		t.Errorf("expected first agent to win on equal load, got %s", result.Agent.Name)
	}
}

// TestAgentSelSelectAgent_AgentWithUnlimitedCapacity verifies that an agent
// with MaxConcurrentJobs == 0 (no limit) is returned immediately.
func TestAgentSelSelectAgent_AgentWithUnlimitedCapacity(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()

	unlimited := makeAgentSelAgent("unlimited", 0, 0) // MaxConcurrentJobs = 0 → no limit
	heavy := makeAgentSelAgent("heavy", 4, 5)

	// unlimited is listed second; because it has MaxConcurrentJobs == 0 the
	// implementation returns it immediately when encountered.
	repo.availableAgents = []*agent.Agent{heavy, unlimited}

	sel := newAgentSelSelector(repo)

	result, err := sel.SelectAgent(context.Background(), app.SelectAgentRequest{
		TenantID: shared.NewID(),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Agent == nil {
		t.Fatal("expected agent to be set")
	}
	if result.Agent.ID != unlimited.ID {
		t.Errorf("expected unlimited-capacity agent, got %s", result.Agent.Name)
	}
}

// TestAgentSelSelectAgent_AllFullyLoaded verifies that if every agent has
// load == 1.0 (CurrentJobs == MaxConcurrentJobs) no agent is selected and
// the result agent is nil (because none beat the 100% threshold).
func TestAgentSelSelectAgent_AllFullyLoaded(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()

	// Three agents all at 100% capacity
	a1 := makeAgentSelAgent("a1", 5, 5)
	a2 := makeAgentSelAgent("a2", 3, 3)
	a3 := makeAgentSelAgent("a3", 10, 10)
	repo.availableAgents = []*agent.Agent{a1, a2, a3}

	sel := newAgentSelSelector(repo)

	result, err := sel.SelectAgent(context.Background(), app.SelectAgentRequest{
		TenantID: shared.NewID(),
	})

	// The implementation starts bestLoad at 1.0 and uses strict < so a fully
	// loaded agent (load == 1.0) will never be selected; best remains nil.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil SelectAgentResult")
	}
	if result.Agent != nil {
		t.Errorf("expected nil Agent when all agents are at 100%% load, got %s", result.Agent.Name)
	}
}

// TestAgentSelSelectAgent_Message verifies that the result message is
// populated for a successful assignment.
func TestAgentSelSelectAgent_Message(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()
	a := makeAgentSelAgent("worker", 0, 5)
	repo.availableAgents = []*agent.Agent{a}

	sel := newAgentSelSelector(repo)

	result, err := sel.SelectAgent(context.Background(), app.SelectAgentRequest{
		TenantID: shared.NewID(),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Message == "" {
		t.Error("expected non-empty message in result")
	}
}

// =============================================================================
// Tests: CheckAgentAvailability
// =============================================================================

// TestAgentSelCheckAvailability_TenantAgentAvailable verifies that when
// agents exist the result shows availability.
func TestAgentSelCheckAvailability_TenantAgentAvailable(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()
	repo.availableAgents = []*agent.Agent{makeAgentSelAgent("worker", 1, 5)}

	sel := newAgentSelSelector(repo)

	result := sel.CheckAgentAvailability(context.Background(), shared.NewID(), "nuclei", true)

	if result == nil {
		t.Fatal("expected non-nil availability result")
	}
	if !result.HasTenantAgent {
		t.Error("expected HasTenantAgent=true")
	}
	if !result.Available {
		t.Error("expected Available=true")
	}
	if result.Message == "" {
		t.Error("expected non-empty message")
	}
}

// TestAgentSelCheckAvailability_NoAgentsAvailable verifies that the result
// shows unavailability when no agents exist.
func TestAgentSelCheckAvailability_NoAgentsAvailable(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()
	repo.availableAgents = []*agent.Agent{}

	sel := newAgentSelSelector(repo)

	result := sel.CheckAgentAvailability(context.Background(), shared.NewID(), "nuclei", true)

	if result.HasTenantAgent {
		t.Error("expected HasTenantAgent=false")
	}
	if result.Available {
		t.Error("expected Available=false")
	}
	if result.Message == "" {
		t.Error("expected a non-empty message describing unavailability")
	}
}

// TestAgentSelCheckAvailability_RepoError verifies that repository errors
// cause HasTenantAgent to remain false (error is tolerated).
func TestAgentSelCheckAvailability_RepoError(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()
	repo.availableErr = errors.New("connection refused")

	sel := newAgentSelSelector(repo)

	result := sel.CheckAgentAvailability(context.Background(), shared.NewID(), "trivy", false)

	if result == nil {
		t.Fatal("expected non-nil result even on repo error")
	}
	if result.HasTenantAgent {
		t.Error("expected HasTenantAgent=false on repo error")
	}
	if result.Available {
		t.Error("expected Available=false on repo error")
	}
}

// TestAgentSelCheckAvailability_ToolPassedToRepo verifies that the tool
// name is forwarded to the repository query.
func TestAgentSelCheckAvailability_ToolPassedToRepo(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()
	repo.availableAgents = []*agent.Agent{}

	sel := newAgentSelSelector(repo)

	wantTool := "semgrep"
	_ = sel.CheckAgentAvailability(context.Background(), shared.NewID(), wantTool, true)

	if repo.lastTool != wantTool {
		t.Errorf("expected tool=%q forwarded to repo, got %q", wantTool, repo.lastTool)
	}
}

// TestAgentSelCheckAvailability_TenantIDPassedToRepo verifies the tenant ID
// is forwarded to the repository query.
func TestAgentSelCheckAvailability_TenantIDPassedToRepo(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()
	repo.availableAgents = []*agent.Agent{}

	sel := newAgentSelSelector(repo)

	tenantID := shared.NewID()
	_ = sel.CheckAgentAvailability(context.Background(), tenantID, "nmap", false)

	if repo.lastTenantID != tenantID {
		t.Errorf("expected tenantID=%s, got %s", tenantID, repo.lastTenantID)
	}
}

// TestAgentSelCheckAvailability_MultipleAgents verifies that having multiple
// available agents still reports a single available status.
func TestAgentSelCheckAvailability_MultipleAgents(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()
	repo.availableAgents = []*agent.Agent{
		makeAgentSelAgent("worker-1", 2, 5),
		makeAgentSelAgent("worker-2", 0, 5),
		makeAgentSelAgent("worker-3", 4, 5),
	}

	sel := newAgentSelSelector(repo)

	result := sel.CheckAgentAvailability(context.Background(), shared.NewID(), "trivy", true)

	if !result.HasTenantAgent {
		t.Error("expected HasTenantAgent=true with multiple agents")
	}
	if !result.Available {
		t.Error("expected Available=true with multiple agents")
	}
}

// =============================================================================
// Tests: selectLeastLoaded (exercised via SelectAgent)
// =============================================================================

// TestAgentSelLeastLoaded_ZeroCurrentJobs verifies that an agent with no
// active jobs (load == 0%) beats one with higher load.
func TestAgentSelLeastLoaded_ZeroCurrentJobs(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()

	idle := makeAgentSelAgent("idle", 0, 5) // 0% load
	busy := makeAgentSelAgent("busy", 4, 5) // 80% load

	repo.availableAgents = []*agent.Agent{busy, idle}

	sel := newAgentSelSelector(repo)

	result, err := sel.SelectAgent(context.Background(), app.SelectAgentRequest{
		TenantID: shared.NewID(),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Agent.ID != idle.ID {
		t.Errorf("expected idle agent, got %s", result.Agent.Name)
	}
}

// TestAgentSelLeastLoaded_SingleAgentPartialLoad verifies that a single
// agent with a partial load is returned.
func TestAgentSelLeastLoaded_SingleAgentPartialLoad(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()
	a := makeAgentSelAgent("partial", 2, 5) // 40% load
	repo.availableAgents = []*agent.Agent{a}

	sel := newAgentSelSelector(repo)

	result, err := sel.SelectAgent(context.Background(), app.SelectAgentRequest{
		TenantID: shared.NewID(),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Agent.ID != a.ID {
		t.Errorf("expected agent %s, got %s", a.ID, result.Agent.ID)
	}
}

// TestAgentSelLeastLoaded_MaxJobsOne verifies the boundary case where the
// max concurrent jobs is 1.
func TestAgentSelLeastLoaded_MaxJobsOne(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()

	empty := makeAgentSelAgent("empty", 0, 1) // 0% load
	full := makeAgentSelAgent("full", 1, 1)   // 100% load

	repo.availableAgents = []*agent.Agent{full, empty}

	sel := newAgentSelSelector(repo)

	result, err := sel.SelectAgent(context.Background(), app.SelectAgentRequest{
		TenantID: shared.NewID(),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Agent.ID != empty.ID {
		t.Errorf("expected empty-slot agent, got %s", result.Agent.Name)
	}
}

// =============================================================================
// Tests: load-balancing weights actually reach scheduling
// =============================================================================

// withFreshMetrics stamps resource metrics on an agent and marks them as just
// reported, so the selector treats them as trustworthy.
func withFreshMetrics(a *agent.Agent, cpu, mem float64) *agent.Agent {
	now := time.Now()
	a.CPUPercent = cpu
	a.MemoryPercent = mem
	a.MetricsUpdatedAt = &now
	return a
}

// TestAgentSelLoadBalancing_CPUBreaksJobLoadTie pins that agent selection uses
// the reported resource metrics, not just the job-count ratio.
//
// Both agents sit at the same 2/5 job load. The one pegged at 95% CPU must
// lose to the idle one. Before the load-balancing weights were wired in, the
// selector compared only CurrentJobs/MaxConcurrentJobs, so the tie was broken
// by slice order and CPU was ignored entirely.
func TestAgentSelLoadBalancing_CPUBreaksJobLoadTie(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()

	hot := withFreshMetrics(makeAgentSelAgent("hot", 2, 5), 95, 10)
	cool := withFreshMetrics(makeAgentSelAgent("cool", 2, 5), 5, 10)

	// hot is listed first: a job-ratio-only selector returns it.
	repo.availableAgents = []*agent.Agent{hot, cool}

	sel := newAgentSelSelector(repo)

	result, err := sel.SelectAgent(context.Background(), app.SelectAgentRequest{
		TenantID: shared.NewID(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Agent == nil {
		t.Fatal("expected an agent to be selected")
	}
	if result.Agent.ID != cool.ID {
		t.Errorf("selected %q (95%% CPU) over %q (5%% CPU) at identical job load; "+
			"CPU/memory metrics are not influencing scheduling", result.Agent.Name, cool.Name)
	}
}

// TestAgentSelLoadBalancing_WeightsChangeSelection pins that the AGENT_LB_*
// weights are the knob they claim to be: an operator who declares memory the
// dominant signal must get a different placement decision than one who
// declares CPU dominant, from identical agent state.
func TestAgentSelLoadBalancing_WeightsChangeSelection(t *testing.T) {
	t.Parallel()

	// cpuHeavy: 90% CPU / 10% memory. memHeavy: 10% CPU / 90% memory.
	// Same job load, so only the weights decide.
	newPair := func() (*agent.Agent, *agent.Agent) {
		return withFreshMetrics(makeAgentSelAgent("cpu-heavy", 1, 5), 90, 10),
			withFreshMetrics(makeAgentSelAgent("mem-heavy", 1, 5), 10, 90)
	}

	selectWith := func(w agent.LoadBalancingWeights) string {
		cpuHeavy, memHeavy := newPair()
		repo := newAgentSelMockAgentRepo()
		repo.availableAgents = []*agent.Agent{cpuHeavy, memHeavy}

		sel := newAgentSelSelector(repo)
		sel.SetLoadBalancingWeights(w)

		result, err := sel.SelectAgent(context.Background(), app.SelectAgentRequest{
			TenantID: shared.NewID(),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Agent == nil {
			t.Fatal("expected an agent to be selected")
		}
		return result.Agent.Name
	}

	// CPU dominant → avoid the CPU-heavy agent.
	if got := selectWith(agent.LoadBalancingWeights{JobLoad: 0.1, CPU: 0.9}); got != "mem-heavy" {
		t.Errorf("with CPU weighted 0.9 the CPU-heavy agent should lose; selected %q", got)
	}

	// Memory dominant → avoid the memory-heavy agent instead.
	if got := selectWith(agent.LoadBalancingWeights{JobLoad: 0.1, Memory: 0.9}); got != "cpu-heavy" {
		t.Errorf("with memory weighted 0.9 the memory-heavy agent should lose; selected %q; "+
			"AGENT_LB_* weights do not affect scheduling", got)
	}
}

// TestAgentSelLoadBalancing_StaleMetricsIgnored pins the safety valve: an
// agent whose last metrics report is ancient must be ranked on queue depth
// alone. Otherwise one bad CPU sample from a wedged agent would bias
// scheduling forever, since nothing refreshes the row while it is stuck.
func TestAgentSelLoadBalancing_StaleMetricsIgnored(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()

	stale := makeAgentSelAgent("stale-but-idle", 0, 5)
	old := time.Now().Add(-2 * time.Hour)
	stale.CPUPercent = 99
	stale.MetricsUpdatedAt = &old

	busy := withFreshMetrics(makeAgentSelAgent("fresh-but-busy", 4, 5), 1, 1)

	repo.availableAgents = []*agent.Agent{busy, stale}

	sel := newAgentSelSelector(repo)

	result, err := sel.SelectAgent(context.Background(), app.SelectAgentRequest{
		TenantID: shared.NewID(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Agent.ID != stale.ID {
		t.Errorf("selected %q; a two-hour-old 99%% CPU reading should not outweigh "+
			"an 80%% job queue", result.Agent.Name)
	}
}

// TestAgentSelLoadBalancing_ZeroWeightsRejected pins that a misconfigured
// all-zero weight set is ignored rather than flattening every agent's score to
// zero (which would make selection arbitrary).
func TestAgentSelLoadBalancing_ZeroWeightsRejected(t *testing.T) {
	t.Parallel()

	repo := newAgentSelMockAgentRepo()
	hot := withFreshMetrics(makeAgentSelAgent("hot", 2, 5), 95, 95)
	cool := withFreshMetrics(makeAgentSelAgent("cool", 2, 5), 1, 1)
	repo.availableAgents = []*agent.Agent{hot, cool}

	sel := newAgentSelSelector(repo)
	sel.SetLoadBalancingWeights(agent.LoadBalancingWeights{}) // all zero

	result, err := sel.SelectAgent(context.Background(), app.SelectAgentRequest{
		TenantID: shared.NewID(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Agent.ID != cool.ID {
		t.Errorf("all-zero weights should fall back to the defaults, but selection "+
			"picked %q over the idle agent", result.Agent.Name)
	}
}

// =============================================================================
// Tests: mode constants
// =============================================================================

// TestAgentSelModeConstants verifies that the exported mode constants have
// the expected string values documented in the code.
func TestAgentSelModeConstants(t *testing.T) {
	t.Parallel()

	if app.SelectTenantOnly != "tenant_only" {
		t.Errorf("SelectTenantOnly = %q, want %q", app.SelectTenantOnly, "tenant_only")
	}
	if app.SelectAny != "any" {
		t.Errorf("SelectAny = %q, want %q", app.SelectAny, "any")
	}
}

// TestAgentSelErrNoAgentAvailable verifies that ErrNoAgentAvailable is
// exported and has a non-empty message.
func TestAgentSelErrNoAgentAvailable(t *testing.T) {
	t.Parallel()

	if app.ErrNoAgentAvailable == nil {
		t.Fatal("ErrNoAgentAvailable should not be nil")
	}
	if app.ErrNoAgentAvailable.Error() == "" {
		t.Error("ErrNoAgentAvailable should have a non-empty message")
	}
}
