package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/scansession"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock: scansession.Repository (scanSessionMockRepo)
// =============================================================================

type scanSessionMockRepo struct {
	sessions map[string]*scansession.ScanSession

	createErr       error
	getByTenantErr  error
	updateErr       error
	deleteErr       error
	listErr         error
	findBaselineErr error
	getStatsErr     error
	listRunningErr  error

	baselineCommitSha string
	stats             *scansession.Stats
	runningSessions   []*scansession.ScanSession
}

func newScanSessionMockRepo() *scanSessionMockRepo {
	return &scanSessionMockRepo{
		sessions: make(map[string]*scansession.ScanSession),
	}
}

func (m *scanSessionMockRepo) Create(_ context.Context, s *scansession.ScanSession) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.sessions[s.ID.String()] = s
	return nil
}

func (m *scanSessionMockRepo) GetByID(_ context.Context, id shared.ID) (*scansession.ScanSession, error) {
	s, ok := m.sessions[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return s, nil
}

func (m *scanSessionMockRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*scansession.ScanSession, error) {
	if m.getByTenantErr != nil {
		return nil, m.getByTenantErr
	}
	s, ok := m.sessions[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	if s.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return s, nil
}

func (m *scanSessionMockRepo) Update(_ context.Context, s *scansession.ScanSession) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.sessions[s.ID.String()] = s
	return nil
}

func (m *scanSessionMockRepo) List(_ context.Context, _ scansession.Filter, page pagination.Pagination) (pagination.Result[*scansession.ScanSession], error) {
	if m.listErr != nil {
		return pagination.Result[*scansession.ScanSession]{}, m.listErr
	}
	result := make([]*scansession.ScanSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		result = append(result, s)
	}
	total := int64(len(result))
	return pagination.Result[*scansession.ScanSession]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *scanSessionMockRepo) Delete(_ context.Context, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.sessions[id.String()]; !ok {
		return shared.ErrNotFound
	}
	delete(m.sessions, id.String())
	return nil
}

func (m *scanSessionMockRepo) FindBaseline(_ context.Context, _ shared.ID, _, _, _ string) (string, error) {
	if m.findBaselineErr != nil {
		return "", m.findBaselineErr
	}
	return m.baselineCommitSha, nil
}

func (m *scanSessionMockRepo) GetStats(_ context.Context, _ shared.ID, _ time.Time) (*scansession.Stats, error) {
	if m.getStatsErr != nil {
		return nil, m.getStatsErr
	}
	if m.stats != nil {
		return m.stats, nil
	}
	return &scansession.Stats{}, nil
}

func (m *scanSessionMockRepo) ListRunning(_ context.Context, _ shared.ID) ([]*scansession.ScanSession, error) {
	if m.listRunningErr != nil {
		return nil, m.listRunningErr
	}
	if m.runningSessions != nil {
		return m.runningSessions, nil
	}
	result := make([]*scansession.ScanSession, 0)
	for _, s := range m.sessions {
		if s.Status == scansession.StatusRunning {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *scanSessionMockRepo) addSession(s *scansession.ScanSession) {
	m.sessions[s.ID.String()] = s
}

// =============================================================================
// Mock: agent.Repository (scanSessionMockAgentRepo)
// =============================================================================

type scanSessionMockAgentRepo struct {
	agents map[string]*agent.Agent
}

func newScanSessionMockAgentRepo() *scanSessionMockAgentRepo {
	return &scanSessionMockAgentRepo{
		agents: make(map[string]*agent.Agent),
	}
}

func (m *scanSessionMockAgentRepo) Create(_ context.Context, a *agent.Agent) error {
	m.agents[a.ID.String()] = a
	return nil
}

func (m *scanSessionMockAgentRepo) CountByTenant(_ context.Context, _ shared.ID) (int, error) {
	return len(m.agents), nil
}

func (m *scanSessionMockAgentRepo) GetByID(_ context.Context, id shared.ID) (*agent.Agent, error) {
	a, ok := m.agents[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return a, nil
}

func (m *scanSessionMockAgentRepo) GetByTenantAndID(_ context.Context, _, id shared.ID) (*agent.Agent, error) {
	a, ok := m.agents[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return a, nil
}

func (m *scanSessionMockAgentRepo) GetByAPIKeyHash(_ context.Context, _ string) (*agent.Agent, error) {
	return nil, shared.ErrNotFound
}

func (m *scanSessionMockAgentRepo) List(_ context.Context, _ agent.Filter, _ pagination.Pagination) (pagination.Result[*agent.Agent], error) {
	return pagination.Result[*agent.Agent]{}, nil
}

func (m *scanSessionMockAgentRepo) Update(_ context.Context, _ *agent.Agent) error { return nil }
func (m *scanSessionMockAgentRepo) Delete(_ context.Context, _ shared.ID) error     { return nil }
func (m *scanSessionMockAgentRepo) UpdateLastSeen(_ context.Context, _ shared.ID) error {
	return nil
}

func (m *scanSessionMockAgentRepo) IncrementStats(_ context.Context, _ shared.ID, _, _, _ int64) error {
	return nil
}

func (m *scanSessionMockAgentRepo) FindByCapabilities(_ context.Context, _ shared.ID, _ []string, _ string) ([]*agent.Agent, error) {
	return nil, nil
}

func (m *scanSessionMockAgentRepo) FindAvailable(_ context.Context, _ shared.ID, _ []string, _ string) ([]*agent.Agent, error) {
	return nil, nil
}

func (m *scanSessionMockAgentRepo) FindAvailableWithTool(_ context.Context, _ shared.ID, _ string) (*agent.Agent, error) {
	return nil, shared.ErrNotFound
}

func (m *scanSessionMockAgentRepo) MarkStaleAsOffline(_ context.Context, _ time.Duration) (int64, error) {
	return 0, nil
}

func (m *scanSessionMockAgentRepo) FindAvailableWithCapacity(_ context.Context, _ shared.ID, _ []string, _ string) ([]*agent.Agent, error) {
	return nil, nil
}

func (m *scanSessionMockAgentRepo) ClaimJob(_ context.Context, _ shared.ID) error   { return nil }
func (m *scanSessionMockAgentRepo) ReleaseJob(_ context.Context, _ shared.ID) error { return nil }
func (m *scanSessionMockAgentRepo) UpdateOfflineTimestamp(_ context.Context, _ shared.ID) error {
	return nil
}

func (m *scanSessionMockAgentRepo) MarkStaleAgentsOffline(_ context.Context, _ time.Duration) ([]shared.ID, error) {
	return nil, nil
}

func (m *scanSessionMockAgentRepo) GetAgentsOfflineSince(_ context.Context, _ time.Time) ([]*agent.Agent, error) {
	return nil, nil
}

func (m *scanSessionMockAgentRepo) GetAvailableToolsForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return nil, nil
}

func (m *scanSessionMockAgentRepo) HasAgentForTool(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}

func (m *scanSessionMockAgentRepo) GetAvailableCapabilitiesForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return nil, nil
}

func (m *scanSessionMockAgentRepo) HasAgentForCapability(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}

func (m *scanSessionMockAgentRepo) GetPlatformAgentStats(_ context.Context, _ shared.ID) (*agent.PlatformAgentStatsResult, error) {
	return nil, nil
}

func (m *scanSessionMockAgentRepo) GetTenantAgentStats(_ context.Context, _ shared.ID) (*agent.TenantAgentStats, error) {
	return nil, nil
}

// =============================================================================
// Helpers
// =============================================================================

func newTestScanSessionService() (*app.ScanSessionService, *scanSessionMockRepo, *scanSessionMockAgentRepo) {
	sessionRepo := newScanSessionMockRepo()
	agentRepo := newScanSessionMockAgentRepo()
	log := logger.New(logger.Config{Level: "error", Format: "text"})
	svc := app.NewScanSessionService(sessionRepo, agentRepo, log)
	return svc, sessionRepo, agentRepo
}

func newTestAgentWithTenant(tenantID shared.ID) *agent.Agent {
	agt, _ := agent.NewAgent(tenantID, "test-agent", agent.AgentTypeRunner, "test", []string{"sast"}, []string{"semgrep"}, agent.ExecutionModeStandalone)
	return agt
}

func newTestAgentWithoutTenant() *agent.Agent {
	agt, _ := agent.NewAgent(shared.NewID(), "platform-agent", agent.AgentTypeWorker, "platform", []string{"sast"}, []string{"semgrep"}, agent.ExecutionModeDaemon)
	agt.TenantID = nil // Platform agent has no tenant
	agt.IsPlatformAgent = true
	return agt
}

func defaultRegisterScanInput() app.RegisterScanInput {
	return app.RegisterScanInput{
		ScannerName:    "semgrep",
		ScannerVersion: "1.2.3",
		ScannerType:    "sast",
		AssetType:      "repository",
		AssetValue:     "https://github.com/example/repo",
		CommitSha:      "abc123",
		Branch:         "main",
	}
}

// =============================================================================
// Tests: RegisterScan
// =============================================================================

func TestScanSessionService_RegisterScan_Success(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)
	input := defaultRegisterScanInput()

	output, err := svc.RegisterScan(context.Background(), agt, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if output.ScanID == "" {
		t.Error("expected scan_id to be set")
	}

	// Verify session was saved
	if len(sessionRepo.sessions) != 1 {
		t.Fatalf("expected 1 session in repo, got %d", len(sessionRepo.sessions))
	}

	// Verify the session is in running state (Start() was called)
	for _, s := range sessionRepo.sessions {
		if s.Status != scansession.StatusRunning {
			t.Errorf("expected status running, got %s", s.Status)
		}
		if s.ScannerName != "semgrep" {
			t.Errorf("expected scanner_name semgrep, got %s", s.ScannerName)
		}
		if s.ScannerVersion != "1.2.3" {
			t.Errorf("expected scanner_version 1.2.3, got %s", s.ScannerVersion)
		}
		if s.ScannerType != "sast" {
			t.Errorf("expected scanner_type sast, got %s", s.ScannerType)
		}
		if s.AssetType != "repository" {
			t.Errorf("expected asset_type repository, got %s", s.AssetType)
		}
		if s.AssetValue != "https://github.com/example/repo" {
			t.Errorf("expected asset_value, got %s", s.AssetValue)
		}
		if s.CommitSha != "abc123" {
			t.Errorf("expected commit_sha abc123, got %s", s.CommitSha)
		}
		if s.Branch != "main" {
			t.Errorf("expected branch main, got %s", s.Branch)
		}
		if s.AgentID == nil || !s.AgentID.Equals(agt.ID) {
			t.Error("expected agent_id to match")
		}
	}
}

func TestScanSessionService_RegisterScan_NoTenantContext(t *testing.T) {
	svc, _, _ := newTestScanSessionService()
	agt := newTestAgentWithoutTenant()
	input := defaultRegisterScanInput()

	_, err := svc.RegisterScan(context.Background(), agt, input)
	if err == nil {
		t.Fatal("expected error for agent without tenant context")
	}

	if err.Error() != "agent has no tenant context: platform agents require job assignment" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestScanSessionService_RegisterScan_WithBaseline(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)
	input := defaultRegisterScanInput()

	sessionRepo.baselineCommitSha = "baseline-sha-456"

	output, err := svc.RegisterScan(context.Background(), agt, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if output.BaseCommitSha != "baseline-sha-456" {
		t.Errorf("expected base_commit_sha baseline-sha-456, got %s", output.BaseCommitSha)
	}

	// Verify session has baseline set
	for _, s := range sessionRepo.sessions {
		if s.BaseCommitSha != "baseline-sha-456" {
			t.Errorf("expected session base_commit_sha baseline-sha-456, got %s", s.BaseCommitSha)
		}
	}
}

func TestScanSessionService_RegisterScan_BaselineError_Continues(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)
	input := defaultRegisterScanInput()

	sessionRepo.findBaselineErr = errors.New("db connection failed")

	output, err := svc.RegisterScan(context.Background(), agt, input)
	if err != nil {
		t.Fatalf("expected no error (baseline failure should not fail registration), got %v", err)
	}

	if output.BaseCommitSha != "" {
		t.Errorf("expected empty base_commit_sha on baseline error, got %s", output.BaseCommitSha)
	}

	if len(sessionRepo.sessions) != 1 {
		t.Fatal("expected session to be created despite baseline error")
	}
}

func TestScanSessionService_RegisterScan_CreateError(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)
	input := defaultRegisterScanInput()

	sessionRepo.createErr = errors.New("db write failed")

	_, err := svc.RegisterScan(context.Background(), agt, input)
	if err == nil {
		t.Fatal("expected error when repo create fails")
	}
}

func TestScanSessionService_RegisterScan_EmptyRequiredFields(t *testing.T) {
	svc, _, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)

	tests := []struct {
		name  string
		input app.RegisterScanInput
	}{
		{
			name:  "empty scanner_name",
			input: app.RegisterScanInput{ScannerName: "", AssetType: "repo", AssetValue: "val"},
		},
		{
			name:  "empty asset_type",
			input: app.RegisterScanInput{ScannerName: "semgrep", AssetType: "", AssetValue: "val"},
		},
		{
			name:  "empty asset_value",
			input: app.RegisterScanInput{ScannerName: "semgrep", AssetType: "repo", AssetValue: ""},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.RegisterScan(context.Background(), agt, tc.input)
			if err == nil {
				t.Errorf("expected validation error for %s", tc.name)
			}
		})
	}
}

func TestScanSessionService_RegisterScan_NoBaseline(t *testing.T) {
	svc, _, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)
	input := defaultRegisterScanInput()

	output, err := svc.RegisterScan(context.Background(), agt, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if output.BaseCommitSha != "" {
		t.Errorf("expected empty base_commit_sha when no baseline, got %s", output.BaseCommitSha)
	}
}

// =============================================================================
// Tests: UpdateScanSession
// =============================================================================

func TestScanSessionService_UpdateScanSession_Complete(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)

	// Create a running session
	session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
	session.SetAgent(agt.ID)
	_ = session.Start()
	sessionRepo.addSession(session)

	input := app.UpdateScanSessionInput{
		Status:        "completed",
		FindingsTotal: 10,
		FindingsNew:   3,
		FindingsFixed: 2,
		FindingsBySeverity: map[string]int{
			"critical": 1,
			"high":     2,
			"medium":   7,
		},
	}

	err := svc.UpdateScanSession(context.Background(), agt, session.ID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	updated := sessionRepo.sessions[session.ID.String()]
	if updated.Status != scansession.StatusCompleted {
		t.Errorf("expected status completed, got %s", updated.Status)
	}
	if updated.FindingsTotal != 10 {
		t.Errorf("expected findings_total 10, got %d", updated.FindingsTotal)
	}
	if updated.FindingsNew != 3 {
		t.Errorf("expected findings_new 3, got %d", updated.FindingsNew)
	}
	if updated.FindingsFixed != 2 {
		t.Errorf("expected findings_fixed 2, got %d", updated.FindingsFixed)
	}
}

func TestScanSessionService_UpdateScanSession_Failed(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)

	session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
	session.SetAgent(agt.ID)
	_ = session.Start()
	sessionRepo.addSession(session)

	input := app.UpdateScanSessionInput{
		Status:       "failed",
		ErrorMessage: "scanner crashed",
	}

	err := svc.UpdateScanSession(context.Background(), agt, session.ID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	updated := sessionRepo.sessions[session.ID.String()]
	if updated.Status != scansession.StatusFailed {
		t.Errorf("expected status failed, got %s", updated.Status)
	}
	if updated.ErrorMessage != "scanner crashed" {
		t.Errorf("expected error_message 'scanner crashed', got %s", updated.ErrorMessage)
	}
}

func TestScanSessionService_UpdateScanSession_Canceled(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)

	session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
	session.SetAgent(agt.ID)
	_ = session.Start()
	sessionRepo.addSession(session)

	input := app.UpdateScanSessionInput{
		Status: "canceled",
	}

	err := svc.UpdateScanSession(context.Background(), agt, session.ID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	updated := sessionRepo.sessions[session.ID.String()]
	if updated.Status != scansession.StatusCanceled {
		t.Errorf("expected status canceled, got %s", updated.Status)
	}
}

func TestScanSessionService_UpdateScanSession_NoTenantContext(t *testing.T) {
	svc, _, _ := newTestScanSessionService()
	agt := newTestAgentWithoutTenant()

	input := app.UpdateScanSessionInput{Status: "completed"}

	err := svc.UpdateScanSession(context.Background(), agt, shared.NewID().String(), input)
	if err == nil {
		t.Fatal("expected error for agent without tenant context")
	}
}

func TestScanSessionService_UpdateScanSession_InvalidScanID(t *testing.T) {
	svc, _, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)

	input := app.UpdateScanSessionInput{Status: "completed"}

	err := svc.UpdateScanSession(context.Background(), agt, "not-a-valid-uuid", input)
	if err == nil {
		t.Fatal("expected error for invalid scan_id")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScanSessionService_UpdateScanSession_NotFound(t *testing.T) {
	svc, _, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)

	input := app.UpdateScanSessionInput{Status: "completed"}

	err := svc.UpdateScanSession(context.Background(), agt, shared.NewID().String(), input)
	if err == nil {
		t.Fatal("expected error when session not found")
	}
}

func TestScanSessionService_UpdateScanSession_WrongAgent(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	ownerAgent := newTestAgentWithTenant(tenantID)
	otherAgent := newTestAgentWithTenant(tenantID)

	session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
	session.SetAgent(ownerAgent.ID)
	_ = session.Start()
	sessionRepo.addSession(session)

	input := app.UpdateScanSessionInput{Status: "completed"}

	err := svc.UpdateScanSession(context.Background(), otherAgent, session.ID.String(), input)
	if err == nil {
		t.Fatal("expected forbidden error when agent does not own session")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

func TestScanSessionService_UpdateScanSession_UpdateRepoError(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)

	session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
	session.SetAgent(agt.ID)
	_ = session.Start()
	sessionRepo.addSession(session)
	sessionRepo.updateErr = errors.New("db update failed")

	input := app.UpdateScanSessionInput{Status: "completed"}

	err := svc.UpdateScanSession(context.Background(), agt, session.ID.String(), input)
	if err == nil {
		t.Fatal("expected error when repo update fails")
	}
}

func TestScanSessionService_UpdateScanSession_InvalidStateTransition(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)

	// Create a session that is already completed (terminal state)
	session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
	session.SetAgent(agt.ID)
	_ = session.Start()
	_ = session.Complete(5, 2, 1, nil)
	sessionRepo.addSession(session)

	// Try to complete again
	input := app.UpdateScanSessionInput{Status: "completed"}

	err := svc.UpdateScanSession(context.Background(), agt, session.ID.String(), input)
	if err == nil {
		t.Fatal("expected error when transitioning from terminal state")
	}
}

func TestScanSessionService_UpdateScanSession_CancelTerminalState(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)

	// Create a session that is already failed (terminal)
	session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
	session.SetAgent(agt.ID)
	_ = session.Start()
	_ = session.Fail("some error")
	sessionRepo.addSession(session)

	input := app.UpdateScanSessionInput{Status: "canceled"}

	err := svc.UpdateScanSession(context.Background(), agt, session.ID.String(), input)
	if err == nil {
		t.Fatal("expected error when canceling an already terminal session")
	}
}

// =============================================================================
// Tests: GetScan
// =============================================================================

func TestScanSessionService_GetScan_Success(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()

	session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
	sessionRepo.addSession(session)

	result, err := svc.GetScan(context.Background(), tenantID, session.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !result.ID.Equals(session.ID) {
		t.Error("expected returned session ID to match")
	}
}

func TestScanSessionService_GetScan_InvalidID(t *testing.T) {
	svc, _, _ := newTestScanSessionService()
	tenantID := shared.NewID()

	_, err := svc.GetScan(context.Background(), tenantID, "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid scan_id")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScanSessionService_GetScan_NotFound(t *testing.T) {
	svc, _, _ := newTestScanSessionService()
	tenantID := shared.NewID()

	_, err := svc.GetScan(context.Background(), tenantID, shared.NewID().String())
	if err == nil {
		t.Fatal("expected error when session not found")
	}
}

func TestScanSessionService_GetScan_WrongTenant(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
	sessionRepo.addSession(session)

	_, err := svc.GetScan(context.Background(), otherTenantID, session.ID.String())
	if err == nil {
		t.Fatal("expected error when accessing session from wrong tenant")
	}
}

// =============================================================================
// Tests: ListScanSessions
// =============================================================================

func TestScanSessionService_ListScanSessions_Success(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()

	for i := 0; i < 3; i++ {
		session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
		sessionRepo.addSession(session)
	}

	input := app.ListScanSessionsInput{}
	page := pagination.Pagination{Page: 1, PerPage: 10}

	result, err := svc.ListScanSessions(context.Background(), tenantID, input, page)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Total != 3 {
		t.Errorf("expected total 3, got %d", result.Total)
	}
}

func TestScanSessionService_ListScanSessions_WithStatusFilter(t *testing.T) {
	svc, _, _ := newTestScanSessionService()
	tenantID := shared.NewID()

	input := app.ListScanSessionsInput{
		Status: "running",
	}
	page := pagination.Pagination{Page: 1, PerPage: 10}

	// This mainly tests that status is correctly parsed and passed to the filter
	_, err := svc.ListScanSessions(context.Background(), tenantID, input, page)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestScanSessionService_ListScanSessions_WithFilters(t *testing.T) {
	svc, _, _ := newTestScanSessionService()
	tenantID := shared.NewID()

	now := time.Now()
	input := app.ListScanSessionsInput{
		ScannerName: "trivy",
		AssetType:   "container",
		AssetValue:  "nginx:latest",
		Branch:      "develop",
		Status:      "completed",
		Since:       &now,
		Until:       &now,
	}
	page := pagination.Pagination{Page: 1, PerPage: 10}

	_, err := svc.ListScanSessions(context.Background(), tenantID, input, page)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestScanSessionService_ListScanSessions_RepoError(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()

	sessionRepo.listErr = errors.New("db error")

	input := app.ListScanSessionsInput{}
	page := pagination.Pagination{Page: 1, PerPage: 10}

	_, err := svc.ListScanSessions(context.Background(), tenantID, input, page)
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// =============================================================================
// Tests: GetStats
// =============================================================================

func TestScanSessionService_GetStats_Success(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()

	sessionRepo.stats = &scansession.Stats{
		Total:     100,
		Running:   5,
		Completed: 80,
		Failed:    10,
		Canceled:  5,
		ByScanner: map[string]int64{"semgrep": 50, "trivy": 50},
	}

	since := time.Now().Add(-24 * time.Hour)
	stats, err := svc.GetStats(context.Background(), tenantID, since)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if stats.Total != 100 {
		t.Errorf("expected total 100, got %d", stats.Total)
	}
	if stats.Running != 5 {
		t.Errorf("expected running 5, got %d", stats.Running)
	}
	if stats.Completed != 80 {
		t.Errorf("expected completed 80, got %d", stats.Completed)
	}
}

func TestScanSessionService_GetStats_RepoError(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()

	sessionRepo.getStatsErr = errors.New("db error")

	since := time.Now().Add(-24 * time.Hour)
	_, err := svc.GetStats(context.Background(), tenantID, since)
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// =============================================================================
// Tests: ListRunning
// =============================================================================

func TestScanSessionService_ListRunning_Success(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()

	// Create running sessions
	for i := 0; i < 2; i++ {
		session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
		_ = session.Start()
		sessionRepo.addSession(session)
	}

	// Create a completed session (should not appear)
	completed, _ := scansession.NewScanSession(tenantID, "trivy", "container", "nginx")
	_ = completed.Start()
	_ = completed.Complete(0, 0, 0, nil)
	sessionRepo.addSession(completed)

	result, err := svc.ListRunning(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 running sessions, got %d", len(result))
	}
}

func TestScanSessionService_ListRunning_Empty(t *testing.T) {
	svc, _, _ := newTestScanSessionService()
	tenantID := shared.NewID()

	result, err := svc.ListRunning(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(result) != 0 {
		t.Errorf("expected 0 running sessions, got %d", len(result))
	}
}

func TestScanSessionService_ListRunning_RepoError(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()

	sessionRepo.listRunningErr = errors.New("db error")

	_, err := svc.ListRunning(context.Background(), tenantID)
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// =============================================================================
// Tests: DeleteScan
// =============================================================================

func TestScanSessionService_DeleteScan_Success(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()

	session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
	sessionRepo.addSession(session)

	err := svc.DeleteScan(context.Background(), tenantID, session.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(sessionRepo.sessions) != 0 {
		t.Error("expected session to be deleted from repo")
	}
}

func TestScanSessionService_DeleteScan_InvalidID(t *testing.T) {
	svc, _, _ := newTestScanSessionService()
	tenantID := shared.NewID()

	err := svc.DeleteScan(context.Background(), tenantID, "not-valid")
	if err == nil {
		t.Fatal("expected error for invalid scan_id")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScanSessionService_DeleteScan_NotFound(t *testing.T) {
	svc, _, _ := newTestScanSessionService()
	tenantID := shared.NewID()

	err := svc.DeleteScan(context.Background(), tenantID, shared.NewID().String())
	if err == nil {
		t.Fatal("expected error when session not found")
	}
}

func TestScanSessionService_DeleteScan_WrongTenant(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
	sessionRepo.addSession(session)

	err := svc.DeleteScan(context.Background(), otherTenantID, session.ID.String())
	if err == nil {
		t.Fatal("expected error when deleting session from wrong tenant")
	}
}

func TestScanSessionService_DeleteScan_RepoDeleteError(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()

	session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
	sessionRepo.addSession(session)
	sessionRepo.deleteErr = errors.New("db delete failed")

	err := svc.DeleteScan(context.Background(), tenantID, session.ID.String())
	if err == nil {
		t.Fatal("expected error when repo delete fails")
	}
}

// =============================================================================
// Tests: Status Transitions (integration with domain entity)
// =============================================================================

func TestScanSessionService_UpdateScanSession_CompleteFromPending(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)

	// Create a pending session (not started yet) - Complete should work on pending too
	session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
	session.SetAgent(agt.ID)
	// Do NOT call Start() - leave in pending state
	sessionRepo.addSession(session)

	input := app.UpdateScanSessionInput{
		Status:        "completed",
		FindingsTotal: 5,
	}

	err := svc.UpdateScanSession(context.Background(), agt, session.ID.String(), input)
	if err != nil {
		t.Fatalf("expected no error (complete from pending is valid), got %v", err)
	}

	updated := sessionRepo.sessions[session.ID.String()]
	if updated.Status != scansession.StatusCompleted {
		t.Errorf("expected status completed, got %s", updated.Status)
	}
}

func TestScanSessionService_UpdateScanSession_FailFromPending(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)

	session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
	session.SetAgent(agt.ID)
	sessionRepo.addSession(session)

	input := app.UpdateScanSessionInput{
		Status:       "failed",
		ErrorMessage: "could not start scanner",
	}

	err := svc.UpdateScanSession(context.Background(), agt, session.ID.String(), input)
	if err != nil {
		t.Fatalf("expected no error (fail from pending is valid), got %v", err)
	}

	updated := sessionRepo.sessions[session.ID.String()]
	if updated.Status != scansession.StatusFailed {
		t.Errorf("expected status failed, got %s", updated.Status)
	}
}

// =============================================================================
// Tests: Agent ownership edge cases
// =============================================================================

func TestScanSessionService_UpdateScanSession_NilAgentID_OnSession(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)

	// Session without an agent assigned (AgentID is nil)
	session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
	// Do NOT call session.SetAgent - leave AgentID nil
	_ = session.Start()
	sessionRepo.addSession(session)

	input := app.UpdateScanSessionInput{Status: "completed"}

	// When session has no AgentID, ownership check should pass (no owner to verify against)
	err := svc.UpdateScanSession(context.Background(), agt, session.ID.String(), input)
	if err != nil {
		t.Fatalf("expected no error when session has nil AgentID, got %v", err)
	}
}

func TestScanSessionService_UpdateScanSession_SameAgent_Succeeds(t *testing.T) {
	svc, sessionRepo, _ := newTestScanSessionService()
	tenantID := shared.NewID()
	agt := newTestAgentWithTenant(tenantID)

	session, _ := scansession.NewScanSession(tenantID, "semgrep", "repository", "repo-url")
	session.SetAgent(agt.ID)
	_ = session.Start()
	sessionRepo.addSession(session)

	input := app.UpdateScanSessionInput{
		Status:        "completed",
		FindingsTotal: 42,
		FindingsNew:   10,
		FindingsFixed: 5,
		FindingsBySeverity: map[string]int{
			"critical": 2,
			"high":     8,
			"medium":   20,
			"low":      12,
		},
	}

	err := svc.UpdateScanSession(context.Background(), agt, session.ID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	updated := sessionRepo.sessions[session.ID.String()]
	if updated.FindingsTotal != 42 {
		t.Errorf("expected findings_total 42, got %d", updated.FindingsTotal)
	}
	if updated.FindingsBySeverity["critical"] != 2 {
		t.Errorf("expected critical=2, got %d", updated.FindingsBySeverity["critical"])
	}
}

// =============================================================================
// Tests: Constructor
// =============================================================================

func TestNewScanSessionService(t *testing.T) {
	svc, _, _ := newTestScanSessionService()
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}
