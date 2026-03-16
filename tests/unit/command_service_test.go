package unit

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock: command.Repository (prefixed with cmd)
// =============================================================================

type cmdMockRepo struct {
	commands map[string]*command.Command

	// Error overrides
	createErr             error
	getByTenantAndIDErr   error
	updateErr             error
	deleteErr             error
	listErr               error
	getPendingErr         error
	expireErr             error
	expireCount           int64
	findExpiredResult     []*command.Command
	findExpiredErr        error
	getByAuthTokenHashErr error
	countActiveErr        error
	countQueuedTenantErr  error
	countQueuedAllErr     error
	getQueuedErr          error
	getNextErr            error
	updatePrioritiesErr   error
	recoverStuckErr       error
	expirePlatformErr     error
	getQueuePositionErr   error
	listPlatformTenantErr error
	listPlatformAdminErr  error
	getPlatformByAgentErr error
	recoverTenantErr      error
	failExhaustedErr      error
	getStatsByTenantErr   error
}

func newCmdMockRepo() *cmdMockRepo {
	return &cmdMockRepo{commands: make(map[string]*command.Command)}
}

func (m *cmdMockRepo) Create(_ context.Context, cmd *command.Command) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.commands[cmd.ID.String()] = cmd
	return nil
}

func (m *cmdMockRepo) GetByID(_ context.Context, id shared.ID) (*command.Command, error) {
	c, ok := m.commands[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return c, nil
}

func (m *cmdMockRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*command.Command, error) {
	if m.getByTenantAndIDErr != nil {
		return nil, m.getByTenantAndIDErr
	}
	c, ok := m.commands[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	if c.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return c, nil
}

func (m *cmdMockRepo) GetPendingForAgent(_ context.Context, _ shared.ID, _ *shared.ID, limit int) ([]*command.Command, error) {
	if m.getPendingErr != nil {
		return nil, m.getPendingErr
	}
	result := make([]*command.Command, 0)
	for _, c := range m.commands {
		if c.Status == command.CommandStatusPending {
			result = append(result, c)
			if len(result) >= limit {
				break
			}
		}
	}
	return result, nil
}

func (m *cmdMockRepo) List(_ context.Context, _ command.Filter, page pagination.Pagination) (pagination.Result[*command.Command], error) {
	if m.listErr != nil {
		return pagination.Result[*command.Command]{}, m.listErr
	}
	result := make([]*command.Command, 0, len(m.commands))
	for _, c := range m.commands {
		result = append(result, c)
	}
	total := int64(len(result))
	return pagination.Result[*command.Command]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *cmdMockRepo) Update(_ context.Context, cmd *command.Command) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.commands[cmd.ID.String()] = cmd
	return nil
}

func (m *cmdMockRepo) Delete(_ context.Context, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.commands, id.String())
	return nil
}

func (m *cmdMockRepo) ExpireOldCommands(_ context.Context) (int64, error) {
	if m.expireErr != nil {
		return 0, m.expireErr
	}
	return m.expireCount, nil
}

func (m *cmdMockRepo) FindExpired(_ context.Context) ([]*command.Command, error) {
	if m.findExpiredErr != nil {
		return nil, m.findExpiredErr
	}
	return m.findExpiredResult, nil
}

func (m *cmdMockRepo) GetByAuthTokenHash(_ context.Context, _ string) (*command.Command, error) {
	if m.getByAuthTokenHashErr != nil {
		return nil, m.getByAuthTokenHashErr
	}
	return nil, shared.ErrNotFound
}

func (m *cmdMockRepo) CountActivePlatformJobsByTenant(_ context.Context, _ shared.ID) (int, error) {
	if m.countActiveErr != nil {
		return 0, m.countActiveErr
	}
	return 0, nil
}

func (m *cmdMockRepo) CountQueuedPlatformJobsByTenant(_ context.Context, _ shared.ID) (int, error) {
	if m.countQueuedTenantErr != nil {
		return 0, m.countQueuedTenantErr
	}
	return 0, nil
}

func (m *cmdMockRepo) CountQueuedPlatformJobs(_ context.Context) (int, error) {
	if m.countQueuedAllErr != nil {
		return 0, m.countQueuedAllErr
	}
	return 0, nil
}

func (m *cmdMockRepo) GetQueuedPlatformJobs(_ context.Context, _ int) ([]*command.Command, error) {
	if m.getQueuedErr != nil {
		return nil, m.getQueuedErr
	}
	return nil, nil
}

func (m *cmdMockRepo) GetNextPlatformJob(_ context.Context, _ shared.ID, _ []string, _ []string) (*command.Command, error) {
	if m.getNextErr != nil {
		return nil, m.getNextErr
	}
	return nil, nil
}

func (m *cmdMockRepo) UpdateQueuePriorities(_ context.Context) (int64, error) {
	if m.updatePrioritiesErr != nil {
		return 0, m.updatePrioritiesErr
	}
	return 0, nil
}

func (m *cmdMockRepo) RecoverStuckJobs(_ context.Context, _ int, _ int) (int64, error) {
	if m.recoverStuckErr != nil {
		return 0, m.recoverStuckErr
	}
	return 0, nil
}

func (m *cmdMockRepo) ExpireOldPlatformJobs(_ context.Context, _ int) (int64, error) {
	if m.expirePlatformErr != nil {
		return 0, m.expirePlatformErr
	}
	return 0, nil
}

func (m *cmdMockRepo) GetQueuePosition(_ context.Context, _ shared.ID) (*command.QueuePosition, error) {
	if m.getQueuePositionErr != nil {
		return nil, m.getQueuePositionErr
	}
	return &command.QueuePosition{Position: 1, TotalQueued: 1}, nil
}

func (m *cmdMockRepo) ListPlatformJobsByTenant(_ context.Context, _ shared.ID, page pagination.Pagination) (pagination.Result[*command.Command], error) {
	if m.listPlatformTenantErr != nil {
		return pagination.Result[*command.Command]{}, m.listPlatformTenantErr
	}
	return pagination.Result[*command.Command]{Page: page.Page, PerPage: page.PerPage}, nil
}

func (m *cmdMockRepo) ListPlatformJobsAdmin(_ context.Context, _ *shared.ID, _ *shared.ID, _ *command.CommandStatus, page pagination.Pagination) (pagination.Result[*command.Command], error) {
	if m.listPlatformAdminErr != nil {
		return pagination.Result[*command.Command]{}, m.listPlatformAdminErr
	}
	return pagination.Result[*command.Command]{Page: page.Page, PerPage: page.PerPage}, nil
}

func (m *cmdMockRepo) GetPlatformJobsByAgent(_ context.Context, _ shared.ID, _ *command.CommandStatus) ([]*command.Command, error) {
	if m.getPlatformByAgentErr != nil {
		return nil, m.getPlatformByAgentErr
	}
	return nil, nil
}

func (m *cmdMockRepo) RecoverStuckTenantCommands(_ context.Context, _ int, _ int) (int64, error) {
	if m.recoverTenantErr != nil {
		return 0, m.recoverTenantErr
	}
	return 0, nil
}

func (m *cmdMockRepo) FailExhaustedCommands(_ context.Context, _ int) (int64, error) {
	if m.failExhaustedErr != nil {
		return 0, m.failExhaustedErr
	}
	return 0, nil
}

func (m *cmdMockRepo) GetStatsByTenant(_ context.Context, _ shared.ID) (command.CommandStats, error) {
	if m.getStatsByTenantErr != nil {
		return command.CommandStats{}, m.getStatsByTenantErr
	}
	return command.CommandStats{}, nil
}

// =============================================================================
// Helper functions
// =============================================================================

func newCmdTestLogger() *logger.Logger {
	return logger.New(logger.Config{Level: "error"})
}

func newCmdTestService(repo command.Repository) *app.CommandService {
	return app.NewCommandService(repo, newCmdTestLogger())
}

func newCmdTestTenantID() string {
	return shared.NewID().String()
}

// createTestCommand creates a command in the repo and returns its ID as string.
func createTestCommand(t *testing.T, svc *app.CommandService, tenantID string, cmdType string, priority string) *command.Command {
	t.Helper()
	input := app.CreateCommandInput{
		TenantID: tenantID,
		Type:     cmdType,
		Priority: priority,
	}
	cmd, err := svc.CreateCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to create test command: %v", err)
	}
	return cmd
}

// =============================================================================
// Tests: CreateCommand
// =============================================================================

func TestCommandService_CreateCommand_Success(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.CreateCommandInput{
		TenantID: tenantID,
		Type:     "scan",
		Priority: "high",
		Payload:  json.RawMessage(`{"target":"example.com"}`),
	}

	cmd, err := svc.CreateCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cmd == nil {
		t.Fatal("expected command, got nil")
	}
	if cmd.Type != command.CommandTypeScan {
		t.Errorf("expected type scan, got %s", cmd.Type)
	}
	if cmd.Priority != command.CommandPriorityHigh {
		t.Errorf("expected priority high, got %s", cmd.Priority)
	}
	if cmd.Status != command.CommandStatusPending {
		t.Errorf("expected status pending, got %s", cmd.Status)
	}
	if string(cmd.Payload) != `{"target":"example.com"}` {
		t.Errorf("unexpected payload: %s", cmd.Payload)
	}
}

func TestCommandService_CreateCommand_AllTypes(t *testing.T) {
	types := []string{"scan", "collect", "health_check", "config_update", "cancel"}
	for _, cmdType := range types {
		t.Run(cmdType, func(t *testing.T) {
			repo := newCmdMockRepo()
			svc := newCmdTestService(repo)
			tenantID := newCmdTestTenantID()

			input := app.CreateCommandInput{
				TenantID: tenantID,
				Type:     cmdType,
			}
			cmd, err := svc.CreateCommand(context.Background(), input)
			if err != nil {
				t.Fatalf("expected no error for type %s, got %v", cmdType, err)
			}
			if string(cmd.Type) != cmdType {
				t.Errorf("expected type %s, got %s", cmdType, cmd.Type)
			}
		})
	}
}

func TestCommandService_CreateCommand_AllPriorities(t *testing.T) {
	priorities := []string{"low", "normal", "high", "critical"}
	for _, p := range priorities {
		t.Run(p, func(t *testing.T) {
			repo := newCmdMockRepo()
			svc := newCmdTestService(repo)
			tenantID := newCmdTestTenantID()

			input := app.CreateCommandInput{
				TenantID: tenantID,
				Type:     "scan",
				Priority: p,
			}
			cmd, err := svc.CreateCommand(context.Background(), input)
			if err != nil {
				t.Fatalf("expected no error for priority %s, got %v", p, err)
			}
			if string(cmd.Priority) != p {
				t.Errorf("expected priority %s, got %s", p, cmd.Priority)
			}
		})
	}
}

func TestCommandService_CreateCommand_DefaultPriority(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.CreateCommandInput{
		TenantID: tenantID,
		Type:     "scan",
		// Priority omitted
	}
	cmd, err := svc.CreateCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cmd.Priority != command.CommandPriorityNormal {
		t.Errorf("expected default priority normal, got %s", cmd.Priority)
	}
}

func TestCommandService_CreateCommand_WithAgentID(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()
	agentID := shared.NewID().String()

	input := app.CreateCommandInput{
		TenantID: tenantID,
		AgentID:  agentID,
		Type:     "scan",
	}
	cmd, err := svc.CreateCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cmd.AgentID == nil {
		t.Fatal("expected agent ID to be set")
	}
	if cmd.AgentID.String() != agentID {
		t.Errorf("expected agent ID %s, got %s", agentID, cmd.AgentID.String())
	}
}

func TestCommandService_CreateCommand_WithExpiration(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.CreateCommandInput{
		TenantID:  tenantID,
		Type:      "scan",
		ExpiresIn: 3600, // 1 hour
	}
	cmd, err := svc.CreateCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cmd.ExpiresAt == nil {
		t.Fatal("expected expiration to be set")
	}
}

func TestCommandService_CreateCommand_NoExpiration(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.CreateCommandInput{
		TenantID: tenantID,
		Type:     "scan",
	}
	cmd, err := svc.CreateCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cmd.ExpiresAt != nil {
		t.Error("expected no expiration, got one")
	}
}

func TestCommandService_CreateCommand_InvalidTenantID(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)

	input := app.CreateCommandInput{
		TenantID: "invalid-uuid",
		Type:     "scan",
	}
	_, err := svc.CreateCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCommandService_CreateCommand_InvalidAgentID(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.CreateCommandInput{
		TenantID: tenantID,
		AgentID:  "not-a-uuid",
		Type:     "scan",
	}
	_, err := svc.CreateCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid agent ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCommandService_CreateCommand_RepoError(t *testing.T) {
	repo := newCmdMockRepo()
	repo.createErr = errors.New("db connection lost")
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.CreateCommandInput{
		TenantID: tenantID,
		Type:     "scan",
	}
	_, err := svc.CreateCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

func TestCommandService_CreateCommand_EmptyType(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.CreateCommandInput{
		TenantID: tenantID,
		Type:     "",
	}
	_, err := svc.CreateCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for empty command type")
	}
}

// =============================================================================
// Tests: GetCommand
// =============================================================================

func TestCommandService_GetCommand_Success(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")

	got, err := svc.GetCommand(context.Background(), tenantID, created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("expected ID %s, got %s", created.ID, got.ID)
	}
}

func TestCommandService_GetCommand_NotFound(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()
	missingID := shared.NewID().String()

	_, err := svc.GetCommand(context.Background(), tenantID, missingID)
	if err == nil {
		t.Fatal("expected not found error")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestCommandService_GetCommand_InvalidTenantID(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)

	_, err := svc.GetCommand(context.Background(), "bad-id", shared.NewID().String())
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCommandService_GetCommand_InvalidCommandID(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	_, err := svc.GetCommand(context.Background(), tenantID, "bad-command-id")
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCommandService_GetCommand_WrongTenant(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()
	otherTenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")

	_, err := svc.GetCommand(context.Background(), otherTenantID, created.ID.String())
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
}

// =============================================================================
// Tests: ListCommands
// =============================================================================

func TestCommandService_ListCommands_Success(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	createTestCommand(t, svc, tenantID, "scan", "normal")
	createTestCommand(t, svc, tenantID, "collect", "high")

	input := app.ListCommandsInput{
		TenantID: tenantID,
		Page:     1,
		PerPage:  10,
	}
	result, err := svc.ListCommands(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total < 2 {
		t.Errorf("expected at least 2 commands, got %d", result.Total)
	}
}

func TestCommandService_ListCommands_WithFilters(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()
	agentID := shared.NewID().String()

	input := app.ListCommandsInput{
		TenantID: tenantID,
		AgentID:  agentID,
		Type:     "scan",
		Status:   "pending",
		Priority: "high",
		Page:     1,
		PerPage:  10,
	}
	_, err := svc.ListCommands(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error with filters, got %v", err)
	}
}

func TestCommandService_ListCommands_InvalidTenantID(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)

	input := app.ListCommandsInput{
		TenantID: "bad",
		Page:     1,
		PerPage:  10,
	}
	_, err := svc.ListCommands(context.Background(), input)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCommandService_ListCommands_InvalidAgentID(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.ListCommandsInput{
		TenantID: tenantID,
		AgentID:  "not-uuid",
		Page:     1,
		PerPage:  10,
	}
	_, err := svc.ListCommands(context.Background(), input)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCommandService_ListCommands_RepoError(t *testing.T) {
	repo := newCmdMockRepo()
	repo.listErr = errors.New("db error")
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.ListCommandsInput{
		TenantID: tenantID,
		Page:     1,
		PerPage:  10,
	}
	_, err := svc.ListCommands(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// =============================================================================
// Tests: PollCommands
// =============================================================================

func TestCommandService_PollCommands_Success(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	createTestCommand(t, svc, tenantID, "scan", "normal")

	input := app.PollCommandsInput{
		TenantID: tenantID,
		Limit:    10,
	}
	cmds, err := svc.PollCommands(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(cmds) == 0 {
		t.Error("expected at least one pending command")
	}
}

func TestCommandService_PollCommands_WithAgentID(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()
	agentID := shared.NewID().String()

	input := app.PollCommandsInput{
		TenantID: tenantID,
		AgentID:  agentID,
		Limit:    10,
	}
	_, err := svc.PollCommands(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCommandService_PollCommands_DefaultLimit(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	// Limit <= 0 should default to 10
	input := app.PollCommandsInput{
		TenantID: tenantID,
		Limit:    0,
	}
	_, err := svc.PollCommands(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCommandService_PollCommands_LimitCappedAt100(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.PollCommandsInput{
		TenantID: tenantID,
		Limit:    200, // Should be capped to 100
	}
	_, err := svc.PollCommands(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCommandService_PollCommands_InvalidTenantID(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)

	input := app.PollCommandsInput{
		TenantID: "bad-uuid",
		Limit:    10,
	}
	_, err := svc.PollCommands(context.Background(), input)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCommandService_PollCommands_InvalidAgentID(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.PollCommandsInput{
		TenantID: tenantID,
		AgentID:  "not-valid",
		Limit:    10,
	}
	_, err := svc.PollCommands(context.Background(), input)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCommandService_PollCommands_RepoError(t *testing.T) {
	repo := newCmdMockRepo()
	repo.getPendingErr = errors.New("db error")
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.PollCommandsInput{
		TenantID: tenantID,
		Limit:    10,
	}
	_, err := svc.PollCommands(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// =============================================================================
// Tests: AcknowledgeCommand
// =============================================================================

func TestCommandService_AcknowledgeCommand_Success(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")

	acked, err := svc.AcknowledgeCommand(context.Background(), tenantID, created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if acked.Status != command.CommandStatusAcknowledged {
		t.Errorf("expected status acknowledged, got %s", acked.Status)
	}
	if acked.AcknowledgedAt == nil {
		t.Error("expected AcknowledgedAt to be set")
	}
}

func TestCommandService_AcknowledgeCommand_AlreadyAcknowledged(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")

	// Acknowledge once
	_, err := svc.AcknowledgeCommand(context.Background(), tenantID, created.ID.String())
	if err != nil {
		t.Fatalf("first acknowledge failed: %v", err)
	}

	// Try to acknowledge again - should fail
	_, err = svc.AcknowledgeCommand(context.Background(), tenantID, created.ID.String())
	if err == nil {
		t.Fatal("expected error when acknowledging already acknowledged command")
	}
}

func TestCommandService_AcknowledgeCommand_RunningCommand(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")

	// Move to acknowledged, then running
	_, _ = svc.AcknowledgeCommand(context.Background(), tenantID, created.ID.String())
	_, _ = svc.StartCommand(context.Background(), tenantID, created.ID.String())

	// Try to acknowledge a running command
	_, err := svc.AcknowledgeCommand(context.Background(), tenantID, created.ID.String())
	if err == nil {
		t.Fatal("expected error when acknowledging running command")
	}
}

func TestCommandService_AcknowledgeCommand_NotFound(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()
	missingID := shared.NewID().String()

	_, err := svc.AcknowledgeCommand(context.Background(), tenantID, missingID)
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func TestCommandService_AcknowledgeCommand_UpdateError(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")
	repo.updateErr = errors.New("update failed")

	_, err := svc.AcknowledgeCommand(context.Background(), tenantID, created.ID.String())
	if err == nil {
		t.Fatal("expected error from repo update")
	}
}

// =============================================================================
// Tests: StartCommand
// =============================================================================

func TestCommandService_StartCommand_Success(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")
	_, _ = svc.AcknowledgeCommand(context.Background(), tenantID, created.ID.String())

	started, err := svc.StartCommand(context.Background(), tenantID, created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if started.Status != command.CommandStatusRunning {
		t.Errorf("expected status running, got %s", started.Status)
	}
	if started.StartedAt == nil {
		t.Error("expected StartedAt to be set")
	}
}

func TestCommandService_StartCommand_NotAcknowledged(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")

	// Try to start a pending command (not acknowledged)
	_, err := svc.StartCommand(context.Background(), tenantID, created.ID.String())
	if err == nil {
		t.Fatal("expected error when starting non-acknowledged command")
	}
}

func TestCommandService_StartCommand_AlreadyRunning(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")
	_, _ = svc.AcknowledgeCommand(context.Background(), tenantID, created.ID.String())
	_, _ = svc.StartCommand(context.Background(), tenantID, created.ID.String())

	// Try to start again
	_, err := svc.StartCommand(context.Background(), tenantID, created.ID.String())
	if err == nil {
		t.Fatal("expected error when starting already running command")
	}
}

func TestCommandService_StartCommand_NotFound(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	_, err := svc.StartCommand(context.Background(), tenantID, shared.NewID().String())
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func TestCommandService_StartCommand_UpdateError(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")
	_, _ = svc.AcknowledgeCommand(context.Background(), tenantID, created.ID.String())

	repo.updateErr = errors.New("update failed")
	_, err := svc.StartCommand(context.Background(), tenantID, created.ID.String())
	if err == nil {
		t.Fatal("expected error from repo update")
	}
}

// =============================================================================
// Tests: CompleteCommand
// =============================================================================

func TestCommandService_CompleteCommand_Success(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")
	_, _ = svc.AcknowledgeCommand(context.Background(), tenantID, created.ID.String())
	_, _ = svc.StartCommand(context.Background(), tenantID, created.ID.String())

	result := json.RawMessage(`{"found":42}`)
	input := app.CompleteCommandInput{
		TenantID:  tenantID,
		CommandID: created.ID.String(),
		Result:    result,
	}
	completed, err := svc.CompleteCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if completed.Status != command.CommandStatusCompleted {
		t.Errorf("expected status completed, got %s", completed.Status)
	}
	if completed.CompletedAt == nil {
		t.Error("expected CompletedAt to be set")
	}
	if string(completed.Result) != `{"found":42}` {
		t.Errorf("unexpected result: %s", completed.Result)
	}
}

func TestCommandService_CompleteCommand_NotRunning(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")

	input := app.CompleteCommandInput{
		TenantID:  tenantID,
		CommandID: created.ID.String(),
	}
	_, err := svc.CompleteCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when completing non-running command")
	}
}

func TestCommandService_CompleteCommand_AlreadyCompleted(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")
	_, _ = svc.AcknowledgeCommand(context.Background(), tenantID, created.ID.String())
	_, _ = svc.StartCommand(context.Background(), tenantID, created.ID.String())

	input := app.CompleteCommandInput{
		TenantID:  tenantID,
		CommandID: created.ID.String(),
	}
	_, _ = svc.CompleteCommand(context.Background(), input)

	// Try to complete again
	_, err := svc.CompleteCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when completing already completed command")
	}
}

func TestCommandService_CompleteCommand_NotFound(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.CompleteCommandInput{
		TenantID:  tenantID,
		CommandID: shared.NewID().String(),
	}
	_, err := svc.CompleteCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func TestCommandService_CompleteCommand_UpdateError(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")
	_, _ = svc.AcknowledgeCommand(context.Background(), tenantID, created.ID.String())
	_, _ = svc.StartCommand(context.Background(), tenantID, created.ID.String())

	repo.updateErr = errors.New("update failed")
	input := app.CompleteCommandInput{
		TenantID:  tenantID,
		CommandID: created.ID.String(),
	}
	_, err := svc.CompleteCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from repo update")
	}
}

// =============================================================================
// Tests: FailCommand
// =============================================================================

func TestCommandService_FailCommand_Success(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")

	input := app.FailCommandInput{
		TenantID:     tenantID,
		CommandID:    created.ID.String(),
		ErrorMessage: "scanner crashed",
	}
	failed, err := svc.FailCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if failed.Status != command.CommandStatusFailed {
		t.Errorf("expected status failed, got %s", failed.Status)
	}
	if failed.ErrorMessage != "scanner crashed" {
		t.Errorf("expected error message 'scanner crashed', got %s", failed.ErrorMessage)
	}
	if failed.CompletedAt == nil {
		t.Error("expected CompletedAt to be set on failure")
	}
}

func TestCommandService_FailCommand_FromRunning(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")
	_, _ = svc.AcknowledgeCommand(context.Background(), tenantID, created.ID.String())
	_, _ = svc.StartCommand(context.Background(), tenantID, created.ID.String())

	input := app.FailCommandInput{
		TenantID:     tenantID,
		CommandID:    created.ID.String(),
		ErrorMessage: "timeout",
	}
	failed, err := svc.FailCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if failed.Status != command.CommandStatusFailed {
		t.Errorf("expected status failed, got %s", failed.Status)
	}
}

func TestCommandService_FailCommand_NotFound(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.FailCommandInput{
		TenantID:  tenantID,
		CommandID: shared.NewID().String(),
	}
	_, err := svc.FailCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func TestCommandService_FailCommand_UpdateError(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")
	repo.updateErr = errors.New("update failed")

	input := app.FailCommandInput{
		TenantID:     tenantID,
		CommandID:    created.ID.String(),
		ErrorMessage: "error",
	}
	_, err := svc.FailCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from repo update")
	}
}

// =============================================================================
// Tests: CancelCommand
// =============================================================================

func TestCommandService_CancelCommand_FromPending(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")

	canceled, err := svc.CancelCommand(context.Background(), tenantID, created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if canceled.Status != command.CommandStatusCanceled {
		t.Errorf("expected status canceled, got %s", canceled.Status)
	}
	if canceled.CompletedAt == nil {
		t.Error("expected CompletedAt to be set on cancel")
	}
}

func TestCommandService_CancelCommand_FromAcknowledged(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")
	_, _ = svc.AcknowledgeCommand(context.Background(), tenantID, created.ID.String())

	canceled, err := svc.CancelCommand(context.Background(), tenantID, created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if canceled.Status != command.CommandStatusCanceled {
		t.Errorf("expected status canceled, got %s", canceled.Status)
	}
}

func TestCommandService_CancelCommand_FromRunning(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")
	_, _ = svc.AcknowledgeCommand(context.Background(), tenantID, created.ID.String())
	_, _ = svc.StartCommand(context.Background(), tenantID, created.ID.String())

	canceled, err := svc.CancelCommand(context.Background(), tenantID, created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if canceled.Status != command.CommandStatusCanceled {
		t.Errorf("expected status canceled, got %s", canceled.Status)
	}
}

func TestCommandService_CancelCommand_CompletedCannotBeCanceled(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")
	_, _ = svc.AcknowledgeCommand(context.Background(), tenantID, created.ID.String())
	_, _ = svc.StartCommand(context.Background(), tenantID, created.ID.String())
	_, _ = svc.CompleteCommand(context.Background(), app.CompleteCommandInput{
		TenantID:  tenantID,
		CommandID: created.ID.String(),
	})

	_, err := svc.CancelCommand(context.Background(), tenantID, created.ID.String())
	if err == nil {
		t.Fatal("expected error when canceling completed command")
	}
}

func TestCommandService_CancelCommand_FromFailed(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")
	_, _ = svc.FailCommand(context.Background(), app.FailCommandInput{
		TenantID:     tenantID,
		CommandID:    created.ID.String(),
		ErrorMessage: "error",
	})

	// Failed commands can be canceled (only completed is blocked)
	canceled, err := svc.CancelCommand(context.Background(), tenantID, created.ID.String())
	if err != nil {
		t.Fatalf("expected no error canceling failed command, got %v", err)
	}
	if canceled.Status != command.CommandStatusCanceled {
		t.Errorf("expected status canceled, got %s", canceled.Status)
	}
}

func TestCommandService_CancelCommand_NotFound(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	_, err := svc.CancelCommand(context.Background(), tenantID, shared.NewID().String())
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func TestCommandService_CancelCommand_UpdateError(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")
	repo.updateErr = errors.New("update failed")

	_, err := svc.CancelCommand(context.Background(), tenantID, created.ID.String())
	if err == nil {
		t.Fatal("expected error from repo update")
	}
}

// =============================================================================
// Tests: DeleteCommand
// =============================================================================

func TestCommandService_DeleteCommand_Success(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")

	err := svc.DeleteCommand(context.Background(), tenantID, created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify it's gone
	_, err = svc.GetCommand(context.Background(), tenantID, created.ID.String())
	if err == nil {
		t.Fatal("expected not found after delete")
	}
}

func TestCommandService_DeleteCommand_InvalidTenantID(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)

	err := svc.DeleteCommand(context.Background(), "bad-id", shared.NewID().String())
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCommandService_DeleteCommand_InvalidCommandID(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	err := svc.DeleteCommand(context.Background(), tenantID, "bad-id")
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCommandService_DeleteCommand_NotFound(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	err := svc.DeleteCommand(context.Background(), tenantID, shared.NewID().String())
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func TestCommandService_DeleteCommand_WrongTenant(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()
	otherTenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")

	err := svc.DeleteCommand(context.Background(), otherTenantID, created.ID.String())
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
}

func TestCommandService_DeleteCommand_RepoDeleteError(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	created := createTestCommand(t, svc, tenantID, "scan", "normal")
	repo.deleteErr = errors.New("delete failed")

	err := svc.DeleteCommand(context.Background(), tenantID, created.ID.String())
	if err == nil {
		t.Fatal("expected error from repo delete")
	}
}

// =============================================================================
// Tests: ExpireOldCommands
// =============================================================================

func TestCommandService_ExpireOldCommands_Success(t *testing.T) {
	repo := newCmdMockRepo()
	repo.expireCount = 5
	svc := newCmdTestService(repo)

	count, err := svc.ExpireOldCommands(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 5 {
		t.Errorf("expected 5 expired, got %d", count)
	}
}

func TestCommandService_ExpireOldCommands_Zero(t *testing.T) {
	repo := newCmdMockRepo()
	repo.expireCount = 0
	svc := newCmdTestService(repo)

	count, err := svc.ExpireOldCommands(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 expired, got %d", count)
	}
}

func TestCommandService_ExpireOldCommands_RepoError(t *testing.T) {
	repo := newCmdMockRepo()
	repo.expireErr = errors.New("expire failed")
	svc := newCmdTestService(repo)

	_, err := svc.ExpireOldCommands(context.Background())
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// =============================================================================
// Tests: Full State Machine Transitions
// =============================================================================

func TestCommandService_FullLifecycle_PendingToCompleted(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	// Create (pending)
	cmd := createTestCommand(t, svc, tenantID, "scan", "high")
	if cmd.Status != command.CommandStatusPending {
		t.Fatalf("expected pending, got %s", cmd.Status)
	}

	// Acknowledge
	cmd, err := svc.AcknowledgeCommand(context.Background(), tenantID, cmd.ID.String())
	if err != nil {
		t.Fatalf("acknowledge failed: %v", err)
	}
	if cmd.Status != command.CommandStatusAcknowledged {
		t.Fatalf("expected acknowledged, got %s", cmd.Status)
	}

	// Start
	cmd, err = svc.StartCommand(context.Background(), tenantID, cmd.ID.String())
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}
	if cmd.Status != command.CommandStatusRunning {
		t.Fatalf("expected running, got %s", cmd.Status)
	}

	// Complete
	cmd, err = svc.CompleteCommand(context.Background(), app.CompleteCommandInput{
		TenantID:  tenantID,
		CommandID: cmd.ID.String(),
		Result:    json.RawMessage(`{"success":true}`),
	})
	if err != nil {
		t.Fatalf("complete failed: %v", err)
	}
	if cmd.Status != command.CommandStatusCompleted {
		t.Fatalf("expected completed, got %s", cmd.Status)
	}
}

func TestCommandService_FullLifecycle_PendingToFailed(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	cmd := createTestCommand(t, svc, tenantID, "collect", "critical")

	_, _ = svc.AcknowledgeCommand(context.Background(), tenantID, cmd.ID.String())
	_, _ = svc.StartCommand(context.Background(), tenantID, cmd.ID.String())

	failed, err := svc.FailCommand(context.Background(), app.FailCommandInput{
		TenantID:     tenantID,
		CommandID:    cmd.ID.String(),
		ErrorMessage: "connection refused",
	})
	if err != nil {
		t.Fatalf("fail failed: %v", err)
	}
	if failed.Status != command.CommandStatusFailed {
		t.Errorf("expected failed, got %s", failed.Status)
	}
	if failed.ErrorMessage != "connection refused" {
		t.Errorf("expected error message 'connection refused', got %s", failed.ErrorMessage)
	}
}

func TestCommandService_FullLifecycle_PendingToCanceled(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	cmd := createTestCommand(t, svc, tenantID, "health_check", "low")

	canceled, err := svc.CancelCommand(context.Background(), tenantID, cmd.ID.String())
	if err != nil {
		t.Fatalf("cancel failed: %v", err)
	}
	if canceled.Status != command.CommandStatusCanceled {
		t.Errorf("expected canceled, got %s", canceled.Status)
	}
}

// =============================================================================
// Tests: Invalid State Transitions
// =============================================================================

func TestCommandService_InvalidTransition_StartFromPending(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	cmd := createTestCommand(t, svc, tenantID, "scan", "normal")

	// Cannot start directly from pending (must acknowledge first)
	_, err := svc.StartCommand(context.Background(), tenantID, cmd.ID.String())
	if err == nil {
		t.Fatal("expected error: cannot start from pending")
	}
}

func TestCommandService_InvalidTransition_CompleteFromPending(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	cmd := createTestCommand(t, svc, tenantID, "scan", "normal")

	_, err := svc.CompleteCommand(context.Background(), app.CompleteCommandInput{
		TenantID:  tenantID,
		CommandID: cmd.ID.String(),
	})
	if err == nil {
		t.Fatal("expected error: cannot complete from pending")
	}
}

func TestCommandService_InvalidTransition_CompleteFromAcknowledged(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	cmd := createTestCommand(t, svc, tenantID, "scan", "normal")
	_, _ = svc.AcknowledgeCommand(context.Background(), tenantID, cmd.ID.String())

	_, err := svc.CompleteCommand(context.Background(), app.CompleteCommandInput{
		TenantID:  tenantID,
		CommandID: cmd.ID.String(),
	})
	if err == nil {
		t.Fatal("expected error: cannot complete from acknowledged (must be running)")
	}
}

func TestCommandService_InvalidTransition_AcknowledgeFromCompleted(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	cmd := createTestCommand(t, svc, tenantID, "scan", "normal")
	_, _ = svc.AcknowledgeCommand(context.Background(), tenantID, cmd.ID.String())
	_, _ = svc.StartCommand(context.Background(), tenantID, cmd.ID.String())
	_, _ = svc.CompleteCommand(context.Background(), app.CompleteCommandInput{
		TenantID:  tenantID,
		CommandID: cmd.ID.String(),
	})

	_, err := svc.AcknowledgeCommand(context.Background(), tenantID, cmd.ID.String())
	if err == nil {
		t.Fatal("expected error: cannot acknowledge completed command")
	}
}

func TestCommandService_InvalidTransition_StartFromCompleted(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	cmd := createTestCommand(t, svc, tenantID, "scan", "normal")
	_, _ = svc.AcknowledgeCommand(context.Background(), tenantID, cmd.ID.String())
	_, _ = svc.StartCommand(context.Background(), tenantID, cmd.ID.String())
	_, _ = svc.CompleteCommand(context.Background(), app.CompleteCommandInput{
		TenantID:  tenantID,
		CommandID: cmd.ID.String(),
	})

	_, err := svc.StartCommand(context.Background(), tenantID, cmd.ID.String())
	if err == nil {
		t.Fatal("expected error: cannot start completed command")
	}
}

func TestCommandService_InvalidTransition_CancelCompleted(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	cmd := createTestCommand(t, svc, tenantID, "scan", "normal")
	_, _ = svc.AcknowledgeCommand(context.Background(), tenantID, cmd.ID.String())
	_, _ = svc.StartCommand(context.Background(), tenantID, cmd.ID.String())
	_, _ = svc.CompleteCommand(context.Background(), app.CompleteCommandInput{
		TenantID:  tenantID,
		CommandID: cmd.ID.String(),
	})

	_, err := svc.CancelCommand(context.Background(), tenantID, cmd.ID.String())
	if err == nil {
		t.Fatal("expected error: cannot cancel completed command")
	}
}

// =============================================================================
// Tests: Multiple Commands Isolation
// =============================================================================

func TestCommandService_MultipleCommands_IndependentState(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	cmd1 := createTestCommand(t, svc, tenantID, "scan", "high")
	cmd2 := createTestCommand(t, svc, tenantID, "collect", "low")

	// Acknowledge cmd1 only
	_, err := svc.AcknowledgeCommand(context.Background(), tenantID, cmd1.ID.String())
	if err != nil {
		t.Fatalf("failed to acknowledge cmd1: %v", err)
	}

	// Verify cmd2 is still pending
	got2, err := svc.GetCommand(context.Background(), tenantID, cmd2.ID.String())
	if err != nil {
		t.Fatalf("failed to get cmd2: %v", err)
	}
	if got2.Status != command.CommandStatusPending {
		t.Errorf("cmd2 should still be pending, got %s", got2.Status)
	}

	// Verify cmd1 is acknowledged
	got1, err := svc.GetCommand(context.Background(), tenantID, cmd1.ID.String())
	if err != nil {
		t.Fatalf("failed to get cmd1: %v", err)
	}
	if got1.Status != command.CommandStatusAcknowledged {
		t.Errorf("cmd1 should be acknowledged, got %s", got1.Status)
	}
}

func TestCommandService_TenantIsolation(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenant1 := newCmdTestTenantID()
	tenant2 := newCmdTestTenantID()

	cmd1 := createTestCommand(t, svc, tenant1, "scan", "normal")

	// Tenant 2 should not see tenant 1's command
	_, err := svc.GetCommand(context.Background(), tenant2, cmd1.ID.String())
	if err == nil {
		t.Fatal("expected error: tenant 2 should not access tenant 1 command")
	}

	// Tenant 2 should not be able to delete tenant 1's command
	err = svc.DeleteCommand(context.Background(), tenant2, cmd1.ID.String())
	if err == nil {
		t.Fatal("expected error: tenant 2 should not delete tenant 1 command")
	}

	// Tenant 2 should not be able to acknowledge tenant 1's command
	_, err = svc.AcknowledgeCommand(context.Background(), tenant2, cmd1.ID.String())
	if err == nil {
		t.Fatal("expected error: tenant 2 should not acknowledge tenant 1 command")
	}
}

// =============================================================================
// Tests: Edge Cases
// =============================================================================

func TestCommandService_CreateCommand_NilPayload(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.CreateCommandInput{
		TenantID: tenantID,
		Type:     "health_check",
	}
	cmd, err := svc.CreateCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error with nil payload, got %v", err)
	}
	if cmd.Payload != nil {
		t.Errorf("expected nil payload, got %s", cmd.Payload)
	}
}

func TestCommandService_CompleteCommand_NilResult(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	cmd := createTestCommand(t, svc, tenantID, "scan", "normal")
	_, _ = svc.AcknowledgeCommand(context.Background(), tenantID, cmd.ID.String())
	_, _ = svc.StartCommand(context.Background(), tenantID, cmd.ID.String())

	completed, err := svc.CompleteCommand(context.Background(), app.CompleteCommandInput{
		TenantID:  tenantID,
		CommandID: cmd.ID.String(),
		// Result omitted
	})
	if err != nil {
		t.Fatalf("expected no error with nil result, got %v", err)
	}
	if completed.Status != command.CommandStatusCompleted {
		t.Errorf("expected completed, got %s", completed.Status)
	}
}

func TestCommandService_FailCommand_EmptyErrorMessage(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	cmd := createTestCommand(t, svc, tenantID, "scan", "normal")

	input := app.FailCommandInput{
		TenantID:     tenantID,
		CommandID:    cmd.ID.String(),
		ErrorMessage: "",
	}
	failed, err := svc.FailCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error with empty error message, got %v", err)
	}
	if failed.Status != command.CommandStatusFailed {
		t.Errorf("expected failed, got %s", failed.Status)
	}
}

func TestCommandService_PollCommands_NegativeLimit(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.PollCommandsInput{
		TenantID: tenantID,
		Limit:    -5,
	}
	_, err := svc.PollCommands(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error for negative limit (should default), got %v", err)
	}
}

func TestCommandService_CreateCommand_ZeroExpiresIn(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.CreateCommandInput{
		TenantID:  tenantID,
		Type:      "scan",
		ExpiresIn: 0,
	}
	cmd, err := svc.CreateCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cmd.ExpiresAt != nil {
		t.Error("expected no expiration for zero ExpiresIn")
	}
}

func TestCommandService_CreateCommand_NegativeExpiresIn(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	input := app.CreateCommandInput{
		TenantID:  tenantID,
		Type:      "scan",
		ExpiresIn: -100,
	}
	cmd, err := svc.CreateCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Negative ExpiresIn is <= 0, so should not set expiration
	if cmd.ExpiresAt != nil {
		t.Error("expected no expiration for negative ExpiresIn")
	}
}

func TestCommandService_GetCommand_RepoError(t *testing.T) {
	repo := newCmdMockRepo()
	repo.getByTenantAndIDErr = errors.New("db error")
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()

	_, err := svc.GetCommand(context.Background(), tenantID, shared.NewID().String())
	if err == nil {
		t.Fatal("expected error from repo")
	}
}
