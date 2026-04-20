package unit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Audit Repository
// =============================================================================

type mockAuditRepo struct {
	mu   sync.Mutex
	logs map[shared.ID]*audit.AuditLog

	// Error overrides
	createErr         error
	createBatchErr    error
	getByIDErr        error
	listErr           error
	countErr          error
	deleteOlderErr    error
	getLatestErr      error
	listByActorErr    error
	listByResourceErr error
	countByActionErr  error

	// Call tracking
	createCalls         int
	createBatchCalls    int
	getByIDCalls        int
	listCalls           int
	countCalls          int
	deleteOlderCalls    int
	getLatestCalls      int
	listByActorCalls    int
	listByResourceCalls int
	countByActionCalls  int

	// Captured arguments
	lastFilter       audit.Filter
	lastPagination   pagination.Pagination
	lastDeleteBefore time.Time
	lastCountAction  audit.Action
	lastCountTenant  *shared.ID
	lastCountSince   time.Time
	lastCreated      *audit.AuditLog

	// Return overrides
	deleteOlderCount  int64
	countByActionVal  int64
}

func newMockAuditRepo() *mockAuditRepo {
	return &mockAuditRepo{
		logs: make(map[shared.ID]*audit.AuditLog),
	}
}

func (m *mockAuditRepo) Create(_ context.Context, log *audit.AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createCalls++
	m.lastCreated = log
	if m.createErr != nil {
		return m.createErr
	}
	m.logs[log.ID()] = log
	return nil
}

func (m *mockAuditRepo) CreateBatch(_ context.Context, logs []*audit.AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createBatchCalls++
	if m.createBatchErr != nil {
		return m.createBatchErr
	}
	for _, l := range logs {
		m.logs[l.ID()] = l
	}
	return nil
}

func (m *mockAuditRepo) GetByID(_ context.Context, id shared.ID) (*audit.AuditLog, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getByIDCalls++
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	log, ok := m.logs[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return log, nil
}

func (m *mockAuditRepo) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*audit.AuditLog, error) {
	return nil, nil
}

func (m *mockAuditRepo) List(_ context.Context, filter audit.Filter, page pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listCalls++
	m.lastFilter = filter
	m.lastPagination = page
	if m.listErr != nil {
		return pagination.Result[*audit.AuditLog]{}, m.listErr
	}
	items := make([]*audit.AuditLog, 0, len(m.logs))
	for _, l := range m.logs {
		items = append(items, l)
	}
	return pagination.Result[*audit.AuditLog]{
		Data:       items,
		Total:      int64(len(items)),
		Page:       1,
		PerPage:    20,
		TotalPages: 1,
	}, nil
}

func (m *mockAuditRepo) Count(_ context.Context, filter audit.Filter) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.countCalls++
	m.lastFilter = filter
	if m.countErr != nil {
		return 0, m.countErr
	}
	return int64(len(m.logs)), nil
}

func (m *mockAuditRepo) DeleteOlderThan(_ context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteOlderCalls++
	m.lastDeleteBefore = before
	if m.deleteOlderErr != nil {
		return 0, m.deleteOlderErr
	}
	return m.deleteOlderCount, nil
}

func (m *mockAuditRepo) DeleteOlderThanForTenant(_ context.Context, _ shared.ID, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *mockAuditRepo) GetLatestByResource(_ context.Context, _ shared.ID, resourceType audit.ResourceType, resourceID string) (*audit.AuditLog, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getLatestCalls++
	if m.getLatestErr != nil {
		return nil, m.getLatestErr
	}
	for _, l := range m.logs {
		if l.ResourceType() == resourceType && l.ResourceID() == resourceID {
			return l, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *mockAuditRepo) ListByActor(_ context.Context, actorID shared.ID, page pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listByActorCalls++
	m.lastPagination = page
	if m.listByActorErr != nil {
		return pagination.Result[*audit.AuditLog]{}, m.listByActorErr
	}
	items := make([]*audit.AuditLog, 0)
	for _, l := range m.logs {
		if l.ActorID() != nil && l.ActorID().Equals(actorID) {
			items = append(items, l)
		}
	}
	return pagination.Result[*audit.AuditLog]{
		Data:       items,
		Total:      int64(len(items)),
		Page:       1,
		PerPage:    20,
		TotalPages: 1,
	}, nil
}

func (m *mockAuditRepo) ListByResource(_ context.Context, _ shared.ID, resourceType audit.ResourceType, resourceID string, page pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listByResourceCalls++
	m.lastPagination = page
	if m.listByResourceErr != nil {
		return pagination.Result[*audit.AuditLog]{}, m.listByResourceErr
	}
	items := make([]*audit.AuditLog, 0)
	for _, l := range m.logs {
		if l.ResourceType() == resourceType && l.ResourceID() == resourceID {
			items = append(items, l)
		}
	}
	return pagination.Result[*audit.AuditLog]{
		Data:       items,
		Total:      int64(len(items)),
		Page:       1,
		PerPage:    20,
		TotalPages: 1,
	}, nil
}

func (m *mockAuditRepo) CountByAction(_ context.Context, tenantID *shared.ID, action audit.Action, since time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.countByActionCalls++
	m.lastCountAction = action
	m.lastCountTenant = tenantID
	m.lastCountSince = since
	if m.countByActionErr != nil {
		return 0, m.countByActionErr
	}
	return m.countByActionVal, nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func newTestAuditService() (*app.AuditService, *mockAuditRepo) {
	repo := newMockAuditRepo()
	log := logger.NewNop()
	svc := app.NewAuditService(repo, log)
	return svc, repo
}

func newTestAuditContext() app.AuditContext {
	return app.AuditContext{
		TenantID:   shared.NewID().String(),
		ActorID:    shared.NewID().String(),
		ActorEmail: "test@example.com",
		ActorIP:    "192.168.1.100",
		UserAgent:  "TestAgent/1.0",
		RequestID:  "req-12345",
		SessionID:  "sess-67890",
	}
}

// =============================================================================
// LogEvent Tests
// =============================================================================

func TestAuditService_LogEvent_SuccessFullContext(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()
	actx := newTestAuditContext()

	changes := audit.NewChanges().Set("name", "old", "new")
	event := app.NewSuccessEvent(audit.ActionUserCreated, audit.ResourceTypeUser, "user-123").
		WithResourceName("John Doe").
		WithChanges(changes).
		WithMessage("User created").
		WithSeverity(audit.SeverityMedium).
		WithMetadata("source", "api")

	err := svc.LogEvent(ctx, actx, event)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.createCalls != 1 {
		t.Fatalf("expected 1 create call, got %d", repo.createCalls)
	}

	created := repo.lastCreated
	if created == nil {
		t.Fatal("expected created log to be set")
	}

	if created.Action() != audit.ActionUserCreated {
		t.Errorf("expected action %s, got %s", audit.ActionUserCreated, created.Action())
	}
	if created.ResourceType() != audit.ResourceTypeUser {
		t.Errorf("expected resource type %s, got %s", audit.ResourceTypeUser, created.ResourceType())
	}
	if created.ResourceID() != "user-123" {
		t.Errorf("expected resource id user-123, got %s", created.ResourceID())
	}
	if created.ResourceName() != "John Doe" {
		t.Errorf("expected resource name John Doe, got %s", created.ResourceName())
	}
	if created.Result() != audit.ResultSuccess {
		t.Errorf("expected result success, got %s", created.Result())
	}
	if created.Severity() != audit.SeverityMedium {
		t.Errorf("expected severity medium, got %s", created.Severity())
	}
	if created.Message() != "User created" {
		t.Errorf("expected message 'User created', got %s", created.Message())
	}
	if created.ActorEmail() != "test@example.com" {
		t.Errorf("expected actor email test@example.com, got %s", created.ActorEmail())
	}
	if created.ActorIP() != "192.168.1.100" {
		t.Errorf("expected actor IP 192.168.1.100, got %s", created.ActorIP())
	}
	if created.ActorAgent() != "TestAgent/1.0" {
		t.Errorf("expected user agent TestAgent/1.0, got %s", created.ActorAgent())
	}
	if created.RequestID() != "req-12345" {
		t.Errorf("expected request id req-12345, got %s", created.RequestID())
	}
	if created.SessionID() != "sess-67890" {
		t.Errorf("expected session id sess-67890, got %s", created.SessionID())
	}
	if created.TenantID() == nil {
		t.Error("expected tenant id to be set")
	}
	if created.ActorID() == nil {
		t.Error("expected actor id to be set")
	}
	if !created.HasChanges() {
		t.Error("expected changes to be set")
	}
	metadata := created.Metadata()
	if metadata["source"] != "api" {
		t.Errorf("expected metadata source=api, got %v", metadata["source"])
	}
}

func TestAuditService_LogEvent_SuccessMinimalContext(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()

	actx := app.AuditContext{} // Empty context - no IPs, no tenant, no actor

	event := app.NewSuccessEvent(audit.ActionSettingsUpdated, audit.ResourceTypeSettings, "settings-1")

	err := svc.LogEvent(ctx, actx, event)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.createCalls != 1 {
		t.Fatalf("expected 1 create call, got %d", repo.createCalls)
	}

	created := repo.lastCreated
	if created.TenantID() != nil {
		t.Error("expected tenant id to be nil for empty context")
	}
	if created.ActorID() != nil {
		t.Error("expected actor id to be nil for empty context")
	}
	if created.ActorIP() != "" {
		t.Errorf("expected empty actor IP, got %s", created.ActorIP())
	}
	if created.ActorAgent() != "" {
		t.Errorf("expected empty user agent, got %s", created.ActorAgent())
	}
	if created.RequestID() != "" {
		t.Errorf("expected empty request id, got %s", created.RequestID())
	}
	if created.SessionID() != "" {
		t.Errorf("expected empty session id, got %s", created.SessionID())
	}
}

func TestAuditService_LogEvent_RepositoryError(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()
	actx := newTestAuditContext()

	repoErr := errors.New("database connection refused")
	repo.createErr = repoErr

	event := app.NewSuccessEvent(audit.ActionUserCreated, audit.ResourceTypeUser, "user-123")

	err := svc.LogEvent(ctx, actx, event)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, repoErr) {
		t.Errorf("expected error to be %v, got %v", repoErr, err)
	}

	if repo.createCalls != 1 {
		t.Fatalf("expected 1 create call, got %d", repo.createCalls)
	}
}

func TestAuditService_LogEvent_InvalidTenantID(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()

	actx := app.AuditContext{
		TenantID:   "not-a-valid-uuid",
		ActorID:    shared.NewID().String(),
		ActorEmail: "test@example.com",
	}

	event := app.NewSuccessEvent(audit.ActionUserCreated, audit.ResourceTypeUser, "user-123")

	// LogEvent should handle invalid tenant ID gracefully (skip setting it)
	err := svc.LogEvent(ctx, actx, event)
	if err != nil {
		t.Fatalf("expected no error for invalid tenant id, got %v", err)
	}

	if repo.createCalls != 1 {
		t.Fatalf("expected 1 create call, got %d", repo.createCalls)
	}

	// Tenant ID should be nil because it was invalid
	created := repo.lastCreated
	if created.TenantID() != nil {
		t.Error("expected tenant id to be nil for invalid tenant id string")
	}
	// Actor ID should still be set
	if created.ActorID() == nil {
		t.Error("expected actor id to be set despite invalid tenant id")
	}
}

// =============================================================================
// GetAuditLog Tests
// =============================================================================

func TestAuditService_GetAuditLog_Success(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()

	// Seed a log
	log, err := audit.NewAuditLog(audit.ActionUserCreated, audit.ResourceTypeUser, "user-1", audit.ResultSuccess)
	if err != nil {
		t.Fatalf("failed to create audit log: %v", err)
	}
	repo.logs[log.ID()] = log

	result, err := svc.GetAuditLog(ctx, log.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.getByIDCalls != 1 {
		t.Fatalf("expected 1 getByID call, got %d", repo.getByIDCalls)
	}

	if !result.ID().Equals(log.ID()) {
		t.Errorf("expected id %s, got %s", log.ID(), result.ID())
	}
}

func TestAuditService_GetAuditLog_NotFound(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()

	id := shared.NewID()
	_, err := svc.GetAuditLog(ctx, id.String())
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	if repo.getByIDCalls != 1 {
		t.Fatalf("expected 1 getByID call, got %d", repo.getByIDCalls)
	}
}

func TestAuditService_GetAuditLog_InvalidID(t *testing.T) {
	svc, _ := newTestAuditService()
	ctx := context.Background()

	_, err := svc.GetAuditLog(ctx, "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid id, got nil")
	}

	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// ListAuditLogs Tests
// =============================================================================

func TestAuditService_ListAuditLogs_SuccessWithFilters(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()

	// Seed some logs
	for i := 0; i < 3; i++ {
		log, err := audit.NewAuditLog(audit.ActionUserCreated, audit.ResourceTypeUser, "user-1", audit.ResultSuccess)
		if err != nil {
			t.Fatalf("failed to create audit log: %v", err)
		}
		repo.logs[log.ID()] = log
	}

	tenantID := shared.NewID()
	actorID := shared.NewID()
	since := time.Now().Add(-24 * time.Hour)
	until := time.Now()

	input := app.ListAuditLogsInput{
		TenantID:      tenantID.String(),
		ActorID:       actorID.String(),
		Actions:       []string{"user.created"},
		ResourceTypes: []string{"user"},
		ResourceID:    "user-1",
		Results:       []string{"success"},
		Severities:    []string{"medium"},
		RequestID:     "req-abc",
		Since:         &since,
		Until:         &until,
		SearchTerm:    "test",
		Page:          1,
		PerPage:       10,
		SortBy:        "logged_at",
		SortOrder:     "desc",
		ExcludeSystem: true,
	}

	result, err := svc.ListAuditLogs(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.listCalls != 1 {
		t.Fatalf("expected 1 list call, got %d", repo.listCalls)
	}

	if result.Total != 3 {
		t.Errorf("expected total 3, got %d", result.Total)
	}

	// Verify filter was constructed properly
	f := repo.lastFilter
	if f.TenantID == nil {
		t.Error("expected tenant id filter to be set")
	}
	if f.ActorID == nil {
		t.Error("expected actor id filter to be set")
	}
	if len(f.Actions) != 1 || f.Actions[0] != audit.Action("user.created") {
		t.Errorf("expected actions filter [user.created], got %v", f.Actions)
	}
	if len(f.ResourceTypes) != 1 || f.ResourceTypes[0] != audit.ResourceType("user") {
		t.Errorf("expected resource types filter [user], got %v", f.ResourceTypes)
	}
	if f.ResourceID == nil || *f.ResourceID != "user-1" {
		t.Error("expected resource id filter to be user-1")
	}
	if len(f.Results) != 1 || f.Results[0] != audit.ResultSuccess {
		t.Errorf("expected results filter [success], got %v", f.Results)
	}
	if len(f.Severities) != 1 || f.Severities[0] != audit.SeverityMedium {
		t.Errorf("expected severities filter [medium], got %v", f.Severities)
	}
	if f.RequestID == nil || *f.RequestID != "req-abc" {
		t.Error("expected request id filter to be req-abc")
	}
	if f.Since == nil {
		t.Error("expected since filter to be set")
	}
	if f.Until == nil {
		t.Error("expected until filter to be set")
	}
	if f.SearchTerm == nil || *f.SearchTerm != "test" {
		t.Error("expected search term filter to be test")
	}
	if f.SortBy != "logged_at" {
		t.Errorf("expected sort by logged_at, got %s", f.SortBy)
	}
	if f.SortOrder != "desc" {
		t.Errorf("expected sort order desc, got %s", f.SortOrder)
	}
	if !f.ExcludeSystem {
		t.Error("expected exclude system to be true")
	}
}

func TestAuditService_ListAuditLogs_EmptyResult(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()

	input := app.ListAuditLogsInput{
		Page:    1,
		PerPage: 10,
	}

	result, err := svc.ListAuditLogs(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.listCalls != 1 {
		t.Fatalf("expected 1 list call, got %d", repo.listCalls)
	}

	if result.Total != 0 {
		t.Errorf("expected total 0, got %d", result.Total)
	}
	if len(result.Data) != 0 {
		t.Errorf("expected empty data, got %d items", len(result.Data))
	}
}

func TestAuditService_ListAuditLogs_InvalidTenantID(t *testing.T) {
	svc, _ := newTestAuditService()
	ctx := context.Background()

	input := app.ListAuditLogsInput{
		TenantID: "not-a-uuid",
	}

	_, err := svc.ListAuditLogs(ctx, input)
	if err == nil {
		t.Fatal("expected error for invalid tenant id, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAuditService_ListAuditLogs_InvalidActorID(t *testing.T) {
	svc, _ := newTestAuditService()
	ctx := context.Background()

	input := app.ListAuditLogsInput{
		ActorID: "bad-id",
	}

	_, err := svc.ListAuditLogs(ctx, input)
	if err == nil {
		t.Fatal("expected error for invalid actor id, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// GetResourceHistory Tests
// =============================================================================

func TestAuditService_GetResourceHistory_Success(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()

	// Seed a log for a specific resource
	log, err := audit.NewAuditLog(audit.ActionUserUpdated, audit.ResourceTypeUser, "user-42", audit.ResultSuccess)
	if err != nil {
		t.Fatalf("failed to create audit log: %v", err)
	}
	repo.logs[log.ID()] = log

	tid := shared.NewID()
	result, err := svc.GetResourceHistory(ctx, tid, "user", "user-42", 1, 20)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.listByResourceCalls != 1 {
		t.Fatalf("expected 1 listByResource call, got %d", repo.listByResourceCalls)
	}

	if result.Total != 1 {
		t.Errorf("expected total 1, got %d", result.Total)
	}
}

// =============================================================================
// GetUserActivity Tests
// =============================================================================

func TestAuditService_GetUserActivity_Success(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()

	actorID := shared.NewID()

	// Seed a log with this actor
	log, err := audit.NewAuditLog(audit.ActionAuthLogin, audit.ResourceTypeUser, "user-1", audit.ResultSuccess)
	if err != nil {
		t.Fatalf("failed to create audit log: %v", err)
	}
	log.WithActor(actorID, "actor@example.com")
	repo.logs[log.ID()] = log

	result, err := svc.GetUserActivity(ctx, actorID.String(), 1, 20)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.listByActorCalls != 1 {
		t.Fatalf("expected 1 listByActor call, got %d", repo.listByActorCalls)
	}

	if result.Total != 1 {
		t.Errorf("expected total 1, got %d", result.Total)
	}
}

func TestAuditService_GetUserActivity_InvalidUserID(t *testing.T) {
	svc, _ := newTestAuditService()
	ctx := context.Background()

	_, err := svc.GetUserActivity(ctx, "not-a-uuid", 1, 20)
	if err == nil {
		t.Fatal("expected error for invalid user id, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// CleanupOldLogs Tests
// =============================================================================

func TestAuditService_CleanupOldLogs_Success(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()

	repo.deleteOlderCount = 150

	count, err := svc.CleanupOldLogs(ctx, 90)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.deleteOlderCalls != 1 {
		t.Fatalf("expected 1 deleteOlderThan call, got %d", repo.deleteOlderCalls)
	}

	if count != 150 {
		t.Errorf("expected count 150, got %d", count)
	}

	// Verify the before time is approximately correct (90 days ago)
	expectedBefore := time.Now().AddDate(0, 0, -90)
	diff := repo.lastDeleteBefore.Sub(expectedBefore)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("expected delete before ~%v, got %v", expectedBefore, repo.lastDeleteBefore)
	}
}

func TestAuditService_CleanupOldLogs_RetentionTooShort(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()

	// Should reject retention < 30 days
	_, err := svc.CleanupOldLogs(ctx, 29)
	if err == nil {
		t.Fatal("expected error for retention < 30 days, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}

	// Repo should not be called
	if repo.deleteOlderCalls != 0 {
		t.Fatalf("expected 0 deleteOlderThan calls, got %d", repo.deleteOlderCalls)
	}

	// Boundary: exactly 30 days should be accepted
	repo.deleteOlderCount = 5
	count, err := svc.CleanupOldLogs(ctx, 30)
	if err != nil {
		t.Fatalf("expected no error for retention = 30 days, got %v", err)
	}
	if count != 5 {
		t.Errorf("expected count 5, got %d", count)
	}
}

func TestAuditService_CleanupOldLogs_RepositoryError(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()

	repo.deleteOlderErr = errors.New("storage error")

	count, err := svc.CleanupOldLogs(ctx, 90)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if count != 0 {
		t.Errorf("expected count 0 on error, got %d", count)
	}
}

// =============================================================================
// GetActionCount Tests
// =============================================================================

func TestAuditService_GetActionCount_WithTenantID(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()

	tenantID := shared.NewID()
	repo.countByActionVal = 42
	since := time.Now().Add(-24 * time.Hour)

	count, err := svc.GetActionCount(ctx, tenantID.String(), audit.ActionAuthLogin, since)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.countByActionCalls != 1 {
		t.Fatalf("expected 1 countByAction call, got %d", repo.countByActionCalls)
	}

	if count != 42 {
		t.Errorf("expected count 42, got %d", count)
	}

	if repo.lastCountTenant == nil {
		t.Fatal("expected tenant id to be passed to repo")
	}
	if !repo.lastCountTenant.Equals(tenantID) {
		t.Errorf("expected tenant id %s, got %s", tenantID, repo.lastCountTenant)
	}
	if repo.lastCountAction != audit.ActionAuthLogin {
		t.Errorf("expected action %s, got %s", audit.ActionAuthLogin, repo.lastCountAction)
	}
}

func TestAuditService_GetActionCount_WithoutTenantID(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()

	repo.countByActionVal = 100
	since := time.Now().Add(-1 * time.Hour)

	count, err := svc.GetActionCount(ctx, "", audit.ActionAuthFailed, since)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if count != 100 {
		t.Errorf("expected count 100, got %d", count)
	}

	if repo.lastCountTenant != nil {
		t.Error("expected nil tenant id when empty string passed")
	}
}

func TestAuditService_GetActionCount_InvalidTenantID(t *testing.T) {
	svc, _ := newTestAuditService()
	ctx := context.Background()

	_, err := svc.GetActionCount(ctx, "bad-uuid", audit.ActionAuthLogin, time.Now())
	if err == nil {
		t.Fatal("expected error for invalid tenant id, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// Convenience Method Tests
// =============================================================================

func TestAuditService_LogUserCreated(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()
	actx := newTestAuditContext()

	err := svc.LogUserCreated(ctx, actx, "user-abc", "john@example.com")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.createCalls != 1 {
		t.Fatalf("expected 1 create call, got %d", repo.createCalls)
	}

	created := repo.lastCreated
	if created.Action() != audit.ActionUserCreated {
		t.Errorf("expected action %s, got %s", audit.ActionUserCreated, created.Action())
	}
	if created.ResourceType() != audit.ResourceTypeUser {
		t.Errorf("expected resource type %s, got %s", audit.ResourceTypeUser, created.ResourceType())
	}
	if created.ResourceID() != "user-abc" {
		t.Errorf("expected resource id user-abc, got %s", created.ResourceID())
	}
	if created.ResourceName() != "john@example.com" {
		t.Errorf("expected resource name john@example.com, got %s", created.ResourceName())
	}
	if created.Result() != audit.ResultSuccess {
		t.Errorf("expected result success, got %s", created.Result())
	}
	if created.Message() == "" {
		t.Error("expected message to be set")
	}
}

func TestAuditService_LogPermissionDenied(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()
	actx := newTestAuditContext()

	err := svc.LogPermissionDenied(ctx, actx, audit.ResourceTypeAsset, "asset-123", "delete", "insufficient permissions")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.createCalls != 1 {
		t.Fatalf("expected 1 create call, got %d", repo.createCalls)
	}

	created := repo.lastCreated
	if created.Action() != audit.ActionPermissionDenied {
		t.Errorf("expected action %s, got %s", audit.ActionPermissionDenied, created.Action())
	}
	if created.ResourceType() != audit.ResourceTypeAsset {
		t.Errorf("expected resource type %s, got %s", audit.ResourceTypeAsset, created.ResourceType())
	}
	if created.ResourceID() != "asset-123" {
		t.Errorf("expected resource id asset-123, got %s", created.ResourceID())
	}
	if created.Result() != audit.ResultDenied {
		t.Errorf("expected result denied, got %s", created.Result())
	}
	if created.Severity() != audit.SeverityHigh {
		t.Errorf("expected severity high, got %s", created.Severity())
	}

	metadata := created.Metadata()
	if metadata["reason"] != "insufficient permissions" {
		t.Errorf("expected metadata reason=insufficient permissions, got %v", metadata["reason"])
	}
}

func TestAuditService_LogAuthFailed(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()
	actx := newTestAuditContext()

	err := svc.LogAuthFailed(ctx, actx, "invalid credentials")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.createCalls != 1 {
		t.Fatalf("expected 1 create call, got %d", repo.createCalls)
	}

	created := repo.lastCreated
	if created.Action() != audit.ActionAuthFailed {
		t.Errorf("expected action %s, got %s", audit.ActionAuthFailed, created.Action())
	}
	if created.ResourceType() != audit.ResourceTypeToken {
		t.Errorf("expected resource type %s, got %s", audit.ResourceTypeToken, created.ResourceType())
	}
	if created.Result() != audit.ResultFailure {
		t.Errorf("expected result failure, got %s", created.Result())
	}
	if created.Severity() != audit.SeverityCritical {
		t.Errorf("expected severity critical, got %s", created.Severity())
	}

	metadata := created.Metadata()
	if metadata["reason"] != "invalid credentials" {
		t.Errorf("expected metadata reason=invalid credentials, got %v", metadata["reason"])
	}
	if created.Message() == "" {
		t.Error("expected message to be set")
	}
}

// =============================================================================
// Event Constructor Tests
// =============================================================================

func TestNewSuccessEvent(t *testing.T) {
	event := app.NewSuccessEvent(audit.ActionUserCreated, audit.ResourceTypeUser, "user-1")

	if event.Action != audit.ActionUserCreated {
		t.Errorf("expected action %s, got %s", audit.ActionUserCreated, event.Action)
	}
	if event.ResourceType != audit.ResourceTypeUser {
		t.Errorf("expected resource type %s, got %s", audit.ResourceTypeUser, event.ResourceType)
	}
	if event.ResourceID != "user-1" {
		t.Errorf("expected resource id user-1, got %s", event.ResourceID)
	}
	if event.Result != audit.ResultSuccess {
		t.Errorf("expected result success, got %s", event.Result)
	}
	if event.Metadata == nil {
		t.Error("expected metadata map to be initialized")
	}
}

func TestNewFailureEvent(t *testing.T) {
	origErr := errors.New("something went wrong")
	event := app.NewFailureEvent(audit.ActionScanFailed, audit.ResourceTypeScan, "scan-1", origErr)

	if event.Result != audit.ResultFailure {
		t.Errorf("expected result failure, got %s", event.Result)
	}
	if event.Metadata["error"] != "something went wrong" {
		t.Errorf("expected metadata error, got %v", event.Metadata["error"])
	}
}

func TestNewFailureEvent_NilError(t *testing.T) {
	event := app.NewFailureEvent(audit.ActionScanFailed, audit.ResourceTypeScan, "scan-1", nil)

	if event.Result != audit.ResultFailure {
		t.Errorf("expected result failure, got %s", event.Result)
	}
	if _, ok := event.Metadata["error"]; ok {
		t.Error("expected no error key in metadata when nil error passed")
	}
}

func TestNewDeniedEvent(t *testing.T) {
	event := app.NewDeniedEvent(audit.ActionPermissionDenied, audit.ResourceTypeAsset, "asset-1", "no access")

	if event.Result != audit.ResultDenied {
		t.Errorf("expected result denied, got %s", event.Result)
	}
	if event.Severity != audit.SeverityHigh {
		t.Errorf("expected severity high, got %s", event.Severity)
	}
	if event.Metadata["reason"] != "no access" {
		t.Errorf("expected metadata reason=no access, got %v", event.Metadata["reason"])
	}
}

func TestNewDeniedEvent_EmptyReason(t *testing.T) {
	event := app.NewDeniedEvent(audit.ActionPermissionDenied, audit.ResourceTypeAsset, "asset-1", "")

	if _, ok := event.Metadata["reason"]; ok {
		t.Error("expected no reason key in metadata when empty reason passed")
	}
}

// =============================================================================
// audit.Event Builder Tests
// =============================================================================

func TestAuditEvent_BuilderChain(t *testing.T) {
	changes := audit.NewChanges().Set("role", "viewer", "admin")

	event := app.NewSuccessEvent(audit.ActionMemberRoleChanged, audit.ResourceTypeMembership, "m-1").
		WithResourceName("user@example.com").
		WithChanges(changes).
		WithMessage("Role changed").
		WithSeverity(audit.SeverityHigh).
		WithMetadata("old_role", "viewer").
		WithMetadata("new_role", "admin")

	if event.ResourceName != "user@example.com" {
		t.Errorf("expected resource name user@example.com, got %s", event.ResourceName)
	}
	if event.Changes == nil {
		t.Error("expected changes to be set")
	}
	if event.Message != "Role changed" {
		t.Errorf("expected message 'Role changed', got %s", event.Message)
	}
	if event.Severity != audit.SeverityHigh {
		t.Errorf("expected severity high, got %s", event.Severity)
	}
	if event.Metadata["old_role"] != "viewer" {
		t.Errorf("expected metadata old_role=viewer, got %v", event.Metadata["old_role"])
	}
	if event.Metadata["new_role"] != "admin" {
		t.Errorf("expected metadata new_role=admin, got %v", event.Metadata["new_role"])
	}
}

// =============================================================================
// LogEvent with ActorEmail-only (no ActorID)
// =============================================================================

func TestAuditService_LogEvent_ActorEmailOnly(t *testing.T) {
	svc, repo := newTestAuditService()
	ctx := context.Background()

	actx := app.AuditContext{
		ActorEmail: "system@example.com",
	}

	event := app.NewSuccessEvent(audit.ActionSettingsUpdated, audit.ResourceTypeSettings, "settings-1")

	err := svc.LogEvent(ctx, actx, event)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	created := repo.lastCreated
	if created.ActorEmail() != "system@example.com" {
		t.Errorf("expected actor email system@example.com, got %s", created.ActorEmail())
	}
	// ActorID should be set but zero (empty ID)
	if created.ActorID() == nil {
		t.Error("expected actor id to be set (even if zero)")
	}
}
