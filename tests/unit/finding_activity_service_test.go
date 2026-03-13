package unit

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Repositories (prefixed with findingAct to avoid conflicts)
// =============================================================================

// findingActActivityRepo implements vulnerability.FindingActivityRepository.
type findingActActivityRepo struct {
	CreateFunc      func(ctx context.Context, a *vulnerability.FindingActivity) error
	CreateBatchFunc func(ctx context.Context, activities []*vulnerability.FindingActivity) error
	GetByIDFunc     func(ctx context.Context, id shared.ID) (*vulnerability.FindingActivity, error)
	ListByFindFunc  func(ctx context.Context, findingID, tenantID shared.ID, filter vulnerability.FindingActivityFilter, page pagination.Pagination) (pagination.Result[*vulnerability.FindingActivity], error)
	CountByFindFunc func(ctx context.Context, findingID, tenantID shared.ID, filter vulnerability.FindingActivityFilter) (int64, error)
	ListByTenFunc   func(ctx context.Context, tenantID shared.ID, filter vulnerability.FindingActivityFilter, page pagination.Pagination) (pagination.Result[*vulnerability.FindingActivity], error)

	// tracking
	CreateCalls     []*vulnerability.FindingActivity
	CreateBatchArgs [][]*vulnerability.FindingActivity
}

func (m *findingActActivityRepo) Create(ctx context.Context, a *vulnerability.FindingActivity) error {
	m.CreateCalls = append(m.CreateCalls, a)
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, a)
	}
	return nil
}

func (m *findingActActivityRepo) CreateBatch(ctx context.Context, activities []*vulnerability.FindingActivity) error {
	m.CreateBatchArgs = append(m.CreateBatchArgs, activities)
	if m.CreateBatchFunc != nil {
		return m.CreateBatchFunc(ctx, activities)
	}
	return nil
}

func (m *findingActActivityRepo) GetByID(ctx context.Context, id shared.ID) (*vulnerability.FindingActivity, error) {
	if m.GetByIDFunc != nil {
		return m.GetByIDFunc(ctx, id)
	}
	return nil, nil
}

func (m *findingActActivityRepo) ListByFinding(ctx context.Context, findingID, tenantID shared.ID, filter vulnerability.FindingActivityFilter, page pagination.Pagination) (pagination.Result[*vulnerability.FindingActivity], error) {
	if m.ListByFindFunc != nil {
		return m.ListByFindFunc(ctx, findingID, tenantID, filter, page)
	}
	return pagination.Result[*vulnerability.FindingActivity]{}, nil
}

func (m *findingActActivityRepo) CountByFinding(ctx context.Context, findingID, tenantID shared.ID, filter vulnerability.FindingActivityFilter) (int64, error) {
	if m.CountByFindFunc != nil {
		return m.CountByFindFunc(ctx, findingID, tenantID, filter)
	}
	return 0, nil
}

func (m *findingActActivityRepo) ListByTenant(ctx context.Context, tenantID shared.ID, filter vulnerability.FindingActivityFilter, page pagination.Pagination) (pagination.Result[*vulnerability.FindingActivity], error) {
	if m.ListByTenFunc != nil {
		return m.ListByTenFunc(ctx, tenantID, filter, page)
	}
	return pagination.Result[*vulnerability.FindingActivity]{}, nil
}

// findingActUserRepo implements user.Repository for testing broadcasts.
type findingActUserRepo struct {
	GetByIDFunc func(ctx context.Context, id shared.ID) (*user.User, error)
}

func (m *findingActUserRepo) Create(_ context.Context, _ *user.User) error   { return nil }
func (m *findingActUserRepo) Update(_ context.Context, _ *user.User) error   { return nil }
func (m *findingActUserRepo) Delete(_ context.Context, _ shared.ID) error    { return nil }
func (m *findingActUserRepo) ExistsByEmail(_ context.Context, _ string) (bool, error) {
	return false, nil
}
func (m *findingActUserRepo) ExistsByKeycloakID(_ context.Context, _ string) (bool, error) {
	return false, nil
}
func (m *findingActUserRepo) GetByKeycloakID(_ context.Context, _ string) (*user.User, error) {
	return nil, nil
}
func (m *findingActUserRepo) GetByEmail(_ context.Context, _ string) (*user.User, error) {
	return nil, nil
}
func (m *findingActUserRepo) UpsertFromKeycloak(_ context.Context, _, _, _ string) (*user.User, error) {
	return nil, nil
}
func (m *findingActUserRepo) GetByIDs(_ context.Context, _ []shared.ID) ([]*user.User, error) {
	return nil, nil
}
func (m *findingActUserRepo) Count(_ context.Context, _ user.Filter) (int64, error) { return 0, nil }
func (m *findingActUserRepo) GetByEmailForAuth(_ context.Context, _ string) (*user.User, error) {
	return nil, nil
}
func (m *findingActUserRepo) GetByEmailVerificationToken(_ context.Context, _ string) (*user.User, error) {
	return nil, nil
}
func (m *findingActUserRepo) GetByPasswordResetToken(_ context.Context, _ string) (*user.User, error) {
	return nil, nil
}
func (m *findingActUserRepo) GetByID(ctx context.Context, id shared.ID) (*user.User, error) {
	if m.GetByIDFunc != nil {
		return m.GetByIDFunc(ctx, id)
	}
	return nil, nil
}

// findingActBroadcaster implements app.ActivityBroadcaster for testing.
type findingActBroadcaster struct {
	Calls []struct {
		Channel  string
		Data     any
		TenantID string
	}
}

func (b *findingActBroadcaster) BroadcastActivity(channel string, data any, tenantID string) {
	b.Calls = append(b.Calls, struct {
		Channel  string
		Data     any
		TenantID string
	}{Channel: channel, Data: data, TenantID: tenantID})
}

// =============================================================================
// Helper
// =============================================================================

func newFindingActService(activityRepo *findingActActivityRepo) *app.FindingActivityService {
	log := logger.NewNop()
	return app.NewFindingActivityService(activityRepo, &stubFindingRepo{}, log)
}

func validUUID() string {
	return shared.NewID().String()
}

func findingActStrPtr(s string) *string {
	return &s
}

// =============================================================================
// RecordActivity Tests
// =============================================================================

func TestFindingActivityService_RecordActivity_Success(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	tenantID := validUUID()
	findingID := validUUID()
	actorID := validUUID()

	result, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:     tenantID,
		FindingID:    findingID,
		ActivityType: string(vulnerability.ActivityStatusChanged),
		ActorID:      &actorID,
		ActorType:    string(vulnerability.ActorTypeUser),
		Changes:      map[string]interface{}{"old_status": "open", "new_status": "resolved"},
		Source:       string(vulnerability.SourceUI),
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(repo.CreateCalls) != 1 {
		t.Fatalf("expected 1 Create call, got %d", len(repo.CreateCalls))
	}
	if result.ActivityType() != vulnerability.ActivityStatusChanged {
		t.Errorf("activity type = %s, want %s", result.ActivityType(), vulnerability.ActivityStatusChanged)
	}
	if result.ActorType() != vulnerability.ActorTypeUser {
		t.Errorf("actor type = %s, want %s", result.ActorType(), vulnerability.ActorTypeUser)
	}
	if result.ActorID() == nil {
		t.Error("expected non-nil actor ID")
	}
}

func TestFindingActivityService_RecordActivity_NilActorID(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	result, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:     validUUID(),
		FindingID:    validUUID(),
		ActivityType: string(vulnerability.ActivityCreated),
		ActorID:      nil,
		ActorType:    string(vulnerability.ActorTypeSystem),
		Changes:      map[string]interface{}{},
		Source:       string(vulnerability.SourceAuto),
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ActorID() != nil {
		t.Errorf("expected nil actor ID for system action, got %v", result.ActorID())
	}
}

func TestFindingActivityService_RecordActivity_EmptyActorID(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	emptyStr := ""
	result, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:     validUUID(),
		FindingID:    validUUID(),
		ActivityType: string(vulnerability.ActivityCreated),
		ActorID:      &emptyStr,
		ActorType:    string(vulnerability.ActorTypeSystem),
		Changes:      map[string]interface{}{},
		Source:       string(vulnerability.SourceAuto),
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ActorID() != nil {
		t.Errorf("expected nil actor ID for empty string, got %v", result.ActorID())
	}
}

func TestFindingActivityService_RecordActivity_InvalidTenantID(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	_, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:     "not-a-uuid",
		FindingID:    validUUID(),
		ActivityType: string(vulnerability.ActivityCreated),
		ActorType:    string(vulnerability.ActorTypeSystem),
		Changes:      map[string]interface{}{},
	})
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestFindingActivityService_RecordActivity_InvalidFindingID(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	_, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:     validUUID(),
		FindingID:    "bad-id",
		ActivityType: string(vulnerability.ActivityCreated),
		ActorType:    string(vulnerability.ActorTypeSystem),
		Changes:      map[string]interface{}{},
	})
	if err == nil {
		t.Fatal("expected error for invalid finding ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestFindingActivityService_RecordActivity_InvalidActorID(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	badActor := "not-uuid"
	_, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:     validUUID(),
		FindingID:    validUUID(),
		ActivityType: string(vulnerability.ActivityCreated),
		ActorID:      &badActor,
		ActorType:    string(vulnerability.ActorTypeUser),
		Changes:      map[string]interface{}{},
	})
	if err == nil {
		t.Fatal("expected error for invalid actor ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestFindingActivityService_RecordActivity_ChangesExceedMaxSize(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	// Create changes that exceed 15KB
	largeContent := strings.Repeat("x", 16*1024)
	changes := map[string]interface{}{
		"content": largeContent,
	}

	_, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:     validUUID(),
		FindingID:    validUUID(),
		ActivityType: string(vulnerability.ActivityCommentAdded),
		ActorType:    string(vulnerability.ActorTypeUser),
		Changes:      changes,
	})
	if err == nil {
		t.Fatal("expected error for oversized changes")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestFindingActivityService_RecordActivity_ChangesAtMaxSize(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	// Create changes just under 15KB - the JSON overhead of {"k":"..."} adds ~7 bytes
	content := strings.Repeat("a", app.MaxChangesSize-10)
	changes := map[string]interface{}{
		"k": content,
	}

	_, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:     validUUID(),
		FindingID:    validUUID(),
		ActivityType: string(vulnerability.ActivityCommentAdded),
		ActorID:      findingActStrPtr(validUUID()),
		ActorType:    string(vulnerability.ActorTypeUser),
		Changes:      changes,
	})
	// Should succeed since it's under the limit
	if err != nil {
		t.Fatalf("expected no error for changes at max size, got %v", err)
	}
}

func TestFindingActivityService_RecordActivity_NilChanges(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	// nil changes should skip the size check and be handled by domain
	_, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:     validUUID(),
		FindingID:    validUUID(),
		ActivityType: string(vulnerability.ActivityCreated),
		ActorType:    string(vulnerability.ActorTypeSystem),
		Changes:      nil,
	})
	// The domain layer validates changes; the service only checks size when non-nil
	// This may succeed or fail depending on domain validation - we just ensure no panic
	_ = err
}

func TestFindingActivityService_RecordActivity_CreateError(t *testing.T) {
	dbErr := errors.New("connection refused")
	repo := &findingActActivityRepo{
		CreateFunc: func(_ context.Context, _ *vulnerability.FindingActivity) error {
			return dbErr
		},
	}
	svc := newFindingActService(repo)

	_, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:     validUUID(),
		FindingID:    validUUID(),
		ActivityType: string(vulnerability.ActivityCreated),
		ActorType:    string(vulnerability.ActorTypeSystem),
		Changes:      map[string]interface{}{},
	})
	if err == nil {
		t.Fatal("expected error from repo Create")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got %v", err)
	}
}

func TestFindingActivityService_RecordActivity_WithSourceMetadata(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	meta := map[string]interface{}{
		"pipeline": "ci-main",
		"commit":   "abc123",
	}

	result, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:       validUUID(),
		FindingID:      validUUID(),
		ActivityType:   string(vulnerability.ActivityScanDetected),
		ActorType:      string(vulnerability.ActorTypeScanner),
		Changes:        map[string]interface{}{"scan_id": "s1"},
		Source:         string(vulnerability.SourceCI),
		SourceMetadata: meta,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.SourceMetadata() == nil {
		t.Error("expected source metadata to be set")
	}
	if result.SourceMetadata()["pipeline"] != "ci-main" {
		t.Errorf("source metadata pipeline = %v, want ci-main", result.SourceMetadata()["pipeline"])
	}
}

// =============================================================================
// RecordActivity with Broadcaster Tests
// =============================================================================

func TestFindingActivityService_RecordActivity_BroadcastsWhenSet(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	bc := &findingActBroadcaster{}
	svc.SetBroadcaster(bc)

	findingID := validUUID()
	_, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:     validUUID(),
		FindingID:    findingID,
		ActivityType: string(vulnerability.ActivityCreated),
		ActorType:    string(vulnerability.ActorTypeSystem),
		Changes:      map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(bc.Calls) != 1 {
		t.Fatalf("expected 1 broadcast call, got %d", len(bc.Calls))
	}
	expectedChannel := "finding:" + findingID
	if bc.Calls[0].Channel != expectedChannel {
		t.Errorf("broadcast channel = %s, want %s", bc.Calls[0].Channel, expectedChannel)
	}
}

func TestFindingActivityService_RecordActivity_NoBroadcastWithoutBroadcaster(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)
	// Do not set broadcaster

	_, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:     validUUID(),
		FindingID:    validUUID(),
		ActivityType: string(vulnerability.ActivityCreated),
		ActorType:    string(vulnerability.ActorTypeSystem),
		Changes:      map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// No panic means success; broadcaster was nil and skipped
}

// =============================================================================
// RecordStatusChange Tests
// =============================================================================

func TestFindingActivityService_RecordStatusChange_Success(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	tenantID := validUUID()
	findingID := validUUID()
	actorID := validUUID()

	result, err := svc.RecordStatusChange(context.Background(),
		tenantID, findingID, &actorID,
		"open", "resolved", "fixed in v2.1", string(vulnerability.SourceUI),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ActivityType() != vulnerability.ActivityStatusChanged {
		t.Errorf("type = %s, want %s", result.ActivityType(), vulnerability.ActivityStatusChanged)
	}
	changes := result.Changes()
	if changes["old_status"] != "open" {
		t.Errorf("old_status = %v, want open", changes["old_status"])
	}
	if changes["new_status"] != "resolved" {
		t.Errorf("new_status = %v, want resolved", changes["new_status"])
	}
	if changes["reason"] != "fixed in v2.1" {
		t.Errorf("reason = %v, want 'fixed in v2.1'", changes["reason"])
	}
}

func TestFindingActivityService_RecordStatusChange_EmptyReason(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	result, err := svc.RecordStatusChange(context.Background(),
		validUUID(), validUUID(), findingActStrPtr(validUUID()),
		"open", "resolved", "", string(vulnerability.SourceUI),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	changes := result.Changes()
	if _, ok := changes["reason"]; ok {
		t.Error("expected no reason key when reason is empty")
	}
}

func TestFindingActivityService_RecordStatusChange_InvalidIDs(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	_, err := svc.RecordStatusChange(context.Background(),
		"bad", validUUID(), nil, "open", "resolved", "", "",
	)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// RecordSeverityChange Tests
// =============================================================================

func TestFindingActivityService_RecordSeverityChange_Success(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	actorID := validUUID()
	result, err := svc.RecordSeverityChange(context.Background(),
		validUUID(), validUUID(), &actorID,
		"medium", "critical", string(vulnerability.SourceUI),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ActivityType() != vulnerability.ActivitySeverityChanged {
		t.Errorf("type = %s, want %s", result.ActivityType(), vulnerability.ActivitySeverityChanged)
	}
	changes := result.Changes()
	if changes["old_severity"] != "medium" {
		t.Errorf("old_severity = %v, want medium", changes["old_severity"])
	}
	if changes["new_severity"] != "critical" {
		t.Errorf("new_severity = %v, want critical", changes["new_severity"])
	}
}

func TestFindingActivityService_RecordSeverityChange_InvalidFindingID(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	_, err := svc.RecordSeverityChange(context.Background(),
		validUUID(), "invalid", nil, "low", "high", "",
	)
	if err == nil {
		t.Fatal("expected error for invalid finding ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// RecordAssignment Tests
// =============================================================================

func TestFindingActivityService_RecordAssignment_Success(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	actorID := validUUID()
	assigneeID := validUUID()
	result, err := svc.RecordAssignment(context.Background(),
		validUUID(), validUUID(), &actorID,
		assigneeID, "Jane Doe", "jane@example.com", string(vulnerability.SourceUI),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ActivityType() != vulnerability.ActivityAssigned {
		t.Errorf("type = %s, want %s", result.ActivityType(), vulnerability.ActivityAssigned)
	}
	changes := result.Changes()
	if changes["assignee_id"] != assigneeID {
		t.Errorf("assignee_id = %v, want %s", changes["assignee_id"], assigneeID)
	}
	if changes["assignee_name"] != "Jane Doe" {
		t.Errorf("assignee_name = %v, want Jane Doe", changes["assignee_name"])
	}
	if changes["assignee_email"] != "jane@example.com" {
		t.Errorf("assignee_email = %v, want jane@example.com", changes["assignee_email"])
	}
}

// =============================================================================
// RecordUnassignment Tests
// =============================================================================

func TestFindingActivityService_RecordUnassignment_Success(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	actorID := validUUID()
	result, err := svc.RecordUnassignment(context.Background(),
		validUUID(), validUUID(), &actorID,
		"Previous Person", string(vulnerability.SourceUI),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ActivityType() != vulnerability.ActivityUnassigned {
		t.Errorf("type = %s, want %s", result.ActivityType(), vulnerability.ActivityUnassigned)
	}
	changes := result.Changes()
	if changes["previous_assignee_name"] != "Previous Person" {
		t.Errorf("previous_assignee_name = %v, want Previous Person", changes["previous_assignee_name"])
	}
}

// =============================================================================
// RecordCommentAdded Tests
// =============================================================================

func TestFindingActivityService_RecordCommentAdded_Success(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	actorID := validUUID()
	commentID := validUUID()
	result, err := svc.RecordCommentAdded(context.Background(),
		validUUID(), validUUID(), &actorID,
		commentID, "This is a comment", string(vulnerability.SourceUI),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ActivityType() != vulnerability.ActivityCommentAdded {
		t.Errorf("type = %s, want %s", result.ActivityType(), vulnerability.ActivityCommentAdded)
	}
	changes := result.Changes()
	if changes["comment_id"] != commentID {
		t.Errorf("comment_id = %v, want %s", changes["comment_id"], commentID)
	}
	if changes["content"] != "This is a comment" {
		t.Errorf("content = %v, want 'This is a comment'", changes["content"])
	}
	if changes["preview"] != "This is a comment" {
		t.Errorf("preview should equal content when content is short")
	}
}

func TestFindingActivityService_RecordCommentAdded_LongContentTruncatesPreview(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	longContent := strings.Repeat("a", 200)
	result, err := svc.RecordCommentAdded(context.Background(),
		validUUID(), validUUID(), findingActStrPtr(validUUID()),
		validUUID(), longContent, "",
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	changes := result.Changes()
	content, ok := changes["content"].(string)
	if !ok {
		t.Fatal("expected content to be a string")
	}
	if content != longContent {
		t.Error("full content should be preserved")
	}
	preview, ok := changes["preview"].(string)
	if !ok {
		t.Fatal("expected preview to be a string")
	}
	if len(preview) != 103 { // 100 chars + "..."
		t.Errorf("preview length = %d, want 103", len(preview))
	}
	if !strings.HasSuffix(preview, "...") {
		t.Error("truncated preview should end with ...")
	}
}

func TestFindingActivityService_RecordCommentAdded_EmptyContent(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	result, err := svc.RecordCommentAdded(context.Background(),
		validUUID(), validUUID(), findingActStrPtr(validUUID()),
		validUUID(), "", "",
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	changes := result.Changes()
	if _, ok := changes["content"]; ok {
		t.Error("expected no content key when content is empty")
	}
	if _, ok := changes["preview"]; ok {
		t.Error("expected no preview key when content is empty")
	}
	if _, ok := changes["comment_id"]; !ok {
		t.Error("comment_id should always be present")
	}
}

// =============================================================================
// RecordCommentUpdated Tests
// =============================================================================

func TestFindingActivityService_RecordCommentUpdated_Success(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	commentID := validUUID()
	result, err := svc.RecordCommentUpdated(context.Background(),
		validUUID(), validUUID(), findingActStrPtr(validUUID()),
		commentID, string(vulnerability.SourceUI),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ActivityType() != vulnerability.ActivityCommentUpdated {
		t.Errorf("type = %s, want %s", result.ActivityType(), vulnerability.ActivityCommentUpdated)
	}
	changes := result.Changes()
	if changes["comment_id"] != commentID {
		t.Errorf("comment_id = %v, want %s", changes["comment_id"], commentID)
	}
}

// =============================================================================
// RecordCommentDeleted Tests
// =============================================================================

func TestFindingActivityService_RecordCommentDeleted_Success(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	commentID := validUUID()
	result, err := svc.RecordCommentDeleted(context.Background(),
		validUUID(), validUUID(), findingActStrPtr(validUUID()),
		commentID, string(vulnerability.SourceUI),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ActivityType() != vulnerability.ActivityCommentDeleted {
		t.Errorf("type = %s, want %s", result.ActivityType(), vulnerability.ActivityCommentDeleted)
	}
	changes := result.Changes()
	if changes["comment_id"] != commentID {
		t.Errorf("comment_id = %v, want %s", changes["comment_id"], commentID)
	}
}

// =============================================================================
// RecordScanDetected Tests
// =============================================================================

func TestFindingActivityService_RecordScanDetected_Success(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	meta := map[string]interface{}{"pipeline": "main"}
	result, err := svc.RecordScanDetected(context.Background(),
		validUUID(), validUUID(),
		"scan-1", "nuclei", "full_scan", meta,
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ActivityType() != vulnerability.ActivityScanDetected {
		t.Errorf("type = %s, want %s", result.ActivityType(), vulnerability.ActivityScanDetected)
	}
	if result.ActorType() != vulnerability.ActorTypeScanner {
		t.Errorf("actor type = %s, want %s", result.ActorType(), vulnerability.ActorTypeScanner)
	}
	changes := result.Changes()
	if changes["scan_id"] != "scan-1" {
		t.Errorf("scan_id = %v, want scan-1", changes["scan_id"])
	}
	if changes["scanner"] != "nuclei" {
		t.Errorf("scanner = %v, want nuclei", changes["scanner"])
	}
	if changes["scan_type"] != "full_scan" {
		t.Errorf("scan_type = %v, want full_scan", changes["scan_type"])
	}
}

func TestFindingActivityService_RecordScanDetected_NilSourceMetadata(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	result, err := svc.RecordScanDetected(context.Background(),
		validUUID(), validUUID(),
		"scan-2", "semgrep", "incremental", nil,
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// =============================================================================
// RecordCreated Tests
// =============================================================================

func TestFindingActivityService_RecordCreated_Success(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	meta := map[string]interface{}{"ingestion_batch": "b1"}
	result, err := svc.RecordCreated(context.Background(),
		validUUID(), validUUID(),
		string(vulnerability.SourceCI), meta,
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ActivityType() != vulnerability.ActivityCreated {
		t.Errorf("type = %s, want %s", result.ActivityType(), vulnerability.ActivityCreated)
	}
	if result.ActorType() != vulnerability.ActorTypeSystem {
		t.Errorf("actor type = %s, want %s", result.ActorType(), vulnerability.ActorTypeSystem)
	}
	if result.ActorID() != nil {
		t.Error("expected nil actor ID for system-created activity")
	}
}

func TestFindingActivityService_RecordCreated_InvalidTenantID(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	_, err := svc.RecordCreated(context.Background(),
		"invalid", validUUID(), "", nil,
	)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// RecordBatchAutoResolved (additional to existing tests)
// =============================================================================

func TestFindingActivityService_RecordBatchAutoResolved_RepoError(t *testing.T) {
	dbErr := errors.New("batch insert failed")
	repo := &findingActActivityRepo{
		CreateBatchFunc: func(_ context.Context, _ []*vulnerability.FindingActivity) error {
			return dbErr
		},
	}
	svc := newFindingActService(repo)

	err := svc.RecordBatchAutoResolved(context.Background(),
		shared.NewID(), []shared.ID{shared.NewID()}, "nuclei", "s1",
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got %v", err)
	}
}

func TestFindingActivityService_RecordBatchAutoResolved_EmptySlice(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	err := svc.RecordBatchAutoResolved(context.Background(),
		shared.NewID(), []shared.ID{}, "nuclei", "s1",
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(repo.CreateBatchArgs) != 0 {
		t.Error("expected no CreateBatch calls for empty slice")
	}
}

// =============================================================================
// RecordBatchAutoReopened (additional to existing tests)
// =============================================================================

func TestFindingActivityService_RecordBatchAutoReopened_RepoError(t *testing.T) {
	dbErr := errors.New("batch insert failed")
	repo := &findingActActivityRepo{
		CreateBatchFunc: func(_ context.Context, _ []*vulnerability.FindingActivity) error {
			return dbErr
		},
	}
	svc := newFindingActService(repo)

	err := svc.RecordBatchAutoReopened(context.Background(),
		shared.NewID(), []shared.ID{shared.NewID()},
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got %v", err)
	}
}

func TestFindingActivityService_RecordBatchAutoReopened_EmptySlice(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	err := svc.RecordBatchAutoReopened(context.Background(),
		shared.NewID(), []shared.ID{},
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(repo.CreateBatchArgs) != 0 {
		t.Error("expected no CreateBatch calls for empty slice")
	}
}

func TestFindingActivityService_RecordBatchAutoReopened_CorrectChanges(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	err := svc.RecordBatchAutoReopened(context.Background(),
		shared.NewID(), []shared.ID{shared.NewID(), shared.NewID()},
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(repo.CreateBatchArgs) != 1 {
		t.Fatalf("expected 1 CreateBatch call, got %d", len(repo.CreateBatchArgs))
	}
	for i, a := range repo.CreateBatchArgs[0] {
		if a.ActivityType() != vulnerability.ActivityAutoReopened {
			t.Errorf("activity %d: type = %s, want %s", i, a.ActivityType(), vulnerability.ActivityAutoReopened)
		}
		if a.Source() != vulnerability.SourceAuto {
			t.Errorf("activity %d: source = %s, want %s", i, a.Source(), vulnerability.SourceAuto)
		}
		if a.Changes()["reason"] != "finding_detected_again" {
			t.Errorf("activity %d: reason = %v, want finding_detected_again", i, a.Changes()["reason"])
		}
	}
}

// =============================================================================
// ListActivities Tests
// =============================================================================

func TestFindingActivityService_ListActivities_Success(t *testing.T) {
	repo := &findingActActivityRepo{
		ListByFindFunc: func(_ context.Context, _, _ shared.ID, _ vulnerability.FindingActivityFilter, _ pagination.Pagination) (pagination.Result[*vulnerability.FindingActivity], error) {
			return pagination.Result[*vulnerability.FindingActivity]{
				Total: 5,
			}, nil
		},
	}
	svc := newFindingActService(repo)

	result, err := svc.ListActivities(context.Background(), app.ListActivitiesInput{
		TenantID:  validUUID(),
		FindingID: validUUID(),
		Page:      0,
		PageSize:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 5 {
		t.Errorf("total items = %d, want 5", result.Total)
	}
}

func TestFindingActivityService_ListActivities_WithActivityTypeFilter(t *testing.T) {
	var capturedFilter vulnerability.FindingActivityFilter
	repo := &findingActActivityRepo{
		ListByFindFunc: func(_ context.Context, _, _ shared.ID, filter vulnerability.FindingActivityFilter, _ pagination.Pagination) (pagination.Result[*vulnerability.FindingActivity], error) {
			capturedFilter = filter
			return pagination.Result[*vulnerability.FindingActivity]{}, nil
		},
	}
	svc := newFindingActService(repo)

	_, err := svc.ListActivities(context.Background(), app.ListActivitiesInput{
		TenantID:      validUUID(),
		FindingID:     validUUID(),
		ActivityTypes: []string{"status_changed", "comment_added"},
		Page:          0,
		PageSize:      20,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(capturedFilter.ActivityTypes) != 2 {
		t.Fatalf("expected 2 activity type filters, got %d", len(capturedFilter.ActivityTypes))
	}
	if capturedFilter.ActivityTypes[0] != vulnerability.ActivityStatusChanged {
		t.Errorf("filter[0] = %s, want %s", capturedFilter.ActivityTypes[0], vulnerability.ActivityStatusChanged)
	}
	if capturedFilter.ActivityTypes[1] != vulnerability.ActivityCommentAdded {
		t.Errorf("filter[1] = %s, want %s", capturedFilter.ActivityTypes[1], vulnerability.ActivityCommentAdded)
	}
}

func TestFindingActivityService_ListActivities_NoFilterTypes(t *testing.T) {
	var capturedFilter vulnerability.FindingActivityFilter
	repo := &findingActActivityRepo{
		ListByFindFunc: func(_ context.Context, _, _ shared.ID, filter vulnerability.FindingActivityFilter, _ pagination.Pagination) (pagination.Result[*vulnerability.FindingActivity], error) {
			capturedFilter = filter
			return pagination.Result[*vulnerability.FindingActivity]{}, nil
		},
	}
	svc := newFindingActService(repo)

	_, err := svc.ListActivities(context.Background(), app.ListActivitiesInput{
		TenantID:  validUUID(),
		FindingID: validUUID(),
		Page:      0,
		PageSize:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(capturedFilter.ActivityTypes) != 0 {
		t.Errorf("expected empty activity types filter, got %d", len(capturedFilter.ActivityTypes))
	}
}

func TestFindingActivityService_ListActivities_InvalidTenantID(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	_, err := svc.ListActivities(context.Background(), app.ListActivitiesInput{
		TenantID:  "bad",
		FindingID: validUUID(),
		Page:      0,
		PageSize:  10,
	})
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestFindingActivityService_ListActivities_InvalidFindingID(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	_, err := svc.ListActivities(context.Background(), app.ListActivitiesInput{
		TenantID:  validUUID(),
		FindingID: "bad",
		Page:      0,
		PageSize:  10,
	})
	if err == nil {
		t.Fatal("expected error for invalid finding ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestFindingActivityService_ListActivities_RepoError(t *testing.T) {
	dbErr := errors.New("query timeout")
	repo := &findingActActivityRepo{
		ListByFindFunc: func(_ context.Context, _, _ shared.ID, _ vulnerability.FindingActivityFilter, _ pagination.Pagination) (pagination.Result[*vulnerability.FindingActivity], error) {
			return pagination.Result[*vulnerability.FindingActivity]{}, dbErr
		},
	}
	svc := newFindingActService(repo)

	_, err := svc.ListActivities(context.Background(), app.ListActivitiesInput{
		TenantID:  validUUID(),
		FindingID: validUUID(),
		Page:      0,
		PageSize:  10,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got %v", err)
	}
}

// =============================================================================
// GetActivity Tests
// =============================================================================

func TestFindingActivityService_GetActivity_Success(t *testing.T) {
	activityID := shared.NewID()
	tenantID := shared.NewID()
	findingID := shared.NewID()

	// Build a real activity via the domain constructor
	activity, _ := vulnerability.NewFindingActivity(
		tenantID, findingID,
		vulnerability.ActivityCreated,
		nil, vulnerability.ActorTypeSystem,
		map[string]interface{}{},
		vulnerability.SourceAuto, nil,
	)

	repo := &findingActActivityRepo{
		GetByIDFunc: func(_ context.Context, id shared.ID) (*vulnerability.FindingActivity, error) {
			if id == activityID {
				return activity, nil
			}
			return nil, errors.New("not found")
		},
	}
	svc := newFindingActService(repo)

	result, err := svc.GetActivity(context.Background(), activityID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestFindingActivityService_GetActivity_InvalidID(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	_, err := svc.GetActivity(context.Background(), "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid activity ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestFindingActivityService_GetActivity_RepoError(t *testing.T) {
	dbErr := errors.New("db unavailable")
	repo := &findingActActivityRepo{
		GetByIDFunc: func(_ context.Context, _ shared.ID) (*vulnerability.FindingActivity, error) {
			return nil, dbErr
		},
	}
	svc := newFindingActService(repo)

	_, err := svc.GetActivity(context.Background(), validUUID())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got %v", err)
	}
}

// =============================================================================
// CountActivities Tests
// =============================================================================

func TestFindingActivityService_CountActivities_Success(t *testing.T) {
	repo := &findingActActivityRepo{
		CountByFindFunc: func(_ context.Context, _, _ shared.ID, _ vulnerability.FindingActivityFilter) (int64, error) {
			return 42, nil
		},
	}
	svc := newFindingActService(repo)

	count, err := svc.CountActivities(context.Background(),
		validUUID(), validUUID(), vulnerability.NewFindingActivityFilter(),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 42 {
		t.Errorf("count = %d, want 42", count)
	}
}

func TestFindingActivityService_CountActivities_InvalidTenantID(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	_, err := svc.CountActivities(context.Background(),
		"bad", validUUID(), vulnerability.NewFindingActivityFilter(),
	)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestFindingActivityService_CountActivities_InvalidFindingID(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	_, err := svc.CountActivities(context.Background(),
		validUUID(), "bad", vulnerability.NewFindingActivityFilter(),
	)
	if err == nil {
		t.Fatal("expected error for invalid finding ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestFindingActivityService_CountActivities_RepoError(t *testing.T) {
	dbErr := errors.New("count failed")
	repo := &findingActActivityRepo{
		CountByFindFunc: func(_ context.Context, _, _ shared.ID, _ vulnerability.FindingActivityFilter) (int64, error) {
			return 0, dbErr
		},
	}
	svc := newFindingActService(repo)

	_, err := svc.CountActivities(context.Background(),
		validUUID(), validUUID(), vulnerability.NewFindingActivityFilter(),
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got %v", err)
	}
}

// =============================================================================
// SetBroadcaster / SetUserRepo Tests
// =============================================================================

func TestFindingActivityService_SetBroadcaster(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	bc := &findingActBroadcaster{}
	svc.SetBroadcaster(bc)

	// Verify broadcast is called after recording
	_, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:     validUUID(),
		FindingID:    validUUID(),
		ActivityType: string(vulnerability.ActivityCreated),
		ActorType:    string(vulnerability.ActorTypeSystem),
		Changes:      map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(bc.Calls) != 1 {
		t.Errorf("expected 1 broadcast, got %d", len(bc.Calls))
	}
}

func TestFindingActivityService_SetUserRepo(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	userRepo := &findingActUserRepo{}
	svc.SetUserRepo(userRepo)
	// Just verify no panic - SetUserRepo stores the reference
}

// =============================================================================
// Broadcast with User Resolution Tests
// =============================================================================

func TestFindingActivityService_BroadcastResolvesActorInfo(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	bc := &findingActBroadcaster{}
	svc.SetBroadcaster(bc)

	actorID := shared.NewID()
	actorIDStr := actorID.String()

	userRepo := &findingActUserRepo{
		GetByIDFunc: func(_ context.Context, id shared.ID) (*user.User, error) {
			if id == actorID {
				u, _ := user.New("actor@example.com", "Test Actor")
				return u, nil
			}
			return nil, errors.New("not found")
		},
	}
	svc.SetUserRepo(userRepo)

	_, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:     validUUID(),
		FindingID:    validUUID(),
		ActivityType: string(vulnerability.ActivityStatusChanged),
		ActorID:      &actorIDStr,
		ActorType:    string(vulnerability.ActorTypeUser),
		Changes:      map[string]interface{}{"old_status": "open", "new_status": "resolved"},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(bc.Calls) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(bc.Calls))
	}

	// Verify the broadcast data includes actor info
	data, ok := bc.Calls[0].Data.(map[string]any)
	if !ok {
		t.Fatal("expected broadcast data to be map[string]any")
	}
	activity, ok := data["activity"].(map[string]any)
	if !ok {
		t.Fatal("expected activity key in broadcast data")
	}
	if activity["actor_name"] != "Test Actor" {
		t.Errorf("actor_name = %v, want Test Actor", activity["actor_name"])
	}
	if activity["actor_email"] != "actor@example.com" {
		t.Errorf("actor_email = %v, want actor@example.com", activity["actor_email"])
	}
}

func TestFindingActivityService_BroadcastWithNilActorID(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	bc := &findingActBroadcaster{}
	svc.SetBroadcaster(bc)

	_, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:     validUUID(),
		FindingID:    validUUID(),
		ActivityType: string(vulnerability.ActivityCreated),
		ActorID:      nil,
		ActorType:    string(vulnerability.ActorTypeSystem),
		Changes:      map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(bc.Calls) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(bc.Calls))
	}

	data := bc.Calls[0].Data.(map[string]any)
	activity := data["activity"].(map[string]any)
	if activity["actor_id"] != (*string)(nil) {
		t.Errorf("expected nil actor_id for system activity, got %v", activity["actor_id"])
	}
}

func TestFindingActivityService_BroadcastTenantIDMatches(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	bc := &findingActBroadcaster{}
	svc.SetBroadcaster(bc)

	tenantID := validUUID()
	_, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:     tenantID,
		FindingID:    validUUID(),
		ActivityType: string(vulnerability.ActivityCreated),
		ActorType:    string(vulnerability.ActorTypeSystem),
		Changes:      map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if bc.Calls[0].TenantID != tenantID {
		t.Errorf("broadcast tenant ID = %s, want %s", bc.Calls[0].TenantID, tenantID)
	}
}

// =============================================================================
// Convenience Method Actor Type Tests
// =============================================================================

func TestFindingActivityService_ConvenienceMethodsSetUserActorType(t *testing.T) {
	tests := []struct {
		name     string
		callFunc func(svc *app.FindingActivityService) (*vulnerability.FindingActivity, error)
		wantType vulnerability.ActivityType
	}{
		{
			name: "RecordStatusChange",
			callFunc: func(svc *app.FindingActivityService) (*vulnerability.FindingActivity, error) {
				return svc.RecordStatusChange(context.Background(),
					validUUID(), validUUID(), findingActStrPtr(validUUID()),
					"open", "resolved", "", "",
				)
			},
			wantType: vulnerability.ActivityStatusChanged,
		},
		{
			name: "RecordSeverityChange",
			callFunc: func(svc *app.FindingActivityService) (*vulnerability.FindingActivity, error) {
				return svc.RecordSeverityChange(context.Background(),
					validUUID(), validUUID(), findingActStrPtr(validUUID()),
					"low", "high", "",
				)
			},
			wantType: vulnerability.ActivitySeverityChanged,
		},
		{
			name: "RecordAssignment",
			callFunc: func(svc *app.FindingActivityService) (*vulnerability.FindingActivity, error) {
				return svc.RecordAssignment(context.Background(),
					validUUID(), validUUID(), findingActStrPtr(validUUID()),
					validUUID(), "Name", "email@test.com", "",
				)
			},
			wantType: vulnerability.ActivityAssigned,
		},
		{
			name: "RecordUnassignment",
			callFunc: func(svc *app.FindingActivityService) (*vulnerability.FindingActivity, error) {
				return svc.RecordUnassignment(context.Background(),
					validUUID(), validUUID(), findingActStrPtr(validUUID()),
					"Previous", "",
				)
			},
			wantType: vulnerability.ActivityUnassigned,
		},
		{
			name: "RecordCommentAdded",
			callFunc: func(svc *app.FindingActivityService) (*vulnerability.FindingActivity, error) {
				return svc.RecordCommentAdded(context.Background(),
					validUUID(), validUUID(), findingActStrPtr(validUUID()),
					validUUID(), "text", "",
				)
			},
			wantType: vulnerability.ActivityCommentAdded,
		},
		{
			name: "RecordCommentUpdated",
			callFunc: func(svc *app.FindingActivityService) (*vulnerability.FindingActivity, error) {
				return svc.RecordCommentUpdated(context.Background(),
					validUUID(), validUUID(), findingActStrPtr(validUUID()),
					validUUID(), "",
				)
			},
			wantType: vulnerability.ActivityCommentUpdated,
		},
		{
			name: "RecordCommentDeleted",
			callFunc: func(svc *app.FindingActivityService) (*vulnerability.FindingActivity, error) {
				return svc.RecordCommentDeleted(context.Background(),
					validUUID(), validUUID(), findingActStrPtr(validUUID()),
					validUUID(), "",
				)
			},
			wantType: vulnerability.ActivityCommentDeleted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &findingActActivityRepo{}
			svc := newFindingActService(repo)

			result, err := tt.callFunc(svc)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if result.ActivityType() != tt.wantType {
				t.Errorf("activity type = %s, want %s", result.ActivityType(), tt.wantType)
			}
			if result.ActorType() != vulnerability.ActorTypeUser {
				t.Errorf("actor type = %s, want %s", result.ActorType(), vulnerability.ActorTypeUser)
			}
		})
	}
}

// =============================================================================
// RecordScanDetected uses Scanner actor type
// =============================================================================

func TestFindingActivityService_RecordScanDetected_UsesActorTypeScanner(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	result, err := svc.RecordScanDetected(context.Background(),
		validUUID(), validUUID(),
		"s1", "trivy", "full", nil,
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ActorType() != vulnerability.ActorTypeScanner {
		t.Errorf("actor type = %s, want scanner", result.ActorType())
	}
	if result.Source() != vulnerability.SourceCI {
		t.Errorf("source = %s, want ci", result.Source())
	}
}

// =============================================================================
// RecordCreated uses System actor type
// =============================================================================

func TestFindingActivityService_RecordCreated_UsesActorTypeSystem(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	result, err := svc.RecordCreated(context.Background(),
		validUUID(), validUUID(), string(vulnerability.SourceAuto), nil,
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ActorType() != vulnerability.ActorTypeSystem {
		t.Errorf("actor type = %s, want system", result.ActorType())
	}
}

// =============================================================================
// MaxChangesSize constant test
// =============================================================================

func TestMaxChangesSize_Is15KB(t *testing.T) {
	expected := 15 * 1024
	if app.MaxChangesSize != expected {
		t.Errorf("MaxChangesSize = %d, want %d", app.MaxChangesSize, expected)
	}
}

// =============================================================================
// Multiple sequential activities create unique IDs
// =============================================================================

func TestFindingActivityService_RecordActivity_UniqueIDs(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	ids := make(map[string]bool)
	for i := 0; i < 10; i++ {
		result, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
			TenantID:     validUUID(),
			FindingID:    validUUID(),
			ActivityType: string(vulnerability.ActivityCreated),
			ActorType:    string(vulnerability.ActorTypeSystem),
			Changes:      map[string]interface{}{},
		})
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
		idStr := result.ID().String()
		if ids[idStr] {
			t.Errorf("duplicate activity ID at iteration %d: %s", i, idStr)
		}
		ids[idStr] = true
	}
}

// =============================================================================
// Timestamp is set on creation
// =============================================================================

func TestFindingActivityService_RecordActivity_TimestampIsSet(t *testing.T) {
	repo := &findingActActivityRepo{}
	svc := newFindingActService(repo)

	result, err := svc.RecordActivity(context.Background(), app.RecordActivityInput{
		TenantID:     validUUID(),
		FindingID:    validUUID(),
		ActivityType: string(vulnerability.ActivityCreated),
		ActorType:    string(vulnerability.ActorTypeSystem),
		Changes:      map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CreatedAt().IsZero() {
		t.Error("CreatedAt should not be zero")
	}
}
