package unit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/credential"
	"github.com/openctemio/api/pkg/domain/exposure"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Exposure Repository (credImport-prefixed)
// =============================================================================

type credImportMockExposureRepo struct {
	events          map[string]*exposure.ExposureEvent
	fingerprintMap  map[string]*exposure.ExposureEvent // fingerprint -> event
	tenantEvents    map[string][]*exposure.ExposureEvent // tenantID -> events

	// Configurable errors
	createErr     error
	getByIDErr    error
	getFPErr      error
	updateErr     error
	deleteErr     error
	listErr       error
	countErr      error
	countStateErr error
	countSevErr   error

	// Configurable results
	countByStateResult    map[exposure.State]int64
	countBySeverityResult map[exposure.Severity]int64

	// Call tracking
	createCalls     int
	getByIDCalls    int
	getFPCalls      int
	updateCalls     int
	deleteCalls     int
	listCalls       int
	countCalls      int
	countStateCalls int
	countSevCalls   int
}

func newCredImportMockExposureRepo() *credImportMockExposureRepo {
	return &credImportMockExposureRepo{
		events:         make(map[string]*exposure.ExposureEvent),
		fingerprintMap: make(map[string]*exposure.ExposureEvent),
		tenantEvents:   make(map[string][]*exposure.ExposureEvent),
	}
}

func (m *credImportMockExposureRepo) Create(_ context.Context, event *exposure.ExposureEvent) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.events[event.ID().String()] = event
	m.fingerprintMap[event.Fingerprint()] = event
	tid := event.TenantID().String()
	m.tenantEvents[tid] = append(m.tenantEvents[tid], event)
	return nil
}

func (m *credImportMockExposureRepo) CreateInTx(_ context.Context, _ *sql.Tx, event *exposure.ExposureEvent) error {
	return m.Create(context.Background(), event)
}

func (m *credImportMockExposureRepo) GetByID(_ context.Context, id shared.ID) (*exposure.ExposureEvent, error) {
	m.getByIDCalls++
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	e, ok := m.events[id.String()]
	if !ok {
		return nil, exposure.NewExposureEventNotFoundError(id.String())
	}
	return e, nil
}

func (m *credImportMockExposureRepo) GetByFingerprint(_ context.Context, _ shared.ID, fingerprint string) (*exposure.ExposureEvent, error) {
	m.getFPCalls++
	if m.getFPErr != nil {
		return nil, m.getFPErr
	}
	e, ok := m.fingerprintMap[fingerprint]
	if !ok {
		return nil, exposure.NewExposureEventNotFoundError(fingerprint)
	}
	return e, nil
}

func (m *credImportMockExposureRepo) Update(_ context.Context, event *exposure.ExposureEvent) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.events[event.ID().String()] = event
	return nil
}

func (m *credImportMockExposureRepo) Delete(_ context.Context, id shared.ID) error {
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.events, id.String())
	return nil
}

func (m *credImportMockExposureRepo) List(_ context.Context, filter exposure.Filter, _ exposure.ListOptions, page pagination.Pagination) (pagination.Result[*exposure.ExposureEvent], error) {
	m.listCalls++
	if m.listErr != nil {
		return pagination.Result[*exposure.ExposureEvent]{}, m.listErr
	}

	result := make([]*exposure.ExposureEvent, 0, len(m.events))
	for _, e := range m.events {
		// Filter by tenant ID
		if filter.TenantID != nil {
			tid, err := shared.IDFromString(*filter.TenantID)
			if err != nil || e.TenantID() != tid {
				continue
			}
		}
		// Filter by event type
		if len(filter.EventTypes) > 0 {
			match := false
			for _, et := range filter.EventTypes {
				if e.EventType() == et {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		result = append(result, e)
	}

	total := int64(len(result))
	perPage := page.PerPage
	if perPage == 0 {
		perPage = 20
	}

	return pagination.Result[*exposure.ExposureEvent]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    perPage,
		TotalPages: int((total + int64(perPage) - 1) / int64(perPage)),
	}, nil
}

func (m *credImportMockExposureRepo) Count(_ context.Context, _ exposure.Filter) (int64, error) {
	m.countCalls++
	if m.countErr != nil {
		return 0, m.countErr
	}
	return int64(len(m.events)), nil
}

func (m *credImportMockExposureRepo) ListByAsset(_ context.Context, _ shared.ID, page pagination.Pagination) (pagination.Result[*exposure.ExposureEvent], error) {
	return pagination.Result[*exposure.ExposureEvent]{
		Data:    []*exposure.ExposureEvent{},
		Total:   0,
		Page:    page.Page,
		PerPage: page.PerPage,
	}, nil
}

func (m *credImportMockExposureRepo) ExistsByFingerprint(_ context.Context, _ shared.ID, fingerprint string) (bool, error) {
	_, ok := m.fingerprintMap[fingerprint]
	return ok, nil
}

func (m *credImportMockExposureRepo) Upsert(_ context.Context, event *exposure.ExposureEvent) error {
	m.events[event.ID().String()] = event
	return nil
}

func (m *credImportMockExposureRepo) BulkUpsert(_ context.Context, events []*exposure.ExposureEvent) error {
	for _, e := range events {
		m.events[e.ID().String()] = e
	}
	return nil
}

func (m *credImportMockExposureRepo) CountByState(_ context.Context, _ shared.ID) (map[exposure.State]int64, error) {
	m.countStateCalls++
	if m.countStateErr != nil {
		return nil, m.countStateErr
	}
	if m.countByStateResult != nil {
		return m.countByStateResult, nil
	}
	return map[exposure.State]int64{}, nil
}

func (m *credImportMockExposureRepo) CountBySeverity(_ context.Context, _ shared.ID) (map[exposure.Severity]int64, error) {
	m.countSevCalls++
	if m.countSevErr != nil {
		return nil, m.countSevErr
	}
	if m.countBySeverityResult != nil {
		return m.countBySeverityResult, nil
	}
	return map[exposure.Severity]int64{}, nil
}

// addExistingEvent is a helper to pre-populate the repo with an event.
func (m *credImportMockExposureRepo) addExistingEvent(event *exposure.ExposureEvent) {
	m.events[event.ID().String()] = event
	m.fingerprintMap[event.Fingerprint()] = event
	tid := event.TenantID().String()
	m.tenantEvents[tid] = append(m.tenantEvents[tid], event)
}

// =============================================================================
// Mock State History Repository (credImport-prefixed)
// =============================================================================

type credImportMockStateHistoryRepo struct {
	histories map[string][]*exposure.StateHistory

	createErr error
	listErr   error

	createCalls int
	listCalls   int
}

func newCredImportMockStateHistoryRepo() *credImportMockStateHistoryRepo {
	return &credImportMockStateHistoryRepo{
		histories: make(map[string][]*exposure.StateHistory),
	}
}

func (m *credImportMockStateHistoryRepo) Create(_ context.Context, history *exposure.StateHistory) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	key := history.ExposureEventID().String()
	m.histories[key] = append(m.histories[key], history)
	return nil
}

func (m *credImportMockStateHistoryRepo) ListByExposureEvent(_ context.Context, exposureEventID shared.ID) ([]*exposure.StateHistory, error) {
	m.listCalls++
	if m.listErr != nil {
		return nil, m.listErr
	}
	key := exposureEventID.String()
	if h, ok := m.histories[key]; ok {
		return h, nil
	}
	return []*exposure.StateHistory{}, nil
}

func (m *credImportMockStateHistoryRepo) GetLatest(_ context.Context, exposureEventID shared.ID) (*exposure.StateHistory, error) {
	key := exposureEventID.String()
	if h, ok := m.histories[key]; ok && len(h) > 0 {
		return h[len(h)-1], nil
	}
	return nil, shared.ErrNotFound
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func newCredImportTestService() (*app.CredentialImportService, *credImportMockExposureRepo, *credImportMockStateHistoryRepo) {
	repo := newCredImportMockExposureRepo()
	historyRepo := newCredImportMockStateHistoryRepo()
	log := logger.NewNop()
	svc := app.NewCredentialImportService(repo, historyRepo, log)
	return svc, repo, historyRepo
}

func validCredentialImport() credential.CredentialImport {
	return credential.CredentialImport{
		Identifier:     "user@example.com",
		CredentialType: credential.CredentialTypePassword,
		Source: credential.CredentialSource{
			Type: credential.SourceTypeDataBreach,
			Name: "TestBreach",
		},
		DedupKey: credential.DedupKey{
			BreachName: "test_breach_2024",
		},
		Context: credential.CredentialContext{
			Email:    "user@example.com",
			Username: "testuser",
		},
	}
}

func validImportRequest(creds ...credential.CredentialImport) credential.ImportRequest {
	if len(creds) == 0 {
		creds = []credential.CredentialImport{validCredentialImport()}
	}
	return credential.ImportRequest{
		Credentials: creds,
		Options:     credential.DefaultImportOptions(),
		Metadata: credential.ImportMetadata{
			SourceTool: "unit_test",
			ImportDate: time.Now().UTC(),
		},
	}
}

// createActiveExposureEvent creates an active exposure event for testing.
func createCredImportTestEvent(tenantID shared.ID, identifier, source string) *exposure.ExposureEvent {
	now := time.Now().UTC()
	return exposure.Reconstitute(
		shared.NewID(),
		tenantID,
		nil,
		exposure.EventTypeCredentialLeaked,
		exposure.SeverityHigh,
		exposure.StateActive,
		identifier,
		"",
		map[string]any{
			"credential_type": "password",
			"email":           identifier,
			"username":        "testuser",
			"is_verified":     false,
			"is_revoked":      false,
		},
		"test-fingerprint-"+identifier,
		source,
		now, now,
		nil, nil, "",
		now, now,
	)
}

// createResolvedExposureEvent creates a resolved exposure event for testing.
func createResolvedCredImportTestEvent(tenantID shared.ID, identifier, source string) *exposure.ExposureEvent {
	now := time.Now().UTC()
	resolvedAt := now.Add(-1 * time.Hour)
	resolvedBy := shared.NewID()
	return exposure.Reconstitute(
		shared.NewID(),
		tenantID,
		nil,
		exposure.EventTypeCredentialLeaked,
		exposure.SeverityHigh,
		exposure.StateResolved,
		identifier,
		"",
		map[string]any{
			"credential_type": "password",
			"email":           identifier,
			"username":        "testuser",
			"is_verified":     false,
			"is_revoked":      false,
		},
		"test-fingerprint-"+identifier,
		source,
		now.Add(-24*time.Hour), now.Add(-2*time.Hour),
		&resolvedAt, &resolvedBy, "resolved for testing",
		now.Add(-24*time.Hour), resolvedAt,
	)
}

// createFalsePositiveCredImportTestEvent creates a false positive exposure event.
func createFalsePositiveCredImportTestEvent(tenantID shared.ID, identifier, source string) *exposure.ExposureEvent {
	now := time.Now().UTC()
	fpAt := now.Add(-1 * time.Hour)
	fpBy := shared.NewID()
	return exposure.Reconstitute(
		shared.NewID(),
		tenantID,
		nil,
		exposure.EventTypeCredentialLeaked,
		exposure.SeverityLow,
		exposure.StateFalsePositive,
		identifier,
		"",
		map[string]any{
			"credential_type": "password",
			"email":           identifier,
			"is_verified":     false,
			"is_revoked":      false,
		},
		"test-fingerprint-fp-"+identifier,
		source,
		now.Add(-24*time.Hour), now.Add(-2*time.Hour),
		&fpAt, &fpBy, "false positive",
		now.Add(-24*time.Hour), fpAt,
	)
}

// =============================================================================
// Import Tests - New Credentials
// =============================================================================

func TestCredentialImportService_Import_NewCredential_Success(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	req := validImportRequest()
	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}
	if result.Updated != 0 {
		t.Errorf("expected 0 updated, got %d", result.Updated)
	}
	if result.Skipped != 0 {
		t.Errorf("expected 0 skipped, got %d", result.Skipped)
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected 0 errors, got %d", len(result.Errors))
	}
	if len(result.Details) != 1 {
		t.Fatalf("expected 1 detail, got %d", len(result.Details))
	}
	if result.Details[0].Action != "imported" {
		t.Errorf("expected action 'imported', got %s", result.Details[0].Action)
	}
	if result.Details[0].ID == "" {
		t.Error("expected non-empty ID in result detail")
	}
	if repo.createCalls != 1 {
		t.Errorf("expected 1 Create call, got %d", repo.createCalls)
	}
}

func TestCredentialImportService_Import_MultipleCredentials(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred1 := validCredentialImport()
	cred1.Identifier = "user1@example.com"
	cred1.DedupKey.BreachName = "breach_a"

	cred2 := validCredentialImport()
	cred2.Identifier = "user2@example.com"
	cred2.DedupKey.BreachName = "breach_b"

	cred3 := validCredentialImport()
	cred3.Identifier = "user3@example.com"
	cred3.CredentialType = credential.CredentialTypeAWSKey
	cred3.Source.Type = credential.SourceTypeCodeRepository
	cred3.DedupKey = credential.DedupKey{Repository: "github.com/test/repo", FilePath: "config.yml"}

	req := validImportRequest(cred1, cred2, cred3)
	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Imported != 3 {
		t.Errorf("expected 3 imported, got %d", result.Imported)
	}
	if result.Summary.TotalProcessed != 3 {
		t.Errorf("expected 3 total processed, got %d", result.Summary.TotalProcessed)
	}
	if result.Summary.SuccessCount != 3 {
		t.Errorf("expected 3 success count, got %d", result.Summary.SuccessCount)
	}
	if repo.createCalls != 3 {
		t.Errorf("expected 3 Create calls, got %d", repo.createCalls)
	}
}

func TestCredentialImportService_Import_InvalidTenantID(t *testing.T) {
	svc, _, _ := newCredImportTestService()

	req := validImportRequest()
	_, err := svc.Import(context.Background(), "not-a-valid-uuid", req)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCredentialImportService_Import_InvalidCredentialType(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred := validCredentialImport()
	cred.CredentialType = credential.CredentialType("invalid_type")

	req := validImportRequest(cred)
	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no top-level error, got %v", err)
	}

	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.Errors))
	}
	if result.Imported != 0 {
		t.Errorf("expected 0 imported, got %d", result.Imported)
	}
	if result.Summary.ErrorCount != 1 {
		t.Errorf("expected 1 error count in summary, got %d", result.Summary.ErrorCount)
	}
}

func TestCredentialImportService_Import_InvalidSourceType(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred := validCredentialImport()
	cred.Source.Type = credential.SourceType("invalid_source")

	req := validImportRequest(cred)
	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no top-level error, got %v", err)
	}

	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.Errors))
	}
	if result.Errors[0].Index != 0 {
		t.Errorf("expected error index 0, got %d", result.Errors[0].Index)
	}
}

func TestCredentialImportService_Import_CreateError(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	repo.createErr = fmt.Errorf("database connection lost")

	req := validImportRequest()
	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no top-level error, got %v", err)
	}

	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.Errors))
	}
	if result.Imported != 0 {
		t.Errorf("expected 0 imported, got %d", result.Imported)
	}
}

func TestCredentialImportService_Import_WithNotes(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred := validCredentialImport()
	cred.Notes = "Found in public paste site on 2024-01-15"

	req := validImportRequest(cred)
	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}

	// Verify the event was stored with a description
	if repo.createCalls != 1 {
		t.Errorf("expected 1 Create call, got %d", repo.createCalls)
	}
}

func TestCredentialImportService_Import_CriticalSeverity(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred := validCredentialImport()
	cred.CredentialType = credential.CredentialTypeAWSKey
	cred.Source.Type = credential.SourceTypeCodeRepository
	cred.DedupKey = credential.DedupKey{Repository: "repo", FilePath: "creds.env"}
	cred.Severity = "critical"

	req := validImportRequest(cred)
	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Summary.CriticalCount != 1 {
		t.Errorf("expected 1 critical count, got %d", result.Summary.CriticalCount)
	}
}

func TestCredentialImportService_Import_AutoClassifySeverity(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	// AWS key should auto-classify as critical
	cred := validCredentialImport()
	cred.CredentialType = credential.CredentialTypeAWSKey
	cred.Source.Type = credential.SourceTypeCodeRepository
	cred.DedupKey = credential.DedupKey{Repository: "repo", FilePath: "config.env"}
	cred.Severity = "" // Let auto-classify determine it

	req := validImportRequest(cred)
	req.Options.AutoClassifySeverity = true

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}
	if result.Summary.CriticalCount != 1 {
		t.Errorf("expected 1 critical (auto-classified AWS key), got %d", result.Summary.CriticalCount)
	}
}

func TestCredentialImportService_Import_DefaultDedupStrategy(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	req := validImportRequest()
	req.Options.DedupStrategy = "" // Empty should default to update_last_seen

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}
}

// =============================================================================
// Import Tests - Deduplication Strategies
// =============================================================================

func TestCredentialImportService_Import_DedupSkip(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	// Create an existing active event
	existing := createCredImportTestEvent(tenantID, "user@example.com", "data_breach - TestBreach")

	// Pre-compute the fingerprint that Import will generate
	cred := validCredentialImport()
	fingerprint := cred.CalculateFingerprint(tenantID.String())
	// We need to set the fingerprint in our mock to match
	existingWithFP := exposure.Reconstitute(
		existing.ID(), existing.TenantID(), nil,
		existing.EventType(), existing.Severity(), existing.State(),
		existing.Title(), existing.Description(), existing.Details(),
		fingerprint, existing.Source(),
		existing.FirstSeenAt(), existing.LastSeenAt(),
		nil, nil, "",
		existing.CreatedAt(), existing.UpdatedAt(),
	)
	repo.addExistingEvent(existingWithFP)

	req := validImportRequest(cred)
	req.Options.DedupStrategy = credential.DedupStrategySkip

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", result.Skipped)
	}
	if result.Imported != 0 {
		t.Errorf("expected 0 imported, got %d", result.Imported)
	}
	if len(result.Details) != 1 {
		t.Fatalf("expected 1 detail, got %d", len(result.Details))
	}
	if result.Details[0].Action != "skipped" {
		t.Errorf("expected action 'skipped', got %s", result.Details[0].Action)
	}
	if result.Details[0].Reason != "duplicate" {
		t.Errorf("expected reason 'duplicate', got %s", result.Details[0].Reason)
	}
}

func TestCredentialImportService_Import_DedupUpdateLastSeen(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred := validCredentialImport()
	fingerprint := cred.CalculateFingerprint(tenantID.String())

	existing := exposure.Reconstitute(
		shared.NewID(), tenantID, nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityHigh, exposure.StateActive,
		"user@example.com", "", map[string]any{"credential_type": "password"},
		fingerprint, "data_breach - TestBreach",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
		nil, nil, "",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
	)
	repo.addExistingEvent(existing)

	req := validImportRequest(cred)
	req.Options.DedupStrategy = credential.DedupStrategyUpdateLastSeen

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Updated != 1 {
		t.Errorf("expected 1 updated, got %d", result.Updated)
	}
	if len(result.Details) != 1 {
		t.Fatalf("expected 1 detail, got %d", len(result.Details))
	}
	if result.Details[0].Action != "updated" {
		t.Errorf("expected action 'updated', got %s", result.Details[0].Action)
	}
	if result.Details[0].Reason != "last_seen_updated" {
		t.Errorf("expected reason 'last_seen_updated', got %s", result.Details[0].Reason)
	}
	if repo.updateCalls != 1 {
		t.Errorf("expected 1 Update call, got %d", repo.updateCalls)
	}
}

func TestCredentialImportService_Import_DedupUpdateAll(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred := validCredentialImport()
	cred.Notes = "Updated notes"
	fingerprint := cred.CalculateFingerprint(tenantID.String())

	existing := exposure.Reconstitute(
		shared.NewID(), tenantID, nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityHigh, exposure.StateActive,
		"user@example.com", "old notes",
		map[string]any{"credential_type": "password", "is_verified": false, "is_revoked": false},
		fingerprint, "data_breach - TestBreach",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
		nil, nil, "",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
	)
	repo.addExistingEvent(existing)

	req := validImportRequest(cred)
	req.Options.DedupStrategy = credential.DedupStrategyUpdateAll

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Updated != 1 {
		t.Errorf("expected 1 updated, got %d", result.Updated)
	}
	if len(result.Details) != 1 {
		t.Fatalf("expected 1 detail, got %d", len(result.Details))
	}
	if result.Details[0].Reason != "all_fields_updated" {
		t.Errorf("expected reason 'all_fields_updated', got %s", result.Details[0].Reason)
	}
	if repo.updateCalls != 1 {
		t.Errorf("expected 1 Update call, got %d", repo.updateCalls)
	}
}

func TestCredentialImportService_Import_DedupCreateNew_FingerprintExists(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred := validCredentialImport()
	fingerprint := cred.CalculateFingerprint(tenantID.String())

	existing := exposure.Reconstitute(
		shared.NewID(), tenantID, nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityHigh, exposure.StateActive,
		"user@example.com", "", map[string]any{"credential_type": "password"},
		fingerprint, "data_breach - TestBreach",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
		nil, nil, "",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
	)
	repo.addExistingEvent(existing)

	req := validImportRequest(cred)
	req.Options.DedupStrategy = credential.DedupStrategyCreateNew

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// When fingerprint already exists, create_new falls back to update
	if result.Updated != 1 {
		t.Errorf("expected 1 updated, got %d", result.Updated)
	}
	if result.Details[0].Reason != "fingerprint_exists" {
		t.Errorf("expected reason 'fingerprint_exists', got %s", result.Details[0].Reason)
	}
}

func TestCredentialImportService_Import_DedupUpdateError(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred := validCredentialImport()
	fingerprint := cred.CalculateFingerprint(tenantID.String())

	existing := exposure.Reconstitute(
		shared.NewID(), tenantID, nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityHigh, exposure.StateActive,
		"user@example.com", "", map[string]any{"credential_type": "password"},
		fingerprint, "data_breach - TestBreach",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
		nil, nil, "",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
	)
	repo.addExistingEvent(existing)
	repo.updateErr = fmt.Errorf("update failed")

	req := validImportRequest(cred)
	req.Options.DedupStrategy = credential.DedupStrategyUpdateLastSeen

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no top-level error, got %v", err)
	}

	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.Errors))
	}
	if result.Updated != 0 {
		t.Errorf("expected 0 updated, got %d", result.Updated)
	}
}

// =============================================================================
// Import Tests - Existing Credential State Handling
// =============================================================================

func TestCredentialImportService_Import_ExistingFalsePositive_Skipped(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred := validCredentialImport()
	fingerprint := cred.CalculateFingerprint(tenantID.String())

	existing := exposure.Reconstitute(
		shared.NewID(), tenantID, nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityLow, exposure.StateFalsePositive,
		"user@example.com", "", map[string]any{"credential_type": "password"},
		fingerprint, "data_breach - TestBreach",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
		nil, nil, "false positive",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
	)
	repo.addExistingEvent(existing)

	req := validImportRequest(cred)
	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", result.Skipped)
	}
	if result.Details[0].Reason != "marked_as_false_positive" {
		t.Errorf("expected reason 'marked_as_false_positive', got %s", result.Details[0].Reason)
	}
}

func TestCredentialImportService_Import_ExistingResolved_SkippedWhenNoReactivate(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred := validCredentialImport()
	fingerprint := cred.CalculateFingerprint(tenantID.String())

	existing := exposure.Reconstitute(
		shared.NewID(), tenantID, nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityHigh, exposure.StateResolved,
		"user@example.com", "", map[string]any{"credential_type": "password"},
		fingerprint, "data_breach - TestBreach",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
		nil, nil, "resolved",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
	)
	repo.addExistingEvent(existing)

	req := validImportRequest(cred)
	req.Options.ReactivateResolved = false

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", result.Skipped)
	}
	if result.Details[0].Reason != "already_resolved" {
		t.Errorf("expected reason 'already_resolved', got %s", result.Details[0].Reason)
	}
}

func TestCredentialImportService_Import_ExistingResolved_Reactivated(t *testing.T) {
	svc, repo, historyRepo := newCredImportTestService()
	tenantID := shared.NewID()

	cred := validCredentialImport()
	fingerprint := cred.CalculateFingerprint(tenantID.String())

	existing := exposure.Reconstitute(
		shared.NewID(), tenantID, nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityHigh, exposure.StateResolved,
		"user@example.com", "", map[string]any{"credential_type": "password"},
		fingerprint, "data_breach - TestBreach",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
		nil, nil, "was resolved",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
	)
	repo.addExistingEvent(existing)

	req := validImportRequest(cred)
	req.Options.ReactivateResolved = true

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Reactivated != 1 {
		t.Errorf("expected 1 reactivated, got %d", result.Reactivated)
	}
	if result.Details[0].Action != "reactivated" {
		t.Errorf("expected action 'reactivated', got %s", result.Details[0].Action)
	}
	if result.Details[0].Reason != "found_after_resolution" {
		t.Errorf("expected reason 'found_after_resolution', got %s", result.Details[0].Reason)
	}
	if repo.updateCalls != 1 {
		t.Errorf("expected 1 Update call, got %d", repo.updateCalls)
	}
	// State history should be recorded
	if historyRepo.createCalls != 1 {
		t.Errorf("expected 1 history Create call, got %d", historyRepo.createCalls)
	}
}

func TestCredentialImportService_Import_Reactivated_NotifyFlag(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred := validCredentialImport()
	fingerprint := cred.CalculateFingerprint(tenantID.String())

	existing := exposure.Reconstitute(
		shared.NewID(), tenantID, nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityHigh, exposure.StateResolved,
		"user@example.com", "", map[string]any{"credential_type": "password"},
		fingerprint, "data_breach - TestBreach",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
		nil, nil, "",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
	)
	repo.addExistingEvent(existing)

	req := validImportRequest(cred)
	req.Options.ReactivateResolved = true
	req.Options.NotifyReactivated = true

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !result.Summary.ReactivatedAlertSent {
		t.Error("expected ReactivatedAlertSent to be true")
	}
}

func TestCredentialImportService_Import_ExistingAccepted_Updated(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred := validCredentialImport()
	fingerprint := cred.CalculateFingerprint(tenantID.String())

	existing := exposure.Reconstitute(
		shared.NewID(), tenantID, nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityHigh, exposure.StateAccepted,
		"user@example.com", "", map[string]any{"credential_type": "password"},
		fingerprint, "data_breach - TestBreach",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
		nil, nil, "accepted risk",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
	)
	repo.addExistingEvent(existing)

	req := validImportRequest(cred)
	req.Options.DedupStrategy = credential.DedupStrategyUpdateLastSeen

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Updated != 1 {
		t.Errorf("expected 1 updated, got %d", result.Updated)
	}
}

func TestCredentialImportService_Import_GetByFingerprintError(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	repo.getFPErr = fmt.Errorf("database error")

	req := validImportRequest()
	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no top-level error, got %v", err)
	}

	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.Errors))
	}
}

// =============================================================================
// Import Tests - Summary
// =============================================================================

func TestCredentialImportService_Import_SummaryFields(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred1 := validCredentialImport()
	cred1.Identifier = "a@example.com"
	cred1.DedupKey.BreachName = "breach_1"
	cred1.Context.Email = "a@example.com"

	cred2 := validCredentialImport()
	cred2.Identifier = "b@example.com"
	cred2.DedupKey.BreachName = "breach_2"
	cred2.Context.Email = "b@example.com"

	// Third credential with invalid type to produce an error
	cred3 := validCredentialImport()
	cred3.Identifier = "c@example.com"
	cred3.CredentialType = credential.CredentialType("bogus")

	req := validImportRequest(cred1, cred2, cred3)

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Summary.TotalProcessed != 3 {
		t.Errorf("expected total_processed=3, got %d", result.Summary.TotalProcessed)
	}
	if result.Summary.SuccessCount != 2 {
		t.Errorf("expected success_count=2, got %d", result.Summary.SuccessCount)
	}
	if result.Summary.ErrorCount != 1 {
		t.Errorf("expected error_count=1, got %d", result.Summary.ErrorCount)
	}
}

// =============================================================================
// ImportCSV Tests
// =============================================================================

func TestCredentialImportService_ImportCSV_Success(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	records := [][]string{
		{"identifier", "credential_type", "source_type", "source_name", "severity", "notes"},
		{"admin@corp.com", "password", "data_breach", "MegaBreach", "high", "found in dump"},
		{"dev@corp.com", "api_key", "code_repository", "GitGuardian", "critical", "exposed in repo"},
	}

	options := credential.DefaultImportOptions()
	result, err := svc.ImportCSV(context.Background(), tenantID.String(), records, options)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Imported != 2 {
		t.Errorf("expected 2 imported, got %d", result.Imported)
	}
	if repo.createCalls != 2 {
		t.Errorf("expected 2 Create calls, got %d", repo.createCalls)
	}
}

func TestCredentialImportService_ImportCSV_MissingHeader(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	// Only header, no data
	records := [][]string{
		{"identifier", "credential_type", "source_type"},
	}

	_, err := svc.ImportCSV(context.Background(), tenantID.String(), records, credential.DefaultImportOptions())
	if err == nil {
		t.Fatal("expected error for CSV with only header, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCredentialImportService_ImportCSV_EmptyRecords(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	records := [][]string{}

	_, err := svc.ImportCSV(context.Background(), tenantID.String(), records, credential.DefaultImportOptions())
	if err == nil {
		t.Fatal("expected error for empty CSV, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCredentialImportService_ImportCSV_MissingRequiredColumn(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	// Missing "credential_type" column
	records := [][]string{
		{"identifier", "source_type"},
		{"admin@corp.com", "data_breach"},
	}

	_, err := svc.ImportCSV(context.Background(), tenantID.String(), records, credential.DefaultImportOptions())
	if err == nil {
		t.Fatal("expected error for missing required column, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCredentialImportService_ImportCSV_InvalidCredentialTypeInRow(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	records := [][]string{
		{"identifier", "credential_type", "source_type"},
		{"admin@corp.com", "invalid_cred_type", "data_breach"},
	}

	// The invalid row should be skipped during parsing; if all rows are invalid
	// we get a "no valid credentials" error
	_, err := svc.ImportCSV(context.Background(), tenantID.String(), records, credential.DefaultImportOptions())
	if err == nil {
		t.Fatal("expected error when all rows are invalid, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCredentialImportService_ImportCSV_WithOptionalFields(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	records := [][]string{
		{"identifier", "credential_type", "source_type", "username", "email", "domain", "is_verified", "is_revoked", "tags", "notes", "breach_name", "severity"},
		{"admin@corp.com", "password", "data_breach", "admin", "admin@corp.com", "corp.com", "true", "false", "critical,breach", "found in breach DB", "MegaBreach2024", "high"},
	}

	result, err := svc.ImportCSV(context.Background(), tenantID.String(), records, credential.DefaultImportOptions())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}
}

func TestCredentialImportService_ImportCSV_DiscoveredAtParsing(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	records := [][]string{
		{"identifier", "credential_type", "source_type", "discovered_at"},
		{"user1@test.com", "password", "data_breach", "2024-01-15"},
		{"user2@test.com", "api_key", "code_repository", "2024-06-01T10:30:00Z"},
	}

	result, err := svc.ImportCSV(context.Background(), tenantID.String(), records, credential.DefaultImportOptions())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Imported != 2 {
		t.Errorf("expected 2 imported, got %d", result.Imported)
	}
}

func TestCredentialImportService_ImportCSV_BooleanParsing(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	records := [][]string{
		{"identifier", "credential_type", "source_type", "is_verified", "is_revoked"},
		{"user1@test.com", "password", "data_breach", "true", "false"},
		{"user2@test.com", "password", "data_breach", "1", "0"},
		{"user3@test.com", "password", "data_breach", "false", "true"},
	}

	result, err := svc.ImportCSV(context.Background(), tenantID.String(), records, credential.DefaultImportOptions())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Imported != 3 {
		t.Errorf("expected 3 imported, got %d", result.Imported)
	}
}

func TestCredentialImportService_ImportCSV_MixedValidAndInvalidRows(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	records := [][]string{
		{"identifier", "credential_type", "source_type"},
		{"valid@test.com", "password", "data_breach"},       // valid
		{"invalid@test.com", "bogus_type", "data_breach"},   // invalid cred type
		{"valid2@test.com", "api_key", "code_repository"},   // valid
	}

	result, err := svc.ImportCSV(context.Background(), tenantID.String(), records, credential.DefaultImportOptions())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// One row was skipped during parsing, two valid rows imported
	if result.Imported != 2 {
		t.Errorf("expected 2 imported, got %d", result.Imported)
	}
}

// =============================================================================
// List Tests
// =============================================================================

func TestCredentialImportService_List_Success(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	event1 := createCredImportTestEvent(tenantID, "user1@test.com", "data_breach")
	event2 := createCredImportTestEvent(tenantID, "user2@test.com", "code_repository")
	repo.addExistingEvent(event1)
	repo.addExistingEvent(event2)

	result, err := svc.List(context.Background(), tenantID.String(), app.CredentialListOptions{}, 1, 20)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Total != 2 {
		t.Errorf("expected total 2, got %d", result.Total)
	}
	if len(result.Items) != 2 {
		t.Errorf("expected 2 items, got %d", len(result.Items))
	}
	if result.Page != 1 {
		t.Errorf("expected page 1, got %d", result.Page)
	}
	if result.PageSize != 20 {
		t.Errorf("expected page size 20, got %d", result.PageSize)
	}
}

func TestCredentialImportService_List_WithFilters(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	event := createCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)

	opts := app.CredentialListOptions{
		Severities: []string{"high"},
		States:     []string{"active"},
		Search:     "user",
	}

	result, err := svc.List(context.Background(), tenantID.String(), opts, 1, 10)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Total < 0 {
		t.Errorf("expected non-negative total, got %d", result.Total)
	}
}

func TestCredentialImportService_List_RepoError(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	repo.listErr = fmt.Errorf("database unavailable")

	_, err := svc.List(context.Background(), tenantID.String(), app.CredentialListOptions{}, 1, 20)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestCredentialImportService_List_TotalPages(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	// Add 5 events
	for i := 0; i < 5; i++ {
		event := createCredImportTestEvent(tenantID, fmt.Sprintf("user%d@test.com", i), "data_breach")
		repo.addExistingEvent(event)
	}

	result, err := svc.List(context.Background(), tenantID.String(), app.CredentialListOptions{}, 1, 2)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.TotalPages != 3 {
		t.Errorf("expected 3 total pages (5 items, page size 2), got %d", result.TotalPages)
	}
}

// =============================================================================
// GetByID Tests
// =============================================================================

func TestCredentialImportService_GetByID_Success(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	event := createCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)

	item, err := svc.GetByID(context.Background(), tenantID.String(), event.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if item.ID != event.ID().String() {
		t.Errorf("expected ID %s, got %s", event.ID().String(), item.ID)
	}
	if item.Identifier != "user@test.com" {
		t.Errorf("expected identifier user@test.com, got %s", item.Identifier)
	}
	if item.State != "active" {
		t.Errorf("expected state active, got %s", item.State)
	}
}

func TestCredentialImportService_GetByID_InvalidID(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	_, err := svc.GetByID(context.Background(), tenantID.String(), "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCredentialImportService_GetByID_NotFound(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()
	nonExistentID := shared.NewID()

	_, err := svc.GetByID(context.Background(), tenantID.String(), nonExistentID.String())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestCredentialImportService_GetByID_WrongTenant(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	event := createCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)

	_, err := svc.GetByID(context.Background(), otherTenantID.String(), event.ID().String())
	if err == nil {
		t.Fatal("expected error for wrong tenant, got nil")
	}
}

func TestCredentialImportService_GetByID_WrongEventType(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	// Create a non-credential event
	now := time.Now().UTC()
	portEvent := exposure.Reconstitute(
		shared.NewID(), tenantID, nil,
		exposure.EventTypePortOpen, exposure.SeverityHigh, exposure.StateActive,
		"Port 22 Open", "", map[string]any{"port": 22},
		"fp-port-22", "nmap",
		now, now, nil, nil, "", now, now,
	)
	repo.addExistingEvent(portEvent)

	_, err := svc.GetByID(context.Background(), tenantID.String(), portEvent.ID().String())
	if err == nil {
		t.Fatal("expected error for non-credential event type, got nil")
	}
}

// =============================================================================
// GetCredentialStats Tests
// =============================================================================

func TestCredentialImportService_GetCredentialStats_Success(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	repo.countByStateResult = map[exposure.State]int64{
		exposure.StateActive:   10,
		exposure.StateResolved: 5,
	}
	repo.countBySeverityResult = map[exposure.Severity]int64{
		exposure.SeverityCritical: 3,
		exposure.SeverityHigh:     7,
		exposure.SeverityMedium:   5,
	}

	stats, err := svc.GetCredentialStats(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if stats["total"] == nil {
		t.Error("expected 'total' key in stats")
	}

	byState, ok := stats["by_state"].(map[string]int64)
	if !ok {
		t.Fatal("expected 'by_state' to be map[string]int64")
	}
	if byState["active"] != 10 {
		t.Errorf("expected active=10, got %d", byState["active"])
	}
	if byState["resolved"] != 5 {
		t.Errorf("expected resolved=5, got %d", byState["resolved"])
	}

	bySeverity, ok := stats["by_severity"].(map[string]int64)
	if !ok {
		t.Fatal("expected 'by_severity' to be map[string]int64")
	}
	if bySeverity["critical"] != 3 {
		t.Errorf("expected critical=3, got %d", bySeverity["critical"])
	}
}

func TestCredentialImportService_GetCredentialStats_InvalidTenantID(t *testing.T) {
	svc, _, _ := newCredImportTestService()

	_, err := svc.GetCredentialStats(context.Background(), "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCredentialImportService_GetCredentialStats_CountError(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	repo.countErr = fmt.Errorf("count failed")

	_, err := svc.GetCredentialStats(context.Background(), tenantID.String())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestCredentialImportService_GetCredentialStats_CountByStateError(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	repo.countStateErr = fmt.Errorf("count by state failed")

	_, err := svc.GetCredentialStats(context.Background(), tenantID.String())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestCredentialImportService_GetCredentialStats_CountBySeverityError(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	repo.countSevErr = fmt.Errorf("count by severity failed")

	_, err := svc.GetCredentialStats(context.Background(), tenantID.String())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// =============================================================================
// State Transition Tests
// =============================================================================

func TestCredentialImportService_ResolveCredential_Success(t *testing.T) {
	svc, repo, historyRepo := newCredImportTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)

	item, err := svc.ResolveCredential(context.Background(), tenantID.String(), event.ID().String(), userID.String(), "credential rotated")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if item.State != "resolved" {
		t.Errorf("expected state resolved, got %s", item.State)
	}
	if repo.updateCalls != 1 {
		t.Errorf("expected 1 Update call, got %d", repo.updateCalls)
	}
	if historyRepo.createCalls != 1 {
		t.Errorf("expected 1 history Create call, got %d", historyRepo.createCalls)
	}
}

func TestCredentialImportService_AcceptCredential_Success(t *testing.T) {
	svc, repo, historyRepo := newCredImportTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)

	item, err := svc.AcceptCredential(context.Background(), tenantID.String(), event.ID().String(), userID.String(), "accepted risk")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if item.State != "accepted" {
		t.Errorf("expected state accepted, got %s", item.State)
	}
	if repo.updateCalls != 1 {
		t.Errorf("expected 1 Update call, got %d", repo.updateCalls)
	}
	if historyRepo.createCalls != 1 {
		t.Errorf("expected 1 history Create call, got %d", historyRepo.createCalls)
	}
}

func TestCredentialImportService_MarkFalsePositive_Success(t *testing.T) {
	svc, repo, historyRepo := newCredImportTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)

	item, err := svc.MarkCredentialFalsePositive(context.Background(), tenantID.String(), event.ID().String(), userID.String(), "test data, not real")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if item.State != "false_positive" {
		t.Errorf("expected state false_positive, got %s", item.State)
	}
	if repo.updateCalls != 1 {
		t.Errorf("expected 1 Update call, got %d", repo.updateCalls)
	}
	if historyRepo.createCalls != 1 {
		t.Errorf("expected 1 history Create call, got %d", historyRepo.createCalls)
	}
}

func TestCredentialImportService_ReactivateCredential_Success(t *testing.T) {
	svc, repo, historyRepo := newCredImportTestService()
	tenantID := shared.NewID()

	event := createResolvedCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)

	item, err := svc.ReactivateCredential(context.Background(), tenantID.String(), event.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if item.State != "active" {
		t.Errorf("expected state active, got %s", item.State)
	}
	if repo.updateCalls != 1 {
		t.Errorf("expected 1 Update call, got %d", repo.updateCalls)
	}
	if historyRepo.createCalls != 1 {
		t.Errorf("expected 1 history Create call, got %d", historyRepo.createCalls)
	}
}

func TestCredentialImportService_ReactivateCredential_InvalidID(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	_, err := svc.ReactivateCredential(context.Background(), tenantID.String(), "not-valid")
	if err == nil {
		t.Fatal("expected error for invalid ID, got nil")
	}
}

func TestCredentialImportService_ReactivateCredential_WrongTenant(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	event := createResolvedCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)

	_, err := svc.ReactivateCredential(context.Background(), otherTenantID.String(), event.ID().String())
	if err == nil {
		t.Fatal("expected error for wrong tenant, got nil")
	}
}

func TestCredentialImportService_ReactivateCredential_AlreadyActive(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	event := createCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)

	_, err := svc.ReactivateCredential(context.Background(), tenantID.String(), event.ID().String())
	if err == nil {
		t.Fatal("expected error when reactivating already active credential, got nil")
	}
}

func TestCredentialImportService_ResolveCredential_WrongTenant(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()
	userID := shared.NewID()

	event := createCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)

	_, err := svc.ResolveCredential(context.Background(), otherTenantID.String(), event.ID().String(), userID.String(), "notes")
	if err == nil {
		t.Fatal("expected error for wrong tenant, got nil")
	}
}

func TestCredentialImportService_ResolveCredential_InvalidID(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	_, err := svc.ResolveCredential(context.Background(), tenantID.String(), "bad-id", userID.String(), "notes")
	if err == nil {
		t.Fatal("expected error for invalid ID, got nil")
	}
}

func TestCredentialImportService_ResolveCredential_UpdateError(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)
	repo.updateErr = fmt.Errorf("update failed")

	_, err := svc.ResolveCredential(context.Background(), tenantID.String(), event.ID().String(), userID.String(), "notes")
	if err == nil {
		t.Fatal("expected error when update fails, got nil")
	}
}

func TestCredentialImportService_ResolveCredential_AlreadyResolved(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createResolvedCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)

	_, err := svc.ResolveCredential(context.Background(), tenantID.String(), event.ID().String(), userID.String(), "notes")
	if err == nil {
		t.Fatal("expected error when resolving already resolved credential, got nil")
	}
}

// =============================================================================
// State Transition Chain Tests
// =============================================================================

func TestCredentialImportService_StateTransitionChain_ActiveToResolvedToActive(t *testing.T) {
	svc, repo, historyRepo := newCredImportTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)

	// Active -> Resolved
	item, err := svc.ResolveCredential(context.Background(), tenantID.String(), event.ID().String(), userID.String(), "rotated password")
	if err != nil {
		t.Fatalf("resolve: expected no error, got %v", err)
	}
	if item.State != "resolved" {
		t.Errorf("expected resolved, got %s", item.State)
	}

	// Resolved -> Active (reactivate)
	item, err = svc.ReactivateCredential(context.Background(), tenantID.String(), event.ID().String())
	if err != nil {
		t.Fatalf("reactivate: expected no error, got %v", err)
	}
	if item.State != "active" {
		t.Errorf("expected active, got %s", item.State)
	}

	if historyRepo.createCalls != 2 {
		t.Errorf("expected 2 history entries, got %d", historyRepo.createCalls)
	}
}

func TestCredentialImportService_StateTransitionChain_ActiveToAcceptedToActive(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)

	// Active -> Accepted
	item, err := svc.AcceptCredential(context.Background(), tenantID.String(), event.ID().String(), userID.String(), "accepted risk")
	if err != nil {
		t.Fatalf("accept: expected no error, got %v", err)
	}
	if item.State != "accepted" {
		t.Errorf("expected accepted, got %s", item.State)
	}

	// Accepted -> Active (reactivate)
	item, err = svc.ReactivateCredential(context.Background(), tenantID.String(), event.ID().String())
	if err != nil {
		t.Fatalf("reactivate: expected no error, got %v", err)
	}
	if item.State != "active" {
		t.Errorf("expected active, got %s", item.State)
	}
}

func TestCredentialImportService_StateTransitionChain_FalsePositiveToActive(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	event := createFalsePositiveCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)

	item, err := svc.ReactivateCredential(context.Background(), tenantID.String(), event.ID().String())
	if err != nil {
		t.Fatalf("reactivate from false_positive: expected no error, got %v", err)
	}
	if item.State != "active" {
		t.Errorf("expected active, got %s", item.State)
	}
}

// =============================================================================
// ListByIdentity Tests
// =============================================================================

func TestCredentialImportService_ListByIdentity_Success(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	// Two events for same identity (email)
	event1 := createCredImportTestEvent(tenantID, "user@test.com", "data_breach - BreachA")
	event2 := createCredImportTestEvent(tenantID, "user@test.com", "data_breach - BreachB")
	// One event for different identity
	now := time.Now().UTC()
	event3 := exposure.Reconstitute(
		shared.NewID(), tenantID, nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityCritical, exposure.StateActive,
		"admin@test.com", "", map[string]any{
			"credential_type": "aws_key",
			"email":           "admin@test.com",
			"is_verified":     false,
			"is_revoked":      false,
		},
		"fp-admin", "code_repository",
		now, now, nil, nil, "", now, now,
	)

	repo.addExistingEvent(event1)
	repo.addExistingEvent(event2)
	repo.addExistingEvent(event3)

	result, err := svc.ListByIdentity(context.Background(), tenantID.String(), app.CredentialListOptions{}, 1, 20)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Total != 2 {
		t.Errorf("expected 2 identities, got %d", result.Total)
	}
}

func TestCredentialImportService_ListByIdentity_SortsBySeverity(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()
	now := time.Now().UTC()

	// Low severity identity
	lowEvent := exposure.Reconstitute(
		shared.NewID(), tenantID, nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityLow, exposure.StateActive,
		"lowrisk@test.com", "", map[string]any{
			"credential_type": "password",
			"email":           "lowrisk@test.com",
			"is_verified":     false,
			"is_revoked":      false,
		},
		"fp-low", "data_breach",
		now, now, nil, nil, "", now, now,
	)

	// Critical severity identity
	critEvent := exposure.Reconstitute(
		shared.NewID(), tenantID, nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityCritical, exposure.StateActive,
		"highrisk@test.com", "", map[string]any{
			"credential_type": "aws_key",
			"email":           "highrisk@test.com",
			"is_verified":     false,
			"is_revoked":      false,
		},
		"fp-crit", "code_repository",
		now, now, nil, nil, "", now, now,
	)

	repo.addExistingEvent(lowEvent)
	repo.addExistingEvent(critEvent)

	result, err := svc.ListByIdentity(context.Background(), tenantID.String(), app.CredentialListOptions{}, 1, 20)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(result.Items) < 2 {
		t.Fatalf("expected at least 2 items, got %d", len(result.Items))
	}

	// Critical should come first
	if result.Items[0].HighestSeverity != "critical" {
		t.Errorf("expected first item to have critical severity, got %s", result.Items[0].HighestSeverity)
	}
}

func TestCredentialImportService_ListByIdentity_Pagination(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()
	now := time.Now().UTC()

	// Create 3 different identities
	for i := 0; i < 3; i++ {
		email := fmt.Sprintf("user%d@test.com", i)
		event := exposure.Reconstitute(
			shared.NewID(), tenantID, nil,
			exposure.EventTypeCredentialLeaked, exposure.SeverityMedium, exposure.StateActive,
			email, "", map[string]any{
				"credential_type": "password",
				"email":           email,
				"is_verified":     false,
				"is_revoked":      false,
			},
			fmt.Sprintf("fp-%d", i), "data_breach",
			now, now, nil, nil, "", now, now,
		)
		repo.addExistingEvent(event)
	}

	// Page 1 with page size 2
	result, err := svc.ListByIdentity(context.Background(), tenantID.String(), app.CredentialListOptions{}, 1, 2)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Total != 3 {
		t.Errorf("expected total 3, got %d", result.Total)
	}
	if len(result.Items) != 2 {
		t.Errorf("expected 2 items on page 1, got %d", len(result.Items))
	}
	if result.TotalPages != 2 {
		t.Errorf("expected 2 total pages, got %d", result.TotalPages)
	}

	// Page 2
	result2, err := svc.ListByIdentity(context.Background(), tenantID.String(), app.CredentialListOptions{}, 2, 2)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result2.Items) != 1 {
		t.Errorf("expected 1 item on page 2, got %d", len(result2.Items))
	}
}

func TestCredentialImportService_ListByIdentity_RepoError(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	repo.listErr = fmt.Errorf("database error")

	_, err := svc.ListByIdentity(context.Background(), tenantID.String(), app.CredentialListOptions{}, 1, 20)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// =============================================================================
// GetExposuresForIdentity Tests
// =============================================================================

func TestCredentialImportService_GetExposuresForIdentity_Success(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	// Two events with same email identity
	event1 := createCredImportTestEvent(tenantID, "user@test.com", "data_breach - BreachA")
	event2 := createCredImportTestEvent(tenantID, "user@test.com", "data_breach - BreachB")
	// One with different identity
	now := time.Now().UTC()
	event3 := exposure.Reconstitute(
		shared.NewID(), tenantID, nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityMedium, exposure.StateActive,
		"other@test.com", "", map[string]any{
			"credential_type": "password",
			"email":           "other@test.com",
			"is_verified":     false,
			"is_revoked":      false,
		},
		"fp-other", "data_breach",
		now, now, nil, nil, "", now, now,
	)

	repo.addExistingEvent(event1)
	repo.addExistingEvent(event2)
	repo.addExistingEvent(event3)

	result, err := svc.GetExposuresForIdentity(context.Background(), tenantID.String(), "user@test.com", 1, 20)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should only get the 2 events matching "user@test.com" identity
	if result.Total != 2 {
		t.Errorf("expected total 2, got %d", result.Total)
	}
}

func TestCredentialImportService_GetExposuresForIdentity_RepoError(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	repo.listErr = fmt.Errorf("database error")

	_, err := svc.GetExposuresForIdentity(context.Background(), tenantID.String(), "user@test.com", 1, 20)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestCredentialImportService_GetExposuresForIdentity_NoMatch(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	event := createCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)

	result, err := svc.GetExposuresForIdentity(context.Background(), tenantID.String(), "nonexistent@test.com", 1, 20)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Total != 0 {
		t.Errorf("expected total 0, got %d", result.Total)
	}
}

// =============================================================================
// GetRelatedCredentials Tests
// =============================================================================

func TestCredentialImportService_GetRelatedCredentials_Success(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	event1 := createCredImportTestEvent(tenantID, "user@test.com", "data_breach - BreachA")
	event2 := createCredImportTestEvent(tenantID, "user@test.com", "data_breach - BreachB")

	repo.addExistingEvent(event1)
	repo.addExistingEvent(event2)

	related, err := svc.GetRelatedCredentials(context.Background(), tenantID.String(), event1.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should get event2 as related (same identity, different ID)
	if len(related) != 1 {
		t.Errorf("expected 1 related credential, got %d", len(related))
	}
	if len(related) > 0 && related[0].ID != event2.ID().String() {
		t.Errorf("expected related ID %s, got %s", event2.ID().String(), related[0].ID)
	}
}

func TestCredentialImportService_GetRelatedCredentials_NotFound(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()
	nonExistentID := shared.NewID()

	_, err := svc.GetRelatedCredentials(context.Background(), tenantID.String(), nonExistentID.String())
	if err == nil {
		t.Fatal("expected error for non-existent credential, got nil")
	}
}

func TestCredentialImportService_GetRelatedCredentials_NoRelated(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	event := createCredImportTestEvent(tenantID, "lonely@test.com", "data_breach")
	repo.addExistingEvent(event)

	related, err := svc.GetRelatedCredentials(context.Background(), tenantID.String(), event.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(related) != 0 {
		t.Errorf("expected 0 related credentials, got %d", len(related))
	}
}

// =============================================================================
// CredentialItem Conversion Tests
// =============================================================================

func TestCredentialImportService_ToCredentialItem_Fields(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	now := time.Now().UTC()
	event := exposure.Reconstitute(
		shared.NewID(), tenantID, nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityCritical, exposure.StateActive,
		"admin@corp.com", "admin password leaked",
		map[string]any{
			"credential_type": "aws_key",
			"secret_value":    "AKIAIOSFODNN7EXAMPLE",
			"is_verified":     true,
			"is_revoked":      false,
			"email":           "admin@corp.com",
			"source_type":     "code_repository",
		},
		"fp-admin-aws", "code_repository - GitGuardian",
		now.Add(-48*time.Hour), now,
		nil, nil, "",
		now.Add(-48*time.Hour), now,
	)
	repo.addExistingEvent(event)

	item, err := svc.GetByID(context.Background(), tenantID.String(), event.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if item.CredentialType != "aws_key" {
		t.Errorf("expected credential_type aws_key, got %s", item.CredentialType)
	}
	if item.SecretValue != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("expected secret_value, got %s", item.SecretValue)
	}
	if !item.IsVerified {
		t.Error("expected is_verified=true")
	}
	if item.IsRevoked {
		t.Error("expected is_revoked=false")
	}
	if item.Severity != "critical" {
		t.Errorf("expected severity critical, got %s", item.Severity)
	}
	if item.Source != "code_repository - GitGuardian" {
		t.Errorf("expected source 'code_repository - GitGuardian', got %s", item.Source)
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestCredentialImportService_Import_EmptyCredentialsList(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	req := credential.ImportRequest{
		Credentials: []credential.CredentialImport{},
		Options:     credential.DefaultImportOptions(),
	}

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Imported != 0 {
		t.Errorf("expected 0 imported, got %d", result.Imported)
	}
	if result.Summary.TotalProcessed != 0 {
		t.Errorf("expected 0 total processed, got %d", result.Summary.TotalProcessed)
	}
	if repo.createCalls != 0 {
		t.Errorf("expected 0 Create calls, got %d", repo.createCalls)
	}
}

func TestCredentialImportService_Import_PartialFailures(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	validCred := validCredentialImport()
	invalidCred := validCredentialImport()
	invalidCred.Identifier = "invalid@test.com"
	invalidCred.CredentialType = credential.CredentialType("nonexistent")

	validCred2 := validCredentialImport()
	validCred2.Identifier = "another@test.com"
	validCred2.DedupKey.BreachName = "different_breach"

	req := validImportRequest(validCred, invalidCred, validCred2)

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no top-level error, got %v", err)
	}

	if result.Imported != 2 {
		t.Errorf("expected 2 imported, got %d", result.Imported)
	}
	if len(result.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(result.Errors))
	}
	if result.Errors[0].Index != 1 {
		t.Errorf("expected error at index 1, got %d", result.Errors[0].Index)
	}
	if result.Errors[0].Identifier != "invalid@test.com" {
		t.Errorf("expected identifier invalid@test.com in error, got %s", result.Errors[0].Identifier)
	}
}

func TestCredentialImportService_Import_ReactivateUpdateError(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred := validCredentialImport()
	fingerprint := cred.CalculateFingerprint(tenantID.String())

	existing := exposure.Reconstitute(
		shared.NewID(), tenantID, nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityHigh, exposure.StateResolved,
		"user@example.com", "", map[string]any{"credential_type": "password"},
		fingerprint, "data_breach - TestBreach",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
		nil, nil, "",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
	)
	repo.addExistingEvent(existing)
	repo.updateErr = fmt.Errorf("update failed during reactivate")

	req := validImportRequest(cred)
	req.Options.ReactivateResolved = true

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no top-level error, got %v", err)
	}

	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.Errors))
	}
	if result.Reactivated != 0 {
		t.Errorf("expected 0 reactivated, got %d", result.Reactivated)
	}
}

func TestCredentialImportService_Import_SeverityFallbackToMedium(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred := validCredentialImport()
	cred.Severity = "not_a_valid_severity"

	req := validImportRequest(cred)
	req.Options.AutoClassifySeverity = false

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Invalid severity string should fallback to medium in createCredentialExposure
	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}
}

func TestCredentialImportService_Import_NoSeverity_NoAutoClassify(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred := validCredentialImport()
	cred.Severity = ""

	req := validImportRequest(cred)
	req.Options.AutoClassifySeverity = false

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Without auto-classify and no severity set, defaults to "medium"
	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}
}

func TestCredentialImportService_ReactivateCredential_UpdateError(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	event := createResolvedCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)
	repo.updateErr = fmt.Errorf("update failed")

	_, err := svc.ReactivateCredential(context.Background(), tenantID.String(), event.ID().String())
	if err == nil {
		t.Fatal("expected error when update fails, got nil")
	}
}

func TestCredentialImportService_AcceptCredential_NotFound(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()
	nonExistentID := shared.NewID()

	_, err := svc.AcceptCredential(context.Background(), tenantID.String(), nonExistentID.String(), userID.String(), "notes")
	if err == nil {
		t.Fatal("expected error for non-existent credential, got nil")
	}
}

func TestCredentialImportService_MarkFalsePositive_AlreadyFalsePositive(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createFalsePositiveCredImportTestEvent(tenantID, "user@test.com", "data_breach")
	repo.addExistingEvent(event)

	_, err := svc.MarkCredentialFalsePositive(context.Background(), tenantID.String(), event.ID().String(), userID.String(), "notes")
	if err == nil {
		t.Fatal("expected error when marking already false-positive credential, got nil")
	}
}

func TestCredentialImportService_Import_DefaultDedupStrategyOnUnknown(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	tenantID := shared.NewID()

	cred := validCredentialImport()
	fingerprint := cred.CalculateFingerprint(tenantID.String())

	existing := exposure.Reconstitute(
		shared.NewID(), tenantID, nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityHigh, exposure.StateActive,
		"user@example.com", "", map[string]any{"credential_type": "password"},
		fingerprint, "data_breach - TestBreach",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
		nil, nil, "",
		time.Now().Add(-24*time.Hour), time.Now().Add(-12*time.Hour),
	)
	repo.addExistingEvent(existing)

	req := validImportRequest(cred)
	req.Options.DedupStrategy = credential.DedupStrategy("unknown_strategy")

	result, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Unknown strategy falls through to default case which does update_last_seen
	if result.Updated != 1 {
		t.Errorf("expected 1 updated (default behavior), got %d", result.Updated)
	}
	if result.Details[0].Reason != "last_seen_updated" {
		t.Errorf("expected reason 'last_seen_updated', got %s", result.Details[0].Reason)
	}
}
