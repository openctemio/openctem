package unit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/exposure"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Exposure Repository
// =============================================================================

type mockExposureRepo struct {
	events map[string]*exposure.ExposureEvent

	// Configurable errors
	createErr      error
	getErr         error
	updateErr      error
	deleteErr      error
	listErr        error
	countErr       error
	upsertErr      error
	bulkUpsertErr  error
	countStateErr  error
	countSevErr    error

	// Configurable results
	countByStateResult    map[exposure.State]int64
	countBySeverityResult map[exposure.Severity]int64

	// Call tracking
	createCalls     int
	getCalls        int
	updateCalls     int
	deleteCalls     int
	listCalls       int
	upsertCalls     int
	bulkUpsertCalls int
	countStateCalls int
	countSevCalls   int
}

func newMockExposureRepo() *mockExposureRepo {
	return &mockExposureRepo{
		events: make(map[string]*exposure.ExposureEvent),
	}
}

func (m *mockExposureRepo) Create(_ context.Context, event *exposure.ExposureEvent) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.events[event.ID().String()] = event
	return nil
}

func (m *mockExposureRepo) CreateInTx(_ context.Context, _ *sql.Tx, event *exposure.ExposureEvent) error {
	return m.Create(context.Background(), event)
}

func (m *mockExposureRepo) GetByID(_ context.Context, id shared.ID) (*exposure.ExposureEvent, error) {
	m.getCalls++
	if m.getErr != nil {
		return nil, m.getErr
	}
	e, ok := m.events[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return e, nil
}

func (m *mockExposureRepo) GetByFingerprint(_ context.Context, _ shared.ID, _ string) (*exposure.ExposureEvent, error) {
	return nil, shared.ErrNotFound
}

func (m *mockExposureRepo) Update(_ context.Context, event *exposure.ExposureEvent) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	if _, ok := m.events[event.ID().String()]; !ok {
		return shared.ErrNotFound
	}
	m.events[event.ID().String()] = event
	return nil
}

func (m *mockExposureRepo) Delete(_ context.Context, id shared.ID) error {
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.events[id.String()]; !ok {
		return shared.ErrNotFound
	}
	delete(m.events, id.String())
	return nil
}

func (m *mockExposureRepo) List(_ context.Context, filter exposure.Filter, _ exposure.ListOptions, page pagination.Pagination) (pagination.Result[*exposure.ExposureEvent], error) {
	m.listCalls++
	if m.listErr != nil {
		return pagination.Result[*exposure.ExposureEvent]{}, m.listErr
	}
	result := make([]*exposure.ExposureEvent, 0, len(m.events))
	for _, e := range m.events {
		if filter.TenantID != nil {
			tid, err := shared.IDFromString(*filter.TenantID)
			if err != nil || e.TenantID() != tid {
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

func (m *mockExposureRepo) Count(_ context.Context, _ exposure.Filter) (int64, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	return int64(len(m.events)), nil
}

func (m *mockExposureRepo) ListByAsset(_ context.Context, _ shared.ID, page pagination.Pagination) (pagination.Result[*exposure.ExposureEvent], error) {
	return pagination.Result[*exposure.ExposureEvent]{
		Data:    []*exposure.ExposureEvent{},
		Total:   0,
		Page:    page.Page,
		PerPage: page.PerPage,
	}, nil
}

func (m *mockExposureRepo) ExistsByFingerprint(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}

func (m *mockExposureRepo) Upsert(_ context.Context, event *exposure.ExposureEvent) error {
	m.upsertCalls++
	if m.upsertErr != nil {
		return m.upsertErr
	}
	m.events[event.ID().String()] = event
	return nil
}

func (m *mockExposureRepo) BulkUpsert(_ context.Context, events []*exposure.ExposureEvent) error {
	m.bulkUpsertCalls++
	if m.bulkUpsertErr != nil {
		return m.bulkUpsertErr
	}
	for _, e := range events {
		m.events[e.ID().String()] = e
	}
	return nil
}

func (m *mockExposureRepo) CountByState(_ context.Context, _ shared.ID) (map[exposure.State]int64, error) {
	m.countStateCalls++
	if m.countStateErr != nil {
		return nil, m.countStateErr
	}
	if m.countByStateResult != nil {
		return m.countByStateResult, nil
	}
	return map[exposure.State]int64{}, nil
}

func (m *mockExposureRepo) CountBySeverity(_ context.Context, _ shared.ID) (map[exposure.Severity]int64, error) {
	m.countSevCalls++
	if m.countSevErr != nil {
		return nil, m.countSevErr
	}
	if m.countBySeverityResult != nil {
		return m.countBySeverityResult, nil
	}
	return map[exposure.Severity]int64{}, nil
}

// =============================================================================
// Mock State History Repository
// =============================================================================

type mockStateHistoryRepo struct {
	histories map[string][]*exposure.StateHistory

	// Configurable errors
	createErr error
	listErr   error

	// Call tracking
	createCalls int
	listCalls   int
}

func newMockStateHistoryRepo() *mockStateHistoryRepo {
	return &mockStateHistoryRepo{
		histories: make(map[string][]*exposure.StateHistory),
	}
}

func (m *mockStateHistoryRepo) Create(_ context.Context, history *exposure.StateHistory) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	key := history.ExposureEventID().String()
	m.histories[key] = append(m.histories[key], history)
	return nil
}

func (m *mockStateHistoryRepo) ListByExposureEvent(_ context.Context, exposureEventID shared.ID) ([]*exposure.StateHistory, error) {
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

func (m *mockStateHistoryRepo) GetLatest(_ context.Context, exposureEventID shared.ID) (*exposure.StateHistory, error) {
	key := exposureEventID.String()
	if h, ok := m.histories[key]; ok && len(h) > 0 {
		return h[len(h)-1], nil
	}
	return nil, shared.ErrNotFound
}

// =============================================================================
// Test Helper
// =============================================================================

func newExposureTestService() (*app.ExposureService, *mockExposureRepo, *mockStateHistoryRepo) {
	repo := newMockExposureRepo()
	historyRepo := newMockStateHistoryRepo()
	log := logger.NewNop()
	svc := app.NewExposureService(repo, historyRepo, log)
	return svc, repo, historyRepo
}

func validCreateExposureInput(tenantID string) app.CreateExposureInput {
	return app.CreateExposureInput{
		TenantID:    tenantID,
		EventType:   "port_open",
		Severity:    "high",
		Title:       "Open Port 22 Detected",
		Description: "SSH port 22 is open to the internet",
		Source:      "nmap_scan",
		Details:     map[string]any{"port": 22, "protocol": "tcp"},
	}
}

// createTestExposureEvent creates an exposure event via the service and returns it.
func createTestExposureEvent(t *testing.T, svc *app.ExposureService, tenantID string) *exposure.ExposureEvent {
	t.Helper()
	input := validCreateExposureInput(tenantID)
	event, err := svc.CreateExposure(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to create test exposure event: %v", err)
	}
	return event
}

// =============================================================================
// CreateExposure Tests
// =============================================================================

func TestExposureService_CreateExposure_Success(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()

	input := app.CreateExposureInput{
		TenantID:    tenantID.String(),
		EventType:   "port_open",
		Severity:    "critical",
		Title:       "Critical Port Exposure",
		Description: "Port 3389 (RDP) is open to the internet",
		Source:      "nmap_scan",
		Details:     map[string]any{"port": 3389, "protocol": "tcp"},
	}

	event, err := svc.CreateExposure(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if event.TenantID() != tenantID {
		t.Errorf("expected tenant ID %s, got %s", tenantID, event.TenantID())
	}
	if event.EventType() != exposure.EventTypePortOpen {
		t.Errorf("expected event type port_open, got %s", event.EventType())
	}
	if event.Severity() != exposure.SeverityCritical {
		t.Errorf("expected severity critical, got %s", event.Severity())
	}
	if event.Title() != input.Title {
		t.Errorf("expected title %s, got %s", input.Title, event.Title())
	}
	if event.Description() != input.Description {
		t.Errorf("expected description %s, got %s", input.Description, event.Description())
	}
	if event.Source() != input.Source {
		t.Errorf("expected source %s, got %s", input.Source, event.Source())
	}
	if event.State() != exposure.StateActive {
		t.Errorf("expected state active, got %s", event.State())
	}
	if event.Fingerprint() == "" {
		t.Error("expected non-empty fingerprint")
	}
	if repo.createCalls != 1 {
		t.Errorf("expected 1 Create call, got %d", repo.createCalls)
	}
}

func TestExposureService_CreateExposure_WithAssetID(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	input := validCreateExposureInput(tenantID.String())
	input.AssetID = assetID.String()

	event, err := svc.CreateExposure(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if event.AssetID() == nil {
		t.Fatal("expected asset ID to be set")
	}
	if *event.AssetID() != assetID {
		t.Errorf("expected asset ID %s, got %s", assetID, event.AssetID())
	}
}

func TestExposureService_CreateExposure_WithoutDescription(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	input := validCreateExposureInput(tenantID.String())
	input.Description = ""

	event, err := svc.CreateExposure(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if event.Description() != "" {
		t.Errorf("expected empty description, got %s", event.Description())
	}
}

func TestExposureService_CreateExposure_InvalidTenantID(t *testing.T) {
	svc, _, _ := newExposureTestService()

	input := validCreateExposureInput("not-a-uuid")

	_, err := svc.CreateExposure(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestExposureService_CreateExposure_InvalidEventType(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	input := validCreateExposureInput(tenantID.String())
	input.EventType = "invalid_type"

	_, err := svc.CreateExposure(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid event type")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestExposureService_CreateExposure_InvalidSeverity(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	input := validCreateExposureInput(tenantID.String())
	input.Severity = "super_critical"

	_, err := svc.CreateExposure(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestExposureService_CreateExposure_InvalidAssetID(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	input := validCreateExposureInput(tenantID.String())
	input.AssetID = "not-a-uuid"

	_, err := svc.CreateExposure(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid asset ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestExposureService_CreateExposure_RepoError(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()

	repo.createErr = fmt.Errorf("database connection error")

	input := validCreateExposureInput(tenantID.String())

	_, err := svc.CreateExposure(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

func TestExposureService_CreateExposure_AllSeverities(t *testing.T) {
	severities := []string{"critical", "high", "medium", "low", "info"}

	for _, sev := range severities {
		t.Run(sev, func(t *testing.T) {
			svc, _, _ := newExposureTestService()
			tenantID := shared.NewID()

			input := validCreateExposureInput(tenantID.String())
			input.Severity = sev

			event, err := svc.CreateExposure(context.Background(), input)
			if err != nil {
				t.Fatalf("expected no error for severity %s, got %v", sev, err)
			}
			if event.Severity().String() != sev {
				t.Errorf("expected severity %s, got %s", sev, event.Severity())
			}
		})
	}
}

func TestExposureService_CreateExposure_AllEventTypes(t *testing.T) {
	eventTypes := []string{
		"port_open", "port_closed", "service_detected", "service_changed",
		"subdomain_discovered", "subdomain_removed", "certificate_expiring",
		"certificate_expired", "bucket_public", "bucket_private",
		"repo_public", "repo_private", "api_exposed", "api_removed",
		"credential_leaked", "sensitive_data_exposed", "misconfiguration",
		"dns_change", "ssl_issue", "header_missing", "custom",
	}

	for _, et := range eventTypes {
		t.Run(et, func(t *testing.T) {
			svc, _, _ := newExposureTestService()
			tenantID := shared.NewID()

			input := validCreateExposureInput(tenantID.String())
			input.EventType = et

			event, err := svc.CreateExposure(context.Background(), input)
			if err != nil {
				t.Fatalf("expected no error for event type %s, got %v", et, err)
			}
			if event.EventType().String() != et {
				t.Errorf("expected event type %s, got %s", et, event.EventType())
			}
		})
	}
}

// =============================================================================
// GetExposure Tests
// =============================================================================

func TestExposureService_GetExposure_Success(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	created := createTestExposureEvent(t, svc, tenantID.String())

	fetched, err := svc.GetExposure(context.Background(), created.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if fetched.ID() != created.ID() {
		t.Errorf("expected ID %s, got %s", created.ID(), fetched.ID())
	}
	if fetched.Title() != created.Title() {
		t.Errorf("expected title %s, got %s", created.Title(), fetched.Title())
	}
}

func TestExposureService_GetExposure_InvalidID(t *testing.T) {
	svc, _, _ := newExposureTestService()

	_, err := svc.GetExposure(context.Background(), "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected not found error, got %v", err)
	}
}

func TestExposureService_GetExposure_NotFound(t *testing.T) {
	svc, _, _ := newExposureTestService()
	nonExistentID := shared.NewID()

	_, err := svc.GetExposure(context.Background(), nonExistentID.String())
	if err == nil {
		t.Fatal("expected error for non-existent exposure")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected not found error, got %v", err)
	}
}

func TestExposureService_GetExposure_RepoError(t *testing.T) {
	svc, repo, _ := newExposureTestService()

	repo.getErr = fmt.Errorf("database error")

	_, err := svc.GetExposure(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// =============================================================================
// ListExposures Tests
// =============================================================================

func TestExposureService_ListExposures_Success(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	// Create multiple exposure events
	for i := 0; i < 3; i++ {
		input := validCreateExposureInput(tenantID.String())
		input.Title = fmt.Sprintf("Exposure %d", i)
		_, err := svc.CreateExposure(context.Background(), input)
		if err != nil {
			t.Fatalf("failed to create exposure %d: %v", i, err)
		}
	}

	result, err := svc.ListExposures(context.Background(), app.ListExposuresInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  20,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Total != 3 {
		t.Errorf("expected 3 total, got %d", result.Total)
	}
	if len(result.Data) != 3 {
		t.Errorf("expected 3 items, got %d", len(result.Data))
	}
}

func TestExposureService_ListExposures_WithFilters(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()

	input := validCreateExposureInput(tenantID.String())
	_, err := svc.CreateExposure(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to create exposure: %v", err)
	}

	listInput := app.ListExposuresInput{
		TenantID:   tenantID.String(),
		EventTypes: []string{"port_open"},
		Severities: []string{"high"},
		States:     []string{"active"},
		Sources:    []string{"nmap_scan"},
		Search:     "Port",
		Page:       1,
		PerPage:    10,
		SortBy:     "created_at",
		SortOrder:  "desc",
	}

	_, err = svc.ListExposures(context.Background(), listInput)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.listCalls != 1 {
		t.Errorf("expected 1 List call, got %d", repo.listCalls)
	}
}

func TestExposureService_ListExposures_WithTimeFilters(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()

	listInput := app.ListExposuresInput{
		TenantID:        tenantID.String(),
		FirstSeenAfter:  1000,
		FirstSeenBefore: 2000,
		LastSeenAfter:   1000,
		LastSeenBefore:  2000,
		Page:            1,
		PerPage:         10,
	}

	_, err := svc.ListExposures(context.Background(), listInput)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.listCalls != 1 {
		t.Errorf("expected 1 List call, got %d", repo.listCalls)
	}
}

func TestExposureService_ListExposures_EmptyResult(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	result, err := svc.ListExposures(context.Background(), app.ListExposuresInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  20,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Total != 0 {
		t.Errorf("expected 0 total, got %d", result.Total)
	}
}

func TestExposureService_ListExposures_InvalidFilterValues(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	// Invalid event types and severities should be silently ignored
	result, err := svc.ListExposures(context.Background(), app.ListExposuresInput{
		TenantID:   tenantID.String(),
		EventTypes: []string{"invalid_type"},
		Severities: []string{"ultra_high"},
		States:     []string{"nonexistent_state"},
		Page:       1,
		PerPage:    20,
	})
	if err != nil {
		t.Fatalf("expected no error even with invalid filters, got %v", err)
	}

	if result.Total != 0 {
		t.Errorf("expected 0 total, got %d", result.Total)
	}
}

func TestExposureService_ListExposures_RepoError(t *testing.T) {
	svc, repo, _ := newExposureTestService()

	repo.listErr = fmt.Errorf("database error")

	_, err := svc.ListExposures(context.Background(), app.ListExposuresInput{
		TenantID: shared.NewID().String(),
		Page:     1,
		PerPage:  20,
	})
	if err == nil {
		t.Fatal("expected error when repo returns error")
	}
}

func TestExposureService_ListExposures_WithAssetID(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	listInput := app.ListExposuresInput{
		TenantID: tenantID.String(),
		AssetID:  assetID.String(),
		Page:     1,
		PerPage:  10,
	}

	_, err := svc.ListExposures(context.Background(), listInput)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.listCalls != 1 {
		t.Errorf("expected 1 List call, got %d", repo.listCalls)
	}
}

// =============================================================================
// IngestExposure Tests
// =============================================================================

func TestExposureService_IngestExposure_Success(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()

	input := validCreateExposureInput(tenantID.String())

	event, err := svc.IngestExposure(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if event.Title() != input.Title {
		t.Errorf("expected title %s, got %s", input.Title, event.Title())
	}
	if repo.upsertCalls != 1 {
		t.Errorf("expected 1 Upsert call, got %d", repo.upsertCalls)
	}
}

func TestExposureService_IngestExposure_WithAssetID(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()
	assetID := shared.NewID()

	input := validCreateExposureInput(tenantID.String())
	input.AssetID = assetID.String()

	event, err := svc.IngestExposure(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if event.AssetID() == nil || *event.AssetID() != assetID {
		t.Errorf("expected asset ID %s, got %v", assetID, event.AssetID())
	}
}

func TestExposureService_IngestExposure_InvalidTenantID(t *testing.T) {
	svc, _, _ := newExposureTestService()

	input := validCreateExposureInput("not-a-uuid")

	_, err := svc.IngestExposure(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestExposureService_IngestExposure_InvalidEventType(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	input := validCreateExposureInput(tenantID.String())
	input.EventType = "bogus"

	_, err := svc.IngestExposure(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid event type")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestExposureService_IngestExposure_InvalidSeverity(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	input := validCreateExposureInput(tenantID.String())
	input.Severity = "bogus"

	_, err := svc.IngestExposure(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestExposureService_IngestExposure_InvalidAssetID(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	input := validCreateExposureInput(tenantID.String())
	input.AssetID = "not-a-uuid"

	_, err := svc.IngestExposure(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid asset ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestExposureService_IngestExposure_RepoError(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()

	repo.upsertErr = fmt.Errorf("database error")

	input := validCreateExposureInput(tenantID.String())

	_, err := svc.IngestExposure(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// =============================================================================
// BulkIngestExposures Tests
// =============================================================================

func TestExposureService_BulkIngestExposures_Success(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()

	inputs := make([]app.CreateExposureInput, 5)
	for i := 0; i < 5; i++ {
		inputs[i] = validCreateExposureInput(tenantID.String())
		inputs[i].Title = fmt.Sprintf("Exposure %d", i)
	}

	events, err := svc.BulkIngestExposures(context.Background(), inputs)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(events) != 5 {
		t.Errorf("expected 5 events, got %d", len(events))
	}
	if repo.bulkUpsertCalls != 1 {
		t.Errorf("expected 1 BulkUpsert call, got %d", repo.bulkUpsertCalls)
	}
}

func TestExposureService_BulkIngestExposures_EmptyInput(t *testing.T) {
	svc, repo, _ := newExposureTestService()

	events, err := svc.BulkIngestExposures(context.Background(), []app.CreateExposureInput{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
	if repo.bulkUpsertCalls != 0 {
		t.Errorf("expected 0 BulkUpsert calls, got %d", repo.bulkUpsertCalls)
	}
}

func TestExposureService_BulkIngestExposures_MixedValidation(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()

	inputs := []app.CreateExposureInput{
		validCreateExposureInput(tenantID.String()),
		{TenantID: "not-a-uuid", EventType: "port_open", Severity: "high", Title: "Bad Tenant", Source: "test"},
		validCreateExposureInput(tenantID.String()),
		{TenantID: tenantID.String(), EventType: "bogus", Severity: "high", Title: "Bad Type", Source: "test"},
		{TenantID: tenantID.String(), EventType: "port_open", Severity: "bogus", Title: "Bad Sev", Source: "test"},
	}
	inputs[0].Title = "Valid Exposure 1"
	inputs[2].Title = "Valid Exposure 2"

	events, err := svc.BulkIngestExposures(context.Background(), inputs)
	if err != nil {
		t.Fatalf("expected no error for partial validation, got %v", err)
	}

	// Only the 2 valid inputs should produce events
	if len(events) != 2 {
		t.Errorf("expected 2 valid events, got %d", len(events))
	}
	if repo.bulkUpsertCalls != 1 {
		t.Errorf("expected 1 BulkUpsert call, got %d", repo.bulkUpsertCalls)
	}
}

func TestExposureService_BulkIngestExposures_AllInvalid(t *testing.T) {
	svc, repo, _ := newExposureTestService()

	inputs := []app.CreateExposureInput{
		{TenantID: "not-a-uuid", EventType: "port_open", Severity: "high", Title: "Bad 1", Source: "test"},
		{TenantID: "not-a-uuid", EventType: "port_open", Severity: "high", Title: "Bad 2", Source: "test"},
	}

	events, err := svc.BulkIngestExposures(context.Background(), inputs)
	if err != nil {
		t.Fatalf("expected no error (all filtered), got %v", err)
	}

	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
	// BulkUpsert should not be called when all are invalid
	if repo.bulkUpsertCalls != 0 {
		t.Errorf("expected 0 BulkUpsert calls, got %d", repo.bulkUpsertCalls)
	}
}

func TestExposureService_BulkIngestExposures_RepoError(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()

	repo.bulkUpsertErr = fmt.Errorf("bulk insert failed")

	inputs := []app.CreateExposureInput{
		validCreateExposureInput(tenantID.String()),
	}

	_, err := svc.BulkIngestExposures(context.Background(), inputs)
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

func TestExposureService_BulkIngestExposures_WithInvalidAssetID(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	validInput := validCreateExposureInput(tenantID.String())
	invalidAssetInput := validCreateExposureInput(tenantID.String())
	invalidAssetInput.AssetID = "not-a-uuid"

	inputs := []app.CreateExposureInput{validInput, invalidAssetInput}

	events, err := svc.BulkIngestExposures(context.Background(), inputs)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Only the valid one should pass
	if len(events) != 1 {
		t.Errorf("expected 1 valid event, got %d", len(events))
	}
}

// =============================================================================
// ResolveExposure Tests
// =============================================================================

func TestExposureService_ResolveExposure_Success(t *testing.T) {
	svc, _, historyRepo := newExposureTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	resolved, err := svc.ResolveExposure(context.Background(), event.ID().String(), userID.String(), "Fixed the issue")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if resolved.State() != exposure.StateResolved {
		t.Errorf("expected state resolved, got %s", resolved.State())
	}
	if resolved.ResolvedAt() == nil {
		t.Error("expected resolved_at to be set")
	}
	if resolved.ResolvedBy() == nil || *resolved.ResolvedBy() != userID {
		t.Errorf("expected resolved_by to be %s", userID)
	}
	if resolved.ResolutionNotes() != "Fixed the issue" {
		t.Errorf("expected resolution notes 'Fixed the issue', got %s", resolved.ResolutionNotes())
	}
	if historyRepo.createCalls != 1 {
		t.Errorf("expected 1 history Create call, got %d", historyRepo.createCalls)
	}
}

func TestExposureService_ResolveExposure_InvalidExposureID(t *testing.T) {
	svc, _, _ := newExposureTestService()
	userID := shared.NewID()

	_, err := svc.ResolveExposure(context.Background(), "not-a-uuid", userID.String(), "")
	if err == nil {
		t.Fatal("expected error for invalid exposure ID")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected not found error, got %v", err)
	}
}

func TestExposureService_ResolveExposure_InvalidUserID(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	_, err := svc.ResolveExposure(context.Background(), event.ID().String(), "not-a-uuid", "")
	if err == nil {
		t.Fatal("expected error for invalid user ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestExposureService_ResolveExposure_NotFound(t *testing.T) {
	svc, _, _ := newExposureTestService()
	userID := shared.NewID()

	_, err := svc.ResolveExposure(context.Background(), shared.NewID().String(), userID.String(), "")
	if err == nil {
		t.Fatal("expected error for non-existent exposure")
	}
}

func TestExposureService_ResolveExposure_AlreadyResolved(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	// Resolve it first
	_, err := svc.ResolveExposure(context.Background(), event.ID().String(), userID.String(), "First resolve")
	if err != nil {
		t.Fatalf("expected first resolve to succeed, got %v", err)
	}

	// Try to resolve again - should fail because resolved cannot transition to resolved
	_, err = svc.ResolveExposure(context.Background(), event.ID().String(), userID.String(), "Second resolve")
	if err == nil {
		t.Fatal("expected error when resolving already-resolved exposure")
	}
}

func TestExposureService_ResolveExposure_UpdateError(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	repo.updateErr = fmt.Errorf("update failed")

	_, err := svc.ResolveExposure(context.Background(), event.ID().String(), userID.String(), "")
	if err == nil {
		t.Fatal("expected error from repo update")
	}
}

// =============================================================================
// AcceptExposure Tests
// =============================================================================

func TestExposureService_AcceptExposure_Success(t *testing.T) {
	svc, _, historyRepo := newExposureTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	accepted, err := svc.AcceptExposure(context.Background(), event.ID().String(), userID.String(), "Accepted risk")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if accepted.State() != exposure.StateAccepted {
		t.Errorf("expected state accepted, got %s", accepted.State())
	}
	if accepted.ResolutionNotes() != "Accepted risk" {
		t.Errorf("expected resolution notes 'Accepted risk', got %s", accepted.ResolutionNotes())
	}
	if historyRepo.createCalls != 1 {
		t.Errorf("expected 1 history Create call, got %d", historyRepo.createCalls)
	}
}

func TestExposureService_AcceptExposure_InvalidExposureID(t *testing.T) {
	svc, _, _ := newExposureTestService()
	userID := shared.NewID()

	_, err := svc.AcceptExposure(context.Background(), "not-a-uuid", userID.String(), "")
	if err == nil {
		t.Fatal("expected error for invalid exposure ID")
	}
}

func TestExposureService_AcceptExposure_InvalidUserID(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	_, err := svc.AcceptExposure(context.Background(), event.ID().String(), "bad-id", "")
	if err == nil {
		t.Fatal("expected error for invalid user ID")
	}
}

// =============================================================================
// MarkFalsePositive Tests
// =============================================================================

func TestExposureService_MarkFalsePositive_Success(t *testing.T) {
	svc, _, historyRepo := newExposureTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	fp, err := svc.MarkFalsePositive(context.Background(), event.ID().String(), userID.String(), "Not a real exposure")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if fp.State() != exposure.StateFalsePositive {
		t.Errorf("expected state false_positive, got %s", fp.State())
	}
	if fp.ResolutionNotes() != "Not a real exposure" {
		t.Errorf("expected notes 'Not a real exposure', got %s", fp.ResolutionNotes())
	}
	if historyRepo.createCalls != 1 {
		t.Errorf("expected 1 history Create call, got %d", historyRepo.createCalls)
	}
}

func TestExposureService_MarkFalsePositive_InvalidExposureID(t *testing.T) {
	svc, _, _ := newExposureTestService()
	userID := shared.NewID()

	_, err := svc.MarkFalsePositive(context.Background(), "bad-id", userID.String(), "")
	if err == nil {
		t.Fatal("expected error for invalid exposure ID")
	}
}

// =============================================================================
// ReactivateExposure Tests
// =============================================================================

func TestExposureService_ReactivateExposure_Success(t *testing.T) {
	svc, _, historyRepo := newExposureTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	// First resolve
	_, err := svc.ResolveExposure(context.Background(), event.ID().String(), userID.String(), "Resolved")
	if err != nil {
		t.Fatalf("expected resolve to succeed, got %v", err)
	}

	// Then reactivate
	reactivated, err := svc.ReactivateExposure(context.Background(), event.ID().String(), userID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if reactivated.State() != exposure.StateActive {
		t.Errorf("expected state active, got %s", reactivated.State())
	}
	if reactivated.ResolvedAt() != nil {
		t.Error("expected resolved_at to be nil after reactivation")
	}
	if reactivated.ResolvedBy() != nil {
		t.Error("expected resolved_by to be nil after reactivation")
	}
	// 1 for resolve + 1 for reactivate
	if historyRepo.createCalls != 2 {
		t.Errorf("expected 2 history Create calls, got %d", historyRepo.createCalls)
	}
}

func TestExposureService_ReactivateExposure_FromAccepted(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	// Accept first
	_, err := svc.AcceptExposure(context.Background(), event.ID().String(), userID.String(), "Accepted")
	if err != nil {
		t.Fatalf("expected accept to succeed, got %v", err)
	}

	// Then reactivate
	reactivated, err := svc.ReactivateExposure(context.Background(), event.ID().String(), userID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if reactivated.State() != exposure.StateActive {
		t.Errorf("expected state active, got %s", reactivated.State())
	}
}

func TestExposureService_ReactivateExposure_FromFalsePositive(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	// Mark false positive first
	_, err := svc.MarkFalsePositive(context.Background(), event.ID().String(), userID.String(), "FP")
	if err != nil {
		t.Fatalf("expected mark false positive to succeed, got %v", err)
	}

	// Then reactivate
	reactivated, err := svc.ReactivateExposure(context.Background(), event.ID().String(), userID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if reactivated.State() != exposure.StateActive {
		t.Errorf("expected state active, got %s", reactivated.State())
	}
}

func TestExposureService_ReactivateExposure_AlreadyActive(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	// Try to reactivate an already-active exposure
	_, err := svc.ReactivateExposure(context.Background(), event.ID().String(), userID.String())
	if err == nil {
		t.Fatal("expected error when reactivating already-active exposure")
	}
}

func TestExposureService_ReactivateExposure_InvalidID(t *testing.T) {
	svc, _, _ := newExposureTestService()

	_, err := svc.ReactivateExposure(context.Background(), "not-a-uuid", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid exposure ID")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected not found error, got %v", err)
	}
}

func TestExposureService_ReactivateExposure_NotFound(t *testing.T) {
	svc, _, _ := newExposureTestService()

	_, err := svc.ReactivateExposure(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent exposure")
	}
}

func TestExposureService_ReactivateExposure_UpdateError(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	// Resolve it first
	_, err := svc.ResolveExposure(context.Background(), event.ID().String(), userID.String(), "")
	if err != nil {
		t.Fatalf("expected resolve to succeed, got %v", err)
	}

	repo.updateErr = fmt.Errorf("update failed")

	_, err = svc.ReactivateExposure(context.Background(), event.ID().String(), userID.String())
	if err == nil {
		t.Fatal("expected error from repo update")
	}
}

func TestExposureService_ReactivateExposure_WithEmptyUserID(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	// Resolve first
	_, err := svc.ResolveExposure(context.Background(), event.ID().String(), userID.String(), "")
	if err != nil {
		t.Fatalf("expected resolve to succeed, got %v", err)
	}

	// Reactivate with empty user ID (should still work)
	reactivated, err := svc.ReactivateExposure(context.Background(), event.ID().String(), "")
	if err != nil {
		t.Fatalf("expected no error with empty user ID, got %v", err)
	}
	if reactivated.State() != exposure.StateActive {
		t.Errorf("expected state active, got %s", reactivated.State())
	}
}

// =============================================================================
// State Transition Tests (Table-Driven)
// =============================================================================

func TestExposureService_StateTransitions(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(svc *app.ExposureService, eventID, userID string) error
		transition func(svc *app.ExposureService, eventID, userID string) (*exposure.ExposureEvent, error)
		wantState  exposure.State
		wantErr    bool
	}{
		{
			name:  "active to resolved",
			setup: nil,
			transition: func(svc *app.ExposureService, eventID, userID string) (*exposure.ExposureEvent, error) {
				return svc.ResolveExposure(context.Background(), eventID, userID, "resolved")
			},
			wantState: exposure.StateResolved,
			wantErr:   false,
		},
		{
			name:  "active to accepted",
			setup: nil,
			transition: func(svc *app.ExposureService, eventID, userID string) (*exposure.ExposureEvent, error) {
				return svc.AcceptExposure(context.Background(), eventID, userID, "accepted risk")
			},
			wantState: exposure.StateAccepted,
			wantErr:   false,
		},
		{
			name:  "active to false_positive",
			setup: nil,
			transition: func(svc *app.ExposureService, eventID, userID string) (*exposure.ExposureEvent, error) {
				return svc.MarkFalsePositive(context.Background(), eventID, userID, "false positive")
			},
			wantState: exposure.StateFalsePositive,
			wantErr:   false,
		},
		{
			name: "resolved to active (reactivate)",
			setup: func(svc *app.ExposureService, eventID, userID string) error {
				_, err := svc.ResolveExposure(context.Background(), eventID, userID, "")
				return err
			},
			transition: func(svc *app.ExposureService, eventID, userID string) (*exposure.ExposureEvent, error) {
				return svc.ReactivateExposure(context.Background(), eventID, userID)
			},
			wantState: exposure.StateActive,
			wantErr:   false,
		},
		{
			name: "accepted to active (reactivate)",
			setup: func(svc *app.ExposureService, eventID, userID string) error {
				_, err := svc.AcceptExposure(context.Background(), eventID, userID, "")
				return err
			},
			transition: func(svc *app.ExposureService, eventID, userID string) (*exposure.ExposureEvent, error) {
				return svc.ReactivateExposure(context.Background(), eventID, userID)
			},
			wantState: exposure.StateActive,
			wantErr:   false,
		},
		{
			name: "accepted to resolved",
			setup: func(svc *app.ExposureService, eventID, userID string) error {
				_, err := svc.AcceptExposure(context.Background(), eventID, userID, "")
				return err
			},
			transition: func(svc *app.ExposureService, eventID, userID string) (*exposure.ExposureEvent, error) {
				return svc.ResolveExposure(context.Background(), eventID, userID, "now resolved")
			},
			wantState: exposure.StateResolved,
			wantErr:   false,
		},
		{
			name: "false_positive to active (reactivate)",
			setup: func(svc *app.ExposureService, eventID, userID string) error {
				_, err := svc.MarkFalsePositive(context.Background(), eventID, userID, "")
				return err
			},
			transition: func(svc *app.ExposureService, eventID, userID string) (*exposure.ExposureEvent, error) {
				return svc.ReactivateExposure(context.Background(), eventID, userID)
			},
			wantState: exposure.StateActive,
			wantErr:   false,
		},
		{
			name: "resolved cannot resolve again",
			setup: func(svc *app.ExposureService, eventID, userID string) error {
				_, err := svc.ResolveExposure(context.Background(), eventID, userID, "")
				return err
			},
			transition: func(svc *app.ExposureService, eventID, userID string) (*exposure.ExposureEvent, error) {
				return svc.ResolveExposure(context.Background(), eventID, userID, "again")
			},
			wantErr: true,
		},
		{
			name:  "active cannot reactivate",
			setup: nil,
			transition: func(svc *app.ExposureService, eventID, userID string) (*exposure.ExposureEvent, error) {
				return svc.ReactivateExposure(context.Background(), eventID, userID)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _, _ := newExposureTestService()
			tenantID := shared.NewID()
			userID := shared.NewID()

			event := createTestExposureEvent(t, svc, tenantID.String())

			if tt.setup != nil {
				if err := tt.setup(svc, event.ID().String(), userID.String()); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
			}

			result, err := tt.transition(svc, event.ID().String(), userID.String())
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if result.State() != tt.wantState {
				t.Errorf("expected state %s, got %s", tt.wantState, result.State())
			}
		})
	}
}

// =============================================================================
// GetStateHistory Tests
// =============================================================================

func TestExposureService_GetStateHistory_Success(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	// Create some state changes
	_, err := svc.ResolveExposure(context.Background(), event.ID().String(), userID.String(), "Resolved")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	_, err = svc.ReactivateExposure(context.Background(), event.ID().String(), userID.String())
	if err != nil {
		t.Fatalf("reactivate failed: %v", err)
	}

	history, err := svc.GetStateHistory(context.Background(), event.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(history) != 2 {
		t.Errorf("expected 2 history entries, got %d", len(history))
	}
}

func TestExposureService_GetStateHistory_InvalidID(t *testing.T) {
	svc, _, _ := newExposureTestService()

	_, err := svc.GetStateHistory(context.Background(), "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected not found error, got %v", err)
	}
}

func TestExposureService_GetStateHistory_Empty(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	history, err := svc.GetStateHistory(context.Background(), event.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(history) != 0 {
		t.Errorf("expected 0 history entries, got %d", len(history))
	}
}

func TestExposureService_GetStateHistory_RepoError(t *testing.T) {
	svc, _, historyRepo := newExposureTestService()

	historyRepo.listErr = fmt.Errorf("database error")

	_, err := svc.GetStateHistory(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// =============================================================================
// GetExposureStats Tests
// =============================================================================

func TestExposureService_GetExposureStats_Success(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()

	repo.countByStateResult = map[exposure.State]int64{
		exposure.StateActive:   10,
		exposure.StateResolved: 5,
		exposure.StateAccepted: 2,
	}
	repo.countBySeverityResult = map[exposure.Severity]int64{
		exposure.SeverityCritical: 3,
		exposure.SeverityHigh:     7,
		exposure.SeverityMedium:   5,
		exposure.SeverityLow:      2,
	}

	stats, err := svc.GetExposureStats(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	byState, ok := stats["by_state"].(map[string]int64)
	if !ok {
		t.Fatal("expected by_state to be map[string]int64")
	}
	if byState["active"] != 10 {
		t.Errorf("expected active count 10, got %d", byState["active"])
	}
	if byState["resolved"] != 5 {
		t.Errorf("expected resolved count 5, got %d", byState["resolved"])
	}

	bySeverity, ok := stats["by_severity"].(map[string]int64)
	if !ok {
		t.Fatal("expected by_severity to be map[string]int64")
	}
	if bySeverity["critical"] != 3 {
		t.Errorf("expected critical count 3, got %d", bySeverity["critical"])
	}
	if bySeverity["high"] != 7 {
		t.Errorf("expected high count 7, got %d", bySeverity["high"])
	}

	if repo.countStateCalls != 1 {
		t.Errorf("expected 1 CountByState call, got %d", repo.countStateCalls)
	}
	if repo.countSevCalls != 1 {
		t.Errorf("expected 1 CountBySeverity call, got %d", repo.countSevCalls)
	}
}

func TestExposureService_GetExposureStats_InvalidTenantID(t *testing.T) {
	svc, _, _ := newExposureTestService()

	_, err := svc.GetExposureStats(context.Background(), "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestExposureService_GetExposureStats_StateCountError(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()

	repo.countStateErr = fmt.Errorf("database error")

	_, err := svc.GetExposureStats(context.Background(), tenantID.String())
	if err == nil {
		t.Fatal("expected error from state count")
	}
}

func TestExposureService_GetExposureStats_SeverityCountError(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()

	repo.countSevErr = fmt.Errorf("database error")

	_, err := svc.GetExposureStats(context.Background(), tenantID.String())
	if err == nil {
		t.Fatal("expected error from severity count")
	}
}

func TestExposureService_GetExposureStats_EmptyResults(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	stats, err := svc.GetExposureStats(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	byState, ok := stats["by_state"].(map[string]int64)
	if !ok {
		t.Fatal("expected by_state to be map[string]int64")
	}
	if len(byState) != 0 {
		t.Errorf("expected empty state map, got %d entries", len(byState))
	}
}

// =============================================================================
// DeleteExposure Tests
// =============================================================================

func TestExposureService_DeleteExposure_Success(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	err := svc.DeleteExposure(context.Background(), event.ID().String(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.deleteCalls != 1 {
		t.Errorf("expected 1 Delete call, got %d", repo.deleteCalls)
	}

	// Verify it is gone
	_, err = svc.GetExposure(context.Background(), event.ID().String())
	if err == nil {
		t.Fatal("expected error after deletion")
	}
}

func TestExposureService_DeleteExposure_WithoutTenantID(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	// Empty tenantID should skip tenant check
	err := svc.DeleteExposure(context.Background(), event.ID().String(), "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.deleteCalls != 1 {
		t.Errorf("expected 1 Delete call, got %d", repo.deleteCalls)
	}
}

func TestExposureService_DeleteExposure_InvalidExposureID(t *testing.T) {
	svc, _, _ := newExposureTestService()

	err := svc.DeleteExposure(context.Background(), "not-a-uuid", "")
	if err == nil {
		t.Fatal("expected error for invalid exposure ID")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected not found error, got %v", err)
	}
}

func TestExposureService_DeleteExposure_NotFound(t *testing.T) {
	svc, _, _ := newExposureTestService()

	err := svc.DeleteExposure(context.Background(), shared.NewID().String(), "")
	if err == nil {
		t.Fatal("expected error for non-existent exposure")
	}
}

func TestExposureService_DeleteExposure_CrossTenantIsolation(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantA := shared.NewID()
	tenantB := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantA.String())

	// Try to delete with a different tenant ID
	err := svc.DeleteExposure(context.Background(), event.ID().String(), tenantB.String())
	if err == nil {
		t.Fatal("expected error for cross-tenant deletion")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected not found error for cross-tenant isolation, got %v", err)
	}

	// Verify the event still exists
	_, err = svc.GetExposure(context.Background(), event.ID().String())
	if err != nil {
		t.Fatalf("expected event to still exist, got %v", err)
	}
}

func TestExposureService_DeleteExposure_InvalidTenantID(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	err := svc.DeleteExposure(context.Background(), event.ID().String(), "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestExposureService_DeleteExposure_RepoError(t *testing.T) {
	svc, repo, _ := newExposureTestService()
	tenantID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	repo.deleteErr = fmt.Errorf("delete failed")

	err := svc.DeleteExposure(context.Background(), event.ID().String(), tenantID.String())
	if err == nil {
		t.Fatal("expected error from repo delete")
	}
}

// =============================================================================
// Cross-Tenant Isolation Tests
// =============================================================================

func TestExposureService_CrossTenantIsolation_List(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantA := shared.NewID()
	tenantB := shared.NewID()

	// Create exposures for tenant A
	for i := 0; i < 3; i++ {
		input := validCreateExposureInput(tenantA.String())
		input.Title = fmt.Sprintf("Tenant A Exposure %d", i)
		_, err := svc.CreateExposure(context.Background(), input)
		if err != nil {
			t.Fatalf("failed to create exposure: %v", err)
		}
	}

	// Create exposures for tenant B
	for i := 0; i < 2; i++ {
		input := validCreateExposureInput(tenantB.String())
		input.Title = fmt.Sprintf("Tenant B Exposure %d", i)
		_, err := svc.CreateExposure(context.Background(), input)
		if err != nil {
			t.Fatalf("failed to create exposure: %v", err)
		}
	}

	// List for tenant A
	resultA, err := svc.ListExposures(context.Background(), app.ListExposuresInput{
		TenantID: tenantA.String(),
		Page:     1,
		PerPage:  20,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resultA.Total != 3 {
		t.Errorf("expected 3 exposures for tenant A, got %d", resultA.Total)
	}

	// List for tenant B
	resultB, err := svc.ListExposures(context.Background(), app.ListExposuresInput{
		TenantID: tenantB.String(),
		Page:     1,
		PerPage:  20,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resultB.Total != 2 {
		t.Errorf("expected 2 exposures for tenant B, got %d", resultB.Total)
	}
}

func TestExposureService_CrossTenantIsolation_Delete(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantA := shared.NewID()
	tenantB := shared.NewID()

	eventA := createTestExposureEvent(t, svc, tenantA.String())

	// Tenant B cannot delete tenant A's exposure
	err := svc.DeleteExposure(context.Background(), eventA.ID().String(), tenantB.String())
	if err == nil {
		t.Fatal("expected error for cross-tenant delete")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected not found error, got %v", err)
	}

	// Tenant A can delete their own exposure
	err = svc.DeleteExposure(context.Background(), eventA.ID().String(), tenantA.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestExposureService_CreateExposure_NilDetails(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	input := validCreateExposureInput(tenantID.String())
	input.Details = nil

	event, err := svc.CreateExposure(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error with nil details, got %v", err)
	}

	if event.Details() == nil {
		t.Error("expected details to be initialized (not nil)")
	}
}

func TestExposureService_CreateExposure_EmptyDetails(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	input := validCreateExposureInput(tenantID.String())
	input.Details = map[string]any{}

	event, err := svc.CreateExposure(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error with empty details, got %v", err)
	}

	if len(event.Details()) != 0 {
		t.Errorf("expected empty details, got %d entries", len(event.Details()))
	}
}

func TestExposureService_IngestExposure_WithDescription(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	input := validCreateExposureInput(tenantID.String())
	input.Description = "Detailed description of the exposure"

	event, err := svc.IngestExposure(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if event.Description() != input.Description {
		t.Errorf("expected description %s, got %s", input.Description, event.Description())
	}
}

func TestExposureService_IngestExposure_WithoutDescription(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()

	input := validCreateExposureInput(tenantID.String())
	input.Description = ""

	event, err := svc.IngestExposure(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if event.Description() != "" {
		t.Errorf("expected empty description, got %s", event.Description())
	}
}

func TestExposureService_ResolveExposure_WithEmptyNotes(t *testing.T) {
	svc, _, _ := newExposureTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	event := createTestExposureEvent(t, svc, tenantID.String())

	resolved, err := svc.ResolveExposure(context.Background(), event.ID().String(), userID.String(), "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if resolved.ResolutionNotes() != "" {
		t.Errorf("expected empty resolution notes, got %s", resolved.ResolutionNotes())
	}
}

func TestExposureService_FullLifecycle(t *testing.T) {
	svc, _, historyRepo := newExposureTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// 1. Create
	event := createTestExposureEvent(t, svc, tenantID.String())
	if event.State() != exposure.StateActive {
		t.Fatalf("expected initial state active, got %s", event.State())
	}

	// 2. Resolve
	resolved, err := svc.ResolveExposure(context.Background(), event.ID().String(), userID.String(), "Fixed")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if resolved.State() != exposure.StateResolved {
		t.Fatalf("expected resolved state, got %s", resolved.State())
	}

	// 3. Reactivate
	reactivated, err := svc.ReactivateExposure(context.Background(), event.ID().String(), userID.String())
	if err != nil {
		t.Fatalf("reactivate failed: %v", err)
	}
	if reactivated.State() != exposure.StateActive {
		t.Fatalf("expected active state, got %s", reactivated.State())
	}

	// 4. Accept
	accepted, err := svc.AcceptExposure(context.Background(), event.ID().String(), userID.String(), "Accept risk")
	if err != nil {
		t.Fatalf("accept failed: %v", err)
	}
	if accepted.State() != exposure.StateAccepted {
		t.Fatalf("expected accepted state, got %s", accepted.State())
	}

	// 5. Reactivate again
	reactivated2, err := svc.ReactivateExposure(context.Background(), event.ID().String(), userID.String())
	if err != nil {
		t.Fatalf("second reactivate failed: %v", err)
	}
	if reactivated2.State() != exposure.StateActive {
		t.Fatalf("expected active state, got %s", reactivated2.State())
	}

	// 6. Mark false positive
	fp, err := svc.MarkFalsePositive(context.Background(), event.ID().String(), userID.String(), "Not real")
	if err != nil {
		t.Fatalf("mark false positive failed: %v", err)
	}
	if fp.State() != exposure.StateFalsePositive {
		t.Fatalf("expected false_positive state, got %s", fp.State())
	}

	// 7. Get history
	history, err := svc.GetStateHistory(context.Background(), event.ID().String())
	if err != nil {
		t.Fatalf("get history failed: %v", err)
	}
	if len(history) != 5 {
		t.Errorf("expected 5 history entries (resolve, reactivate, accept, reactivate, false_positive), got %d", len(history))
	}

	// 8. Delete
	err = svc.DeleteExposure(context.Background(), event.ID().String(), tenantID.String())
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	// Verify history repo was called for each transition
	if historyRepo.createCalls != 5 {
		t.Errorf("expected 5 history create calls, got %d", historyRepo.createCalls)
	}
}
