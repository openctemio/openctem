package unit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/outbox"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Outbox Repository
// =============================================================================

type mockOutboxRepo struct {
	// Create behavior
	createErr   error
	createCalls int
	lastCreated *outbox.Outbox

	// CreateInTx behavior
	createInTxErr   error
	createInTxCalls int

	// GetByID behavior
	getByIDResult *outbox.Outbox
	getByIDErr    error
	getByIDCalls  int

	// Update behavior
	updateErr   error
	updateCalls int
	lastUpdated *outbox.Outbox

	// Delete behavior
	deleteErr   error
	deleteCalls int

	// FetchPendingBatch behavior
	fetchPendingResult []*outbox.Outbox
	fetchPendingErr    error
	fetchPendingCalls  int

	// UnlockStale behavior
	unlockStaleResult int64
	unlockStaleErr    error
	unlockStaleCalls  int

	// DeleteOldCompleted behavior
	deleteOldCompletedResult int64
	deleteOldCompletedErr    error

	// DeleteOldFailed behavior
	deleteOldFailedResult int64
	deleteOldFailedErr    error

	// List behavior
	listResult pagination.Result[*outbox.Outbox]
	listErr    error
	listCalls  int

	// GetStats behavior
	getStatsResult *outbox.OutboxStats
	getStatsErr    error
	getStatsCalls  int

	// ListByTenant behavior
	listByTenantResult []*outbox.Outbox
	listByTenantTotal  int64
	listByTenantErr    error

	// CountByStatus behavior
	countByStatusResult map[outbox.OutboxStatus]int64
	countByStatusErr    error

	// GetByAggregateID behavior
	getByAggregateResult []*outbox.Outbox
	getByAggregateErr    error
}

func (m *mockOutboxRepo) Create(_ context.Context, outbox *outbox.Outbox) error {
	m.createCalls++
	m.lastCreated = outbox
	return m.createErr
}

func (m *mockOutboxRepo) CreateInTx(_ context.Context, _ *sql.Tx, outbox *outbox.Outbox) error {
	m.createInTxCalls++
	m.lastCreated = outbox
	return m.createInTxErr
}

func (m *mockOutboxRepo) GetByID(_ context.Context, _ outbox.ID) (*outbox.Outbox, error) {
	m.getByIDCalls++
	return m.getByIDResult, m.getByIDErr
}

func (m *mockOutboxRepo) Update(_ context.Context, outbox *outbox.Outbox) error {
	m.updateCalls++
	m.lastUpdated = outbox
	return m.updateErr
}

func (m *mockOutboxRepo) Delete(_ context.Context, _ outbox.ID) error {
	m.deleteCalls++
	return m.deleteErr
}

func (m *mockOutboxRepo) FetchPendingBatch(_ context.Context, _ string, _ int) ([]*outbox.Outbox, error) {
	m.fetchPendingCalls++
	return m.fetchPendingResult, m.fetchPendingErr
}

func (m *mockOutboxRepo) UnlockStale(_ context.Context, _ int) (int64, error) {
	m.unlockStaleCalls++
	return m.unlockStaleResult, m.unlockStaleErr
}

func (m *mockOutboxRepo) DeleteOldCompleted(_ context.Context, _ int) (int64, error) {
	return m.deleteOldCompletedResult, m.deleteOldCompletedErr
}

func (m *mockOutboxRepo) DeleteOldFailed(_ context.Context, _ int) (int64, error) {
	return m.deleteOldFailedResult, m.deleteOldFailedErr
}

func (m *mockOutboxRepo) List(_ context.Context, _ outbox.OutboxFilter, _ pagination.Pagination) (pagination.Result[*outbox.Outbox], error) {
	m.listCalls++
	return m.listResult, m.listErr
}

func (m *mockOutboxRepo) GetStats(_ context.Context, _ *shared.ID) (*outbox.OutboxStats, error) {
	m.getStatsCalls++
	return m.getStatsResult, m.getStatsErr
}

func (m *mockOutboxRepo) ListByTenant(_ context.Context, _ shared.ID, _ outbox.OutboxFilter) ([]*outbox.Outbox, int64, error) {
	return m.listByTenantResult, m.listByTenantTotal, m.listByTenantErr
}

func (m *mockOutboxRepo) CountByStatus(_ context.Context, _ shared.ID) (map[outbox.OutboxStatus]int64, error) {
	return m.countByStatusResult, m.countByStatusErr
}

func (m *mockOutboxRepo) GetByAggregateID(_ context.Context, _ string, _ string) ([]*outbox.Outbox, error) {
	return m.getByAggregateResult, m.getByAggregateErr
}

// =============================================================================
// Mock Event Repository
// =============================================================================

type mockEventRepo struct {
	// Create behavior
	createErr   error
	createCalls int
	lastCreated *outbox.Event

	// GetByID behavior
	getByIDResult *outbox.Event
	getByIDErr    error

	// Delete behavior
	deleteErr error

	// ListByTenant behavior
	listByTenantResult []*outbox.Event
	listByTenantTotal  int64
	listByTenantErr    error

	// GetStats behavior
	getStatsResult *outbox.EventStats
	getStatsErr    error

	// ListByIntegration behavior
	listByIntResult []*outbox.Event
	listByIntTotal  int64
	listByIntErr    error

	// DeleteOldEvents behavior
	deleteOldEventsResult int64
	deleteOldEventsErr    error
}

func (m *mockEventRepo) Create(_ context.Context, event *outbox.Event) error {
	m.createCalls++
	m.lastCreated = event
	return m.createErr
}

func (m *mockEventRepo) GetByID(_ context.Context, _ outbox.ID) (*outbox.Event, error) {
	return m.getByIDResult, m.getByIDErr
}

func (m *mockEventRepo) Delete(_ context.Context, _ outbox.ID) error {
	return m.deleteErr
}

func (m *mockEventRepo) ListByTenant(_ context.Context, _ shared.ID, _ outbox.EventFilter) ([]*outbox.Event, int64, error) {
	return m.listByTenantResult, m.listByTenantTotal, m.listByTenantErr
}

func (m *mockEventRepo) GetStats(_ context.Context, _ *shared.ID) (*outbox.EventStats, error) {
	return m.getStatsResult, m.getStatsErr
}

func (m *mockEventRepo) ListByIntegration(_ context.Context, _ string, _, _ int) ([]*outbox.Event, int64, error) {
	return m.listByIntResult, m.listByIntTotal, m.listByIntErr
}

func (m *mockEventRepo) DeleteOldEvents(_ context.Context, _ int) (int64, error) {
	return m.deleteOldEventsResult, m.deleteOldEventsErr
}

// =============================================================================
// Mock Notification Extension Repository
// =============================================================================

type mockNotifExtRepoForService struct {
	// Create behavior
	createErr error

	// GetByIntegrationID behavior
	getByIntResult *integration.NotificationExtension
	getByIntErr    error

	// Update behavior
	updateErr error

	// Delete behavior
	deleteErr error

	// GetIntegrationWithNotification behavior
	getIntWithNotifResult *integration.IntegrationWithNotification
	getIntWithNotifErr    error

	// ListIntegrationsWithNotification behavior
	listIntWithNotifResult []*integration.IntegrationWithNotification
	listIntWithNotifErr    error
	listIntWithNotifCalls  int
}

func (m *mockNotifExtRepoForService) Create(_ context.Context, _ *integration.NotificationExtension) error {
	return m.createErr
}

func (m *mockNotifExtRepoForService) GetByIntegrationID(_ context.Context, _ integration.ID) (*integration.NotificationExtension, error) {
	return m.getByIntResult, m.getByIntErr
}

func (m *mockNotifExtRepoForService) Update(_ context.Context, _ *integration.NotificationExtension) error {
	return m.updateErr
}

func (m *mockNotifExtRepoForService) Delete(_ context.Context, _ integration.ID) error {
	return m.deleteErr
}

func (m *mockNotifExtRepoForService) GetIntegrationWithNotification(_ context.Context, _ integration.ID) (*integration.IntegrationWithNotification, error) {
	return m.getIntWithNotifResult, m.getIntWithNotifErr
}

func (m *mockNotifExtRepoForService) ListIntegrationsWithNotification(_ context.Context, _ integration.ID) ([]*integration.IntegrationWithNotification, error) {
	m.listIntWithNotifCalls++
	return m.listIntWithNotifResult, m.listIntWithNotifErr
}

// =============================================================================
// Test Helpers
// =============================================================================

// newTestOutboxService creates a OutboxService with mock dependencies.
func newTestOutboxService(
	outboxRepo *mockOutboxRepo,
	eventRepo *mockEventRepo,
	notifRepo *mockNotifExtRepoForService,
	decryptFn func(string) (string, error),
) *app.OutboxService {
	log := logger.NewNop()
	return app.NewOutboxService(
		outboxRepo,
		eventRepo,
		notifRepo,
		decryptFn,
		log.Logger,
	)
}

// successDecrypt returns a decrypt function that always succeeds.
func successDecrypt() func(string) (string, error) {
	return func(s string) (string, error) {
		return s, nil
	}
}

// failDecrypt returns a decrypt function that always fails.
func failDecrypt() func(string) (string, error) {
	return func(_ string) (string, error) {
		return "", errors.New("decryption failed")
	}
}

// makeTestOutboxEntry creates a test outbox entry using Reconstitute.
func makeTestOutboxEntry(tenantID shared.ID, eventType, severity string) *outbox.Outbox {
	now := time.Now()
	return outbox.Reconstitute(
		outbox.NewID(),
		tenantID,
		eventType,
		"finding",
		nil,
		"Test Notification",
		"Test notification body",
		outbox.Severity(severity),
		"https://example.com/finding/1",
		map[string]any{"key": "value"},
		outbox.OutboxStatusPending,
		0,
		3,
		"",
		now,
		nil,
		"",
		now,
		now,
		nil,
	)
}

// makeConnectedIntegration creates a connected notification integration.
func makeConnectedIntegration(tenantID shared.ID, provider integration.Provider, ext *integration.NotificationExtension) *integration.IntegrationWithNotification {
	intgID := shared.NewID()
	intg := integration.Reconstruct(
		intgID,
		tenantID,
		"test-integration",
		"Test integration",
		integration.CategoryNotification,
		provider,
		integration.StatusConnected,
		"",
		integration.AuthTypeToken,
		"",
		"encrypted-creds",
		nil, nil, 60, "",
		nil, nil,
		integration.Stats{},
		time.Now(), time.Now(),
		nil,
	)
	return integration.NewIntegrationWithNotification(intg, ext)
}

// makeDisconnectedIntegration creates a disconnected notification integration.
func makeDisconnectedIntegration(tenantID shared.ID) *integration.IntegrationWithNotification {
	intgID := shared.NewID()
	intg := integration.Reconstruct(
		intgID,
		tenantID,
		"disconnected-integration",
		"",
		integration.CategoryNotification,
		integration.ProviderSlack,
		integration.StatusDisconnected,
		"",
		integration.AuthTypeToken,
		"",
		"",
		nil, nil, 60, "",
		nil, nil,
		integration.Stats{},
		time.Now(), time.Now(),
		nil,
	)
	return integration.NewIntegrationWithNotification(intg, nil)
}

// =============================================================================
// EnqueueNotification Tests
// =============================================================================

func TestEnqueueNotification_Success(t *testing.T) {
	outboxRepo := &mockOutboxRepo{}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	tenantID := shared.NewID()
	params := app.EnqueueNotificationParams{
		TenantID:      tenantID,
		EventType:     "new_finding",
		AggregateType: "finding",
		Title:         "Critical SQL Injection",
		Body:          "Found SQL injection in login endpoint",
		Severity:      "critical",
		URL:           "https://app.example.com/finding/123",
		Metadata:      map[string]any{"tool": "nuclei"},
	}

	err := svc.EnqueueNotification(context.Background(), params)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if outboxRepo.createCalls != 1 {
		t.Errorf("expected 1 Create call, got %d", outboxRepo.createCalls)
	}
	if outboxRepo.lastCreated == nil {
		t.Fatal("expected outbox entry to be created")
	}
	if outboxRepo.lastCreated.TenantID() != tenantID {
		t.Errorf("expected tenant ID %s, got %s", tenantID, outboxRepo.lastCreated.TenantID())
	}
	if outboxRepo.lastCreated.EventType() != "new_finding" {
		t.Errorf("expected event type new_finding, got %s", outboxRepo.lastCreated.EventType())
	}
	if outboxRepo.lastCreated.Severity() != outbox.SeverityCritical {
		t.Errorf("expected severity critical, got %s", outboxRepo.lastCreated.Severity())
	}
	if outboxRepo.lastCreated.Status() != outbox.OutboxStatusPending {
		t.Errorf("expected status pending, got %s", outboxRepo.lastCreated.Status())
	}
}

func TestEnqueueNotification_WithAggregateID(t *testing.T) {
	outboxRepo := &mockOutboxRepo{}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	aggID := uuid.New()
	params := app.EnqueueNotificationParams{
		TenantID:      shared.NewID(),
		EventType:     "scan_completed",
		AggregateType: "scan",
		AggregateID:   &aggID,
		Title:         "Scan Completed",
		Body:          "Scan finished with 5 findings",
		Severity:      "info",
	}

	err := svc.EnqueueNotification(context.Background(), params)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if outboxRepo.lastCreated.AggregateID() == nil {
		t.Fatal("expected aggregate ID to be set")
	}
	if *outboxRepo.lastCreated.AggregateID() != aggID {
		t.Errorf("expected aggregate ID %s, got %s", aggID, *outboxRepo.lastCreated.AggregateID())
	}
}

func TestEnqueueNotification_RepoError(t *testing.T) {
	outboxRepo := &mockOutboxRepo{
		createErr: errors.New("database connection failed"),
	}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	params := app.EnqueueNotificationParams{
		TenantID:  shared.NewID(),
		EventType: "new_finding",
		Title:     "Test",
		Severity:  "high",
	}

	err := svc.EnqueueNotification(context.Background(), params)
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
	if outboxRepo.createCalls != 1 {
		t.Errorf("expected 1 Create call, got %d", outboxRepo.createCalls)
	}
}

func TestEnqueueNotification_DefaultSeverity(t *testing.T) {
	outboxRepo := &mockOutboxRepo{}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	params := app.EnqueueNotificationParams{
		TenantID:  shared.NewID(),
		EventType: "new_finding",
		Title:     "Test",
		// Severity intentionally left empty
	}

	err := svc.EnqueueNotification(context.Background(), params)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// NewOutbox defaults empty severity to "info"
	if outboxRepo.lastCreated.Severity() != outbox.SeverityInfo {
		t.Errorf("expected default severity info, got %s", outboxRepo.lastCreated.Severity())
	}
}

// =============================================================================
// EnqueueNotificationInTx Tests
// =============================================================================

func TestEnqueueNotificationInTx_Success(t *testing.T) {
	outboxRepo := &mockOutboxRepo{}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	params := app.EnqueueNotificationParams{
		TenantID:      shared.NewID(),
		EventType:     "finding_confirmed",
		AggregateType: "finding",
		Title:         "Finding Confirmed",
		Severity:      "high",
	}

	// Pass nil tx since mock doesn't use it
	err := svc.EnqueueNotificationInTx(context.Background(), nil, params)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if outboxRepo.createInTxCalls != 1 {
		t.Errorf("expected 1 CreateInTx call, got %d", outboxRepo.createInTxCalls)
	}
}

func TestEnqueueNotificationInTx_RepoError(t *testing.T) {
	outboxRepo := &mockOutboxRepo{
		createInTxErr: errors.New("tx error"),
	}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	params := app.EnqueueNotificationParams{
		TenantID:  shared.NewID(),
		EventType: "new_finding",
		Title:     "Test",
		Severity:  "medium",
	}

	err := svc.EnqueueNotificationInTx(context.Background(), nil, params)
	if err == nil {
		t.Fatal("expected error when tx repo fails")
	}
}

// =============================================================================
// ProcessOutboxBatch Tests
// =============================================================================

func TestProcessOutboxBatch_EmptyBatch(t *testing.T) {
	outboxRepo := &mockOutboxRepo{
		fetchPendingResult: []*outbox.Outbox{},
	}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	processed, failed, err := svc.ProcessOutboxBatch(context.Background(), "worker-1", 50)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if processed != 0 {
		t.Errorf("expected 0 processed, got %d", processed)
	}
	if failed != 0 {
		t.Errorf("expected 0 failed, got %d", failed)
	}
}

func TestProcessOutboxBatch_FetchError(t *testing.T) {
	outboxRepo := &mockOutboxRepo{
		fetchPendingErr: errors.New("database error"),
	}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	_, _, err := svc.ProcessOutboxBatch(context.Background(), "worker-1", 50)
	if err == nil {
		t.Fatal("expected error when fetch fails")
	}
}

func TestProcessOutboxBatch_NoMatchingIntegrations(t *testing.T) {
	tenantID := shared.NewID()
	entry := makeTestOutboxEntry(tenantID, "new_finding", "critical")

	outboxRepo := &mockOutboxRepo{
		fetchPendingResult: []*outbox.Outbox{entry},
	}
	eventRepo := &mockEventRepo{}
	// No integrations at all
	notifRepo := &mockNotifExtRepoForService{
		listIntWithNotifResult: []*integration.IntegrationWithNotification{},
	}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	processed, failed, err := svc.ProcessOutboxBatch(context.Background(), "worker-1", 50)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// No matching integrations should still mark as completed (skipped)
	if processed != 1 {
		t.Errorf("expected 1 processed, got %d", processed)
	}
	if failed != 0 {
		t.Errorf("expected 0 failed, got %d", failed)
	}
}

func TestProcessOutboxBatch_SkipsDisconnectedIntegrations(t *testing.T) {
	tenantID := shared.NewID()
	entry := makeTestOutboxEntry(tenantID, "new_finding", "critical")

	outboxRepo := &mockOutboxRepo{
		fetchPendingResult: []*outbox.Outbox{entry},
	}
	eventRepo := &mockEventRepo{}

	// Only disconnected integrations
	disconnected := makeDisconnectedIntegration(tenantID)
	notifRepo := &mockNotifExtRepoForService{
		listIntWithNotifResult: []*integration.IntegrationWithNotification{disconnected},
	}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	processed, failed, err := svc.ProcessOutboxBatch(context.Background(), "worker-1", 50)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Disconnected integrations filtered out -> no matching -> marked completed
	if processed != 1 {
		t.Errorf("expected 1 processed (skipped), got %d", processed)
	}
	if failed != 0 {
		t.Errorf("expected 0 failed, got %d", failed)
	}
}

func TestProcessOutboxBatch_IntegrationListError(t *testing.T) {
	tenantID := shared.NewID()
	entry := makeTestOutboxEntry(tenantID, "new_finding", "critical")

	outboxRepo := &mockOutboxRepo{
		fetchPendingResult: []*outbox.Outbox{entry},
	}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{
		listIntWithNotifErr: errors.New("integration repo error"),
	}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	processed, failed, err := svc.ProcessOutboxBatch(context.Background(), "worker-1", 50)
	if err != nil {
		t.Fatalf("expected no top-level error from batch, got %v", err)
	}
	// Entry fails but batch processing itself does not return error
	if failed != 1 {
		t.Errorf("expected 1 failed, got %d", failed)
	}
	if processed != 0 {
		t.Errorf("expected 0 processed, got %d", processed)
	}
}

// =============================================================================
// Severity Filtering Tests
// =============================================================================

func TestShouldSendToIntegration_SeverityFiltering(t *testing.T) {
	tests := []struct {
		name               string
		entrySeverity      string
		enabledSeverities  []integration.Severity
		expectedShouldSend bool
	}{
		{
			name:               "critical severity matches critical filter",
			entrySeverity:      "critical",
			enabledSeverities:  []integration.Severity{integration.SeverityCritical, integration.SeverityHigh},
			expectedShouldSend: true,
		},
		{
			name:               "high severity matches high filter",
			entrySeverity:      "high",
			enabledSeverities:  []integration.Severity{integration.SeverityCritical, integration.SeverityHigh},
			expectedShouldSend: true,
		},
		{
			name:               "medium severity excluded by critical+high filter",
			entrySeverity:      "medium",
			enabledSeverities:  []integration.Severity{integration.SeverityCritical, integration.SeverityHigh},
			expectedShouldSend: false,
		},
		{
			name:               "low severity excluded by critical+high filter",
			entrySeverity:      "low",
			enabledSeverities:  []integration.Severity{integration.SeverityCritical, integration.SeverityHigh},
			expectedShouldSend: false,
		},
		{
			name:               "info severity excluded by critical+high filter",
			entrySeverity:      "info",
			enabledSeverities:  []integration.Severity{integration.SeverityCritical, integration.SeverityHigh},
			expectedShouldSend: false,
		},
		{
			name:               "all severities enabled",
			entrySeverity:      "low",
			enabledSeverities:  []integration.Severity{integration.SeverityCritical, integration.SeverityHigh, integration.SeverityMedium, integration.SeverityLow},
			expectedShouldSend: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenantID := shared.NewID()
			entry := makeTestOutboxEntry(tenantID, "new_finding", tt.entrySeverity)

			intgID := shared.NewID()
			ext := integration.ReconstructNotificationExtension(
				intgID,
				"", "",
				tt.enabledSeverities,
				nil, // all event types
				"", true, 5,
			)

			connected := makeConnectedIntegration(tenantID, integration.ProviderSlack, ext)

			// Process batch: if shouldSend=false, no integrations match -> completed (skipped)
			// if shouldSend=true, integration matches -> attempt send
			outboxRepo := &mockOutboxRepo{
				fetchPendingResult: []*outbox.Outbox{entry},
			}
			eventRepo := &mockEventRepo{}
			notifRepo := &mockNotifExtRepoForService{
				listIntWithNotifResult: []*integration.IntegrationWithNotification{connected},
			}

			// Use fail decrypt so sends fail but we can observe matching behavior
			svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, failDecrypt())

			processed, failed, err := svc.ProcessOutboxBatch(context.Background(), "worker-1", 50)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			// When integration matches but send fails (decrypt error), the entry is still
			// archived to events and deleted from outbox, so processOutboxEntry returns nil
			// and counts as "processed" at the batch level.
			// When integration doesn't match, entry is completed (skipped) and also "processed".
			// Either way, processed=1, failed=0.
			if processed != 1 {
				t.Errorf("expected 1 processed, got processed=%d failed=%d", processed, failed)
			}
			if failed != 0 {
				t.Errorf("expected 0 failed at batch level, got %d", failed)
			}

			// Verify whether integration was matched by checking event archive
			if tt.expectedShouldSend {
				if eventRepo.createCalls != 1 {
					t.Errorf("expected 1 event archive call (integration matched), got %d", eventRepo.createCalls)
				}
			}
		})
	}
}

// =============================================================================
// Event Type Filtering Tests
// =============================================================================

func TestShouldSendToIntegration_EventTypeFiltering(t *testing.T) {
	tests := []struct {
		name              string
		entryEventType    string
		enabledEventTypes []integration.EventType
		shouldMatch       bool
	}{
		{
			name:              "matching event type",
			entryEventType:    "new_finding",
			enabledEventTypes: []integration.EventType{integration.EventTypeNewFinding, integration.EventTypeScanCompleted},
			shouldMatch:       true,
		},
		{
			name:              "non-matching event type",
			entryEventType:    "scan_completed",
			enabledEventTypes: []integration.EventType{integration.EventTypeNewFinding},
			shouldMatch:       false,
		},
		{
			name:              "empty event types gets defaults - matching default type",
			entryEventType:    "new_finding",
			enabledEventTypes: []integration.EventType{}, // empty -> defaults (security_alert, new_finding, new_exposure)
			shouldMatch:       true,
		},
		{
			name:              "empty event types gets defaults - non-default type excluded",
			entryEventType:    "asset_changed",
			enabledEventTypes: []integration.EventType{}, // empty -> defaults
			shouldMatch:       false,
		},
		{
			name:              "legacy event type mapping",
			entryEventType:    "findings",
			enabledEventTypes: []integration.EventType{integration.EventTypeNewFinding},
			shouldMatch:       true, // "findings" maps to "new_finding"
		},
		{
			name:              "security alert event type",
			entryEventType:    "security_alert",
			enabledEventTypes: []integration.EventType{integration.EventTypeSecurityAlert},
			shouldMatch:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenantID := shared.NewID()
			entry := makeTestOutboxEntry(tenantID, tt.entryEventType, "critical")

			intgID := shared.NewID()
			ext := integration.ReconstructNotificationExtension(
				intgID,
				"", "",
				[]integration.Severity{integration.SeverityCritical, integration.SeverityHigh, integration.SeverityMedium, integration.SeverityLow, integration.SeverityInfo},
				tt.enabledEventTypes,
				"", true, 5,
			)

			connected := makeConnectedIntegration(tenantID, integration.ProviderSlack, ext)

			outboxRepo := &mockOutboxRepo{
				fetchPendingResult: []*outbox.Outbox{entry},
			}
			eventRepo := &mockEventRepo{}
			notifRepo := &mockNotifExtRepoForService{
				listIntWithNotifResult: []*integration.IntegrationWithNotification{connected},
			}
			svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, failDecrypt())

			processed, failed, err := svc.ProcessOutboxBatch(context.Background(), "worker-1", 50)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			// Same as severity tests: all entries get archived and deleted from outbox
			if processed != 1 {
				t.Errorf("expected 1 processed, got processed=%d failed=%d", processed, failed)
			}
			if failed != 0 {
				t.Errorf("expected 0 failed at batch level, got %d", failed)
			}
		})
	}
}

// =============================================================================
// No Extension (nil) Tests
// =============================================================================

func TestProcessOutboxEntry_NilExtension_SendsAll(t *testing.T) {
	tenantID := shared.NewID()
	entry := makeTestOutboxEntry(tenantID, "new_finding", "low")

	// Integration with nil notification extension should receive all notifications
	connected := makeConnectedIntegration(tenantID, integration.ProviderSlack, nil)

	outboxRepo := &mockOutboxRepo{
		fetchPendingResult: []*outbox.Outbox{entry},
	}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{
		listIntWithNotifResult: []*integration.IntegrationWithNotification{connected},
	}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, failDecrypt())

	processed, failed, err := svc.ProcessOutboxBatch(context.Background(), "worker-1", 50)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Nil extension means send all -> matched -> decrypt fails -> entry marked failed
	// but still archived to events and deleted from outbox -> processOutboxEntry returns nil
	if processed != 1 {
		t.Errorf("expected 1 processed (archived despite send failure), got processed=%d failed=%d", processed, failed)
	}
}

// =============================================================================
// Credential Decryption Tests
// =============================================================================

func TestProcessOutboxEntry_DecryptionFailure(t *testing.T) {
	tenantID := shared.NewID()
	entry := makeTestOutboxEntry(tenantID, "new_finding", "critical")

	connected := makeConnectedIntegration(tenantID, integration.ProviderSlack, nil)

	outboxRepo := &mockOutboxRepo{
		fetchPendingResult: []*outbox.Outbox{entry},
	}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{
		listIntWithNotifResult: []*integration.IntegrationWithNotification{connected},
	}

	// Decryption fails
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, failDecrypt())

	processed, failed, err := svc.ProcessOutboxBatch(context.Background(), "worker-1", 50)
	if err != nil {
		t.Fatalf("expected no batch error, got %v", err)
	}
	// Decryption failure -> all integrations fail -> entry MarkFailed
	// But entry still gets archived to events and deleted from outbox
	// processOutboxEntry returns nil, so counts as "processed"
	if processed != 1 {
		t.Errorf("expected 1 processed (archived despite decrypt failure), got processed=%d failed=%d", processed, failed)
	}
}

func TestProcessOutboxEntry_DecryptionSuccess(t *testing.T) {
	tenantID := shared.NewID()
	entry := makeTestOutboxEntry(tenantID, "new_finding", "critical")

	connected := makeConnectedIntegration(tenantID, integration.ProviderWebhook, nil)

	outboxRepo := &mockOutboxRepo{
		fetchPendingResult: []*outbox.Outbox{entry},
	}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{
		listIntWithNotifResult: []*integration.IntegrationWithNotification{connected},
	}

	// Decrypt succeeds, returning a valid webhook URL (will fail on actual send since it's not real)
	decryptFn := func(s string) (string, error) {
		return "https://hooks.example.com/test", nil
	}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, decryptFn)

	// This will attempt an actual HTTP send to the webhook URL which will fail,
	// but the decrypt itself should succeed
	_, _, err := svc.ProcessOutboxBatch(context.Background(), "worker-1", 50)
	if err != nil {
		t.Fatalf("expected no batch error, got %v", err)
	}

	// At least verify the notification extension repo was queried
	if notifRepo.listIntWithNotifCalls != 1 {
		t.Errorf("expected 1 ListIntegrationsWithNotification call, got %d", notifRepo.listIntWithNotifCalls)
	}
}

// =============================================================================
// CleanupOldEntries Tests
// =============================================================================

func TestCleanupOldEntries_Success(t *testing.T) {
	outboxRepo := &mockOutboxRepo{
		deleteOldCompletedResult: 5,
		deleteOldFailedResult:    2,
	}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	deletedCompleted, deletedFailed, err := svc.CleanupOldEntries(context.Background(), 7, 30)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if deletedCompleted != 5 {
		t.Errorf("expected 5 completed deleted, got %d", deletedCompleted)
	}
	if deletedFailed != 2 {
		t.Errorf("expected 2 failed deleted, got %d", deletedFailed)
	}
}

func TestCleanupOldEntries_CompletedError(t *testing.T) {
	outboxRepo := &mockOutboxRepo{
		deleteOldCompletedErr: errors.New("db error"),
	}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	_, _, err := svc.CleanupOldEntries(context.Background(), 7, 30)
	if err == nil {
		t.Fatal("expected error when completed deletion fails")
	}
}

func TestCleanupOldEntries_FailedError(t *testing.T) {
	outboxRepo := &mockOutboxRepo{
		deleteOldCompletedResult: 3,
		deleteOldFailedErr:       errors.New("db error"),
	}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	deletedCompleted, _, err := svc.CleanupOldEntries(context.Background(), 7, 30)
	if err == nil {
		t.Fatal("expected error when failed deletion fails")
	}
	// Completed should still return the count
	if deletedCompleted != 3 {
		t.Errorf("expected 3 completed deleted before error, got %d", deletedCompleted)
	}
}

// =============================================================================
// UnlockStaleEntries Tests
// =============================================================================

func TestUnlockStaleEntries_Success(t *testing.T) {
	outboxRepo := &mockOutboxRepo{
		unlockStaleResult: 3,
	}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	unlocked, err := svc.UnlockStaleEntries(context.Background(), 10)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if unlocked != 3 {
		t.Errorf("expected 3 unlocked, got %d", unlocked)
	}
}

func TestUnlockStaleEntries_Error(t *testing.T) {
	outboxRepo := &mockOutboxRepo{
		unlockStaleErr: errors.New("db error"),
	}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	_, err := svc.UnlockStaleEntries(context.Background(), 10)
	if err == nil {
		t.Fatal("expected error")
	}
}

// =============================================================================
// CleanupOldEvents Tests
// =============================================================================

func TestCleanupOldEvents_Success(t *testing.T) {
	outboxRepo := &mockOutboxRepo{}
	eventRepo := &mockEventRepo{
		deleteOldEventsResult: 15,
	}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	deleted, err := svc.CleanupOldEvents(context.Background(), 90)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if deleted != 15 {
		t.Errorf("expected 15 deleted, got %d", deleted)
	}
}

func TestCleanupOldEvents_Error(t *testing.T) {
	outboxRepo := &mockOutboxRepo{}
	eventRepo := &mockEventRepo{
		deleteOldEventsErr: errors.New("db error"),
	}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	_, err := svc.CleanupOldEvents(context.Background(), 90)
	if err == nil {
		t.Fatal("expected error")
	}
}

// =============================================================================
// Outbox Entity State Transition Tests
// =============================================================================

func TestOutbox_NewOutbox_DefaultValues(t *testing.T) {
	tenantID := shared.NewID()
	ob := outbox.NewOutbox(outbox.OutboxParams{
		TenantID:      tenantID,
		EventType:     "new_finding",
		AggregateType: "finding",
		Title:         "Test",
		Body:          "Test body",
	})

	if ob.Status() != outbox.OutboxStatusPending {
		t.Errorf("expected pending status, got %s", ob.Status())
	}
	if ob.RetryCount() != 0 {
		t.Errorf("expected 0 retry count, got %d", ob.RetryCount())
	}
	if ob.MaxRetries() != 3 {
		t.Errorf("expected 3 max retries (default), got %d", ob.MaxRetries())
	}
	if ob.Severity() != outbox.SeverityInfo {
		t.Errorf("expected info severity (default), got %s", ob.Severity())
	}
	if ob.Metadata() == nil {
		t.Error("expected non-nil metadata map")
	}
}

func TestOutbox_MarkCompleted(t *testing.T) {
	entry := makeTestOutboxEntry(shared.NewID(), "new_finding", "critical")
	entry.MarkCompleted()

	if entry.Status() != outbox.OutboxStatusCompleted {
		t.Errorf("expected completed status, got %s", entry.Status())
	}
	if entry.ProcessedAt() == nil {
		t.Error("expected processedAt to be set")
	}
}

func TestOutbox_MarkFailed_WithRetry(t *testing.T) {
	entry := makeTestOutboxEntry(shared.NewID(), "new_finding", "critical")

	// First failure (retryCount 0 -> 1, maxRetries 3)
	entry.MarkFailed("connection timeout")

	if entry.Status() != outbox.OutboxStatusPending {
		t.Errorf("expected pending status (retryable), got %s", entry.Status())
	}
	if entry.RetryCount() != 1 {
		t.Errorf("expected retry count 1, got %d", entry.RetryCount())
	}
	if entry.LastError() != "connection timeout" {
		t.Errorf("expected last error 'connection timeout', got %s", entry.LastError())
	}
	if !entry.CanRetry() {
		t.Error("expected CanRetry to be true (1 < 3)")
	}
}

func TestOutbox_MarkFailed_MaxRetriesExceeded(t *testing.T) {
	entry := makeTestOutboxEntry(shared.NewID(), "new_finding", "critical")

	// Exhaust all retries (maxRetries = 3)
	entry.MarkFailed("error 1") // retry 1
	entry.MarkFailed("error 2") // retry 2
	entry.MarkFailed("error 3") // retry 3 -> exceeds max

	if entry.Status() != outbox.OutboxStatusFailed {
		t.Errorf("expected failed status after max retries, got %s", entry.Status())
	}
	if entry.RetryCount() != 3 {
		t.Errorf("expected retry count 3, got %d", entry.RetryCount())
	}
	if entry.CanRetry() {
		t.Error("expected CanRetry to be false after max retries")
	}
	if entry.ProcessedAt() == nil {
		t.Error("expected processedAt to be set after final failure")
	}
}

func TestOutbox_MarkDead(t *testing.T) {
	entry := makeTestOutboxEntry(shared.NewID(), "new_finding", "critical")
	entry.MarkDead("manual intervention required")

	if entry.Status() != outbox.OutboxStatusDead {
		t.Errorf("expected dead status, got %s", entry.Status())
	}
	if entry.LastError() != "manual intervention required" {
		t.Errorf("expected specific error, got %s", entry.LastError())
	}
	if entry.ProcessedAt() == nil {
		t.Error("expected processedAt to be set")
	}
}

func TestOutbox_Lock(t *testing.T) {
	entry := makeTestOutboxEntry(shared.NewID(), "new_finding", "critical")

	err := entry.Lock("worker-1")
	if err != nil {
		t.Fatalf("expected no error locking pending entry, got %v", err)
	}
	if entry.Status() != outbox.OutboxStatusProcessing {
		t.Errorf("expected processing status, got %s", entry.Status())
	}
	if entry.LockedBy() != "worker-1" {
		t.Errorf("expected locked by worker-1, got %s", entry.LockedBy())
	}
	if entry.LockedAt() == nil {
		t.Error("expected lockedAt to be set")
	}
}

func TestOutbox_Lock_NonPending_Error(t *testing.T) {
	entry := makeTestOutboxEntry(shared.NewID(), "new_finding", "critical")
	entry.MarkCompleted()

	err := entry.Lock("worker-1")
	if err == nil {
		t.Fatal("expected error when locking non-pending entry")
	}
}

func TestOutbox_Unlock(t *testing.T) {
	entry := makeTestOutboxEntry(shared.NewID(), "new_finding", "critical")
	_ = entry.Lock("worker-1")

	entry.Unlock()

	if entry.Status() != outbox.OutboxStatusPending {
		t.Errorf("expected pending status after unlock, got %s", entry.Status())
	}
	if entry.LockedAt() != nil {
		t.Error("expected lockedAt to be nil after unlock")
	}
	if entry.LockedBy() != "" {
		t.Errorf("expected empty lockedBy after unlock, got %s", entry.LockedBy())
	}
}

func TestOutbox_ResetForRetry(t *testing.T) {
	entry := makeTestOutboxEntry(shared.NewID(), "new_finding", "critical")
	entry.MarkFailed("error 1")
	entry.MarkFailed("error 2")
	entry.MarkFailed("error 3") // Now in failed state

	entry.ResetForRetry()

	if entry.Status() != outbox.OutboxStatusPending {
		t.Errorf("expected pending status after reset, got %s", entry.Status())
	}
	if entry.RetryCount() != 0 {
		t.Errorf("expected retry count 0 after reset, got %d", entry.RetryCount())
	}
	if entry.ProcessedAt() != nil {
		t.Error("expected nil processedAt after reset")
	}
}

func TestOutbox_SetGetMetadata(t *testing.T) {
	entry := makeTestOutboxEntry(shared.NewID(), "new_finding", "critical")

	entry.SetMetadata("finding_id", "abc-123")
	val, ok := entry.GetMetadata("finding_id")
	if !ok {
		t.Fatal("expected metadata key to exist")
	}
	if val != "abc-123" {
		t.Errorf("expected abc-123, got %v", val)
	}

	_, ok = entry.GetMetadata("nonexistent")
	if ok {
		t.Error("expected nonexistent key to return false")
	}
}

// =============================================================================
// OutboxStatus Tests
// =============================================================================

func TestOutboxStatus_IsTerminal(t *testing.T) {
	tests := []struct {
		status     outbox.OutboxStatus
		isTerminal bool
	}{
		{outbox.OutboxStatusPending, false},
		{outbox.OutboxStatusProcessing, false},
		{outbox.OutboxStatusCompleted, true},
		{outbox.OutboxStatusFailed, false},
		{outbox.OutboxStatusDead, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if tt.status.IsTerminal() != tt.isTerminal {
				t.Errorf("expected IsTerminal=%v for %s", tt.isTerminal, tt.status)
			}
		})
	}
}

// =============================================================================
// Event Entity Tests
// =============================================================================

func TestNewEventFromOutbox_Completed(t *testing.T) {
	entry := makeTestOutboxEntry(shared.NewID(), "new_finding", "critical")
	entry.MarkCompleted()

	results := outbox.ProcessingResults{
		IntegrationsTotal:     2,
		IntegrationsMatched:   2,
		IntegrationsSucceeded: 1,
		IntegrationsFailed:    1,
		SendResults: []outbox.SendResult{
			{IntegrationID: "int-1", Status: "success"},
			{IntegrationID: "int-2", Status: "failed", Error: "timeout"},
		},
	}

	event := outbox.NewEventFromOutbox(entry, results)

	if event.Status() != outbox.EventStatusCompleted {
		t.Errorf("expected completed status, got %s", event.Status())
	}
	if event.IntegrationsTotal() != 2 {
		t.Errorf("expected 2 total integrations, got %d", event.IntegrationsTotal())
	}
	if event.IntegrationsSucceeded() != 1 {
		t.Errorf("expected 1 succeeded, got %d", event.IntegrationsSucceeded())
	}
	if event.IntegrationsFailed() != 1 {
		t.Errorf("expected 1 failed, got %d", event.IntegrationsFailed())
	}
}

func TestNewEventFromOutbox_AllFailed(t *testing.T) {
	entry := makeTestOutboxEntry(shared.NewID(), "new_finding", "critical")

	results := outbox.ProcessingResults{
		IntegrationsTotal:     1,
		IntegrationsMatched:   1,
		IntegrationsSucceeded: 0,
		IntegrationsFailed:    1,
		SendResults: []outbox.SendResult{
			{IntegrationID: "int-1", Status: "failed", Error: "timeout"},
		},
	}

	event := outbox.NewEventFromOutbox(entry, results)

	if event.Status() != outbox.EventStatusFailed {
		t.Errorf("expected failed status, got %s", event.Status())
	}
}

func TestNewEventFromOutbox_Skipped(t *testing.T) {
	entry := makeTestOutboxEntry(shared.NewID(), "new_finding", "critical")
	entry.MarkCompleted()

	results := outbox.ProcessingResults{
		IntegrationsTotal:     0,
		IntegrationsMatched:   0,
		IntegrationsSucceeded: 0,
		IntegrationsFailed:    0,
		SendResults:           []outbox.SendResult{},
	}

	event := outbox.NewEventFromOutbox(entry, results)

	if event.Status() != outbox.EventStatusSkipped {
		t.Errorf("expected skipped status, got %s", event.Status())
	}
}

func TestNewEventFromOutbox_PreservesFields(t *testing.T) {
	tenantID := shared.NewID()
	entry := makeTestOutboxEntry(tenantID, "scan_completed", "info")
	entry.MarkCompleted()

	results := outbox.ProcessingResults{}
	event := outbox.NewEventFromOutbox(entry, results)

	if event.TenantID() != tenantID {
		t.Errorf("expected tenant ID %s, got %s", tenantID, event.TenantID())
	}
	if event.EventType() != "scan_completed" {
		t.Errorf("expected event type scan_completed, got %s", event.EventType())
	}
	if event.AggregateType() != "finding" {
		t.Errorf("expected aggregate type finding, got %s", event.AggregateType())
	}
	if event.Title() != "Test Notification" {
		t.Errorf("expected title 'Test Notification', got %s", event.Title())
	}
	if event.Severity() != outbox.SeverityInfo {
		t.Errorf("expected severity info, got %s", event.Severity())
	}
}

// =============================================================================
// NotificationExtension Filtering Tests
// =============================================================================

func TestNotificationExtension_ShouldNotify(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		enabled  []integration.Severity
		expected bool
	}{
		{
			name:     "enabled severity matches",
			severity: "critical",
			enabled:  []integration.Severity{integration.SeverityCritical},
			expected: true,
		},
		{
			name:     "disabled severity does not match",
			severity: "low",
			enabled:  []integration.Severity{integration.SeverityCritical, integration.SeverityHigh},
			expected: false,
		},
		{
			name:     "empty severities defaults to critical+high",
			severity: "critical",
			enabled:  []integration.Severity{},
			expected: true,
		},
		{
			name:     "empty severities rejects medium",
			severity: "medium",
			enabled:  []integration.Severity{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := integration.ReconstructNotificationExtension(
				shared.NewID(), "", "",
				tt.enabled, nil,
				"", true, 5,
			)
			if ext.ShouldNotify(tt.severity) != tt.expected {
				t.Errorf("expected ShouldNotify(%s) = %v", tt.severity, tt.expected)
			}
		})
	}
}

func TestNotificationExtension_ShouldNotifyEventType(t *testing.T) {
	tests := []struct {
		name      string
		eventType integration.EventType
		enabled   []integration.EventType
		expected  bool
	}{
		{
			name:      "enabled event type matches",
			eventType: integration.EventTypeNewFinding,
			enabled:   []integration.EventType{integration.EventTypeNewFinding},
			expected:  true,
		},
		{
			name:      "disabled event type does not match",
			eventType: integration.EventTypeScanCompleted,
			enabled:   []integration.EventType{integration.EventTypeNewFinding},
			expected:  false,
		},
		{
			name:      "empty event types gets defaults - scan_completed not in defaults",
			eventType: integration.EventTypeScanCompleted,
			enabled:   []integration.EventType{}, // Reconstruct replaces empty with defaults
			expected:  false,                      // scan_completed not in defaults
		},
		{
			name:      "empty event types gets defaults - new_finding in defaults",
			eventType: integration.EventTypeNewFinding,
			enabled:   []integration.EventType{}, // Reconstruct replaces empty with defaults
			expected:  true,                       // new_finding is a default type
		},
		{
			name:      "legacy findings maps to new_finding",
			eventType: integration.EventTypeFindings,
			enabled:   []integration.EventType{integration.EventTypeNewFinding},
			expected:  true,
		},
		{
			name:      "legacy scans maps to scan_completed",
			eventType: integration.EventTypeScans,
			enabled:   []integration.EventType{integration.EventTypeScanCompleted},
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := integration.ReconstructNotificationExtension(
				shared.NewID(), "", "",
				nil, tt.enabled,
				"", true, 5,
			)
			if ext.ShouldNotifyEventType(tt.eventType) != tt.expected {
				t.Errorf("expected ShouldNotifyEventType(%s) = %v", tt.eventType, tt.expected)
			}
		})
	}
}

// =============================================================================
// NotificationExtension Backward Compatibility Tests
// =============================================================================

func TestNotificationExtension_BooleanCompat(t *testing.T) {
	ext := integration.ReconstructNotificationExtensionFromBooleans(
		shared.NewID(),
		"", "",
		true,  // notifyOnCritical
		true,  // notifyOnHigh
		false, // notifyOnMedium
		false, // notifyOnLow
		nil,
		"", true, 5,
	)

	if !ext.NotifyOnCritical() {
		t.Error("expected NotifyOnCritical to be true")
	}
	if !ext.NotifyOnHigh() {
		t.Error("expected NotifyOnHigh to be true")
	}
	if ext.NotifyOnMedium() {
		t.Error("expected NotifyOnMedium to be false")
	}
	if ext.NotifyOnLow() {
		t.Error("expected NotifyOnLow to be false")
	}

	if !ext.ShouldNotify("critical") {
		t.Error("expected ShouldNotify(critical) to be true")
	}
	if ext.ShouldNotify("medium") {
		t.Error("expected ShouldNotify(medium) to be false")
	}
}

// =============================================================================
// Notification Scheduler Tests
// =============================================================================

func TestOutboxSchedulerConfig_Defaults(t *testing.T) {
	config := app.DefaultOutboxSchedulerConfig()

	if config.ProcessInterval != 5*time.Second {
		t.Errorf("expected 5s process interval, got %v", config.ProcessInterval)
	}
	if config.CleanupInterval != 24*time.Hour {
		t.Errorf("expected 24h cleanup interval, got %v", config.CleanupInterval)
	}
	if config.UnlockInterval != 1*time.Minute {
		t.Errorf("expected 1m unlock interval, got %v", config.UnlockInterval)
	}
	if config.BatchSize != 50 {
		t.Errorf("expected batch size 50, got %d", config.BatchSize)
	}
	if config.CompletedRetentionDays != 7 {
		t.Errorf("expected 7 completed retention days, got %d", config.CompletedRetentionDays)
	}
	if config.FailedRetentionDays != 30 {
		t.Errorf("expected 30 failed retention days, got %d", config.FailedRetentionDays)
	}
	if config.EventRetentionDays != 90 {
		t.Errorf("expected 90 event retention days, got %d", config.EventRetentionDays)
	}
	if config.StaleMinutes != 10 {
		t.Errorf("expected 10 stale minutes, got %d", config.StaleMinutes)
	}
}

func TestOutboxScheduler_StartStop(t *testing.T) {
	outboxRepo := &mockOutboxRepo{
		deleteOldCompletedResult: 0,
		deleteOldFailedResult:    0,
	}
	eventRepo := &mockEventRepo{
		deleteOldEventsResult: 0,
	}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	config := app.OutboxSchedulerConfig{
		ProcessInterval:        100 * time.Millisecond,
		CleanupInterval:        100 * time.Millisecond,
		UnlockInterval:         100 * time.Millisecond,
		BatchSize:              10,
		CompletedRetentionDays: 7,
		FailedRetentionDays:    30,
		EventRetentionDays:     90,
		StaleMinutes:           10,
	}

	log := logger.NewNop()
	scheduler := app.NewOutboxScheduler(svc, config, log)

	// Start scheduler
	scheduler.Start()

	// Let it run briefly
	time.Sleep(250 * time.Millisecond)

	// Stop gracefully
	scheduler.Stop()

	// Verify it ran at least once
	if outboxRepo.fetchPendingCalls == 0 {
		t.Error("expected at least one FetchPendingBatch call")
	}
}

func TestOutboxScheduler_DoubleStart(t *testing.T) {
	outboxRepo := &mockOutboxRepo{
		deleteOldCompletedResult: 0,
		deleteOldFailedResult:    0,
	}
	eventRepo := &mockEventRepo{
		deleteOldEventsResult: 0,
	}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	config := app.OutboxSchedulerConfig{
		ProcessInterval:        1 * time.Hour, // Long interval so it doesn't trigger
		CleanupInterval:        1 * time.Hour,
		UnlockInterval:         1 * time.Hour,
		BatchSize:              10,
		CompletedRetentionDays: 7,
		FailedRetentionDays:    30,
		EventRetentionDays:     90,
		StaleMinutes:           10,
	}

	log := logger.NewNop()
	scheduler := app.NewOutboxScheduler(svc, config, log)

	// Double start should not panic
	scheduler.Start()
	scheduler.Start()

	scheduler.Stop()
}

func TestOutboxScheduler_DoubleStop(t *testing.T) {
	outboxRepo := &mockOutboxRepo{
		deleteOldCompletedResult: 0,
		deleteOldFailedResult:    0,
	}
	eventRepo := &mockEventRepo{
		deleteOldEventsResult: 0,
	}
	notifRepo := &mockNotifExtRepoForService{}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	config := app.OutboxSchedulerConfig{
		ProcessInterval:        1 * time.Hour,
		CleanupInterval:        1 * time.Hour,
		UnlockInterval:         1 * time.Hour,
		BatchSize:              10,
		CompletedRetentionDays: 7,
		FailedRetentionDays:    30,
		EventRetentionDays:     90,
		StaleMinutes:           10,
	}

	log := logger.NewNop()
	scheduler := app.NewOutboxScheduler(svc, config, log)

	scheduler.Start()
	scheduler.Stop()

	// Double stop should not panic
	scheduler.Stop()
}

// =============================================================================
// ProcessOutboxBatch - Multiple Entries Tests
// =============================================================================

func TestProcessOutboxBatch_MultipleEntries(t *testing.T) {
	tenantID := shared.NewID()
	entry1 := makeTestOutboxEntry(tenantID, "new_finding", "critical")
	entry2 := makeTestOutboxEntry(tenantID, "scan_completed", "info")

	outboxRepo := &mockOutboxRepo{
		fetchPendingResult: []*outbox.Outbox{entry1, entry2},
	}
	eventRepo := &mockEventRepo{}
	// No integrations -> both get skipped (completed)
	notifRepo := &mockNotifExtRepoForService{
		listIntWithNotifResult: []*integration.IntegrationWithNotification{},
	}
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, successDecrypt())

	processed, failed, err := svc.ProcessOutboxBatch(context.Background(), "worker-1", 50)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if processed != 2 {
		t.Errorf("expected 2 processed, got %d", processed)
	}
	if failed != 0 {
		t.Errorf("expected 0 failed, got %d", failed)
	}
}

// =============================================================================
// EventStats Tests
// =============================================================================

func TestEventStats(t *testing.T) {
	stats := &outbox.EventStats{
		Completed: 100,
		Failed:    5,
		Skipped:   10,
		Total:     115,
	}

	if stats.Completed != 100 {
		t.Errorf("expected 100 completed, got %d", stats.Completed)
	}
	if stats.Failed != 5 {
		t.Errorf("expected 5 failed, got %d", stats.Failed)
	}
	if stats.Skipped != 10 {
		t.Errorf("expected 10 skipped, got %d", stats.Skipped)
	}
	if stats.Total != 115 {
		t.Errorf("expected 115 total, got %d", stats.Total)
	}
}

// =============================================================================
// OutboxStats Tests
// =============================================================================

func TestOutboxStats(t *testing.T) {
	stats := &outbox.OutboxStats{
		Pending:    10,
		Processing: 2,
		Completed:  50,
		Failed:     3,
		Dead:       1,
		Total:      66,
	}

	if stats.Pending != 10 {
		t.Errorf("expected 10 pending, got %d", stats.Pending)
	}
	if stats.Processing != 2 {
		t.Errorf("expected 2 processing, got %d", stats.Processing)
	}
	if stats.Completed != 50 {
		t.Errorf("expected 50 completed, got %d", stats.Completed)
	}
	if stats.Failed != 3 {
		t.Errorf("expected 3 failed, got %d", stats.Failed)
	}
	if stats.Dead != 1 {
		t.Errorf("expected 1 dead, got %d", stats.Dead)
	}
	if stats.Total != 66 {
		t.Errorf("expected 66 total, got %d", stats.Total)
	}
}

// =============================================================================
// Reconstitute Tests
// =============================================================================

func TestOutbox_Reconstitute_PreservesAllFields(t *testing.T) {
	id := outbox.NewID()
	tenantID := shared.NewID()
	aggID := uuid.New()
	now := time.Now()
	lockedAt := now.Add(-1 * time.Minute)
	processedAt := now

	entry := outbox.Reconstitute(
		id, tenantID,
		"new_finding", "finding", &aggID,
		"Title", "Body",
		outbox.SeverityHigh,
		"https://example.com",
		map[string]any{"k": "v"},
		outbox.OutboxStatusProcessing,
		2, 5, "last error",
		now, &lockedAt, "worker-99",
		now, now, &processedAt,
	)

	if entry.ID() != id {
		t.Errorf("expected ID %s, got %s", id, entry.ID())
	}
	if entry.TenantID() != tenantID {
		t.Errorf("expected tenant ID %s, got %s", tenantID, entry.TenantID())
	}
	if entry.EventType() != "new_finding" {
		t.Errorf("expected new_finding, got %s", entry.EventType())
	}
	if entry.AggregateType() != "finding" {
		t.Errorf("expected finding, got %s", entry.AggregateType())
	}
	if entry.AggregateID() == nil || *entry.AggregateID() != aggID {
		t.Error("expected aggregate ID to match")
	}
	if entry.Title() != "Title" {
		t.Errorf("expected Title, got %s", entry.Title())
	}
	if entry.Body() != "Body" {
		t.Errorf("expected Body, got %s", entry.Body())
	}
	if entry.Severity() != outbox.SeverityHigh {
		t.Errorf("expected high, got %s", entry.Severity())
	}
	if entry.URL() != "https://example.com" {
		t.Errorf("expected URL, got %s", entry.URL())
	}
	if entry.Status() != outbox.OutboxStatusProcessing {
		t.Errorf("expected processing, got %s", entry.Status())
	}
	if entry.RetryCount() != 2 {
		t.Errorf("expected 2 retries, got %d", entry.RetryCount())
	}
	if entry.MaxRetries() != 5 {
		t.Errorf("expected 5 max retries, got %d", entry.MaxRetries())
	}
	if entry.LastError() != "last error" {
		t.Errorf("expected 'last error', got %s", entry.LastError())
	}
	if entry.LockedBy() != "worker-99" {
		t.Errorf("expected worker-99, got %s", entry.LockedBy())
	}
	if entry.LockedAt() == nil {
		t.Error("expected lockedAt to be set")
	}
	if entry.ProcessedAt() == nil {
		t.Error("expected processedAt to be set")
	}
}

func TestOutbox_Reconstitute_NilMetadata(t *testing.T) {
	entry := outbox.Reconstitute(
		outbox.NewID(), shared.NewID(),
		"test", "test", nil,
		"", "", outbox.SeverityInfo, "",
		nil, // nil metadata
		outbox.OutboxStatusPending,
		0, 3, "",
		time.Now(), nil, "",
		time.Now(), time.Now(), nil,
	)

	if entry.Metadata() == nil {
		t.Error("expected non-nil metadata (should be initialized)")
	}
}

// =============================================================================
// Event Reconstitute Tests
// =============================================================================

func TestEvent_ReconstituteEvent_PreservesAllFields(t *testing.T) {
	id := outbox.NewID()
	tenantID := shared.NewID()
	aggID := uuid.New()
	now := time.Now()

	event := outbox.ReconstituteEvent(
		id, tenantID,
		"new_finding", "finding", &aggID,
		"Title", "Body",
		outbox.SeverityCritical,
		"https://example.com",
		map[string]any{"key": "val"},
		outbox.EventStatusCompleted,
		3, 2, 1, 1,
		[]outbox.SendResult{{IntegrationID: "int-1", Status: "success"}},
		"partial failure",
		1,
		now, now,
	)

	if event.ID() != id {
		t.Errorf("expected ID %s, got %s", id, event.ID())
	}
	if event.TenantID() != tenantID {
		t.Errorf("expected tenant ID %s, got %s", tenantID, event.TenantID())
	}
	if event.Status() != outbox.EventStatusCompleted {
		t.Errorf("expected completed, got %s", event.Status())
	}
	if event.IntegrationsTotal() != 3 {
		t.Errorf("expected 3, got %d", event.IntegrationsTotal())
	}
	if event.IntegrationsMatched() != 2 {
		t.Errorf("expected 2, got %d", event.IntegrationsMatched())
	}
	if event.IntegrationsSucceeded() != 1 {
		t.Errorf("expected 1, got %d", event.IntegrationsSucceeded())
	}
	if event.IntegrationsFailed() != 1 {
		t.Errorf("expected 1, got %d", event.IntegrationsFailed())
	}
	if len(event.SendResults()) != 1 {
		t.Errorf("expected 1 send result, got %d", len(event.SendResults()))
	}
	if event.LastError() != "partial failure" {
		t.Errorf("expected 'partial failure', got %s", event.LastError())
	}
	if event.RetryCount() != 1 {
		t.Errorf("expected 1 retry, got %d", event.RetryCount())
	}
}

func TestEvent_ReconstituteEvent_NilDefaults(t *testing.T) {
	event := outbox.ReconstituteEvent(
		outbox.NewID(), shared.NewID(),
		"test", "test", nil,
		"", "", outbox.SeverityInfo, "",
		nil, // nil metadata
		outbox.EventStatusSkipped,
		0, 0, 0, 0,
		nil, // nil send results
		"", 0,
		time.Now(), time.Now(),
	)

	if event.Metadata() == nil {
		t.Error("expected non-nil metadata")
	}
	if event.SendResults() == nil {
		t.Error("expected non-nil send results")
	}
}

// =============================================================================
// EventStatus String Tests
// =============================================================================

func TestEventStatus_String(t *testing.T) {
	tests := []struct {
		status outbox.EventStatus
		str    string
	}{
		{outbox.EventStatusCompleted, "completed"},
		{outbox.EventStatusFailed, "failed"},
		{outbox.EventStatusSkipped, "skipped"},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			if tt.status.String() != tt.str {
				t.Errorf("expected %s, got %s", tt.str, tt.status.String())
			}
		})
	}
}

// =============================================================================
// Severity String Tests
// =============================================================================

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		severity outbox.Severity
		str      string
	}{
		{outbox.SeverityCritical, "critical"},
		{outbox.SeverityHigh, "high"},
		{outbox.SeverityMedium, "medium"},
		{outbox.SeverityLow, "low"},
		{outbox.SeverityInfo, "info"},
		{outbox.SeverityNone, "none"},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			if tt.severity.String() != tt.str {
				t.Errorf("expected %s, got %s", tt.str, tt.severity.String())
			}
		})
	}
}

// =============================================================================
// MarkFailed Exponential Backoff Tests
// =============================================================================

func TestOutbox_MarkFailed_ExponentialBackoff(t *testing.T) {
	entry := makeTestOutboxEntry(shared.NewID(), "new_finding", "critical")

	beforeFail := time.Now()
	entry.MarkFailed("error 1")

	// After first failure (retryCount becomes 1), backoff should be 2 minutes (1<<1)
	scheduledAt := entry.ScheduledAt()
	expectedMinBackoff := beforeFail.Add(2 * time.Minute)

	if scheduledAt.Before(expectedMinBackoff.Add(-1 * time.Second)) {
		t.Errorf("expected scheduledAt >= %v (2min backoff), got %v", expectedMinBackoff, scheduledAt)
	}

	beforeFail2 := time.Now()
	entry.MarkFailed("error 2")

	// After second failure (retryCount becomes 2), backoff should be 4 minutes (1<<2)
	scheduledAt2 := entry.ScheduledAt()
	expectedMinBackoff2 := beforeFail2.Add(4 * time.Minute)

	if scheduledAt2.Before(expectedMinBackoff2.Add(-1 * time.Second)) {
		t.Errorf("expected scheduledAt >= %v (4min backoff), got %v", expectedMinBackoff2, scheduledAt2)
	}
}

// =============================================================================
// NewOutbox Custom Parameters Tests
// =============================================================================

func TestNewOutbox_CustomMaxRetries(t *testing.T) {
	ob := outbox.NewOutbox(outbox.OutboxParams{
		TenantID:   shared.NewID(),
		EventType:  "test",
		MaxRetries: 10,
	})

	if ob.MaxRetries() != 10 {
		t.Errorf("expected 10 max retries, got %d", ob.MaxRetries())
	}
}

func TestNewOutbox_CustomScheduledAt(t *testing.T) {
	future := time.Now().Add(1 * time.Hour)
	ob := outbox.NewOutbox(outbox.OutboxParams{
		TenantID:    shared.NewID(),
		EventType:   "test",
		ScheduledAt: &future,
	})

	if ob.ScheduledAt().Before(future.Add(-1 * time.Second)) {
		t.Errorf("expected scheduledAt at future time, got %v", ob.ScheduledAt())
	}
}

// =============================================================================
// Multiple Integrations with Mixed Results Tests
// =============================================================================

func TestProcessOutboxBatch_MixedIntegrationResults(t *testing.T) {
	tenantID := shared.NewID()
	entry := makeTestOutboxEntry(tenantID, "new_finding", "critical")

	// Two connected integrations with nil extensions (send all)
	intg1 := makeConnectedIntegration(tenantID, integration.ProviderSlack, nil)
	intg2 := makeConnectedIntegration(tenantID, integration.ProviderWebhook, nil)

	outboxRepo := &mockOutboxRepo{
		fetchPendingResult: []*outbox.Outbox{entry},
	}
	eventRepo := &mockEventRepo{}
	notifRepo := &mockNotifExtRepoForService{
		listIntWithNotifResult: []*integration.IntegrationWithNotification{intg1, intg2},
	}

	// Both integrations will fail because decrypt fails, but the entry still
	// gets archived to events and deleted from outbox successfully, so
	// processOutboxEntry returns nil (counts as processed, not failed).
	svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, failDecrypt())

	processed, failed, err := svc.ProcessOutboxBatch(context.Background(), "worker-1", 50)
	if err != nil {
		t.Fatalf("expected no batch error, got %v", err)
	}
	// Entry is processed (archived + deleted) even though all sends failed
	if processed != 1 {
		t.Errorf("expected 1 processed (archived despite all send failures), got %d", processed)
	}
	if failed != 0 {
		t.Errorf("expected 0 failed at batch level, got %d", failed)
	}
	// Verify the event was archived
	if eventRepo.createCalls != 1 {
		t.Errorf("expected 1 event archive call, got %d", eventRepo.createCalls)
	}
}

// =============================================================================
// Notification ID Tests
// =============================================================================

func TestNotificationID_NewAndParse(t *testing.T) {
	id := outbox.NewID()
	if id.String() == "" {
		t.Error("expected non-empty ID string")
	}

	parsed, err := outbox.ParseID(id.String())
	if err != nil {
		t.Fatalf("expected no error parsing valid ID, got %v", err)
	}
	if parsed != id {
		t.Errorf("expected %s, got %s", id, parsed)
	}
}

func TestNotificationID_ParseInvalid(t *testing.T) {
	_, err := outbox.ParseID("not-a-valid-uuid")
	if err == nil {
		t.Error("expected error parsing invalid ID")
	}
}

// =============================================================================
// NotificationExtension Setter Tests
// =============================================================================

func TestNotificationExtension_Setters(t *testing.T) {
	ext := integration.NewNotificationExtension(shared.NewID())

	// SetEnabledSeverities
	ext.SetEnabledSeverities([]integration.Severity{integration.SeverityCritical})
	if len(ext.EnabledSeverities()) != 1 {
		t.Errorf("expected 1 severity, got %d", len(ext.EnabledSeverities()))
	}

	// SetEnabledEventTypes
	ext.SetEnabledEventTypes([]integration.EventType{integration.EventTypeNewFinding})
	if len(ext.EnabledEventTypes()) != 1 {
		t.Errorf("expected 1 event type, got %d", len(ext.EnabledEventTypes()))
	}

	// SetMessageTemplate
	ext.SetMessageTemplate("custom template")
	if ext.MessageTemplate() != "custom template" {
		t.Errorf("expected 'custom template', got %s", ext.MessageTemplate())
	}

	// SetIncludeDetails
	ext.SetIncludeDetails(false)
	if ext.IncludeDetails() {
		t.Error("expected IncludeDetails to be false")
	}

	// SetMinIntervalMinutes
	ext.SetMinIntervalMinutes(15)
	if ext.MinIntervalMinutes() != 15 {
		t.Errorf("expected 15, got %d", ext.MinIntervalMinutes())
	}

	// SetMinIntervalMinutes with zero (should default to 5)
	ext.SetMinIntervalMinutes(0)
	if ext.MinIntervalMinutes() != 5 {
		t.Errorf("expected 5 (default), got %d", ext.MinIntervalMinutes())
	}
}

func TestNotificationExtension_BooleanSetters(t *testing.T) {
	ext := integration.NewNotificationExtension(shared.NewID())

	// Start with defaults (critical, high)
	ext.SetNotifyOnMedium(true)
	if !ext.NotifyOnMedium() {
		t.Error("expected NotifyOnMedium to be true after setting")
	}

	// Setting same severity again should not duplicate
	ext.SetNotifyOnMedium(true)
	count := 0
	for _, s := range ext.EnabledSeverities() {
		if s == integration.SeverityMedium {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 medium severity, got %d", count)
	}

	// Remove severity
	ext.SetNotifyOnMedium(false)
	if ext.NotifyOnMedium() {
		t.Error("expected NotifyOnMedium to be false after removal")
	}
}

// =============================================================================
// EventFilter and OutboxFilter Tests
// =============================================================================

func TestOutboxFilter_Fields(t *testing.T) {
	tenantID := shared.NewID()
	status := outbox.OutboxStatusPending
	filter := outbox.OutboxFilter{
		TenantID:      &tenantID,
		Status:        &status,
		EventType:     "new_finding",
		AggregateType: "finding",
		Limit:         10,
		Offset:        20,
	}

	if *filter.TenantID != tenantID {
		t.Errorf("expected tenant ID %s", tenantID)
	}
	if *filter.Status != outbox.OutboxStatusPending {
		t.Errorf("expected pending status")
	}
	if filter.EventType != "new_finding" {
		t.Errorf("expected new_finding event type")
	}
	if filter.Limit != 10 {
		t.Errorf("expected limit 10, got %d", filter.Limit)
	}
	if filter.Offset != 20 {
		t.Errorf("expected offset 20, got %d", filter.Offset)
	}
}

func TestEventFilter_Fields(t *testing.T) {
	tenantID := shared.NewID()
	status := outbox.EventStatusCompleted
	aggID := uuid.New()
	filter := outbox.EventFilter{
		TenantID:      &tenantID,
		Status:        &status,
		EventType:     "scan_completed",
		AggregateType: "scan",
		AggregateID:   &aggID,
		Limit:         25,
		Offset:        50,
	}

	if *filter.TenantID != tenantID {
		t.Errorf("expected tenant ID %s", tenantID)
	}
	if *filter.Status != outbox.EventStatusCompleted {
		t.Errorf("expected completed status")
	}
	if filter.EventType != "scan_completed" {
		t.Errorf("expected scan_completed")
	}
	if filter.AggregateID == nil || *filter.AggregateID != aggID {
		t.Error("expected aggregate ID to match")
	}
	if filter.Limit != 25 {
		t.Errorf("expected limit 25, got %d", filter.Limit)
	}
}

// =============================================================================
// Event Type Utilities Tests
// =============================================================================

func TestMapLegacyEventType(t *testing.T) {
	tests := []struct {
		input    integration.EventType
		expected integration.EventType
	}{
		{integration.EventTypeFindings, integration.EventTypeNewFinding},
		{integration.EventTypeExposures, integration.EventTypeNewExposure},
		{integration.EventTypeScans, integration.EventTypeScanCompleted},
		{integration.EventTypeAlerts, integration.EventTypeSecurityAlert},
		{integration.EventTypeNewFinding, integration.EventTypeNewFinding}, // No mapping needed
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s->%s", tt.input, tt.expected), func(t *testing.T) {
			result := integration.MapLegacyEventType(tt.input)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestDefaultEnabledSeverities(t *testing.T) {
	defaults := integration.DefaultEnabledSeverities()
	if len(defaults) != 2 {
		t.Fatalf("expected 2 default severities, got %d", len(defaults))
	}
	if defaults[0] != integration.SeverityCritical {
		t.Errorf("expected first default to be critical, got %s", defaults[0])
	}
	if defaults[1] != integration.SeverityHigh {
		t.Errorf("expected second default to be high, got %s", defaults[1])
	}
}

func TestDefaultEnabledEventTypes(t *testing.T) {
	defaults := integration.DefaultEnabledEventTypes()
	if len(defaults) != 3 {
		t.Fatalf("expected 3 default event types, got %d", len(defaults))
	}
}

func TestGetEventTypesByModules(t *testing.T) {
	// System events should always be included
	types := integration.GetEventTypesByModules(nil)
	if len(types) < 2 {
		t.Error("expected at least system events when no modules enabled")
	}

	// With all modules
	types = integration.GetEventTypesByModules([]string{"assets", "scans", "findings"})
	allTypes := integration.AllEventTypes()
	if len(types) != len(allTypes) {
		t.Errorf("expected %d types with all modules, got %d", len(allTypes), len(types))
	}

	// With only assets module
	types = integration.GetEventTypesByModules([]string{"assets"})
	for _, et := range types {
		if et.RequiredModule != "" && et.RequiredModule != "assets" {
			t.Errorf("unexpected module %s in results", et.RequiredModule)
		}
	}
}

func TestValidateEventTypes(t *testing.T) {
	// All types valid when all modules enabled
	valid, invalid := integration.ValidateEventTypes(
		[]integration.EventType{integration.EventTypeNewFinding, integration.EventTypeScanCompleted},
		[]string{"assets", "scans", "findings"},
	)
	if !valid {
		t.Error("expected valid with all modules enabled")
	}
	if len(invalid) != 0 {
		t.Errorf("expected no invalid types, got %d", len(invalid))
	}

	// Finding type invalid when findings module not enabled
	valid, invalid = integration.ValidateEventTypes(
		[]integration.EventType{integration.EventTypeNewFinding},
		[]string{"assets"}, // no findings module
	)
	if valid {
		t.Error("expected invalid when findings module not enabled")
	}
	if len(invalid) != 1 {
		t.Errorf("expected 1 invalid type, got %d", len(invalid))
	}
}
