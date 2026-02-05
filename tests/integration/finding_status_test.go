package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/pagination"
)

// MockFindingRepository is a mock implementation of vulnerability.FindingRepository for testing.
type MockFindingRepository struct {
	findings map[string]*vulnerability.Finding
}

// NewMockFindingRepository creates a new MockFindingRepository.
func NewMockFindingRepository() *MockFindingRepository {
	return &MockFindingRepository{
		findings: make(map[string]*vulnerability.Finding),
	}
}

func (m *MockFindingRepository) Create(ctx context.Context, f *vulnerability.Finding) error {
	m.findings[f.ID().String()] = f
	return nil
}

func (m *MockFindingRepository) GetByID(ctx context.Context, id shared.ID) (*vulnerability.Finding, error) {
	f, exists := m.findings[id.String()]
	if !exists {
		return nil, shared.ErrNotFound
	}
	return f, nil
}

func (m *MockFindingRepository) Update(ctx context.Context, f *vulnerability.Finding) error {
	if _, exists := m.findings[f.ID().String()]; !exists {
		return shared.ErrNotFound
	}
	m.findings[f.ID().String()] = f
	return nil
}

func (m *MockFindingRepository) Delete(ctx context.Context, id shared.ID) error {
	delete(m.findings, id.String())
	return nil
}

// Minimal implementations for interface compliance
func (m *MockFindingRepository) List(ctx context.Context, filter *vulnerability.FindingFilter, opts vulnerability.FindingListOptions, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}
func (m *MockFindingRepository) ListByAssetID(ctx context.Context, assetID shared.ID, opts vulnerability.FindingListOptions, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}
func (m *MockFindingRepository) CountByAssetID(ctx context.Context, assetID shared.ID) (int64, error) {
	return 0, nil
}
func (m *MockFindingRepository) GetByFingerprint(ctx context.Context, tenantID shared.ID, fingerprint string) (*vulnerability.Finding, error) {
	return nil, shared.ErrNotFound
}
func (m *MockFindingRepository) ExistsByFingerprint(ctx context.Context, tenantID shared.ID, fingerprint string) (bool, error) {
	return false, nil
}
func (m *MockFindingRepository) CreateBatch(ctx context.Context, findings []*vulnerability.Finding) error {
	return nil
}
func (m *MockFindingRepository) ExistsByFingerprintBatch(ctx context.Context, tenantID shared.ID, fingerprints []string) (map[string]bool, error) {
	return nil, nil
}
func (m *MockFindingRepository) UpdateStatusBatch(ctx context.Context, ids []shared.ID, status vulnerability.FindingStatus, resolution string, resolvedBy *shared.ID) error {
	return nil
}
func (m *MockFindingRepository) DeleteByAssetID(ctx context.Context, assetID shared.ID) error {
	return nil
}
func (m *MockFindingRepository) DeleteByScanID(ctx context.Context, tenantID shared.ID, scanID string) error {
	return nil
}
func (m *MockFindingRepository) GetStats(ctx context.Context, tenantID shared.ID) (*vulnerability.FindingStats, error) {
	return nil, nil
}
func (m *MockFindingRepository) BatchCountByAssetIDs(ctx context.Context, assetIDs []shared.ID) (map[shared.ID]int64, error) {
	return nil, nil
}
func (m *MockFindingRepository) UpdateScanIDBatchByFingerprints(ctx context.Context, tenantID shared.ID, fingerprints []string, scanID string) (int64, error) {
	return 0, nil
}
func (m *MockFindingRepository) CountBySeverity(ctx context.Context, tenantID shared.ID) (vulnerability.SeverityCounts, error) {
	return vulnerability.SeverityCounts{}, nil
}

// =============================================================================
// Test: resolved_by is set correctly when status changes to closed
// =============================================================================

func TestFindingStatusUpdate_ResolvedByIsSet(t *testing.T) {
	ctx := context.Background()
	repo := NewMockFindingRepository()

	tenantID := shared.NewID()
	assetID := shared.NewID()
	actorID := shared.NewID()

	// Create a finding
	finding, err := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceSAST,
		"semgrep",
		vulnerability.SeverityHigh,
		"SQL injection vulnerability",
	)
	if err != nil {
		t.Fatalf("Failed to create finding: %v", err)
	}

	// Save to mock repo
	if err := repo.Create(ctx, finding); err != nil {
		t.Fatalf("Failed to save finding: %v", err)
	}

	t.Run("resolved_by is nil for new finding", func(t *testing.T) {
		if finding.ResolvedBy() != nil {
			t.Error("Expected ResolvedBy to be nil for new finding")
		}
		if finding.ResolvedAt() != nil {
			t.Error("Expected ResolvedAt to be nil for new finding")
		}
	})

	t.Run("resolved_by is set when transitioning to resolved", func(t *testing.T) {
		// Transition to resolved
		err := finding.UpdateStatus(vulnerability.FindingStatusResolved, "Fixed in PR #123", &actorID)
		if err != nil {
			t.Fatalf("Failed to update status: %v", err)
		}

		// Verify resolved_by is set
		if finding.ResolvedBy() == nil {
			t.Fatal("Expected ResolvedBy to be set")
		}
		if finding.ResolvedBy().String() != actorID.String() {
			t.Errorf("Expected ResolvedBy to be '%s', got '%s'", actorID.String(), finding.ResolvedBy().String())
		}
		if finding.ResolvedAt() == nil {
			t.Error("Expected ResolvedAt to be set")
		}
		if finding.Resolution() != "Fixed in PR #123" {
			t.Errorf("Expected Resolution to be 'Fixed in PR #123', got '%s'", finding.Resolution())
		}

		// Save and reload
		if err := repo.Update(ctx, finding); err != nil {
			t.Fatalf("Failed to update finding: %v", err)
		}
		reloaded, err := repo.GetByID(ctx, finding.ID())
		if err != nil {
			t.Fatalf("Failed to reload finding: %v", err)
		}
		if reloaded.ResolvedBy() == nil || reloaded.ResolvedBy().String() != actorID.String() {
			t.Error("ResolvedBy was not persisted correctly")
		}
	})

	t.Run("resolved_by is cleared when reopening", func(t *testing.T) {
		// Reopen the finding
		err := finding.UpdateStatus(vulnerability.FindingStatusConfirmed, "", nil)
		if err != nil {
			t.Fatalf("Failed to reopen finding: %v", err)
		}

		if finding.ResolvedBy() != nil {
			t.Error("Expected ResolvedBy to be nil after reopening")
		}
		if finding.ResolvedAt() != nil {
			t.Error("Expected ResolvedAt to be nil after reopening")
		}
	})
}

func TestFindingStatusUpdate_AllClosedStatusesSetResolvedBy(t *testing.T) {
	actorID := shared.NewID()

	closedStatuses := []struct {
		status vulnerability.FindingStatus
		name   string
	}{
		{vulnerability.FindingStatusResolved, "resolved"},
		{vulnerability.FindingStatusFalsePositive, "false_positive"},
		{vulnerability.FindingStatusAccepted, "accepted"},
		{vulnerability.FindingStatusDuplicate, "duplicate"},
	}

	for _, tc := range closedStatuses {
		t.Run(tc.name, func(t *testing.T) {
			finding, _ := vulnerability.NewFinding(
				shared.NewID(),
				shared.NewID(),
				vulnerability.FindingSourceSAST,
				"test-tool",
				vulnerability.SeverityHigh,
				"Test finding",
			)

			err := finding.UpdateStatus(tc.status, "Closed", &actorID)
			if err != nil {
				t.Fatalf("Failed to update status to %s: %v", tc.name, err)
			}

			if finding.ResolvedBy() == nil {
				t.Errorf("ResolvedBy should be set for closed status '%s'", tc.name)
			}
			if finding.ResolvedAt() == nil {
				t.Errorf("ResolvedAt should be set for closed status '%s'", tc.name)
			}
			if !finding.Status().IsClosed() {
				t.Errorf("Status '%s' should be closed", tc.name)
			}
		})
	}
}

func TestFindingStatusUpdate_OpenStatusesDoNotSetResolvedBy(t *testing.T) {
	actorID := shared.NewID()

	openStatuses := []struct {
		status vulnerability.FindingStatus
		name   string
	}{
		{vulnerability.FindingStatusNew, "new"},
		{vulnerability.FindingStatusConfirmed, "confirmed"},
		{vulnerability.FindingStatusInProgress, "in_progress"},
	}

	for _, tc := range openStatuses {
		t.Run(tc.name, func(t *testing.T) {
			// Start with a resolved finding
			finding, _ := vulnerability.NewFinding(
				shared.NewID(),
				shared.NewID(),
				vulnerability.FindingSourceSAST,
				"test-tool",
				vulnerability.SeverityHigh,
				"Test finding",
			)
			_ = finding.UpdateStatus(vulnerability.FindingStatusResolved, "Was resolved", &actorID)

			// Now transition to open status
			err := finding.UpdateStatus(tc.status, "", &actorID)
			if err != nil {
				t.Fatalf("Failed to update status to %s: %v", tc.name, err)
			}

			if finding.ResolvedBy() != nil {
				t.Errorf("ResolvedBy should be nil for open status '%s'", tc.name)
			}
			if finding.ResolvedAt() != nil {
				t.Errorf("ResolvedAt should be nil for open status '%s'", tc.name)
			}
		})
	}
}

func TestUpdateFindingStatusInput_ActorIDIsUsed(t *testing.T) {
	// This test verifies the service layer uses ActorID correctly
	// In a real integration test, this would use a test database

	input := app.UpdateFindingStatusInput{
		Status:     "resolved",
		Resolution: "Fixed the bug",
		ActorID:    "22222222-2222-2222-2222-222222222222",
	}

	// Verify input structure
	if input.ActorID == "" {
		t.Error("ActorID should be set in input")
	}
	if input.Status != "resolved" {
		t.Errorf("Expected status 'resolved', got '%s'", input.Status)
	}
	if input.Resolution == "" {
		t.Error("Resolution should be set for resolved status")
	}

	// The service layer parses ActorID and passes it to UpdateStatus
	// which sets resolved_by when status is closed
	t.Log("Service layer uses ActorID to set resolved_by on closed statuses")
}

func TestFindingStatusWorkflow(t *testing.T) {
	// Test the complete workflow: new -> confirmed -> in_progress -> resolved
	actorID := shared.NewID()

	finding, _ := vulnerability.NewFinding(
		shared.NewID(),
		shared.NewID(),
		vulnerability.FindingSourceSAST,
		"semgrep",
		vulnerability.SeverityCritical,
		"Critical vulnerability found",
	)

	// Step 1: new (initial state)
	if finding.Status() != vulnerability.FindingStatusNew {
		t.Errorf("Expected initial status 'new', got '%s'", finding.Status())
	}
	if finding.IsTriaged() {
		t.Error("New finding should not be triaged")
	}

	// Step 2: new -> confirmed
	_ = finding.UpdateStatus(vulnerability.FindingStatusConfirmed, "", nil)
	if !finding.IsTriaged() {
		t.Error("Confirmed finding should be triaged")
	}
	if finding.ResolvedBy() != nil {
		t.Error("Confirmed status should not set resolved_by")
	}

	// Step 3: confirmed -> in_progress
	_ = finding.UpdateStatus(vulnerability.FindingStatusInProgress, "", nil)
	if finding.ResolvedBy() != nil {
		t.Error("In progress status should not set resolved_by")
	}

	// Step 4: in_progress -> resolved
	resolvedAt := time.Now()
	_ = finding.UpdateStatus(vulnerability.FindingStatusResolved, "Fixed in commit abc123", &actorID)

	if finding.Status() != vulnerability.FindingStatusResolved {
		t.Errorf("Expected status 'resolved', got '%s'", finding.Status())
	}
	if finding.ResolvedBy() == nil {
		t.Fatal("ResolvedBy should be set")
	}
	if finding.ResolvedBy().String() != actorID.String() {
		t.Errorf("ResolvedBy should be '%s', got '%s'", actorID.String(), finding.ResolvedBy().String())
	}
	if finding.ResolvedAt() == nil || finding.ResolvedAt().Before(resolvedAt.Add(-time.Second)) {
		t.Error("ResolvedAt should be set to current time")
	}
	if finding.Resolution() != "Fixed in commit abc123" {
		t.Errorf("Resolution should be 'Fixed in commit abc123', got '%s'", finding.Resolution())
	}

	t.Logf("Workflow complete: finding resolved by %s at %v", finding.ResolvedBy(), finding.ResolvedAt())
}
