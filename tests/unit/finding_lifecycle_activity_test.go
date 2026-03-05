package unit

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Repository for Activity Tests
// =============================================================================

// MockFindingActivityRepo implements vulnerability.FindingActivityRepository for testing.
type MockFindingActivityRepo struct {
	CreateCalled     bool
	CreateBatchCalls []struct {
		Activities []*vulnerability.FindingActivity
	}
	CreateBatchError error
}

func (m *MockFindingActivityRepo) Create(_ context.Context, _ *vulnerability.FindingActivity) error {
	m.CreateCalled = true
	return nil
}

func (m *MockFindingActivityRepo) CreateBatch(_ context.Context, activities []*vulnerability.FindingActivity) error {
	m.CreateBatchCalls = append(m.CreateBatchCalls, struct {
		Activities []*vulnerability.FindingActivity
	}{Activities: activities})
	return m.CreateBatchError
}

func (m *MockFindingActivityRepo) GetByID(_ context.Context, _ shared.ID) (*vulnerability.FindingActivity, error) {
	return nil, nil
}

func (m *MockFindingActivityRepo) ListByFinding(_ context.Context, _ shared.ID, _ shared.ID, _ vulnerability.FindingActivityFilter, _ pagination.Pagination) (pagination.Result[*vulnerability.FindingActivity], error) {
	return pagination.Result[*vulnerability.FindingActivity]{}, nil
}

func (m *MockFindingActivityRepo) CountByFinding(_ context.Context, _ shared.ID, _ shared.ID, _ vulnerability.FindingActivityFilter) (int64, error) {
	return 0, nil
}

func (m *MockFindingActivityRepo) ListByTenant(_ context.Context, _ shared.ID, _ vulnerability.FindingActivityFilter, _ pagination.Pagination) (pagination.Result[*vulnerability.FindingActivity], error) {
	return pagination.Result[*vulnerability.FindingActivity]{}, nil
}

// TotalActivitiesBatched returns the total number of activities across all batch calls.
func (m *MockFindingActivityRepo) TotalActivitiesBatched() int {
	total := 0
	for _, call := range m.CreateBatchCalls {
		total += len(call.Activities)
	}
	return total
}

// stubFindingRepo implements vulnerability.FindingRepository with no-op methods.
// Only needed because FindingActivityService constructor requires it.
type stubFindingRepo struct{}

func (s *stubFindingRepo) Create(_ context.Context, _ *vulnerability.Finding) error { return nil }
func (s *stubFindingRepo) CreateInTx(_ context.Context, _ *sql.Tx, _ *vulnerability.Finding) error {
	return nil
}
func (s *stubFindingRepo) CreateBatch(_ context.Context, _ []*vulnerability.Finding) error {
	return nil
}
func (s *stubFindingRepo) CreateBatchWithResult(_ context.Context, _ []*vulnerability.Finding) (*vulnerability.BatchCreateResult, error) {
	return nil, nil
}
func (s *stubFindingRepo) GetByID(_ context.Context, _, _ shared.ID) (*vulnerability.Finding, error) {
	return nil, nil
}
func (s *stubFindingRepo) Update(_ context.Context, _ *vulnerability.Finding) error { return nil }
func (s *stubFindingRepo) Delete(_ context.Context, _, _ shared.ID) error           { return nil }
func (s *stubFindingRepo) List(_ context.Context, _ vulnerability.FindingFilter, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}
func (s *stubFindingRepo) ListByAssetID(_ context.Context, _, _ shared.ID, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}
func (s *stubFindingRepo) ListByVulnerabilityID(_ context.Context, _, _ shared.ID, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}
func (s *stubFindingRepo) ListByComponentID(_ context.Context, _, _ shared.ID, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}
func (s *stubFindingRepo) Count(_ context.Context, _ vulnerability.FindingFilter) (int64, error) {
	return 0, nil
}
func (s *stubFindingRepo) CountByAssetID(_ context.Context, _, _ shared.ID) (int64, error) {
	return 0, nil
}
func (s *stubFindingRepo) CountOpenByAssetID(_ context.Context, _, _ shared.ID) (int64, error) {
	return 0, nil
}
func (s *stubFindingRepo) GetByFingerprint(_ context.Context, _ shared.ID, _ string) (*vulnerability.Finding, error) {
	return nil, nil
}
func (s *stubFindingRepo) ExistsByFingerprint(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}
func (s *stubFindingRepo) CheckFingerprintsExist(_ context.Context, _ shared.ID, _ []string) (map[string]bool, error) {
	return nil, nil
}
func (s *stubFindingRepo) UpdateScanIDBatchByFingerprints(_ context.Context, _ shared.ID, _ []string, _ string) (int64, error) {
	return 0, nil
}
func (s *stubFindingRepo) UpdateSnippetBatchByFingerprints(_ context.Context, _ shared.ID, _ map[string]string) (int64, error) {
	return 0, nil
}
func (s *stubFindingRepo) BatchCountByAssetIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[shared.ID]int64, error) {
	return nil, nil
}
func (s *stubFindingRepo) UpdateStatusBatch(_ context.Context, _ shared.ID, _ []shared.ID, _ vulnerability.FindingStatus, _ string, _ *shared.ID) error {
	return nil
}
func (s *stubFindingRepo) DeleteByAssetID(_ context.Context, _, _ shared.ID) error { return nil }
func (s *stubFindingRepo) DeleteByScanID(_ context.Context, _ shared.ID, _ string) error {
	return nil
}
func (s *stubFindingRepo) GetStats(_ context.Context, _ shared.ID, _ *shared.ID) (*vulnerability.FindingStats, error) {
	return nil, nil
}
func (s *stubFindingRepo) CountBySeverityForScan(_ context.Context, _ shared.ID, _ string) (vulnerability.SeverityCounts, error) {
	return vulnerability.SeverityCounts{}, nil
}
func (s *stubFindingRepo) AutoResolveStale(_ context.Context, _ shared.ID, _ shared.ID, _ string, _ string, _ *shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (s *stubFindingRepo) AutoReopenByFingerprint(_ context.Context, _ shared.ID, _ string) (*shared.ID, error) {
	return nil, nil
}
func (s *stubFindingRepo) AutoReopenByFingerprintsBatch(_ context.Context, _ shared.ID, _ []string) (map[string]shared.ID, error) {
	return nil, nil
}
func (s *stubFindingRepo) ExpireFeatureBranchFindings(_ context.Context, _ shared.ID, _ int) (int64, error) {
	return 0, nil
}
func (s *stubFindingRepo) ExistsByIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[shared.ID]bool, error) {
	return nil, nil
}

func (s *stubFindingRepo) GetByFingerprintsBatch(_ context.Context, _ shared.ID, _ []string) (map[string]*vulnerability.Finding, error) {
	return nil, nil
}

func (s *stubFindingRepo) EnrichBatchByFingerprints(_ context.Context, _ shared.ID, _ []*vulnerability.Finding, _ string) (int64, error) {
	return 0, nil
}

// =============================================================================
// RecordBatchAutoResolved Tests
// =============================================================================

func TestRecordBatchAutoResolved(t *testing.T) {
	ctx := context.Background()
	log := logger.NewNop()
	tenantID := shared.NewID()

	t.Run("creates activities for each finding ID", func(t *testing.T) {
		activityRepo := &MockFindingActivityRepo{}
		svc := app.NewFindingActivityService(activityRepo, &stubFindingRepo{}, log)

		findingIDs := []shared.ID{shared.NewID(), shared.NewID(), shared.NewID()}

		err := svc.RecordBatchAutoResolved(ctx, tenantID, findingIDs, "nuclei", "scan-123")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(activityRepo.CreateBatchCalls) != 1 {
			t.Fatalf("expected 1 CreateBatch call, got %d", len(activityRepo.CreateBatchCalls))
		}

		activities := activityRepo.CreateBatchCalls[0].Activities
		if len(activities) != 3 {
			t.Fatalf("expected 3 activities, got %d", len(activities))
		}

		for i, a := range activities {
			if a.ActivityType() != vulnerability.ActivityAutoResolved {
				t.Errorf("activity %d: expected type %s, got %s", i, vulnerability.ActivityAutoResolved, a.ActivityType())
			}
			if a.ActorType() != vulnerability.ActorTypeSystem {
				t.Errorf("activity %d: expected actor type %s, got %s", i, vulnerability.ActorTypeSystem, a.ActorType())
			}
			if a.Source() != vulnerability.SourceAuto {
				t.Errorf("activity %d: expected source %s, got %s", i, vulnerability.SourceAuto, a.Source())
			}
			if a.TenantID() != tenantID {
				t.Errorf("activity %d: expected tenant ID %s, got %s", i, tenantID, a.TenantID())
			}
			if a.FindingID() != findingIDs[i] {
				t.Errorf("activity %d: expected finding ID %s, got %s", i, findingIDs[i], a.FindingID())
			}
			changes := a.Changes()
			if changes["scanner"] != "nuclei" {
				t.Errorf("activity %d: expected scanner 'nuclei', got %v", i, changes["scanner"])
			}
			if changes["scan_id"] != "scan-123" {
				t.Errorf("activity %d: expected scan_id 'scan-123', got %v", i, changes["scan_id"])
			}
			if changes["reason"] != "not_found_in_full_scan" {
				t.Errorf("activity %d: expected reason 'not_found_in_full_scan', got %v", i, changes["reason"])
			}
		}
	})

	t.Run("empty IDs list is no-op", func(t *testing.T) {
		activityRepo := &MockFindingActivityRepo{}
		svc := app.NewFindingActivityService(activityRepo, &stubFindingRepo{}, log)

		err := svc.RecordBatchAutoResolved(ctx, tenantID, nil, "nuclei", "scan-123")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(activityRepo.CreateBatchCalls) != 0 {
			t.Errorf("expected no CreateBatch calls for empty IDs, got %d", len(activityRepo.CreateBatchCalls))
		}
	})

	t.Run("propagates CreateBatch error", func(t *testing.T) {
		expectedErr := errors.New("database connection lost")
		activityRepo := &MockFindingActivityRepo{CreateBatchError: expectedErr}
		svc := app.NewFindingActivityService(activityRepo, &stubFindingRepo{}, log)

		findingIDs := []shared.ID{shared.NewID()}

		err := svc.RecordBatchAutoResolved(ctx, tenantID, findingIDs, "nuclei", "scan-1")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, expectedErr) {
			t.Errorf("expected wrapped error to contain %v, got %v", expectedErr, err)
		}
	})

	t.Run("each activity has unique ID", func(t *testing.T) {
		activityRepo := &MockFindingActivityRepo{}
		svc := app.NewFindingActivityService(activityRepo, &stubFindingRepo{}, log)

		findingIDs := []shared.ID{shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()}
		err := svc.RecordBatchAutoResolved(ctx, tenantID, findingIDs, "semgrep", "scan-5")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		activities := activityRepo.CreateBatchCalls[0].Activities
		idSet := make(map[shared.ID]bool, len(activities))
		for _, a := range activities {
			if idSet[a.ID()] {
				t.Errorf("duplicate activity ID: %s", a.ID())
			}
			idSet[a.ID()] = true
		}
	})

	t.Run("large batch creates all activities", func(t *testing.T) {
		activityRepo := &MockFindingActivityRepo{}
		svc := app.NewFindingActivityService(activityRepo, &stubFindingRepo{}, log)

		// Simulate a large auto-resolve batch (250 findings)
		findingIDs := make([]shared.ID, 250)
		for i := range findingIDs {
			findingIDs[i] = shared.NewID()
		}

		err := svc.RecordBatchAutoResolved(ctx, tenantID, findingIDs, "nuclei", "scan-large")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		total := activityRepo.TotalActivitiesBatched()
		if total != 250 {
			t.Errorf("expected 250 total activities, got %d", total)
		}
	})

	t.Run("preserves tool name and scan ID across all activities", func(t *testing.T) {
		activityRepo := &MockFindingActivityRepo{}
		svc := app.NewFindingActivityService(activityRepo, &stubFindingRepo{}, log)

		findingIDs := []shared.ID{shared.NewID(), shared.NewID()}
		err := svc.RecordBatchAutoResolved(ctx, tenantID, findingIDs, "trivy", "scan-xyz-789")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for i, a := range activityRepo.CreateBatchCalls[0].Activities {
			changes := a.Changes()
			if changes["scanner"] != "trivy" {
				t.Errorf("activity %d: scanner = %v, want trivy", i, changes["scanner"])
			}
			if changes["scan_id"] != "scan-xyz-789" {
				t.Errorf("activity %d: scan_id = %v, want scan-xyz-789", i, changes["scan_id"])
			}
		}
	})
}

// =============================================================================
// RecordBatchAutoReopened Tests
// =============================================================================

func TestRecordBatchAutoReopened(t *testing.T) {
	ctx := context.Background()
	log := logger.NewNop()
	tenantID := shared.NewID()

	t.Run("creates activities for each finding ID", func(t *testing.T) {
		activityRepo := &MockFindingActivityRepo{}
		svc := app.NewFindingActivityService(activityRepo, &stubFindingRepo{}, log)

		findingIDs := []shared.ID{shared.NewID(), shared.NewID()}

		err := svc.RecordBatchAutoReopened(ctx, tenantID, findingIDs)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(activityRepo.CreateBatchCalls) != 1 {
			t.Fatalf("expected 1 CreateBatch call, got %d", len(activityRepo.CreateBatchCalls))
		}

		activities := activityRepo.CreateBatchCalls[0].Activities
		if len(activities) != 2 {
			t.Fatalf("expected 2 activities, got %d", len(activities))
		}

		for i, a := range activities {
			if a.ActivityType() != vulnerability.ActivityAutoReopened {
				t.Errorf("activity %d: expected type %s, got %s", i, vulnerability.ActivityAutoReopened, a.ActivityType())
			}
			if a.ActorType() != vulnerability.ActorTypeSystem {
				t.Errorf("activity %d: expected actor type %s, got %s", i, vulnerability.ActorTypeSystem, a.ActorType())
			}
			if a.Source() != vulnerability.SourceAuto {
				t.Errorf("activity %d: expected source %s, got %s", i, vulnerability.SourceAuto, a.Source())
			}
			if a.ActorID() != nil {
				t.Errorf("activity %d: expected nil actor ID for system action, got %v", i, a.ActorID())
			}
			changes := a.Changes()
			if changes["reason"] != "finding_detected_again" {
				t.Errorf("activity %d: expected reason 'finding_detected_again', got %v", i, changes["reason"])
			}
		}
	})

	t.Run("empty IDs list is no-op", func(t *testing.T) {
		activityRepo := &MockFindingActivityRepo{}
		svc := app.NewFindingActivityService(activityRepo, &stubFindingRepo{}, log)

		err := svc.RecordBatchAutoReopened(ctx, tenantID, []shared.ID{})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(activityRepo.CreateBatchCalls) != 0 {
			t.Errorf("expected no CreateBatch calls for empty IDs, got %d", len(activityRepo.CreateBatchCalls))
		}
	})

	t.Run("propagates CreateBatch error", func(t *testing.T) {
		expectedErr := errors.New("disk full")
		activityRepo := &MockFindingActivityRepo{CreateBatchError: expectedErr}
		svc := app.NewFindingActivityService(activityRepo, &stubFindingRepo{}, log)

		err := svc.RecordBatchAutoReopened(ctx, tenantID, []shared.ID{shared.NewID()})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, expectedErr) {
			t.Errorf("expected wrapped error to contain %v, got %v", expectedErr, err)
		}
	})

	t.Run("activities have correct tenant and finding IDs", func(t *testing.T) {
		activityRepo := &MockFindingActivityRepo{}
		svc := app.NewFindingActivityService(activityRepo, &stubFindingRepo{}, log)

		fid1 := shared.NewID()
		fid2 := shared.NewID()
		fid3 := shared.NewID()

		err := svc.RecordBatchAutoReopened(ctx, tenantID, []shared.ID{fid1, fid2, fid3})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		activities := activityRepo.CreateBatchCalls[0].Activities
		if len(activities) != 3 {
			t.Fatalf("expected 3 activities, got %d", len(activities))
		}

		expectedIDs := []shared.ID{fid1, fid2, fid3}
		for i, a := range activities {
			if a.TenantID() != tenantID {
				t.Errorf("activity %d: tenant ID = %s, want %s", i, a.TenantID(), tenantID)
			}
			if a.FindingID() != expectedIDs[i] {
				t.Errorf("activity %d: finding ID = %s, want %s", i, a.FindingID(), expectedIDs[i])
			}
		}
	})

	t.Run("single finding ID works", func(t *testing.T) {
		activityRepo := &MockFindingActivityRepo{}
		svc := app.NewFindingActivityService(activityRepo, &stubFindingRepo{}, log)

		fid := shared.NewID()
		err := svc.RecordBatchAutoReopened(ctx, tenantID, []shared.ID{fid})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if activityRepo.TotalActivitiesBatched() != 1 {
			t.Errorf("expected 1 activity, got %d", activityRepo.TotalActivitiesBatched())
		}

		a := activityRepo.CreateBatchCalls[0].Activities[0]
		if a.FindingID() != fid {
			t.Errorf("finding ID = %s, want %s", a.FindingID(), fid)
		}
	})
}

// =============================================================================
// Cross-cutting Activity Tests
// =============================================================================

func TestActivityTimestampsAreSet(t *testing.T) {
	ctx := context.Background()
	log := logger.NewNop()
	tenantID := shared.NewID()

	activityRepo := &MockFindingActivityRepo{}
	svc := app.NewFindingActivityService(activityRepo, &stubFindingRepo{}, log)

	findingIDs := []shared.ID{shared.NewID(), shared.NewID()}
	err := svc.RecordBatchAutoResolved(ctx, tenantID, findingIDs, "nuclei", "scan-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i, a := range activityRepo.CreateBatchCalls[0].Activities {
		if a.CreatedAt().IsZero() {
			t.Errorf("activity %d: CreatedAt is zero", i)
		}
	}
}

func TestDifferentTenantsProduceDifferentActivities(t *testing.T) {
	ctx := context.Background()
	log := logger.NewNop()

	tenant1 := shared.NewID()
	tenant2 := shared.NewID()

	activityRepo := &MockFindingActivityRepo{}
	svc := app.NewFindingActivityService(activityRepo, &stubFindingRepo{}, log)

	_ = svc.RecordBatchAutoResolved(ctx, tenant1, []shared.ID{shared.NewID()}, "nuclei", "s1")
	_ = svc.RecordBatchAutoResolved(ctx, tenant2, []shared.ID{shared.NewID()}, "nuclei", "s2")

	if len(activityRepo.CreateBatchCalls) != 2 {
		t.Fatalf("expected 2 batch calls, got %d", len(activityRepo.CreateBatchCalls))
	}

	a1 := activityRepo.CreateBatchCalls[0].Activities[0]
	a2 := activityRepo.CreateBatchCalls[1].Activities[0]

	if a1.TenantID() != tenant1 {
		t.Errorf("first activity: tenant = %s, want %s", a1.TenantID(), tenant1)
	}
	if a2.TenantID() != tenant2 {
		t.Errorf("second activity: tenant = %s, want %s", a2.TenantID(), tenant2)
	}
}
