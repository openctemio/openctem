package unit

import (
	"context"
	"database/sql"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
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

func (m *MockFindingActivityRepo) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*vulnerability.FindingActivity, error) {
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

func (m *MockFindingActivityRepo) DeleteByCommentID(_ context.Context, _ shared.ID, _ string) error {
	return nil
}

func (m *MockFindingActivityRepo) UpdateContentByCommentID(_ context.Context, _ shared.ID, _ string, _ string) error {
	return nil
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
func (s *stubFindingRepo) GetByIDs(_ context.Context, _ shared.ID, _ []shared.ID) ([]*vulnerability.Finding, error) {
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
func (s *stubFindingRepo) ListAffectedAssetsByVulnerabilityID(_ context.Context, _, _ shared.ID, _ bool, _ pagination.Pagination, _ *shared.DataScope) (pagination.Result[vulnerability.VulnerabilityAffectedAsset], error) {
	return pagination.Result[vulnerability.VulnerabilityAffectedAsset]{}, nil
}
func (s *stubFindingRepo) ListActiveCVEsByTenant(_ context.Context, _ shared.ID, _ vulnerability.ActiveCVEFilter, _ pagination.Pagination) (pagination.Result[vulnerability.ActiveCVE], error) {
	return pagination.Result[vulnerability.ActiveCVE]{}, nil
}
func (s *stubFindingRepo) GetActiveCVEStats(_ context.Context, _ shared.ID, _ bool, _ *shared.DataScope) (*vulnerability.ActiveCVEStats, error) {
	return &vulnerability.ActiveCVEStats{BySeverity: map[string]int{}}, nil
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
func (s *stubFindingRepo) UpdateScanIDBatchByFingerprints(_ context.Context, _ shared.ID, _ []string, _, _ string) (int64, error) {
	return 0, nil
}
func (s *stubFindingRepo) UpdateSnippetBatchByFingerprints(_ context.Context, _ shared.ID, _ map[string]string) (int64, error) {
	return 0, nil
}
func (s *stubFindingRepo) BatchCountByAssetIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[shared.ID]int64, error) {
	return nil, nil
}

// AcceptUntil records an accept like UpdateStatusBatch does.
func (s *stubFindingRepo) AcceptUntil(ctx context.Context, tenantID, id shared.ID, _ time.Time, by *shared.ID) error {
	return s.UpdateStatusBatch(ctx, tenantID, []shared.ID{id}, vulnerability.FindingStatusAccepted, "", by, "")
}

func (s *stubFindingRepo) UpdateStatusBatch(_ context.Context, _ shared.ID, _ []shared.ID, _ vulnerability.FindingStatus, _ string, _ *shared.ID, _ vulnerability.ResolutionMethod) error {
	return nil
}
func (s *stubFindingRepo) DeleteByAssetID(_ context.Context, _, _ shared.ID) error { return nil }
func (s *stubFindingRepo) DeleteByScanID(_ context.Context, _ shared.ID, _ string) error {
	return nil
}
func (s *stubFindingRepo) GetStats(_ context.Context, _ shared.ID, _ *shared.ID, _ vulnerability.FindingStatsFilter) (*vulnerability.FindingStats, error) {
	return nil, nil
}
func (s *stubFindingRepo) CountBySeverityForScan(_ context.Context, _ shared.ID, _ string) (vulnerability.SeverityCounts, error) {
	return vulnerability.SeverityCounts{}, nil
}
func (s *stubFindingRepo) AutoResolveStale(_ context.Context, _ shared.ID, _ shared.ID, _ string, _ string, _ *shared.ID) ([]shared.ID, error) {
	return nil, nil
}

func (s *stubFindingRepo) AutoResolveStaleByAssets(_ context.Context, _ shared.ID, _ []shared.ID, _ string, _ string, _ *shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (s *stubFindingRepo) AutoReopenByFingerprint(_ context.Context, _ shared.ID, _ string) (*shared.ID, error) {
	return nil, nil
}
func (s *stubFindingRepo) AutoReopenByFingerprintsBatch(_ context.Context, _ shared.ID, _ []string) (map[string]vulnerability.ReopenedFinding, error) {
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

func (s *stubFindingRepo) ListComponentCVEPairs(_ context.Context, _ shared.ID, _ vulnerability.ComponentCVEFilter, _ pagination.Pagination) (pagination.Result[*vulnerability.ComponentCVEPair], error) {
	return pagination.Result[*vulnerability.ComponentCVEPair]{}, nil
}

// =============================================================================
// Cross-cutting Activity Tests
// =============================================================================

func (s *stubFindingRepo) UpsertBranchOccurrences(_ context.Context, _ shared.ID, _ []vulnerability.BranchOccurrenceUpsert) error {
	return nil
}

func (s *stubFindingRepo) BackfillFindingBranches(_ context.Context, _ shared.ID, _ []vulnerability.BranchOccurrenceUpsert) (int64, error) {
	return 0, nil
}

func (s *stubFindingRepo) AutoResolveStaleBranchOccurrences(_ context.Context, _, _ shared.ID, _, _ string) (int64, error) {
	return 0, nil
}

func (s *stubFindingRepo) FingerprintsOpenOnBranch(_ context.Context, _, _ shared.ID, _ []string) ([]string, error) {
	return nil, nil
}
