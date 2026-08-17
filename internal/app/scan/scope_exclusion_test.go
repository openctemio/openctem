package scan

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/app/scope"
	"github.com/openctemio/api/pkg/domain/assetgroup"
	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// stubGroupAssetsRepo overrides only GetGroupAssets; the embedded interface
// panics on any other unexpected call.
type stubGroupAssetsRepo struct {
	assetgroup.Repository
	assets []*assetgroup.GroupAsset
}

func (s *stubGroupAssetsRepo) GetGroupAssets(_ context.Context, _ shared.ID, page pagination.Pagination) (pagination.Result[*assetgroup.GroupAsset], error) {
	return pagination.NewResult(s.assets, int64(len(s.assets)), page), nil
}

// stubExclusionFilter returns a fixed excluded-ID set.
type stubExclusionFilter struct {
	excluded map[shared.ID]bool
	called   bool
}

func (s *stubExclusionFilter) FilterExcludedTargets(_ context.Context, _ string, _ []scope.ExclusionCandidate) map[shared.ID]bool {
	s.called = true
	return s.excluded
}

func newScopeTestScan(t *testing.T) *scan.Scan {
	t.Helper()
	sc := &scan.Scan{
		ID:           shared.NewID(),
		TenantID:     shared.NewID(),
		AssetGroupID: shared.NewID(),
		ScannerName:  "nuclei",
	}
	return sc
}

// TestApplyScopeExclusions_RemovesExcludedAssets proves excluded assets are
// recorded in the scan run context (the target set handed to the agent).
func TestApplyScopeExclusions_RemovesExcludedAssets(t *testing.T) {
	keepID := shared.NewID()
	dropID := shared.NewID()

	svc := &Service{
		assetGroupRepo: &stubGroupAssetsRepo{assets: []*assetgroup.GroupAsset{
			{ID: keepID, Name: "kept.example.com"},
			{ID: dropID, Name: "excluded.example.com"},
		}},
		scopeExclusions: &stubExclusionFilter{excluded: map[shared.ID]bool{dropID: true}},
		logger:          logger.NewNop(),
	}

	sc := newScopeTestScan(t)
	runContext := map[string]any{}
	svc.applyScopeExclusions(context.Background(), sc, runContext)

	raw, ok := runContext["excluded_asset_ids"]
	if !ok {
		t.Fatal("excluded_asset_ids must be recorded when an exclusion matches")
	}
	ids, _ := raw.([]string)
	if len(ids) != 1 || ids[0] != dropID.String() {
		t.Fatalf("expected only the excluded asset id, got %v", ids)
	}
}

// TestApplyScopeExclusions_NoneExcludedLeavesTargetSet proves that when nothing
// is excluded, the run context is untouched (all assets retained).
func TestApplyScopeExclusions_NoneExcludedLeavesTargetSet(t *testing.T) {
	svc := &Service{
		assetGroupRepo: &stubGroupAssetsRepo{assets: []*assetgroup.GroupAsset{
			{ID: shared.NewID(), Name: "a.example.com"},
		}},
		scopeExclusions: &stubExclusionFilter{excluded: map[shared.ID]bool{}},
		logger:          logger.NewNop(),
	}

	runContext := map[string]any{}
	svc.applyScopeExclusions(context.Background(), newScopeTestScan(t), runContext)

	if _, ok := runContext["excluded_asset_ids"]; ok {
		t.Fatal("no exclusions should leave the target set untouched")
	}
}

// TestApplyScopeExclusions_NilFilterFailsOpen proves a nil scope filter is a
// no-op (fail-open): scanning proceeds on every asset.
func TestApplyScopeExclusions_NilFilterFailsOpen(t *testing.T) {
	svc := &Service{
		assetGroupRepo:  &stubGroupAssetsRepo{},
		scopeExclusions: nil,
		logger:          logger.NewNop(),
	}
	runContext := map[string]any{}
	svc.applyScopeExclusions(context.Background(), newScopeTestScan(t), runContext)
	if _, ok := runContext["excluded_asset_ids"]; ok {
		t.Fatal("a nil scope filter must not touch the target set")
	}
}
