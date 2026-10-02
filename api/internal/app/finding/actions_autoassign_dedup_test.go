package finding

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// autoAssignFindingRepo serves two pages of unassigned findings all pointing at
// the SAME asset, then an empty page to end the walk. Update is a no-op so the
// assign path completes.
type autoAssignFindingRepo struct {
	vulnerability.FindingRepository // embedded; unused methods must never be called
	pages                           [][]*vulnerability.Finding
}

func (r *autoAssignFindingRepo) List(_ context.Context, _ vulnerability.FindingFilter, _ vulnerability.FindingListOptions, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	idx := page.Page - 1
	var data []*vulnerability.Finding
	if idx >= 0 && idx < len(r.pages) {
		data = r.pages[idx]
	}
	return pagination.Result[*vulnerability.Finding]{Data: data}, nil
}

func (r *autoAssignFindingRepo) Update(_ context.Context, _ *vulnerability.Finding) error {
	return nil
}

// countingAssetRepo counts GetByID calls to prove dedup across pages.
type countingAssetRepo struct {
	asset.Repository // embedded; unused methods must never be called
	assetOwner       *shared.ID
	name             string
	calls            int
}

func (r *countingAssetRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*asset.Asset, error) {
	r.calls++
	a, err := asset.NewAssetWithTenant(tenantID, r.name, asset.AssetTypeHost, asset.CriticalityMedium)
	if err != nil {
		return nil, err
	}
	a.SetOwnerID(r.assetOwner)
	return a, nil
}

func unassignedFinding(t *testing.T, tenantID, assetID shared.ID) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(tenantID, assetID, vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "x")
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

// TestAutoAssignToOwners_DedupsAssetLookups asserts that when many findings
// share one asset (across pages), the asset is fetched exactly once — the N+1
// that the fix collapses. Previously every finding triggered its own GetByID.
func TestAutoAssignToOwners_DedupsAssetLookups(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	owner := shared.NewID()

	mkPage := func(n int) []*vulnerability.Finding {
		out := make([]*vulnerability.Finding, n)
		for i := range out {
			out[i] = unassignedFinding(t, tenantID, assetID)
		}
		return out
	}

	findingRepo := &autoAssignFindingRepo{
		pages: [][]*vulnerability.Finding{mkPage(100), mkPage(50)},
	}
	assetRepo := &countingAssetRepo{assetOwner: &owner, name: "host-1"}

	svc := NewFindingActionsService(findingRepo, nil, nil, assetRepo, nil, nil, logger.NewNop())

	res, err := svc.AutoAssignToOwners(context.Background(), tenantID.String(), shared.NewID().String(), vulnerability.NewFindingFilter())
	if err != nil {
		t.Fatalf("AutoAssignToOwners: %v", err)
	}

	if res.Assigned != 150 {
		t.Errorf("Assigned = %d, want 150", res.Assigned)
	}
	// 150 findings, one shared asset → exactly ONE asset lookup.
	if assetRepo.calls != 1 {
		t.Errorf("asset GetByID calls = %d, want 1 (dedup across pages)", assetRepo.calls)
	}
}
