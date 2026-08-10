package reclassify

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/infra/controller"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// --- fakes ---

type fakeFindingRepo struct {
	vulnerability.FindingRepository // embed; only List/Update used
	findings                        []*vulnerability.Finding
	updated                         []shared.ID
	served                          bool
}

func (r *fakeFindingRepo) ListByAssetID(_ context.Context, _, _ shared.ID, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	if r.served {
		return pagination.Result[*vulnerability.Finding]{}, nil
	}
	r.served = true
	return pagination.Result[*vulnerability.Finding]{Data: r.findings}, nil
}

func (r *fakeFindingRepo) Update(_ context.Context, f *vulnerability.Finding) error {
	r.updated = append(r.updated, f.ID())
	return nil
}

type fakeAssetRepo struct {
	asset.Repository
	a *asset.Asset
}

func (r *fakeAssetRepo) GetByID(_ context.Context, _, _ shared.ID) (*asset.Asset, error) {
	return r.a, nil
}

type fakeClassifier struct{ called int }

func (c *fakeClassifier) ClassifyFinding(_ context.Context, _ shared.ID, _ *vulnerability.Finding, _ *asset.Asset) error {
	c.called++
	return nil
}

type fakeSLA struct{ applied []shared.ID }

func (s *fakeSLA) ApplyBatch(_ context.Context, _ shared.ID, findings []*vulnerability.Finding) error {
	for _, f := range findings {
		s.applied = append(s.applied, f.ID())
	}
	return nil
}

func newFinding(t *testing.T, assetID shared.ID) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(shared.NewID(), assetID, vulnerability.FindingSourceManual, "tool", vulnerability.SeverityHigh, "f")
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	return f
}

func TestReclassify_RecomputesSLAAfterClassify(t *testing.T) {
	assetID := shared.NewID()
	a, err := asset.NewAsset("example.com", asset.AssetTypeDomain, asset.CriticalityHigh)
	if err != nil {
		t.Fatalf("new asset: %v", err)
	}
	f1, f2 := newFinding(t, assetID), newFinding(t, assetID)

	repo := &fakeFindingRepo{findings: []*vulnerability.Finding{f1, f2}}
	sla := &fakeSLA{}
	r := NewReclassifier(repo, &fakeAssetRepo{a: a}, &fakeClassifier{}, logger.NewNop())
	r.SetSLARecomputer(sla)

	n, err := r.reclassifyAsset(context.Background(), shared.NewID(), assetID)
	if err != nil {
		t.Fatalf("reclassifyAsset: %v", err)
	}
	if n != 2 {
		t.Fatalf("reexamined = %d, want 2", n)
	}
	// SLA recompute must run for every reclassified finding, before persistence.
	if len(sla.applied) != 2 {
		t.Fatalf("sla applied to %d findings, want 2", len(sla.applied))
	}
	if len(repo.updated) != 2 {
		t.Fatalf("updated %d findings, want 2", len(repo.updated))
	}
}

func TestReclassify_NilSLARecomputer_StillReclassifies(t *testing.T) {
	assetID := shared.NewID()
	a, _ := asset.NewAsset("example.com", asset.AssetTypeDomain, asset.CriticalityHigh)
	repo := &fakeFindingRepo{findings: []*vulnerability.Finding{newFinding(t, assetID)}}
	r := NewReclassifier(repo, &fakeAssetRepo{a: a}, &fakeClassifier{}, logger.NewNop())
	// no SLA recomputer wired

	n, err := r.reclassifyAsset(context.Background(), shared.NewID(), assetID)
	if err != nil {
		t.Fatalf("reclassifyAsset: %v", err)
	}
	if n != 1 || len(repo.updated) != 1 {
		t.Fatalf("expected 1 reclassified+updated, got n=%d updated=%d", n, len(repo.updated))
	}
}

// tenantFindingRepo maps assets → findings so a whole-tenant sweep resolves
// the distinct asset set from List() then pages each asset via ListByAssetID.
type tenantFindingRepo struct {
	vulnerability.FindingRepository
	all     []*vulnerability.Finding               // returned by List() (open findings)
	byAsset map[shared.ID][]*vulnerability.Finding // returned by ListByAssetID()
	updated []shared.ID
}

func (r *tenantFindingRepo) List(_ context.Context, _ vulnerability.FindingFilter, _ vulnerability.FindingListOptions, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	if page.Page > 1 {
		return pagination.Result[*vulnerability.Finding]{}, nil
	}
	return pagination.Result[*vulnerability.Finding]{Data: r.all}, nil
}

func (r *tenantFindingRepo) ListByAssetID(_ context.Context, _, assetID shared.ID, _ vulnerability.FindingListOptions, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	if page.Page > 1 {
		return pagination.Result[*vulnerability.Finding]{}, nil
	}
	return pagination.Result[*vulnerability.Finding]{Data: r.byAsset[assetID]}, nil
}

func (r *tenantFindingRepo) Update(_ context.Context, f *vulnerability.Finding) error {
	r.updated = append(r.updated, f.ID())
	return nil
}

// TestReclassify_WholeTenantRequest_ReclassifiesDistinctAssets proves the
// empty-AssetIDs (whole-tenant) request path — used by the KEV/EPSS refresh
// and periodic-sweep producers — actually reclassifies. Before the fix this
// branch was a no-op returning 0.
func TestReclassify_WholeTenantRequest_ReclassifiesDistinctAssets(t *testing.T) {
	tenantID := shared.NewID()
	a1, a2, a3 := shared.NewID(), shared.NewID(), shared.NewID()

	// 5 open findings across 3 distinct assets (a1×2, a2×1, a3×2).
	f1, f2 := newFinding(t, a1), newFinding(t, a1)
	f3 := newFinding(t, a2)
	f4, f5 := newFinding(t, a3), newFinding(t, a3)

	repo := &tenantFindingRepo{
		all: []*vulnerability.Finding{f1, f2, f3, f4, f5},
		byAsset: map[shared.ID][]*vulnerability.Finding{
			a1: {f1, f2},
			a2: {f3},
			a3: {f4, f5},
		},
	}
	a, err := asset.NewAsset("example.com", asset.AssetTypeDomain, asset.CriticalityHigh)
	if err != nil {
		t.Fatalf("new asset: %v", err)
	}
	classifier := &fakeClassifier{}
	r := NewReclassifier(repo, &fakeAssetRepo{a: a}, classifier, logger.NewNop())

	// Whole-tenant request: empty AssetIDs.
	n, err := r.ReclassifyForRequest(context.Background(), controller.ReclassifyRequest{
		TenantID: tenantID,
		Reason:   controller.ReasonPeriodicSweep,
	})
	if err != nil {
		t.Fatalf("ReclassifyForRequest: %v", err)
	}
	if n != 5 {
		t.Fatalf("reexamined = %d, want 5 (all open findings across 3 assets)", n)
	}
	if classifier.called != 5 {
		t.Fatalf("classifier called %d times, want 5", classifier.called)
	}
	if len(repo.updated) != 5 {
		t.Fatalf("updated %d findings, want 5", len(repo.updated))
	}
}

// TestReclassify_WholeTenantRequest_SkipsNullAssetFindings verifies findings
// with no asset (NULL asset_id — a known separate gap) are skipped rather than
// crashing the sweep.
func TestReclassify_WholeTenantRequest_SkipsNullAssetFindings(t *testing.T) {
	tenantID := shared.NewID()
	a1 := shared.NewID()
	realFinding := newFinding(t, a1)
	// A pentest finding may have a zero asset_id.
	orphan, err := vulnerability.NewFinding(shared.NewID(), shared.ID{}, vulnerability.FindingSourcePentest, "tool", vulnerability.SeverityHigh, "orphan")
	if err != nil {
		t.Fatalf("new orphan finding: %v", err)
	}

	repo := &tenantFindingRepo{
		all:     []*vulnerability.Finding{realFinding, orphan},
		byAsset: map[shared.ID][]*vulnerability.Finding{a1: {realFinding}},
	}
	a, _ := asset.NewAsset("example.com", asset.AssetTypeDomain, asset.CriticalityHigh)
	classifier := &fakeClassifier{}
	r := NewReclassifier(repo, &fakeAssetRepo{a: a}, classifier, logger.NewNop())

	n, err := r.ReclassifyForRequest(context.Background(), controller.ReclassifyRequest{
		TenantID: tenantID,
		Reason:   controller.ReasonPeriodicSweep,
	})
	if err != nil {
		t.Fatalf("ReclassifyForRequest: %v", err)
	}
	// Only the asset-bearing finding is reclassified; the orphan is skipped.
	if n != 1 {
		t.Fatalf("reexamined = %d, want 1 (orphan skipped)", n)
	}
	if classifier.called != 1 {
		t.Fatalf("classifier called %d times, want 1", classifier.called)
	}
}
