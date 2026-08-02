package reclassify

import (
	"context"
	"testing"

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
