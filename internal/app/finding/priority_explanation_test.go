package finding

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// --- fakes (embed the big interfaces; override only what ExplainFinding uses) ---

type explainFindingRepo struct {
	vulnerability.FindingRepository
	f   *vulnerability.Finding
	err error
}

func (r *explainFindingRepo) GetByID(_ context.Context, _ shared.ID, _ shared.ID) (*vulnerability.Finding, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.f, nil
}

type explainAssetRepo struct {
	asset.Repository
	a *asset.Asset
}

func (r *explainAssetRepo) GetByID(_ context.Context, _ shared.ID, _ shared.ID) (*asset.Asset, error) {
	return r.a, nil
}

type explainRuleRepo struct{}

func (explainRuleRepo) ListActiveByTenant(_ context.Context, _ shared.ID) ([]*vulnerability.PriorityOverrideRule, error) {
	return nil, nil
}

func buildExplainFinding(t *testing.T) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityCritical, "KEV dep")
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	f.SetIsInKEV(true)
	return f
}

func buildExplainAsset(t *testing.T) *asset.Asset {
	t.Helper()
	a, err := asset.NewAssetWithTenant(shared.NewID(), "web-01", asset.AssetTypeDomain, asset.CriticalityMedium)
	if err != nil {
		t.Fatalf("NewAsset: %v", err)
	}
	_ = a.UpdateExposure(asset.ExposurePublic)
	return a
}

func newExplainSvc(fr *explainFindingRepo, ar *explainAssetRepo) *PriorityClassificationService {
	return &PriorityClassificationService{
		findingRepo: fr,
		assetRepo:   ar,
		ruleRepo:    explainRuleRepo{},
		logger:      logger.NewNop(),
	}
}

func TestExplainFinding_PopulatesFactorsAndDecision(t *testing.T) {
	svc := newExplainSvc(
		&explainFindingRepo{f: buildExplainFinding(t)},
		&explainAssetRepo{a: buildExplainAsset(t)},
	)

	exp, err := svc.ExplainFinding(context.Background(), shared.NewID(), shared.NewID())
	if err != nil {
		t.Fatalf("ExplainFinding: %v", err)
	}

	if !exp.Factors.IsInKEV {
		t.Error("expected IsInKEV factor true")
	}
	if exp.Factors.Severity != string(vulnerability.SeverityCritical) {
		t.Errorf("severity factor = %q", exp.Factors.Severity)
	}
	if exp.Factors.AssetCriticality != string(asset.CriticalityMedium) {
		t.Errorf("asset criticality factor = %q", exp.Factors.AssetCriticality)
	}
	if exp.Factors.AssetExposure != string(asset.ExposurePublic) {
		t.Errorf("asset exposure factor = %q", exp.Factors.AssetExposure)
	}
	// Derived "reachable" must equal the documented formula, whatever the
	// underlying reachability wiring produced.
	want := exp.Factors.IsReachable || exp.Factors.IsInternetAccessible
	if exp.Factors.Reachable != want {
		t.Errorf("derived Reachable=%v, want %v", exp.Factors.Reachable, want)
	}
	if exp.Source != "auto" {
		t.Errorf("source = %q, want auto (no rules)", exp.Source)
	}
	switch vulnerability.PriorityClass(exp.Class) {
	case vulnerability.PriorityP0, vulnerability.PriorityP1, vulnerability.PriorityP2, vulnerability.PriorityP3:
	default:
		t.Errorf("class %q is not a valid priority class", exp.Class)
	}
	if exp.Reason == "" {
		t.Error("expected a non-empty reason")
	}
}

func TestExplainFinding_FindingNotFound(t *testing.T) {
	svc := newExplainSvc(&explainFindingRepo{err: errors.New("nope")}, &explainAssetRepo{})
	if _, err := svc.ExplainFinding(context.Background(), shared.NewID(), shared.NewID()); err == nil {
		t.Fatal("expected error when finding load fails")
	}
}
