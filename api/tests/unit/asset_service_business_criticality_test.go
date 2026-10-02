package unit

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// stubAssetBusinessContext implements the asset service's BusinessContextLookup
// with a fixed per-asset business context. It records call count so tests can
// prove the scoring path actually consults it.
type stubAssetBusinessContext struct {
	m     map[shared.ID]asset.BusinessContext
	calls int
}

func (s *stubAssetBusinessContext) GetForAssets(
	_ context.Context, _ shared.ID, assetIDs []shared.ID,
) (map[shared.ID]asset.BusinessContext, error) {
	s.calls++
	out := make(map[shared.ID]asset.BusinessContext, len(assetIDs))
	for _, id := range assetIDs {
		if v, ok := s.m[id]; ok {
			out[id] = v
		}
	}
	return out, nil
}

// TestAssetService_RiskScore_CriticalBURaisesScore proves that, through the real
// service recalculation path, an asset that belongs to a CRITICAL business unit
// gets a HIGHER risk score than an otherwise-identical asset with no business
// context — and that the business-context lookup is actually consulted.
func TestAssetService_RiskScore_CriticalBURaisesScore(t *testing.T) {
	repo := newMockBatchAssetRepository()
	svc := newTestAssetService(repo)

	cfg := asset.LegacyRiskScoringConfig()
	svc.SetScoringConfigProvider(&mockScoringConfigProvider{config: &cfg})

	// Two identical low-criticality, private assets with the same finding load.
	inBU := makeTestAssetForService(asset.ExposurePrivate, asset.CriticalityLow, 1)
	noBU := makeTestAssetForService(asset.ExposurePrivate, asset.CriticalityLow, 1)
	repo.assets[inBU.ID().String()] = inBU
	repo.assets[noBU.ID().String()] = noBU

	// Only `inBU` belongs to a critical business unit.
	stub := &stubAssetBusinessContext{m: map[shared.ID]asset.BusinessContext{
		inBU.ID(): {BusinessUnitCriticality: asset.CriticalityCritical, BusinessUnitName: "Payments"},
	}}
	svc.SetBusinessContextLookup(stub)

	if _, err := svc.RecalculateAllRiskScores(context.Background(), serviceTenantID); err != nil {
		t.Fatalf("RecalculateAllRiskScores: %v", err)
	}

	if stub.calls == 0 {
		t.Fatal("scoring path must consult the business-context lookup")
	}
	if inBU.RiskScore() <= noBU.RiskScore() {
		t.Fatalf("asset in a critical BU should score higher: inBU=%d noBU=%d",
			inBU.RiskScore(), noBU.RiskScore())
	}

	// The no-BU asset must match a plain own-criticality computation — the
	// nil-context path is unchanged.
	engine := asset.NewRiskScoringEngine(cfg)
	control := makeTestAssetForService(asset.ExposurePrivate, asset.CriticalityLow, 1)
	if want := engine.CalculateScore(control); noBU.RiskScore() != want {
		t.Fatalf("no-BU asset score changed: got %d want %d", noBU.RiskScore(), want)
	}
}

// TestAssetService_RiskScore_LowBUNeverLowers proves the floor semantics end to
// end: a CRITICAL asset that happens to sit in a LOW-criticality business unit
// scores exactly the same as the same critical asset with no business context —
// the business signal can only raise, never lower.
func TestAssetService_RiskScore_LowBUNeverLowers(t *testing.T) {
	repo := newMockBatchAssetRepository()
	svc := newTestAssetService(repo)

	cfg := asset.LegacyRiskScoringConfig()
	svc.SetScoringConfigProvider(&mockScoringConfigProvider{config: &cfg})

	inLowBU := makeTestAssetForService(asset.ExposurePublic, asset.CriticalityCritical, 2)
	noBU := makeTestAssetForService(asset.ExposurePublic, asset.CriticalityCritical, 2)
	repo.assets[inLowBU.ID().String()] = inLowBU
	repo.assets[noBU.ID().String()] = noBU

	svc.SetBusinessContextLookup(&stubAssetBusinessContext{m: map[shared.ID]asset.BusinessContext{
		inLowBU.ID(): {BusinessUnitCriticality: asset.CriticalityLow, BusinessUnitName: "IT"},
	}})

	if _, err := svc.RecalculateAllRiskScores(context.Background(), serviceTenantID); err != nil {
		t.Fatalf("RecalculateAllRiskScores: %v", err)
	}

	if inLowBU.RiskScore() != noBU.RiskScore() {
		t.Fatalf("a low BU must not lower a critical asset's score: inLowBU=%d noBU=%d",
			inLowBU.RiskScore(), noBU.RiskScore())
	}
}

// TestAssetService_RiskScore_NoLookupUnchanged proves that with no business-
// context lookup wired at all (the default), scores are computed on own
// criticality exactly as before — the change is fully reversible via the seam.
func TestAssetService_RiskScore_NoLookupUnchanged(t *testing.T) {
	repo := newMockBatchAssetRepository()
	svc := newTestAssetService(repo)

	cfg := asset.LegacyRiskScoringConfig()
	svc.SetScoringConfigProvider(&mockScoringConfigProvider{config: &cfg})

	a := makeTestAssetForService(asset.ExposurePrivate, asset.CriticalityMedium, 3)
	repo.assets[a.ID().String()] = a

	// No SetBusinessContextLookup call.
	if _, err := svc.RecalculateAllRiskScores(context.Background(), serviceTenantID); err != nil {
		t.Fatalf("RecalculateAllRiskScores: %v", err)
	}

	engine := asset.NewRiskScoringEngine(cfg)
	control := makeTestAssetForService(asset.ExposurePrivate, asset.CriticalityMedium, 3)
	if want := engine.CalculateScore(control); a.RiskScore() != want {
		t.Fatalf("no-lookup score should equal own-criticality score: got %d want %d", a.RiskScore(), want)
	}
}
