package finding

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// stubControlLookup returns a fixed reduction factor for one asset.
type stubControlLookup struct {
	assetID   shared.ID
	reduction float64
	calls     int
}

func (s *stubControlLookup) GetEffectiveForAssets(
	_ context.Context, _ shared.ID, assetIDs []shared.ID,
) (map[shared.ID]float64, error) {
	s.calls++
	out := map[shared.ID]float64{}
	for _, id := range assetIDs {
		if id == s.assetID {
			out[id] = s.reduction
		}
	}
	return out, nil
}

type stubRuleRepo struct{}

func (stubRuleRepo) ListActiveByTenant(
	_ context.Context, _ shared.ID,
) ([]*vulnerability.PriorityOverrideRule, error) {
	return nil, nil
}

type stubAuditRepo struct{}

func (stubAuditRepo) LogChange(_ context.Context, _ PriorityAuditEntry) error { return nil }

// newControlSvc builds the minimum service ClassifyFinding needs.
func newControlSvc() *PriorityClassificationService {
	return NewPriorityClassificationService(
		nil, nil, nil, nil, stubRuleRepo{}, stubAuditRepo{}, logger.NewNop(),
	)
}

// criticalReachableFinding is a critical, non-KEV finding on a public asset.
// Unprotected it classifies P1 ("Critical severity, reachable, no compensating
// controls"); the only thing that can pull it down to P2 is a compensating
// control. Non-KEV on purpose — KEV+reachable is P0 and is deliberately NOT
// suppressed by controls.
func criticalReachableFinding(t *testing.T, tenantID shared.ID) (*vulnerability.Finding, *asset.Asset) {
	t.Helper()
	a, err := asset.NewAssetWithTenant(tenantID, "web-01", asset.AssetTypeDomain, asset.CriticalityMedium)
	if err != nil {
		t.Fatalf("NewAssetWithTenant: %v", err)
	}
	if err := a.UpdateExposure(asset.ExposurePublic); err != nil {
		t.Fatalf("UpdateExposure: %v", err)
	}
	f, err := vulnerability.NewFinding(
		tenantID, a.ID(), vulnerability.FindingSourceSCA, "trivy",
		vulnerability.SeverityCritical, "critical dep",
	)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f, a
}

// TestClassifyFinding_HonoursCompensatingControls is the regression guard for
// the gap that made compensating controls inert.
//
// Linking an asset to a control publishes a reclassify sweep, and that sweep
// runs Reclassifier.reclassifyAsset → ClassifyFinding. ClassifyFinding never
// consulted the control lookup, so the fan-out built to make control changes
// reflect in priority fed a classifier that could not see controls: the
// operator linked the asset, the sweep ran, and nothing moved.
func TestClassifyFinding_HonoursCompensatingControls(t *testing.T) {
	tenantID := shared.NewID()
	ctx := context.Background()

	// Baseline: no control lookup wired at all → P1.
	unprotected, a := criticalReachableFinding(t, tenantID)
	if err := newControlSvc().ClassifyFinding(ctx, tenantID, unprotected, a); err != nil {
		t.Fatalf("ClassifyFinding (unprotected): %v", err)
	}
	if got := unprotected.PriorityClass(); got == nil || *got != vulnerability.PriorityP1 {
		t.Fatalf("critical + reachable + no control should be P1, got %v", got)
	}

	// Same finding, same asset, with an effective control on it → P2.
	protected, a2 := criticalReachableFinding(t, tenantID)
	svc := newControlSvc()
	lookup := &stubControlLookup{assetID: a2.ID(), reduction: 0.30}
	svc.SetControlLookup(lookup)

	if err := svc.ClassifyFinding(ctx, tenantID, protected, a2); err != nil {
		t.Fatalf("ClassifyFinding (protected): %v", err)
	}
	if lookup.calls == 0 {
		t.Fatal("ClassifyFinding must consult the compensating control lookup")
	}
	got := protected.PriorityClass()
	if got == nil || *got != vulnerability.PriorityP2 {
		t.Fatalf("an asset covered by a compensating control should drop P1→P2, got %v (%s)",
			got, protected.PriorityClassReason())
	}
}

// A control with reduction_factor 0 — the column default — must NOT count as
// protection, otherwise a control saved without a factor silently suppresses P1.
func TestClassifyFinding_ZeroReductionFactorIsNotProtection(t *testing.T) {
	tenantID := shared.NewID()
	f, a := criticalReachableFinding(t, tenantID)

	svc := newControlSvc()
	svc.SetControlLookup(&stubControlLookup{assetID: a.ID(), reduction: 0})

	if err := svc.ClassifyFinding(context.Background(), tenantID, f, a); err != nil {
		t.Fatalf("ClassifyFinding: %v", err)
	}
	if got := f.PriorityClass(); got == nil || *got != vulnerability.PriorityP1 {
		t.Fatalf("a 0.0 reduction factor must not suppress P1, got %v", got)
	}
}

// A control on a DIFFERENT asset must not protect this finding.
func TestClassifyFinding_ControlOnOtherAssetDoesNotProtect(t *testing.T) {
	tenantID := shared.NewID()
	f, a := criticalReachableFinding(t, tenantID)

	svc := newControlSvc()
	svc.SetControlLookup(&stubControlLookup{assetID: shared.NewID(), reduction: 0.9})

	if err := svc.ClassifyFinding(context.Background(), tenantID, f, a); err != nil {
		t.Fatalf("ClassifyFinding: %v", err)
	}
	if got := f.PriorityClass(); got == nil || *got != vulnerability.PriorityP1 {
		t.Fatalf("a control on an unrelated asset must not suppress P1, got %v", got)
	}
}

// setControlProtection is the single expression of the "protected" rule that
// both the per-finding and batch paths use.
func TestSetControlProtection(t *testing.T) {
	cases := []struct {
		reduction     float64
		wantProtected bool
	}{
		{0, false},
		{-1, false},
		{0.01, true},
		{1, true},
	}
	for _, tc := range cases {
		pctx := vulnerability.PriorityContext{}
		setControlProtection(&pctx, tc.reduction)
		if pctx.IsProtected != tc.wantProtected {
			t.Fatalf("reduction %v: IsProtected = %v, want %v",
				tc.reduction, pctx.IsProtected, tc.wantProtected)
		}
		if tc.wantProtected && pctx.ControlReductionFactor != tc.reduction {
			t.Fatalf("reduction %v: factor not carried through", tc.reduction)
		}
	}
}
