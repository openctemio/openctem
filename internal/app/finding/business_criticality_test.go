package finding

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// stubBusinessContext returns a fixed business context per asset.
type stubBusinessContext struct {
	m     map[shared.ID]AssetBusinessContext
	calls int
}

func (s *stubBusinessContext) GetForAssets(
	_ context.Context, _ shared.ID, assetIDs []shared.ID,
) (map[shared.ID]AssetBusinessContext, error) {
	s.calls++
	out := map[shared.ID]AssetBusinessContext{}
	for _, id := range assetIDs {
		if v, ok := s.m[id]; ok {
			out[id] = v
		}
	}
	return out, nil
}

// The pure floor/MAX semantics now live in the shared resolver and are covered
// by TestEffectiveCriticality in pkg/domain/asset. The tests below prove the
// finding-priority path still applies that rule end-to-end (behavior unchanged
// after the extraction).

// mediumReachableEPSSFinding is a medium-severity, MODERATE-EPSS finding on a
// public (reachable) asset with the given OWN criticality. With own=medium it
// lands P2 (moderate-EPSS reachable safety net); the only thing that lifts it to
// the P1 "high EPSS (>=0.1) + reachable + critical asset" gate is the asset being
// critical/high.
//
// EPSS is 0.2, deliberately BELOW the 0.5 standalone-high-EPSS P1 threshold: at
// >=0.5 the finding would be P1 on its own (reachable + high exploitation prob),
// which would defeat this test's purpose of proving the BU bump does the lifting.
// (This value was 0.5 before the reachability/EPSS escalation fix, when EPSS only
// mattered on critical/high assets.)
func mediumReachableEPSSFinding(t *testing.T, tenantID shared.ID, own asset.Criticality) (*vulnerability.Finding, *asset.Asset) {
	t.Helper()
	a, err := asset.NewAssetWithTenant(tenantID, "web-01", asset.AssetTypeDomain, own)
	if err != nil {
		t.Fatalf("NewAssetWithTenant: %v", err)
	}
	if err := a.UpdateExposure(asset.ExposurePublic); err != nil {
		t.Fatalf("UpdateExposure: %v", err)
	}
	f, err := vulnerability.NewFinding(
		tenantID, a.ID(), vulnerability.FindingSourceSCA, "trivy",
		vulnerability.SeverityMedium, "medium dep",
	)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	f.SetEPSSScore(0.2) // >= 0.1 (so the critical-asset EPSS P1 gate is one criticality away) but < 0.5 (below the standalone-high-EPSS P1 threshold)
	return f, a
}

// TestClassifyFinding_BusinessUnitRaisesPriority proves a medium asset that
// belongs to a critical business unit is classified at the higher, business-
// aligned priority — and that the reason string records why.
func TestClassifyFinding_BusinessUnitRaisesPriority(t *testing.T) {
	tenantID := shared.NewID()
	ctx := context.Background()

	// Baseline: no business context → own medium criticality → P2.
	base, a := mediumReachableEPSSFinding(t, tenantID, asset.CriticalityMedium)
	if err := newControlSvc().ClassifyFinding(ctx, tenantID, base, a); err != nil {
		t.Fatalf("ClassifyFinding (baseline): %v", err)
	}
	if got := base.PriorityClass(); got == nil || *got != vulnerability.PriorityP2 {
		t.Fatalf("medium asset, high EPSS, reachable should be P2, got %v (%s)", got, base.PriorityClassReason())
	}

	// Same finding, but the asset belongs to a CRITICAL business unit → P1.
	raised, a2 := mediumReachableEPSSFinding(t, tenantID, asset.CriticalityMedium)
	svc := newControlSvc()
	stub := &stubBusinessContext{m: map[shared.ID]AssetBusinessContext{
		a2.ID(): {BusinessUnitCriticality: asset.CriticalityCritical, BusinessUnitName: "Payments"},
	}}
	svc.SetBusinessContextLookup(stub)

	if err := svc.ClassifyFinding(ctx, tenantID, raised, a2); err != nil {
		t.Fatalf("ClassifyFinding (raised): %v", err)
	}
	if stub.calls == 0 {
		t.Fatal("ClassifyFinding must consult the business context lookup")
	}
	got := raised.PriorityClass()
	if got == nil || *got != vulnerability.PriorityP1 {
		t.Fatalf("a critical BU should raise medium asset P2→P1, got %v (%s)", got, raised.PriorityClassReason())
	}
	if reason := raised.PriorityClassReason(); !strings.Contains(reason, "business unit 'Payments'") {
		t.Fatalf("reason should record the BU bump, got %q", reason)
	}
}

// TestClassifyFinding_CriticalServiceRaisesPriority proves the business-SERVICE
// path raises priority the same way.
func TestClassifyFinding_CriticalServiceRaisesPriority(t *testing.T) {
	tenantID := shared.NewID()
	f, a := mediumReachableEPSSFinding(t, tenantID, asset.CriticalityMedium)

	svc := newControlSvc()
	svc.SetBusinessContextLookup(&stubBusinessContext{m: map[shared.ID]AssetBusinessContext{
		a.ID(): {BusinessServiceCriticality: asset.CriticalityCritical, BusinessServiceName: "Checkout"},
	}})

	if err := svc.ClassifyFinding(context.Background(), tenantID, f, a); err != nil {
		t.Fatalf("ClassifyFinding: %v", err)
	}
	if got := f.PriorityClass(); got == nil || *got != vulnerability.PriorityP1 {
		t.Fatalf("a critical business service should raise P2→P1, got %v (%s)", got, f.PriorityClassReason())
	}
	if reason := f.PriorityClassReason(); !strings.Contains(reason, "business service 'Checkout'") {
		t.Fatalf("reason should record the service bump, got %q", reason)
	}
}

// TestClassifyFinding_LowerBUIsFloorOnly proves a LOWER-criticality BU never
// lowers an asset's own criticality (floor semantics) and adds no reason.
func TestClassifyFinding_LowerBUIsFloorOnly(t *testing.T) {
	tenantID := shared.NewID()

	// Own criticality high → EPSS P1 gate already fires. A low BU must not change
	// that, and must not add a "raised" reason.
	f, a := mediumReachableEPSSFinding(t, tenantID, asset.CriticalityHigh)
	svc := newControlSvc()
	svc.SetBusinessContextLookup(&stubBusinessContext{m: map[shared.ID]AssetBusinessContext{
		a.ID(): {BusinessUnitCriticality: asset.CriticalityLow, BusinessUnitName: "Lab"},
	}})

	if err := svc.ClassifyFinding(context.Background(), tenantID, f, a); err != nil {
		t.Fatalf("ClassifyFinding: %v", err)
	}
	if got := f.PriorityClass(); got == nil || *got != vulnerability.PriorityP1 {
		t.Fatalf("high asset, high EPSS, reachable should be P1 regardless of a low BU, got %v", got)
	}
	if reason := f.PriorityClassReason(); strings.Contains(reason, "raised") {
		t.Fatalf("a lower BU must not add a raise reason, got %q", reason)
	}
}

// TestEnrichAndClassifyBatch_BusinessUnitRaisesPriority proves the BATCH path
// (the main ingest/sweep path) preloads business context and applies the same
// business-aligned raise.
func TestEnrichAndClassifyBatch_BusinessUnitRaisesPriority(t *testing.T) {
	tenantID := shared.NewID()
	f, a := mediumReachableEPSSFinding(t, tenantID, asset.CriticalityMedium)

	svc := newControlSvc()
	stub := &stubBusinessContext{m: map[shared.ID]AssetBusinessContext{
		a.ID(): {BusinessUnitCriticality: asset.CriticalityCritical, BusinessUnitName: "Payments"},
	}}
	svc.SetBusinessContextLookup(stub)

	assets := map[shared.ID]*asset.Asset{a.ID(): a}
	if err := svc.EnrichAndClassifyBatch(context.Background(), tenantID,
		[]*vulnerability.Finding{f}, assets); err != nil {
		t.Fatalf("EnrichAndClassifyBatch: %v", err)
	}
	// Preload must be a single batch call, not per-finding.
	if stub.calls != 1 {
		t.Fatalf("batch path should call the business lookup exactly once, got %d", stub.calls)
	}
	if got := f.PriorityClass(); got == nil || *got != vulnerability.PriorityP1 {
		t.Fatalf("batch: critical BU should raise medium asset P2→P1, got %v (%s)", got, f.PriorityClassReason())
	}
	if reason := f.PriorityClassReason(); !strings.Contains(reason, "business unit 'Payments'") {
		t.Fatalf("batch: reason should record the BU bump, got %q", reason)
	}
}
