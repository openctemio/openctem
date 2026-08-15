package finding

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// TestClassifyFinding_CIAImpactBumpsPriority proves the asset's CIA impact
// rating (Scoping critical-asset register) flows through buildPriorityContext
// into classification: a borderline P3 finding on an asset whose confidentiality
// impact is HIGH is raised to P2, and the reason records the CIA rating. This is
// the ctem.org CIA-impact business-impact input, previously stored but inert.
func TestClassifyFinding_CIAImpactBumpsPriority(t *testing.T) {
	tenantID := shared.NewID()
	ctx := context.Background()

	// Baseline: low-severity, non-reachable finding with NO CIA rating → P3.
	a, err := asset.NewAssetWithTenant(tenantID, "db-01", asset.AssetTypeDatabase, asset.CriticalityMedium)
	if err != nil {
		t.Fatalf("NewAssetWithTenant: %v", err)
	}
	base, err := vulnerability.NewFinding(tenantID, a.ID(), vulnerability.FindingSourceSCA, "trivy",
		vulnerability.SeverityLow, "low finding")
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	if err := newControlSvc().ClassifyFinding(ctx, tenantID, base, a); err != nil {
		t.Fatalf("ClassifyFinding (baseline): %v", err)
	}
	if got := base.PriorityClass(); got == nil || *got != vulnerability.PriorityP3 {
		t.Fatalf("baseline (no CIA) should be P3, got %v (%s)", got, base.PriorityClassReason())
	}

	// Same finding + asset, but the asset's confidentiality impact is HIGH → P2.
	a2, _ := asset.NewAssetWithTenant(tenantID, "db-02", asset.AssetTypeDatabase, asset.CriticalityMedium)
	if err := a2.SetImpactConfidentiality(asset.ImpactRatingHigh); err != nil {
		t.Fatalf("SetImpactConfidentiality: %v", err)
	}
	raised, _ := vulnerability.NewFinding(tenantID, a2.ID(), vulnerability.FindingSourceSCA, "trivy",
		vulnerability.SeverityLow, "low finding")
	if err := newControlSvc().ClassifyFinding(ctx, tenantID, raised, a2); err != nil {
		t.Fatalf("ClassifyFinding (raised): %v", err)
	}
	got := raised.PriorityClass()
	if got == nil || *got != vulnerability.PriorityP2 {
		t.Fatalf("high CIA impact should raise P3→P2, got %v (%s)", got, raised.PriorityClassReason())
	}
	if reason := raised.PriorityClassReason(); !strings.Contains(reason, "CIA") {
		t.Errorf("reason should record the CIA rating, got %q", reason)
	}
}

// TestClassifyFinding_ControlPlaneRaisesPriority proves the control-plane
// propagation: an asset that is the control plane of a CRITICAL asset (resolved
// via the shared BusinessContext → EffectiveCriticality seam) inherits that
// criticality, lifting a finding on it P2→P1. Mirrors the BU/service raise but
// via the new ControlPlaneServes* signal.
func TestClassifyFinding_ControlPlaneRaisesPriority(t *testing.T) {
	tenantID := shared.NewID()
	f, a := mediumReachableEPSSFinding(t, tenantID, asset.CriticalityMedium)

	svc := newControlSvc()
	svc.SetBusinessContextLookup(&stubBusinessContext{m: map[shared.ID]AssetBusinessContext{
		a.ID(): {ControlPlaneServesCriticality: asset.CriticalityCritical, ControlPlaneServesName: "Checkout"},
	}})

	if err := svc.ClassifyFinding(context.Background(), tenantID, f, a); err != nil {
		t.Fatalf("ClassifyFinding: %v", err)
	}
	if got := f.PriorityClass(); got == nil || *got != vulnerability.PriorityP1 {
		t.Fatalf("control plane of a critical asset should raise P2→P1, got %v (%s)", got, f.PriorityClassReason())
	}
	if reason := f.PriorityClassReason(); !strings.Contains(reason, "control plane of 'Checkout'") {
		t.Errorf("reason should record the control-plane raise, got %q", reason)
	}
}

// TestClassifyFinding_NoCIANoControlPlaneUnchanged is the back-compat guard: an
// asset with no CIA rating and no control-plane context classifies exactly as
// before (no churn for existing data).
func TestClassifyFinding_NoCIANoControlPlaneUnchanged(t *testing.T) {
	tenantID := shared.NewID()
	f, a := mediumReachableEPSSFinding(t, tenantID, asset.CriticalityMedium)
	if err := newControlSvc().ClassifyFinding(context.Background(), tenantID, f, a); err != nil {
		t.Fatalf("ClassifyFinding: %v", err)
	}
	if got := f.PriorityClass(); got == nil || *got != vulnerability.PriorityP2 {
		t.Fatalf("no CIA / no control-plane should stay P2, got %v (%s)", got, f.PriorityClassReason())
	}
	if reason := f.PriorityClassReason(); strings.Contains(reason, "CIA") || strings.Contains(reason, "control plane") {
		t.Errorf("no CIA / control-plane note expected, got %q", reason)
	}
}
