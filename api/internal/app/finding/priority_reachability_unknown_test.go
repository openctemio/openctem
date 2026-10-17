package finding

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func classifyOnExposure(t *testing.T, typ asset.AssetType, exposure asset.Exposure) *vulnerability.Finding {
	t.Helper()
	tenantID := shared.NewID()
	a, err := asset.NewAssetWithTenant(tenantID, "gitlab.com/acme/app", typ, asset.CriticalityMedium)
	if err != nil {
		t.Fatalf("NewAssetWithTenant: %v", err)
	}
	if exposure != "" {
		if err := a.UpdateExposure(exposure); err != nil {
			t.Fatalf("UpdateExposure: %v", err)
		}
	}
	f, err := vulnerability.NewFinding(tenantID, a.ID(), vulnerability.FindingSourceSCA, "trivy",
		vulnerability.SeverityCritical, "SQL injection in Django")
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	if err := newControlSvc().ClassifyFinding(context.Background(), tenantID, f, a); err != nil {
		t.Fatalf("ClassifyFinding: %v", err)
	}
	return f
}

// A repository with no exposure data: reachability is unknown, never "not
// reachable".
func TestClassifyFinding_UnknownExposure_ReasonSaysUnknown(t *testing.T) {
	f := classifyOnExposure(t, asset.AssetTypeRepository, asset.ExposureUnknown)
	if got := f.PriorityClass(); got == nil || *got != vulnerability.PriorityP2 {
		t.Fatalf("want P2, got %v (%s)", got, f.PriorityClassReason())
	}
	r := f.PriorityClassReason()
	if strings.Contains(r, "not reachable") || !strings.Contains(r, "reachability unknown") {
		t.Fatalf("unknown exposure must read as unknown reachability, got %q", r)
	}
}

// An isolated asset is evidence of unreachability and keeps that reason.
func TestClassifyFinding_IsolatedExposure_ReasonSaysNotReachable(t *testing.T) {
	f := classifyOnExposure(t, asset.AssetTypeHost, asset.ExposureIsolated)
	if r := f.PriorityClassReason(); !strings.Contains(r, "not reachable") {
		t.Fatalf("isolated asset keeps the unreachable reason, got %q", r)
	}
}

// A public asset is reachable: P1, no unknown wording.
func TestClassifyFinding_PublicExposure_IsReachable(t *testing.T) {
	f := classifyOnExposure(t, asset.AssetTypeHost, asset.ExposurePublic)
	if got := f.PriorityClass(); got == nil || *got != vulnerability.PriorityP1 {
		t.Fatalf("critical on a public asset is P1, got %v (%s)", got, f.PriorityClassReason())
	}
	if strings.Contains(f.PriorityClassReason(), "unknown") {
		t.Fatalf("public asset must not read as unknown: %q", f.PriorityClassReason())
	}
}
