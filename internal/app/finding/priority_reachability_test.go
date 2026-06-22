package finding

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// newTestFinding builds a minimal KEV-flagged critical finding for priority tests.
func newTestFinding(t *testing.T) *vulnerability.Finding {
	t.Helper()
	tid := shared.NewID()
	aid := shared.NewID()
	f, err := vulnerability.NewFinding(tid, aid, vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityCritical, "CVE in dependency")
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	f.SetIsInKEV(true)
	return f
}

func newTestAsset(t *testing.T, exposure asset.Exposure) *asset.Asset {
	t.Helper()
	a, err := asset.NewAssetWithTenant(shared.NewID(), "web-01", asset.AssetTypeDomain, asset.CriticalityMedium)
	if err != nil {
		t.Fatalf("NewAsset: %v", err)
	}
	if err := a.UpdateExposure(exposure); err != nil {
		t.Fatalf("UpdateExposure(%s): %v", exposure, err)
	}
	return a
}

// buildPriorityContext only reads (finding, asset); a zero-value service is fine.
func newReachabilitySvc() *PriorityClassificationService {
	return &PriorityClassificationService{}
}

func TestBuildPriorityContext_PublicAssetIsInternetReachable(t *testing.T) {
	svc := newReachabilitySvc()
	ctx := svc.buildPriorityContext(newTestFinding(t), newTestAsset(t, asset.ExposurePublic))

	if !ctx.IsInternetAccessible {
		t.Fatal("public asset should be internet-accessible")
	}
	if ctx.ReachableFromCount == 0 {
		t.Fatal("public asset should have a non-zero reachable-from count")
	}

	// KEV + reachable -> P0.
	got := vulnerability.ClassifyPriority(ctx)
	if got.Class != vulnerability.PriorityP0 {
		t.Fatalf("KEV on public asset should be P0, got %s (%s)", got.Class, got.Reason)
	}
}

func TestBuildPriorityContext_PrivateAssetNotInternetReachable(t *testing.T) {
	svc := newReachabilitySvc()
	ctx := svc.buildPriorityContext(newTestFinding(t), newTestAsset(t, asset.ExposurePrivate))

	if ctx.IsInternetAccessible {
		t.Fatal("private asset must not be internet-accessible")
	}
	if !ctx.IsNetworkAccessible {
		t.Fatal("private asset should be network-accessible")
	}

	// KEV on a non-crown-jewel, non-internet-reachable asset must NOT be P0.
	got := vulnerability.ClassifyPriority(ctx)
	if got.Class == vulnerability.PriorityP0 {
		t.Fatalf("KEV on private (non-reachable, non-crown-jewel) asset should not be P0, got %s", got.Reason)
	}
}

func TestBuildPriorityContext_IsolatedAssetNotReachable(t *testing.T) {
	svc := newReachabilitySvc()
	ctx := svc.buildPriorityContext(newTestFinding(t), newTestAsset(t, asset.ExposureIsolated))

	if ctx.IsInternetAccessible || ctx.IsNetworkAccessible {
		t.Fatal("isolated asset should be neither internet- nor network-accessible")
	}
}

func TestBuildPriorityContext_NilAssetNoPanic(t *testing.T) {
	svc := newReachabilitySvc()
	ctx := svc.buildPriorityContext(newTestFinding(t), nil)
	if ctx.IsInternetAccessible || ctx.IsNetworkAccessible {
		t.Fatal("nil asset should leave reachability unset")
	}
}
