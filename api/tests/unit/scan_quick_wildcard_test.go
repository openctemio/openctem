package unit

import (
	"context"
	"slices"
	"testing"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A Quick Scan of a wildcard target stores the typed targets as the scan's
// targets only (never in the scanner settings), so the run expands the
// pattern from the inventory like a saved scan does.
func TestQuickScan_WildcardGoesToScanTargetsAndExpands(t *testing.T) {
	tenantID := shared.NewID()
	inv := newFakeSelectorAssets(tenantID)
	inv.byRoot["pti.com.vn"] = []string{"api.pti.com.vn", "www.pti.com.vn"}
	svc, deps := newTestScanService()
	svc.SetSelectorAssets(inv)
	deps.toolRepo.addTool("nuclei", true)

	res, err := svc.QuickScan(context.Background(), scanservice.QuickScanInput{
		TenantID: tenantID.String(), Targets: []string{"*.pti.com.vn"}, ScannerName: "nuclei",
	})
	if err != nil {
		t.Fatalf("quick scan of a wildcard: %v", err)
	}
	sc := deps.scanRepo.scans[res.ScanID]
	if len(sc.Targets) != 1 || sc.Targets[0] != "*.pti.com.vn" {
		t.Errorf("scan targets = %v", sc.Targets)
	}
	if _, mirrored := sc.ScannerConfig["targets"]; mirrored {
		t.Errorf("typed targets were copied into the scanner settings: %v", sc.ScannerConfig)
	}
	got := dispatchedTargets(t, deps)
	want := []string{"api.pti.com.vn", "pti.com.vn", "www.pti.com.vn"}
	if !slices.Equal(got, want) {
		t.Errorf("dispatched %v, want %v", got, want)
	}
}

// What the caller may not scan, and what is not confirmed, never reaches a
// quick scan run of a wildcard, and the preview counts them.
func TestQuickScan_WildcardRunsInScopeNamesOnlyAndPreviewCounts(t *testing.T) {
	tenantID := shared.NewID()
	inv := newFakeSelectorAssets(tenantID)
	inv.byRoot["example.com"] = []string{"ok.example.com", "review.example.com", "hidden.example.com"}
	gate := &blockAssets{blocked: map[string]attribution.State{inv.id("review.example.com").String(): attribution.StateNeedsReview}}
	act := &refuseAssetIDs{refused: map[shared.ID]bool{inv.id("hidden.example.com"): true}}
	svc, deps := newTestScanService(scanservice.WithAttributionGate(gate), scanservice.WithActScope(act))
	svc.SetSelectorAssets(inv)
	deps.toolRepo.addTool("nuclei", true)

	pv, err := svc.PreviewQuickScan(context.Background(), scanservice.QuickScanPreviewInput{
		TenantID: tenantID.String(), UserID: shared.NewID().String(),
		Targets: []string{"*.example.com"}, ScannerName: "nuclei",
	})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if len(pv.Targets) != 1 {
		t.Fatalf("preview targets = %+v", pv.Targets)
	}
	p := pv.Targets[0]
	if p.Kind != scanservice.QuickKindWildcard || p.Known != 3 || p.InScope != 2 {
		t.Errorf("preview = %+v, want wildcard, 3 known, 2 in scope", p)
	}
	skipped := map[string]int{}
	for _, s := range p.Skipped {
		skipped[s.Reason] = s.Count
	}
	if skipped[scanservice.SkipOutOfScope] != 1 || skipped[scanservice.SkipNotConfirmed] != 1 {
		t.Errorf("skipped = %v, want one out of scope and one unconfirmed", p.Skipped)
	}
	if !slices.Equal(p.Sample, []string{"example.com", "ok.example.com"}) {
		t.Errorf("sample = %v", p.Sample)
	}
	if len(deps.runRepo.runs) != 0 || len(deps.commandRepo.commands) != 0 {
		t.Error("the preview created a run or a command")
	}

	if _, err := svc.QuickScan(context.Background(), scanservice.QuickScanInput{
		TenantID: tenantID.String(), Targets: []string{"*.example.com"}, ScannerName: "nuclei",
	}); err != nil {
		t.Fatalf("quick scan: %v", err)
	}
	if got := dispatchedTargets(t, deps); !slices.Equal(got, []string{"example.com", "ok.example.com"}) {
		t.Errorf("dispatched %v, want only the apex and the confirmed, in-scope name", got)
	}
}

// Another tenant's inventory is invisible to the preview.
func TestQuickScanPreview_OtherTenantSeesNothing(t *testing.T) {
	owner, other := shared.NewID(), shared.NewID()
	inv := newFakeSelectorAssets(owner)
	inv.byRoot["example.com"] = []string{"a.example.com"}
	svc, deps := newTestScanService()
	svc.SetSelectorAssets(inv)
	deps.toolRepo.addTool("nuclei", true)
	pv, err := svc.PreviewQuickScan(context.Background(), scanservice.QuickScanPreviewInput{
		TenantID: other.String(), Targets: []string{"*.example.com"}, ScannerName: "nuclei",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p := pv.Targets[0]; p.Known != 0 || slices.Contains(p.Sample, "a.example.com") {
		t.Errorf("preview leaked another tenant's asset: %+v", p)
	}
}

// A wildcard with no known name offers discovery on its apex when a
// discovery tool exists, and not when the scanner already is one.
func TestQuickScanPreview_ZeroMatchOffersDiscovery(t *testing.T) {
	tenantID := shared.NewID()
	svc, deps := newTestScanService()
	svc.SetSelectorAssets(newFakeSelectorAssets(tenantID))
	deps.toolRepo.addTool("nuclei", true)
	deps.toolRepo.addTool("subfinder", true)
	preview := func(scanner string) scanservice.QuickPreviewTarget {
		pv, err := svc.PreviewQuickScan(context.Background(), scanservice.QuickScanPreviewInput{
			TenantID: tenantID.String(), Targets: []string{"*.pti.com.vn"}, ScannerName: scanner,
		})
		if err != nil {
			t.Fatal(err)
		}
		return pv.Targets[0]
	}
	p := preview("nuclei")
	if p.Known != 0 || p.Discovery == nil || p.Discovery.Tool != "subfinder" || p.Discovery.Root != "pti.com.vn" {
		t.Errorf("preview = %+v, want a subfinder offer on pti.com.vn", p)
	}
	if p := preview("subfinder"); p.Discovery != nil {
		t.Errorf("discovery offered to a discovery scan: %+v", p.Discovery)
	}
}

// A root nobody may cover is refused with a code, not resolved.
func TestQuickScanPreview_SharedRootIsRefused(t *testing.T) {
	tenantID := shared.NewID()
	inv := newFakeSelectorAssets(tenantID)
	svc, deps := newTestScanService()
	svc.SetSelectorAssets(inv)
	deps.toolRepo.addTool("nuclei", true)
	pv, err := svc.PreviewQuickScan(context.Background(), scanservice.QuickScanPreviewInput{
		TenantID: tenantID.String(), Targets: []string{"*.com"}, ScannerName: "nuclei",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p := pv.Targets[0]; p.RefusedCode != scanservice.QuickRefusedInvalid || len(inv.queries) != 0 {
		t.Errorf("preview = %+v, queries = %d", p, len(inv.queries))
	}
}
