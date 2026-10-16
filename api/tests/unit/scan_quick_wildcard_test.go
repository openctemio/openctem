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
	if p.Kind != scanservice.QuickKindWildcard || p.Known != 2 || p.InScope != 2 {
		t.Errorf("preview = %+v, want wildcard, 2 known (not the name out of scope), 2 in scope", p)
	}
	skipped := map[string]int{}
	for _, s := range p.Skipped {
		skipped[s.Reason] = s.Count
	}
	if skipped[scanservice.SkipOutOfScope] != 0 || skipped[scanservice.SkipNotConfirmed] != 1 {
		t.Errorf("skipped = %v, want one unconfirmed and no count of names out of scope", p.Skipped)
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

// A member with a restricted data scope must not learn how many names the
// tenant has beyond it: not in known, not in the skipped counts, not in the
// discovery offer.
func TestQuickScanPreview_RestrictedMemberLearnsNoTenantWideCount(t *testing.T) {
	tenantID := shared.NewID()
	inv := newFakeSelectorAssets(tenantID)
	inv.byRoot["secret.example"] = []string{"a.secret.example", "b.secret.example", "c.secret.example"}
	inv.byRoot["mixed.example"] = []string{"mine.mixed.example", "x.mixed.example", "y.mixed.example"}
	act := &refuseAssetIDs{refused: map[shared.ID]bool{
		inv.id("a.secret.example"): true, inv.id("b.secret.example"): true, inv.id("c.secret.example"): true,
		inv.id("x.mixed.example"): true, inv.id("y.mixed.example"): true,
	}}
	svc, deps := newTestScanService(scanservice.WithActScope(act))
	svc.SetSelectorAssets(inv)
	deps.toolRepo.addTool("nuclei", true)
	deps.toolRepo.addTool("subfinder", true)
	preview := func(target string) scanservice.QuickPreviewTarget {
		pv, err := svc.PreviewQuickScan(context.Background(), scanservice.QuickScanPreviewInput{
			TenantID: tenantID.String(), UserID: shared.NewID().String(),
			Targets: []string{target}, ScannerName: "nuclei",
		})
		if err != nil {
			t.Fatal(err)
		}
		return pv.Targets[0]
	}
	p := preview("*.mixed.example")
	if p.Known != 1 || len(p.Skipped) != 0 {
		t.Errorf("mixed preview = %+v, want 1 known and nothing skipped", p)
	}
	for _, n := range p.Sample {
		if n == "x.mixed.example" || n == "y.mixed.example" {
			t.Errorf("sample names a hidden asset: %v", p.Sample)
		}
	}
	// Everything under the root is hidden: it looks like an unknown root.
	p = preview("*.secret.example")
	if p.Known != 0 || len(p.Skipped) != 0 {
		t.Errorf("hidden preview = %+v, want 0 known and nothing skipped", p)
	}
	if p.Discovery == nil || p.Discovery.Tool != "subfinder" {
		t.Errorf("discovery = %+v, want the same offer an empty root gets", p.Discovery)
	}
}
