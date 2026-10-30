package unit

import (
	"context"
	"strings"
	"testing"
	"time"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	freshdom "github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Skipped targets in the New Scan preview, grouped by reason, through the
// real scan service (docs/architecture/scan-targets.md, "Skipped targets").

// staleEvidence: every name it knows was last seen resolving long ago, in
// one tenant only.
type staleEvidence struct {
	tenant shared.ID
	names  map[string]bool
}

func (e staleEvidence) FreshestByName(_ context.Context, tenant shared.ID, names []string, _ []freshdom.Class) ([]freshdom.NameEvidence, error) {
	var out []freshdom.NameEvidence
	for _, n := range names {
		if tenant == e.tenant && e.names[n] {
			out = append(out, freshdom.NameEvidence{AssetID: shared.NewID(), Name: n, ObservedAt: time.Now().Add(-30 * 24 * time.Hour)})
		}
	}
	return out, nil
}

func skipGroupOf(p *scanservice.ZoneRoutingPreview, reason string) *scanservice.SkipGroup {
	for i := range p.Skipped {
		if p.Skipped[i].Reason == reason {
			return &p.Skipped[i]
		}
	}
	return nil
}

func TestScanPreview_SkippedByReason(t *testing.T) {
	tenant := shared.NewID()
	s1 := shared.NewID()
	dcA := zone(t, tenant, "dc-a", false, []shared.ID{s1}, "10.1.0.0/16")
	empty := zone(t, tenant, "empty", false, nil, "10.3.0.0/16")
	dir := &fakeZoneDir{
		zones:    []*scanzone.Zone{dcA, empty},
		routable: map[shared.ID][]scanzone.SensorCandidate{dcA.ID: candidates(s1)},
	}
	res := tableResolver{"www.example.com": {"93.184.216.34"}, "old.example.com": {"93.184.216.35"}}
	svc, _ := newZonedScanService(dir, res, valueExclusions{"10.1.0.2": true})
	svc.SetResolveEvidence(staleEvidence{tenant: tenant, names: map[string]bool{"old.example.com": true}}, nil)

	p := preview(t, svc, scanservice.ZoneRoutingPreviewInput{
		TenantID:    tenant.String(),
		ScannerName: "nuclei",
		Targets: []string{
			"10.1.0.1", "10.1.0.2", "10.3.0.1", "www.example.com",
			"gone1.example.com", "gone2.example.com", "old.example.com",
		},
	})
	if p.WillScan != 2 || p.SkippedTotal != 5 {
		t.Fatalf("will_scan=%d skipped_total=%d groups=%+v", p.WillScan, p.SkippedTotal, p.Skipped)
	}
	checks := []struct {
		reason, tone string
		count        int
	}{
		{scanzone.KindUnresolved, scanservice.SkipToneInfo, 2},
		{scanservice.SkipExcluded, scanservice.SkipToneInfo, 1},
		{scanzone.KindZoneNoSensor, scanservice.SkipToneWarning, 1},
		// The trigger leaves out a name whose last proof of resolving is
		// old, before routing; the preview does the same.
		{scanservice.SkipNotResolving, scanservice.SkipToneInfo, 1},
	}
	for _, c := range checks {
		g := skipGroupOf(p, c.reason)
		if g == nil || g.Count != c.count || g.Tone != c.tone || len(g.Targets) != c.count {
			t.Errorf("%s = %+v, want count %d tone %s", c.reason, g, c.count, c.tone)
		}
	}
	if p.Skipped[0].Reason != scanzone.KindUnresolved {
		t.Errorf("largest group first: got %s", p.Skipped[0].Reason)
	}
	by := previewByTarget(p)
	if by["gone1.example.com"].Kind != scanzone.KindUnresolved || by["old.example.com"].Kind != scanservice.SkipNotResolving ||
		by["10.3.0.1"].Kind != scanzone.KindZoneNoSensor {
		t.Errorf("per-target kinds: %+v %+v %+v", by["gone1.example.com"], by["old.example.com"], by["10.3.0.1"])
	}

	// Another tenant's stale evidence does not decide for this one.
	other := shared.NewID()
	svc.SetResolveEvidence(staleEvidence{tenant: other, names: map[string]bool{"old.example.com": true}}, nil)
	p = preview(t, svc, scanservice.ZoneRoutingPreviewInput{TenantID: tenant.String(), ScannerName: "nuclei", Targets: []string{"old.example.com"}})
	if p.WillScan != 1 || skipGroupOf(p, scanservice.SkipNotResolving) != nil {
		t.Errorf("cross-tenant evidence decided: will_scan=%d groups=%+v", p.WillScan, p.Skipped)
	}
}

// Nothing skipped: the groups are an empty list, never null.
func TestScanPreview_NothingSkipped(t *testing.T) {
	tenant := shared.NewID()
	svc, _ := newZonedScanService(nil, nil, nil)
	p := preview(t, svc, scanservice.ZoneRoutingPreviewInput{TenantID: tenant.String(), ScannerName: "nuclei", Targets: []string{"8.8.8.8"}})
	if p.Skipped == nil || len(p.Skipped) != 0 || p.SkippedTotal != 0 || p.WillScan != 1 {
		t.Fatalf("skipped=%v total=%d will_scan=%d", p.Skipped, p.SkippedTotal, p.WillScan)
	}
}

// freshEvidence: the listed names resolved an hour ago, in one tenant.
type freshEvidence struct {
	tenant shared.ID
	names  map[string]bool
}

func (e freshEvidence) FreshestByName(_ context.Context, tenant shared.ID, names []string, _ []freshdom.Class) ([]freshdom.NameEvidence, error) {
	var out []freshdom.NameEvidence
	for _, n := range names {
		if tenant == e.tenant && e.names[n] {
			out = append(out, freshdom.NameEvidence{AssetID: shared.NewID(), Name: n, ObservedAt: time.Now().Add(-time.Hour)})
		}
	}
	return out, nil
}

// A wildcard with an active scanner: the inventory names never seen
// resolving are skipped (not_resolving, info), unless the scan includes
// names that do not resolve.
func TestScanPreview_WildcardSkipsNamesWithoutProof(t *testing.T) {
	tenantID := shared.NewID()
	inv := newFakeSelectorAssets(tenantID)
	inv.byRoot["example.org"] = []string{"live.example.org", "dead.example.org"}
	svc, deps := newTestScanService()
	svc.SetSelectorAssets(inv)
	svc.SetResolveEvidence(freshEvidence{tenant: tenantID, names: map[string]bool{"live.example.org": true, "example.org": true}}, nil)
	deps.toolRepo.addTool("nuclei", true)

	in := scanservice.ZoneRoutingPreviewInput{TenantID: tenantID.String(), UserID: shared.NewID().String(), ScannerName: "nuclei", Targets: []string{"*.example.org"}}
	p := preview(t, svc, in)
	g := skipGroupOf(p, scanservice.SkipNotResolving)
	if g == nil || g.Count != 1 || g.Targets[0] != "dead.example.org" || g.Tone != scanservice.SkipToneInfo {
		t.Fatalf("not_resolving = %+v (groups %+v)", g, p.Skipped)
	}
	for _, row := range p.Targets {
		if row.Target == "live.example.org" && row.Status == scanservice.PreviewStatusUncovered {
			t.Errorf("a name with fresh proof was skipped: %+v", row)
		}
	}

	in.TargetOptions.IncludeUnresolved = true
	p = preview(t, svc, in)
	if skipGroupOf(p, scanservice.SkipNotResolving) != nil {
		t.Errorf("include_unresolved still skipped names: %+v", p.Skipped)
	}
}

// A member with a restricted data scope learns nothing about the names
// beyond it: no out_of_scope group, no count, no name.
func TestScanPreview_RestrictedMemberLearnsNoHiddenCount(t *testing.T) {
	tenantID := shared.NewID()
	inv := newFakeSelectorAssets(tenantID)
	inv.byRoot["mixed.example"] = []string{"mine.mixed.example", "x.mixed.example", "y.mixed.example"}
	act := &refuseAssetIDs{refused: map[shared.ID]bool{inv.id("x.mixed.example"): true, inv.id("y.mixed.example"): true}}
	svc, deps := newTestScanService(scanservice.WithActScope(act))
	svc.SetSelectorAssets(inv)
	deps.toolRepo.addTool("nuclei", true)

	p := preview(t, svc, scanservice.ZoneRoutingPreviewInput{
		TenantID: tenantID.String(), UserID: shared.NewID().String(), ScannerName: "nuclei", Targets: []string{"*.mixed.example"},
	})
	if g := skipGroupOf(p, scanservice.SkipOutOfScope); g != nil {
		t.Errorf("out_of_scope group reveals hidden names: %+v", g)
	}
	for _, w := range p.Warnings {
		if strings.Contains(w, "data scope") {
			t.Errorf("warning reveals hidden names: %q", w)
		}
	}
	for _, row := range p.Targets {
		if row.Target == "x.mixed.example" || row.Target == "y.mixed.example" {
			t.Errorf("row names a hidden asset: %+v", row)
		}
	}
}
