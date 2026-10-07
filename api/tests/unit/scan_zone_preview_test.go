package unit

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Scan-zone routing preview and the zone picker (RFC-023 §7, D5), through the
// real scan service with in-memory repositories.

func preview(t *testing.T, svc *scanservice.Service, in scanservice.ZoneRoutingPreviewInput) *scanservice.ZoneRoutingPreview {
	t.Helper()
	p, err := svc.PreviewZoneRouting(context.Background(), in)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	return p
}

func previewByTarget(p *scanservice.ZoneRoutingPreview) map[string]scanservice.PreviewTarget {
	out := map[string]scanservice.PreviewTarget{}
	for _, t := range p.Targets {
		out[t.Target] = t
	}
	return out
}

func TestScanZonePreview_RoutesLikeTheTriggerAndCreatesNothing(t *testing.T) {
	tenant := shared.NewID()
	s1, offline := shared.NewID(), shared.NewID()
	dcA := zone(t, tenant, "dc-a", false, []shared.ID{s1}, "10.1.0.0/16")
	dcB := zone(t, tenant, "dc-b", false, []shared.ID{offline}, "10.2.0.0/16")
	dir := &fakeZoneDir{
		zones:    []*scanzone.Zone{dcA, dcB},
		routable: map[shared.ID][]scanzone.SensorCandidate{dcA.ID: candidates(s1)},
	}
	res := tableResolver{"db.corp.example": {"10.1.0.9"}}
	svc, deps := newZonedScanService(dir, res, valueExclusions{"10.1.0.2": true})

	p := preview(t, svc, scanservice.ZoneRoutingPreviewInput{
		TenantID:    tenant.String(),
		ScannerName: "nuclei",
		Targets:     []string{"10.1.0.1", "10.1.0.2", "10.2.0.1", "8.8.8.8", "db.corp.example", "nope.corp.example"},
	})

	if !p.ZonesEnabled || !p.Routed {
		t.Fatalf("zones_enabled=%v routed=%v, want both", p.ZonesEnabled, p.Routed)
	}
	if p.ResolvedTargets != 5 || p.ExcludedTargets != 1 || len(p.Excluded) != 1 || p.Excluded[0] != "10.1.0.2" {
		t.Errorf("resolved=%d excluded=%d %v", p.ResolvedTargets, p.ExcludedTargets, p.Excluded)
	}
	by := previewByTarget(p)
	if got := by["10.1.0.1"]; got.Status != scanservice.PreviewStatusZone || got.ZoneID != dcA.ID.String() || got.SensorID != s1.String() {
		t.Errorf("10.1.0.1 = %+v, want dc-a pinned to its online sensor", got)
	}
	if got := by["10.2.0.1"]; got.Status != scanservice.PreviewStatusZone || got.ZoneName != "dc-b" || got.SensorID != "" {
		t.Errorf("10.2.0.1 = %+v, want dc-b, queued (no sensor online)", got)
	}
	if got := by["8.8.8.8"]; got.Status != scanservice.PreviewStatusUnzoned {
		t.Errorf("8.8.8.8 = %+v, want unzoned (no default zone)", got)
	}
	if got := by["db.corp.example"]; got.ZoneName != "dc-a" || len(got.Addresses) != 1 || got.Addresses[0] != "10.1.0.9" {
		t.Errorf("hostname = %+v, want dc-a via 10.1.0.9", got)
	}
	if got := by["nope.corp.example"]; got.Status != scanservice.PreviewStatusUncovered || !strings.Contains(got.Reason, "did not resolve") {
		t.Errorf("unresolvable = %+v", got)
	}
	if _, listed := by["10.1.0.2"]; listed {
		t.Error("excluded target listed as routed")
	}
	if p.UncoveredTargets != 1 || p.UnzonedTargets != 1 || p.Jobs != 4 || p.TargetsPerJob != 1 {
		t.Errorf("uncovered=%d unzoned=%d jobs=%d per_job=%d", p.UncoveredTargets, p.UnzonedTargets, p.Jobs, p.TargetsPerJob)
	}
	var zb *scanservice.PreviewZone
	for i := range p.Zones {
		if p.Zones[i].ZoneName == "dc-b" {
			zb = &p.Zones[i]
		}
	}
	if zb == nil || zb.QueuedJobs != 1 || len(zb.SensorIDs) != 0 {
		t.Errorf("dc-b summary = %+v, want 1 queued job", zb)
	}
	if !hasWarning(p.Warnings, "wait in the zone") || !hasWarning(p.Warnings, "nope.corp.example not scanned") {
		t.Errorf("warnings = %v", p.Warnings)
	}
	if p.Error != nil {
		t.Errorf("error = %+v, want none", p.Error)
	}
	order := make([]string, 0, len(p.Targets))
	for _, pt := range p.Targets {
		order = append(order, pt.Target)
	}
	if want := []string{"10.1.0.1", "10.2.0.1", "8.8.8.8", "db.corp.example", "nope.corp.example"}; !slices.Equal(order, want) {
		t.Errorf("targets order = %v, want input order %v", order, want)
	}
	if len(deps.commandRepo.commands) != 0 || len(deps.runRepo.runs) != 0 {
		t.Error("preview created commands or runs")
	}
}

func TestScanZonePreview_ReportsWhatTheTriggerWouldRefuse(t *testing.T) {
	tenant := shared.NewID()
	a := zone(t, tenant, "a", false, []shared.ID{shared.NewID()}, "10.1.0.0/16")
	b := zone(t, tenant, "b", false, []shared.ID{shared.NewID()}, "10.2.0.0/16")
	empty := zone(t, tenant, "empty", false, nil, "10.3.0.0/16")
	svc, _ := newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{a, b, empty}}, nil, valueExclusions{"8.8.8.8": true})

	cases := []struct {
		name string
		in   scanservice.ZoneRoutingPreviewInput
		code string
	}{
		{"workflow across zones", scanservice.ZoneRoutingPreviewInput{ScanType: "workflow", Targets: []string{"10.1.0.1", "10.2.0.1"}}, "ZONE_SPLIT_REQUIRED"},
		{"every target excluded", scanservice.ZoneRoutingPreviewInput{ScannerName: "nuclei", Targets: []string{"8.8.8.8"}}, "ALL_TARGETS_EXCLUDED"},
		{"zone without sensors", scanservice.ZoneRoutingPreviewInput{ScannerName: "nuclei", Targets: []string{"10.3.0.1"}}, "NO_ZONE_COVERAGE"},
		{"private target no zone covers", scanservice.ZoneRoutingPreviewInput{ScannerName: "nuclei", Targets: []string{"10.1.0.1", "192.168.1.1"}}, "INVALID_TARGET"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.in.TenantID = tenant.String()
			p := preview(t, svc, tc.in)
			if p.Error == nil || p.Error.Code != tc.code {
				t.Fatalf("error = %+v, want %s", p.Error, tc.code)
			}
			if strings.Contains(p.Error.Message, `"preview"`) {
				t.Errorf("message names the internal placeholder scan: %q", p.Error.Message)
			}
		})
	}

	p := preview(t, svc, scanservice.ZoneRoutingPreviewInput{TenantID: tenant.String(), ScannerName: "nuclei", Targets: []string{"10.1.0.1", "192.168.1.1"}})
	if got := previewByTarget(p)["192.168.1.1"]; got.Status != scanservice.PreviewStatusUncovered || !strings.Contains(got.Reason, "not accepted by scan creation") {
		t.Errorf("rejected target = %+v", got)
	}
	p = preview(t, svc, scanservice.ZoneRoutingPreviewInput{TenantID: tenant.String(), ScanType: "workflow", Targets: []string{"10.1.0.1"}})
	if p.Error != nil || len(p.Zones) != 1 || p.Zones[0].QueuedJobs != 0 {
		t.Errorf("single-zone workflow: error=%+v zones=%+v", p.Error, p.Zones)
	}
}

func TestScanZonePreview_SelectedZoneEnforcesItsRanges(t *testing.T) {
	tenant := shared.NewID()
	sa, sl := shared.NewID(), shared.NewID()
	a := zone(t, tenant, "a", false, []shared.ID{sa}, "10.1.0.0/16")
	lab := zone(t, tenant, "lab", false, []shared.ID{sl}, "10.1.5.0/24") // narrower, overlapping
	b := zone(t, tenant, "b", false, []shared.ID{shared.NewID()}, "10.2.0.0/16")
	pub := zone(t, tenant, "internet", true, []shared.ID{shared.NewID()})
	dir := &fakeZoneDir{zones: []*scanzone.Zone{a, lab, b, pub},
		routable: map[shared.ID][]scanzone.SensorCandidate{a.ID: candidates(sa), lab.ID: candidates(sl)}}
	svc, _ := newZonedScanService(dir, nil, nil)

	p := preview(t, svc, scanservice.ZoneRoutingPreviewInput{
		TenantID: tenant.String(), ScannerName: "nuclei", ScanZoneID: a.ID.String(),
		Targets: []string{"10.1.5.5", "10.2.0.1", "8.8.8.8"},
	})
	if p.SelectedZoneID != a.ID.String() {
		t.Errorf("selected_zone_id = %q", p.SelectedZoneID)
	}
	by := previewByTarget(p)
	if got := by["10.1.5.5"]; got.ZoneID != a.ID.String() || got.SensorID != sa.String() {
		t.Errorf("10.1.5.5 = %+v, want the selected zone a, not the narrower lab", got)
	}
	for _, target := range []string{"10.2.0.1", "8.8.8.8"} {
		if got := by[target]; got.Status != scanservice.PreviewStatusUncovered || got.Reason != `outside the selected scan zone "a"` {
			t.Errorf("%s = %+v, want uncovered outside the selected zone", target, got)
		}
	}

	if _, err := svc.PreviewZoneRouting(context.Background(), scanservice.ZoneRoutingPreviewInput{
		TenantID: tenant.String(), ScanZoneID: shared.NewID().String(), Targets: []string{"8.8.8.8"},
	}); !errors.Is(err, scanzone.ErrZoneNotFound) {
		t.Errorf("unknown zone: err = %v, want not found", err)
	}
}

func TestScanZonePreview_NotRouted(t *testing.T) {
	tenant := shared.NewID()
	svc, _ := newZonedScanService(&fakeZoneDir{}, nil, nil)
	p := preview(t, svc, scanservice.ZoneRoutingPreviewInput{TenantID: tenant.String(), ScannerName: "nuclei", Targets: []string{"8.8.8.8"}})
	if p.ZonesEnabled || p.Routed || p.NotRoutedReason == "" || len(p.Targets) != 1 || p.Targets[0].Status != scanservice.PreviewStatusUnzoned {
		t.Errorf("no zones: %+v", p)
	}

	a := zone(t, tenant, "a", false, []shared.ID{shared.NewID()}, "10.1.0.0/16")
	svc, _ = newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{a}}, nil, nil)
	p = preview(t, svc, scanservice.ZoneRoutingPreviewInput{TenantID: tenant.String(), ScannerName: "betterleaks", Targets: []string{"github.com/acme/app"}})
	if !p.ZonesEnabled || p.Routed || !strings.Contains(p.NotRoutedReason, "betterleaks") {
		t.Errorf("non-network tool: %+v", p)
	}
}

func TestScanZones_SelectedZoneAtTrigger(t *testing.T) {
	tenant := shared.NewID()
	sa, sl := shared.NewID(), shared.NewID()
	a := zone(t, tenant, "a", false, []shared.ID{sa}, "10.1.0.0/16")
	lab := zone(t, tenant, "lab", false, []shared.ID{sl}, "10.1.5.0/24")
	pub := zone(t, tenant, "internet", true, []shared.ID{shared.NewID()})
	dir := &fakeZoneDir{zones: []*scanzone.Zone{a, lab, pub},
		routable: map[shared.ID][]scanzone.SensorCandidate{a.ID: candidates(sa), lab.ID: candidates(sl)}}
	svc, deps := newZonedScanService(dir, nil, nil)

	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.5.5", "10.2.0.1", "8.8.8.8")
	sc.SetScanZone(&a.ID)
	run, err := trigger(t, svc, sc)
	if err != nil {
		t.Fatal(err)
	}
	byTarget := commandsByTarget(t, deps)
	if c := byTarget["10.1.5.5"]; c == nil || c.ScanZoneID == nil || *c.ScanZoneID != a.ID || c.SensorID == nil || *c.SensorID != sa {
		t.Errorf("10.1.5.5 not pinned to the selected zone a: %+v", c)
	}
	for _, target := range []string{"10.2.0.1", "8.8.8.8"} {
		if byTarget[target] != nil {
			t.Errorf("%s dispatched although it is outside the selected zone", target)
		}
		if !hasWarning(warningsOf(run), target+` not scanned: outside the selected scan zone "a"`) {
			t.Errorf("no warning for %s: %v", target, warningsOf(run))
		}
	}
	summary, _ := run.Context["zone_routing"].(map[string]any)
	if summary["selected_zone_id"] != a.ID.String() {
		t.Errorf("zone_routing.selected_zone_id = %v", summary["selected_zone_id"])
	}

	// A scan pinned to a zone that no longer exists fails closed.
	gone := shared.NewID()
	sc2 := singleScan(t, deps, tenant, "nuclei", 1, nil, "8.8.8.8")
	sc2.SetScanZone(&gone)
	before := len(deps.commandRepo.commands)
	_, err = trigger(t, svc, sc2)
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != "SCAN_ZONE_NOT_FOUND" {
		t.Fatalf("deleted zone: err = %v, want SCAN_ZONE_NOT_FOUND", err)
	}
	if len(deps.commandRepo.commands) != before {
		t.Error("a scan pinned to a deleted zone dispatched commands")
	}
}

func TestScanZones_SelectedZoneOnWorkflow(t *testing.T) {
	tenant := shared.NewID()
	a := zone(t, tenant, "a", false, []shared.ID{shared.NewID()}, "10.1.0.0/16")
	b := zone(t, tenant, "b", false, []shared.ID{shared.NewID()}, "10.2.0.0/16")
	svc, deps := newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{a, b}}, nil, nil)
	s := createTestScanInRepo(deps, tenant, "wf", scan.ScanTypeWorkflow)
	s.SetTargets([]string{"10.1.0.1", "10.2.0.1"})
	s.SetScanZone(&b.ID)
	pid := *s.ScanWorkflowID
	deps.stepRepo.steps[pid.String()] = []*scanworkflow.Step{{ID: shared.NewID(), ScanWorkflowID: pid, StepKey: "s", StepOrder: 1, Tool: "nuclei"}}

	// Without the picker this workflow would need splitting; pinned to b it
	// runs in b and skips the rest.
	run, err := trigger(t, svc, s)
	if err != nil {
		t.Fatal(err)
	}
	if got := scanrun.ScanZoneFromContext(run.Context); got == nil || *got != b.ID {
		t.Errorf("workflow zone = %v, want b", got)
	}
	if !hasWarning(warningsOf(run), `10.1.0.1 not scanned: outside the selected scan zone "b"`) {
		t.Errorf("warnings = %v", warningsOf(run))
	}
}

func TestScanZones_CreateAndUpdateScanZonePicker(t *testing.T) {
	tenant := shared.NewID()
	a := zone(t, tenant, "a", false, []shared.ID{shared.NewID()}, "10.1.0.0/16")
	svc, _ := newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{a}}, nil, nil)
	in := scanservice.CreateScanInput{
		TenantID: tenant.String(), Name: "picked", ScanType: "single", ScannerName: "nuclei",
		ScheduleType: "manual", Targets: []string{"10.1.0.1"}, ScanZoneID: a.ID.String(),
	}
	sc, err := svc.CreateScan(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if sc.ScanZoneID == nil || *sc.ScanZoneID != a.ID {
		t.Errorf("scan_zone_id = %v, want a", sc.ScanZoneID)
	}

	in.Name, in.ScanZoneID = "other tenant zone", shared.NewID().String()
	if _, err := svc.CreateScan(context.Background(), in); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("unknown zone accepted: err = %v", err)
	}

	automatic := ""
	updated, err := svc.UpdateScan(context.Background(), scanservice.UpdateScanInput{
		TenantID: tenant.String(), ScanID: sc.ID.String(), ScanZoneID: &automatic,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ScanZoneID != nil {
		t.Errorf("scan_zone_id = %v after switching to Automatic", updated.ScanZoneID)
	}
}
