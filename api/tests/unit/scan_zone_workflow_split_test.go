package unit

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// splitWorkflow is a one-step workflow scan of targets.
func splitWorkflow(deps *testScanServiceDeps, tenant shared.ID, targets ...string) *scan.Scan {
	s := createTestScanInRepo(deps, tenant, "wf", scan.ScanTypeWorkflow)
	s.SetTargets(targets)
	pid := *s.ScanWorkflowID
	deps.stepRepo.steps[pid.String()] = []*scanworkflow.Step{{ID: shared.NewID(), ScanWorkflowID: pid, StepKey: "s", StepOrder: 1, Tool: "nuclei"}}
	return s
}

func childRuns(deps *testScanServiceDeps, parent shared.ID) []*scanrun.Run {
	var out []*scanrun.Run
	for _, r := range deps.runRepo.runs {
		if r.ParentRunID != nil && *r.ParentRunID == parent {
			out = append(out, r)
		}
	}
	return out
}

func contextTargets(r *scanrun.Run) []string {
	switch v := r.Context["targets"].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// A workflow scan whose targets fall in two zones and outside every zone is
// not refused: it runs as one child run per zone group under a parent run,
// each child stamped with its zone, and the private targets never leave
// their zone.
func TestScanZones_WorkflowAcrossZonesSplitsPerZone(t *testing.T) {
	tenant := shared.NewID()
	internal := zone(t, tenant, "Internal", false, []shared.ID{shared.NewID()}, "10.20.0.0/16")
	public := zone(t, tenant, "Internet public IP", false, []shared.ID{shared.NewID()}, "198.51.100.0/24")
	svc, deps := newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{internal, public}}, nil, nil)
	sc := splitWorkflow(deps, tenant, "10.20.1.0/24", "10.20.2.5", "198.51.100.7", "203.0.113.9")

	parent, err := trigger(t, svc, sc)
	if err != nil {
		t.Fatalf("workflow across zones refused: %v", err)
	}
	if parent.ParentRunID != nil || parent.TotalSteps != 0 {
		t.Fatalf("parent: parent_run_id %v steps %d, want a top-level run without steps", parent.ParentRunID, parent.TotalSteps)
	}
	if scanrun.ScanZoneFromContext(parent.Context) != nil {
		t.Error("the parent is stamped with a zone")
	}
	if parent.ScheduledFor != nil || parent.ScanID == nil || *parent.ScanID != sc.ID {
		t.Errorf("parent scan link = %v", parent.ScanID)
	}

	children := childRuns(deps, parent.ID)
	if len(children) != 3 {
		t.Fatalf("children = %d, want one per zone group (Internal, Internet public IP, no zone)", len(children))
	}
	want := map[string][]string{
		internal.ID.String(): {"10.20.1.0/24", "10.20.2.5"},
		public.ID.String():   {"198.51.100.7"},
		"":                   {"203.0.113.9"},
	}
	for _, c := range children {
		if c.ScanID == nil || *c.ScanID != sc.ID || c.ScheduledFor != nil || c.TenantID != tenant {
			t.Errorf("child %s: scan %v scheduled %v tenant %v", c.ID, c.ScanID, c.ScheduledFor, c.TenantID)
		}
		key := ""
		if z := scanrun.ScanZoneFromContext(c.Context); z != nil {
			key = z.String()
		}
		got := contextTargets(c)
		slices.Sort(got)
		w := want[key]
		slices.Sort(w)
		if !slices.Equal(got, w) {
			t.Errorf("child of zone %q targets = %v, want %v", key, got, w)
		}
		info, _ := c.Context[scanrun.RunContextKeyZoneSplit].(map[string]any)
		if info["parent_run_id"] != parent.ID.String() {
			t.Errorf("child zone_split = %v", info)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Errorf("zone groups without a child: %v", want)
	}

	// Every step command stays in its child's zone; the unzoned one carries
	// no private address.
	for _, c := range deps.commandRepo.commands {
		for _, target := range payloadTargets(t, c) {
			switch {
			case c.ScanZoneID == nil:
				if target != "203.0.113.9" {
					t.Errorf("unzoned command carries %s", target)
				}
			case *c.ScanZoneID == internal.ID:
				if target != "10.20.1.0/24" && target != "10.20.2.5" {
					t.Errorf("Internal command carries %s", target)
				}
			case *c.ScanZoneID == public.ID:
				if target != "198.51.100.7" {
					t.Errorf("public zone command carries %s", target)
				}
			}
		}
	}

	split, _ := parent.Context[scanrun.RunContextKeyZoneSplit].(map[string]any)
	groups, _ := split["groups"].([]map[string]any)
	if len(groups) != 3 {
		t.Fatalf("parent groups = %v", split)
	}
	for _, g := range groups {
		if g["status"] != "started" || g["run_id"] == "" {
			t.Errorf("group %v did not start", g)
		}
	}
}

// A zone without sensors gets no child: its targets are listed as
// uncovered on the parent, and the other groups still run.
func TestScanZones_WorkflowSplitZoneWithoutSensors(t *testing.T) {
	tenant := shared.NewID()
	a := zone(t, tenant, "a", false, []shared.ID{shared.NewID()}, "10.1.0.0/16")
	empty := zone(t, tenant, "empty", false, nil, "10.2.0.0/16")
	svc, deps := newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{a, empty}}, nil, nil)
	sc := splitWorkflow(deps, tenant, "10.1.0.1", "10.2.0.1", "192.0.2.10")

	parent, err := trigger(t, svc, sc)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(childRuns(deps, parent.ID)); n != 2 {
		t.Fatalf("children = %d, want 2 (zone a, no zone)", n)
	}
	if !hasWarning(warningsOf(parent), "10.2.0.1 not scanned") {
		t.Errorf("parent warnings = %v", warningsOf(parent))
	}
	for _, c := range deps.commandRepo.commands {
		if slices.Contains(payloadTargets(t, c), "10.2.0.1") {
			t.Error("a target of a zone without sensors was dispatched")
		}
	}
}

// A zone run that cannot start (a database or internal failure) shows a
// fixed reason on the parent, never the error's own text: the reason is
// returned by the API and shown in the console.
func TestScanZones_WorkflowSplitStartFailureHidesTheError(t *testing.T) {
	tenant := shared.NewID()
	internal := zone(t, tenant, "Internal", false, []shared.ID{shared.NewID()}, "10.20.0.0/16")
	svc, deps := newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{internal}}, nil, nil)
	deps.runRepo.createChildErr = errors.New(`pq: duplicate key value violates unique constraint "scan_runs_pkey" (host db-internal.example.com)`)
	sc := splitWorkflow(deps, tenant, "10.20.1.0/24", "203.0.113.9")

	parent, err := trigger(t, svc, sc)
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	split, _ := parent.Context[scanrun.RunContextKeyZoneSplit].(map[string]any)
	groups, _ := split["groups"].([]map[string]any)
	if len(groups) != 2 {
		t.Fatalf("parent groups = %v", split)
	}
	for _, g := range groups {
		reason, _ := g["reason"].(string)
		if g["status"] != "refused" || reason != "the zone run could not start" {
			t.Errorf("group %v: want refused with the fixed reason", g)
		}
		if strings.Contains(reason, "pq:") || strings.Contains(reason, "example.com") {
			t.Errorf("group reason leaks the internal error: %q", reason)
		}
	}
}
