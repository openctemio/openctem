package unit

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/scanfreeze"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
)

// Scan freeze windows at trigger time, through the real scan service.

// fakeFreeze answers like the repository: the tenant-wide windows and those
// of the asked zones, all active.
type fakeFreeze struct {
	windows []*scanfreeze.Window
	asked   [][]shared.ID
	err     error
}

func (f *fakeFreeze) ActiveAt(_ context.Context, tenantID shared.ID, zoneIDs []shared.ID, _ time.Time) ([]*scanfreeze.Window, error) {
	f.asked = append(f.asked, zoneIDs)
	if f.err != nil {
		return nil, f.err
	}
	var out []*scanfreeze.Window
	for _, w := range f.windows {
		if w.TenantID == tenantID && (w.ScanZoneID == nil || slices.Contains(zoneIDs, *w.ScanZoneID)) {
			out = append(out, w)
		}
	}
	return out, nil
}

func activeWindow(tenant shared.ID, zoneID *shared.ID, name string) *scanfreeze.Window {
	until := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	return &scanfreeze.Window{ID: shared.NewID(), TenantID: tenant, ScanZoneID: zoneID, Name: name, ActiveUntil: &until, Enabled: true}
}

func frozenZoneSetup(t *testing.T, freeze *fakeFreeze) (shared.ID, *scanzone.Zone, *scanzone.Zone, *scanservice.Service, *testScanServiceDeps) {
	t.Helper()
	tenant := shared.NewID()
	s1, s2 := shared.NewID(), shared.NewID()
	dcA := zone(t, tenant, "dc-a", false, []shared.ID{s1}, "10.1.0.0/16")
	dcB := zone(t, tenant, "dc-b", false, []shared.ID{s2}, "10.2.0.0/16")
	dir := &fakeZoneDir{zones: []*scanzone.Zone{dcA, dcB}, routable: map[shared.ID][]scanzone.SensorCandidate{
		dcA.ID: candidates(s1), dcB.ID: candidates(s2),
	}}
	svc, deps := newZonedScanService(dir, nil, nil, scanservice.WithFreezeWindows(freeze))
	return tenant, dcA, dcB, svc, deps
}

func auditActions(deps *testScanServiceDeps) []audit.Action {
	out := make([]audit.Action, 0, len(deps.auditSvc.events))
	for _, e := range deps.auditSvc.events {
		out = append(out, e.Action)
	}
	return out
}

func TestScanFreeze_ManualTriggerRefusedInFrozenZone(t *testing.T) {
	freeze := &fakeFreeze{}
	tenant, dcA, _, svc, deps := frozenZoneSetup(t, freeze)
	freeze.windows = []*scanfreeze.Window{activeWindow(tenant, &dcA.ID, "dc-a patching")}

	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1", "10.2.0.1")
	_, err := trigger(t, svc, sc)
	fe := scanservice.AsFrozen(err)
	if fe == nil {
		t.Fatalf("trigger during the window = %v, want a freeze refusal", err)
	}
	if !errors.Is(err, shared.ErrConflict) || fe.WindowName != "dc-a patching" {
		t.Errorf("refusal = %v (%+v), want a conflict naming the window", err, fe)
	}
	if len(deps.commandRepo.commands) != 0 || len(deps.runRepo.runs) != 0 {
		t.Errorf("a refused trigger created %d commands and %d runs", len(deps.commandRepo.commands), len(deps.runRepo.runs))
	}
	if !slices.Contains(auditActions(deps), audit.ActionScanFreezeRefused) {
		t.Errorf("refusal not audited: %v", auditActions(deps))
	}
	if len(freeze.asked) != 1 || !slices.Contains(freeze.asked[0], dcA.ID) {
		t.Errorf("windows asked for zones %v, want the zones the targets route to", freeze.asked)
	}
}

func TestScanFreeze_WindowOfAnotherZoneOrTenantDoesNotStopTheScan(t *testing.T) {
	freeze := &fakeFreeze{}
	tenant, _, dcB, svc, deps := frozenZoneSetup(t, freeze)
	freeze.windows = []*scanfreeze.Window{
		activeWindow(tenant, &dcB.ID, "dc-b only"),
		activeWindow(shared.NewID(), nil, "another organization"),
	}
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1")
	if _, err := trigger(t, svc, sc); err != nil {
		t.Fatalf("scan of an unfrozen zone refused: %v", err)
	}
	for _, c := range deps.commandRepo.commands {
		if c.FreezeOverride {
			t.Error("a command outside any window carries the override")
		}
	}
}

func TestScanFreeze_OverrideRunsAndStampsCommands(t *testing.T) {
	freeze := &fakeFreeze{}
	tenant, _, _, svc, deps := frozenZoneSetup(t, freeze)
	freeze.windows = []*scanfreeze.Window{activeWindow(tenant, nil, "org-wide change freeze")}
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1", "10.2.0.1")
	user := shared.NewID().String()

	run, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenant.String(), ScanID: sc.ID.String(), TriggeredBy: user, FreezeOverride: true,
	})
	if err != nil {
		t.Fatalf("override refused: %v", err)
	}
	if !run.FreezeOverride {
		t.Error("the run does not record the override")
	}
	if len(deps.commandRepo.commands) != 2 {
		t.Fatalf("commands = %d, want 2", len(deps.commandRepo.commands))
	}
	for _, c := range deps.commandRepo.commands {
		if !c.FreezeOverride {
			t.Error("a command of the overridden run would still be held at claim time")
		}
	}
	found := false
	for i, e := range deps.auditSvc.events {
		if e.Action == audit.ActionScanFreezeOverridden {
			found = true
			if deps.auditSvc.contexts[i].ActorID != user {
				t.Errorf("override audited for actor %q, want %q", deps.auditSvc.contexts[i].ActorID, user)
			}
		}
	}
	if !found {
		t.Errorf("override not audited: %v", auditActions(deps))
	}
}

func TestScanFreeze_ScheduledRunIsFrozenEvenWithOverride(t *testing.T) {
	freeze := &fakeFreeze{}
	tenant, _, _, svc, deps := frozenZoneSetup(t, freeze)
	w := activeWindow(tenant, nil, "nightly backup")
	freeze.windows = []*scanfreeze.Window{w}
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1")
	owner := shared.NewID()
	sc.CreatedBy = &owner

	_, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenant.String(), ScanID: sc.ID.String(),
		TriggerType: pipeline.TriggerTypeSchedule, FreezeOverride: true,
	})
	fe := scanservice.AsFrozen(err)
	if fe == nil || !fe.Until.Equal(*w.ActiveUntil) {
		t.Fatalf("scheduled trigger = %v, want frozen until %s (the scheduler defers to it)", err, w.ActiveUntil)
	}
	if len(deps.commandRepo.commands) != 0 {
		t.Error("a frozen scheduled trigger created commands")
	}
}

func TestScanFreeze_PassiveScanIsNotFrozen(t *testing.T) {
	freeze := &fakeFreeze{}
	svc, deps := newZonedScanService(nil, nil, nil, scanservice.WithFreezeWindows(freeze))
	deps.toolRepo.tools["subfinder"] = &tool.Tool{ID: shared.NewID(), Name: "subfinder", IsActive: true, SupportedTargets: []string{"domain"}}
	tenant := shared.NewID()
	freeze.windows = []*scanfreeze.Window{activeWindow(tenant, nil, "org-wide")}

	sc := singleScan(t, deps, tenant, "subfinder", 1, nil, "example.com")
	if _, err := trigger(t, svc, sc); err != nil {
		t.Fatalf("passive (T0) scan refused during a window: %v", err)
	}
	if len(freeze.asked) != 0 {
		t.Error("a passive scan consulted the freeze windows")
	}
}

func TestScanFreeze_LookupFailureRefuses(t *testing.T) {
	freeze := &fakeFreeze{err: errors.New("db down")}
	tenant, _, _, svc, deps := frozenZoneSetup(t, freeze)
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1")
	if _, err := trigger(t, svc, sc); err == nil {
		t.Fatal("trigger succeeded although the freeze windows could not be read")
	}
	if len(deps.commandRepo.commands) != 0 {
		t.Error("commands created without a freeze check")
	}
}
