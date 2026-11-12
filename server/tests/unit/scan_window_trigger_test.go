package unit

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	swapp "github.com/openctemio/openctem/api/internal/app/scanwindow"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	swdom "github.com/openctemio/openctem/api/pkg/domain/scanwindow"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
)

// Scan windows at trigger time (RFC-067 §6.2, §6.3), through the real scan
// service and the real resolver over a fake policy store.

// fakeWindowPolicies is the policy store: the tenant's policies, or every
// stored one when leaky (to prove the resolver never applies another
// tenant's policy).
type fakeWindowPolicies struct {
	policies []*swdom.Policy
	leaky    bool
	err      error
}

func (f *fakeWindowPolicies) List(_ context.Context, tenantID shared.ID, _ swdom.Filter) ([]*swdom.Policy, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []*swdom.Policy
	for _, p := range f.policies {
		if f.leaky || p.TenantID == tenantID {
			out = append(out, p)
		}
	}
	return out, nil
}

// oneOffPolicy is an enabled policy of tenant with one dated window
// [from, to) relative to now.
func oneOffPolicy(t *testing.T, tenant shared.ID, name string, kind swdom.Kind, sel swdom.Selector, from, to time.Duration) *swdom.Policy {
	t.Helper()
	now := time.Now()
	p, err := swdom.NewPolicy(tenant, swdom.Spec{Name: name, Kind: kind, MinTier: swdom.TierActive, Timezone: "UTC",
		Enabled: true, Selector: sel, OneOffs: []swdom.OneOff{{StartsAt: now.Add(from), EndsAt: now.Add(to)}}}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func windowZoneSetup(t *testing.T, policies *fakeWindowPolicies) (shared.ID, *scanzone.Zone, *scanzone.Zone, *scanservice.Service, *testScanServiceDeps) {
	t.Helper()
	tenant := shared.NewID()
	s1, s2 := shared.NewID(), shared.NewID()
	dcA := zone(t, tenant, "dc-a", false, []shared.ID{s1}, "10.1.0.0/16")
	dcB := zone(t, tenant, "dc-b", false, []shared.ID{s2}, "10.2.0.0/16")
	dir := &fakeZoneDir{zones: []*scanzone.Zone{dcA, dcB}, routable: map[shared.ID][]scanzone.SensorCandidate{
		dcA.ID: candidates(s1), dcB.ID: candidates(s2),
	}}
	var opts []scanservice.ServiceOption
	if policies != nil {
		opts = append(opts, scanservice.WithScanWindows(swapp.NewResolver(policies, nil)))
	}
	svc, deps := newZonedScanService(dir, nil, nil, opts...)
	return tenant, dcA, dcB, svc, deps
}

func auditActions(deps *testScanServiceDeps) []audit.Action {
	out := make([]audit.Action, 0, len(deps.auditSvc.events))
	for _, e := range deps.auditSvc.events {
		out = append(out, e.Action)
	}
	return out
}

// A manual run during a blackout is not refused: it starts, and the run
// records which targets wait and until when (the claim holds them).
func TestScanWindows_ManualRunWaitsInsteadOfRefused(t *testing.T) {
	policies := &fakeWindowPolicies{}
	tenant, _, _, svc, deps := windowZoneSetup(t, policies)
	policies.policies = []*swdom.Policy{oneOffPolicy(t, tenant, "change freeze", swdom.KindBlackout, swdom.Selector{}, -time.Hour, 2*time.Hour)}

	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1", "10.2.0.1")
	run, err := trigger(t, svc, sc)
	if err != nil {
		t.Fatalf("manual trigger during a blackout = %v, want a run that waits", err)
	}
	if len(deps.commandRepo.commands) != 2 {
		t.Fatalf("commands = %d, want the jobs queued (held at claim)", len(deps.commandRepo.commands))
	}
	waits, ok := run.Context[scanservice.RunContextKeyWindowWaits].(map[string]any)
	if !ok || waits["waiting_count"] != 2 {
		t.Fatalf("run context window_waits = %#v", run.Context[scanservice.RunContextKeyWindowWaits])
	}
	for _, c := range deps.commandRepo.commands {
		pctx, _ := payloadMap(t, c.Payload)["context"].(map[string]any)
		if _, leaked := pctx[scanservice.RunContextKeyWindowWaits]; leaked {
			t.Fatal("window_waits must never reach a sensor")
		}
	}
}

// A target whose windows never open together refuses the run with the
// reason, recorded as a blocked run and audited.
func TestScanWindows_NeverOpeningTargetRefusesTheRun(t *testing.T) {
	policies := &fakeWindowPolicies{}
	tenant, _, _, svc, deps := windowZoneSetup(t, policies)
	policies.policies = []*swdom.Policy{
		oneOffPolicy(t, tenant, "pentest slot", swdom.KindAllow, swdom.Selector{}, time.Hour, 2*time.Hour),
		oneOffPolicy(t, tenant, "freeze", swdom.KindBlackout, swdom.Selector{}, 0, 3*time.Hour),
	}
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1")
	_, err := trigger(t, svc, sc)
	var ne *scanservice.NeverOpensError
	if !errors.As(err, &ne) || !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("trigger = %v, want SCAN_WINDOW_NEVER_OPENS (409)", err)
	}
	if !slices.Contains(ne.Sources, "pentest slot") || !slices.Contains(ne.Sources, "freeze") || ne.Targets[0] != "10.1.0.1" {
		t.Errorf("refusal does not explain itself: %+v", ne)
	}
	if len(deps.commandRepo.commands) != 0 || dispatchedRuns(deps) != 0 {
		t.Error("a refused trigger dispatched work")
	}
	if b := blockedRuns(deps, sc.ID); len(b) != 1 || b[0].RefusalCode != scanservice.CodeWindowNeverOpens {
		t.Errorf("blocked runs = %+v", b)
	}
	if !slices.Contains(auditActions(deps), audit.ActionScanWindowRefused) {
		t.Errorf("refusal not audited: %v", auditActions(deps))
	}
}

// A scheduled run with nothing open is deferred to the earliest opening
// (the scheduler moves next_run_at), never skipped and never a blocked run.
func TestScanWindows_ScheduledRunDefersToTheOpening(t *testing.T) {
	policies := &fakeWindowPolicies{}
	tenant, dcA, _, svc, deps := windowZoneSetup(t, policies)
	p := oneOffPolicy(t, tenant, "business hours", swdom.KindAllow, swdom.Selector{}, 3*time.Hour, 5*time.Hour)
	policies.policies = []*swdom.Policy{p}
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1")
	owner := shared.NewID()
	sc.CreatedBy = &owner

	_, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenant.String(), ScanID: sc.ID.String(), TriggerType: scanworkflow.TriggerTypeSchedule,
	})
	we := scanservice.AsWindowDefer(err)
	if we == nil || !we.Until.Equal(p.OneOffs[0].StartsAt) {
		t.Fatalf("scheduled trigger = %v, want deferred to %s", err, p.OneOffs[0].StartsAt)
	}
	if len(deps.commandRepo.commands) != 0 || len(blockedRuns(deps, sc.ID)) != 0 {
		t.Error("a deferred occurrence created commands or a blocked run")
	}

	// One target open: the occurrence runs; the closed one waits at claim.
	policies.policies = []*swdom.Policy{oneOffPolicy(t, tenant, "dc-a freeze", swdom.KindBlackout,
		swdom.Selector{ScanZoneIDs: []string{dcA.ID.String()}}, -time.Hour, time.Hour)}
	sc2 := singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1", "10.2.0.1")
	sc2.CreatedBy = &owner
	if _, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenant.String(), ScanID: sc2.ID.String(), TriggerType: scanworkflow.TriggerTypeSchedule,
	}); err != nil {
		t.Fatalf("scheduled trigger with one open target = %v", err)
	}
}

// A zone policy governs only the targets routed to that zone, and another
// tenant's policy never applies, even if a store returned it.
func TestScanWindows_ZoneSelectorAndTenantIsolation(t *testing.T) {
	policies := &fakeWindowPolicies{leaky: true}
	tenant, dcA, _, svc, deps := windowZoneSetup(t, policies)
	policies.policies = []*swdom.Policy{
		oneOffPolicy(t, tenant, "dc-a patching", swdom.KindBlackout, swdom.Selector{ScanZoneIDs: []string{dcA.ID.String()}}, -time.Hour, time.Hour),
		oneOffPolicy(t, shared.NewID(), "another organization", swdom.KindBlackout, swdom.Selector{}, -time.Hour, time.Hour),
	}
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1", "10.2.0.1")
	run, err := trigger(t, svc, sc)
	if err != nil {
		t.Fatal(err)
	}
	waits := run.Context[scanservice.RunContextKeyWindowWaits].(map[string]any)
	list := waits["waiting"].([]scanservice.TargetWait)
	if waits["waiting_count"] != 1 || len(list) != 1 || list[0].Target != "10.1.0.1" || list[0].Blocking[0].Name != "dc-a patching" {
		t.Fatalf("waits = %#v, want only the dc-a target, held by dc-a's policy", waits)
	}
}

// A passive (T0) scan is not governed by an active-tier policy.
func TestScanWindows_PassiveScanRunsAnyTime(t *testing.T) {
	policies := &fakeWindowPolicies{}
	svc, deps := newZonedScanService(nil, nil, nil, scanservice.WithScanWindows(swapp.NewResolver(policies, nil)))
	deps.toolRepo.tools["subfinder"] = &tool.Tool{ID: shared.NewID(), Name: "subfinder", IsActive: true, SupportedTargets: []string{"domain"}}
	tenant := shared.NewID()
	policies.policies = []*swdom.Policy{oneOffPolicy(t, tenant, "freeze", swdom.KindBlackout, swdom.Selector{}, -time.Hour, time.Hour)}
	sc := singleScan(t, deps, tenant, "subfinder", 1, nil, "example.com")
	run, err := trigger(t, svc, sc)
	if err != nil {
		t.Fatalf("passive scan refused during a blackout: %v", err)
	}
	if _, ok := run.Context[scanservice.RunContextKeyWindowWaits]; ok {
		t.Error("a passive scan was told to wait")
	}
}

// A policy store that cannot be read refuses the trigger (fail closed).
func TestScanWindows_LookupFailureRefuses(t *testing.T) {
	tenant, _, _, svc, deps := windowZoneSetup(t, &fakeWindowPolicies{err: errors.New("db down")})
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1")
	if _, err := trigger(t, svc, sc); err == nil {
		t.Fatal("trigger succeeded although the scan windows could not be read")
	}
	if len(deps.commandRepo.commands) != 0 {
		t.Error("commands created without a window check")
	}
}
