package integration

// The coverage planner (RFC-093) on a migrated database with a recording run
// starter: due pairs go out in one batch per capability, the gate's refusals
// become blocked pairs with its code, a capability whose run is still active
// waits, a finished run settles its pairs (covered with the output check, or
// failed with a back-off), and a Strict tenant gets nothing started.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	coverageapp "github.com/openctemio/openctem/api/internal/app/coverage"
	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeStarter struct {
	t       *testing.T
	mu      sync.Mutex
	calls   map[string][]string // capability -> targets
	runs    map[string]shared.ID
	refuse  map[string]string // target -> code
	busy    map[string]bool
	fail    map[string]error // capability -> refusal of the whole batch
	// never: targets whose scan windows never open; a batch holding one is
	// refused with the error that lists them.
	never map[string]bool
	execRun func(id shared.ID)
	// execTask records the run's one task (command) with its targets.
	execTask func(id shared.ID, targets []string)
}

func (f *fakeStarter) StartCoverage(_ context.Context, in scanapp.CoverageInput) (*scanapp.CoverageResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.busy[in.Capability] {
		return nil, scanapp.ErrCoverageBusy
	}
	f.calls[in.Capability] = append(f.calls[in.Capability], in.Targets...)
	if err, ok := f.fail[in.Capability]; ok {
		return nil, err
	}
	var bad []string
	for _, t := range in.Targets {
		if f.never[t] {
			bad = append(bad, t)
		}
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("failed to trigger coverage: %w", &scanapp.NeverOpensError{Targets: bad})
	}
	res := &scanapp.CoverageResult{Tool: "tool-" + in.Capability}
	for _, t := range in.Targets {
		if code, ok := f.refuse[t]; ok {
			res.Refused = append(res.Refused, scanapp.RefusedTarget{Target: t, Code: code})
			continue
		}
		res.Kept = append(res.Kept, t)
	}
	if len(res.Kept) > 0 {
		id := shared.NewID()
		f.execRun(id)
		if f.execTask != nil {
			f.execTask(id, res.Kept)
		}
		f.runs[in.Capability] = id
		res.RunID = &id
	}
	return res, nil
}

type fixedMode struct{ m scangov.Mode }

func (f fixedMode) EffectiveMode(context.Context, shared.ID) (scangov.Mode, string, scangov.PlatformPolicy, error) {
	return f.m, scangov.SourceOrganization, scangov.PolicyTenantControlled, nil
}

func TestAssetCoverage_PlannerDispatchesAndSettles(t *testing.T) {
	g := newCovRig(t)
	ctx := context.Background()
	a := g.r.newTenant()

	if _, err := g.r.db.Exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern) VALUES ($1, 'domain', '*.plan.test')`, a.tenant.String()); err != nil {
		t.Fatal(err)
	}
	www := g.asset(a, "www.plan.test", "subdomain", "", "")
	api := g.asset(a, "api.plan.test", "subdomain", "", "")
	ip := g.asset(a, "203.0.113.30", "ip_address", "", "")
	g.rel(a, www, ip, "resolves_to")
	g.rel(a, api, ip, "resolves_to")
	web := g.asset(a, "203.0.113.30:8443:tcp", "service", "open_port", `{"port": 8443}`)

	f := &fakeStarter{t: t, calls: map[string][]string{}, runs: map[string]shared.ID{},
		refuse: map[string]string{"api.plan.test": "shared_network"}, busy: map[string]bool{"lookup.asn": true}}
	f.execRun = func(id shared.ID) {
		if _, err := g.r.db.Exec(`INSERT INTO scan_runs (id, tenant_id, trigger_type, status, kind) VALUES ($1, $2, 'manual', 'running', 'system')`,
			id.String(), a.tenant.String()); err != nil {
			t.Fatal(err)
		}
	}
	f.execTask = func(id shared.ID, targets []string) {
		tj, _ := json.Marshal(targets)
		g.exec(`INSERT INTO commands (id, tenant_id, type, status, payload)
			VALUES ($1, $2, 'scan', 'running', jsonb_build_object('scan_run_id', $3::text, 'targets', $4::jsonb))`,
			shared.NewID(), a.tenant, id.String(), string(tj))
	}
	mode := &fixedMode{m: scangov.ModeOff}
	g.svc.EnablePlanning(g.repo, f, coverageapp.GovernanceSwitch{Modes: mode}, coverageapp.Config{})

	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	probe := append([]string(nil), f.calls["probe.http"]...)
	sort.Strings(probe)
	if strings.Join(probe, ",") != "203.0.113.30:8443,api.plan.test,www.plan.test" {
		t.Fatalf("probe.http batch = %v (open ports go as host:port)", probe)
	}
	if got := g.states(a, www)["probe.http"]; got != "queued:" {
		t.Errorf("www probe.http = %q", got)
	}
	if got := g.states(a, api)["probe.http"]; got != "blocked:shared_network" {
		t.Errorf("refused name probe.http = %q", got)
	}
	if got := g.states(a, ip)["lookup.asn"]; got != "due:" {
		t.Errorf("busy capability pair = %q, want it to wait as due", got)
	}
	// A second pass while the run is still running starts nothing new.
	before := len(f.calls["probe.http"])
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	if len(f.calls["probe.http"]) != before {
		t.Fatal("queued pairs were dispatched again")
	}

	// The probe run completes: the name with an origin is covered ok, the
	// open port without one is covered with no output.
	g.asset(a, "https://www.plan.test", "service", "http", "")
	if _, err := g.r.db.Exec(`UPDATE scan_runs SET status = 'completed' WHERE id = $1`, f.runs["probe.http"].String()); err != nil {
		t.Fatal(err)
	}
	g.exec(`UPDATE commands SET status = 'completed' WHERE payload->>'scan_run_id' = $1`, f.runs["probe.http"].String())
	// The port scan fails.
	if _, err := g.r.db.Exec(`UPDATE scan_runs SET status = 'failed', error_message = 'sensor unreachable' WHERE id = $1`, f.runs["scan.ports"].String()); err != nil {
		t.Fatal(err)
	}
	g.exec(`UPDATE commands SET status = 'failed', error_message = 'sensor unreachable' WHERE payload->>'scan_run_id' = $1`, f.runs["scan.ports"].String())
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	rows, _ := g.repo.ListForAsset(ctx, a.tenant, www)
	for _, r := range rows {
		switch r.Capability {
		case "probe.http":
			if r.State != "covered" || r.LastOutcome != "ok" || r.LastSuccessAt == nil || r.LastTool != "tool-probe.http" {
				t.Errorf("www probe.http after run = %+v", r)
			}
		case "scan.ports":
			if r.State != "failed" || r.FailStreak != 1 || r.LastError != "sensor unreachable" || r.NextDueAt == nil {
				t.Errorf("www scan.ports after failed run = %+v", r)
			}
		}
	}
	rows, _ = g.repo.ListForAsset(ctx, a.tenant, web)
	if len(rows) != 1 || rows[0].State != "covered" || rows[0].LastOutcome != "no_output" {
		t.Errorf("open port probe.http after run = %+v", rows)
	}

	// Strict scan approval: nothing is started.
	b := g.r.newTenant()
	g.asset(b, "strict.plan.test", "subdomain", "", "")
	mode.m = scangov.ModeStrict
	n := len(f.calls["resolve.dns"])
	if _, err := g.svc.RunTenant(ctx, b.tenant); err != nil {
		t.Fatal(err)
	}
	if len(f.calls["resolve.dns"]) != n {
		t.Error("a Strict tenant got coverage runs")
	}
}

// A refusal of the whole batch that says the capability cannot run now
// (here the trigger's zone coverage refusal) pauses the capability with its
// readiness reason and retries it after RefusalRetry, instead of being
// retried every pass; a refusal about the batch's targets blocks its pairs
// with the code; any other error leaves them due.
func TestAssetCoverage_WholeBatchRefusal(t *testing.T) {
	g := newCovRig(t)
	ctx := context.Background()
	a := g.r.newTenant()
	g.exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern) VALUES ($1, 'domain', '*.batch.test')`, a.tenant)
	name := g.asset(a, "nozone.batch.test", "subdomain", "", "")
	addr := g.asset(a, "203.0.113.77", "ip_address", "", "")
	f := &fakeStarter{t: t, calls: map[string][]string{}, runs: map[string]shared.ID{}, busy: map[string]bool{},
		fail: map[string]error{
			"resolve.dns": fmt.Errorf("failed to trigger coverage: %w", shared.NewDomainError("NO_SENSOR_AVAILABLE", "no sensor", shared.ErrValidation)),
			"lookup.asn":  errors.New("connection reset"),
			"scan.ports":  fmt.Errorf("failed to trigger coverage: %w", shared.NewDomainError("ALL_TARGETS_EXCLUDED", "every target is excluded", shared.ErrValidation)),
		}}
	f.execRun = func(shared.ID) {}
	g.svc.EnablePlanning(g.repo, f, coverageapp.GovernanceSwitch{Modes: fixedMode{m: scangov.ModeOff}}, coverageapp.Config{})
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	rows, _ := g.repo.ListForAsset(ctx, a.tenant, name)
	for _, r := range rows {
		if r.Capability == "resolve.dns" && (r.State != "paused" || r.Reason != "no_eligible_sensor" || r.NextDueAt == nil ||
			!r.NextDueAt.After(time.Now().Add(coverageapp.RefusalRetry-time.Minute))) {
			t.Errorf("refused batch pair = %+v, want paused no_eligible_sensor, retried later", r)
		}
	}
	rows, _ = g.repo.ListForAsset(ctx, a.tenant, addr)
	for _, r := range rows {
		if r.Capability == "lookup.asn" && r.State != "due" {
			t.Errorf("a database-style error must leave the pair due: %+v", r)
		}
		if r.Capability == "scan.ports" && (r.State != "blocked" || r.Reason != "all_targets_excluded") {
			t.Errorf("a refusal about the targets must block the batch: %+v", r)
		}
	}
	// The paused capability is not tried again on the next pass.
	n := len(f.calls["resolve.dns"])
	if n != 1 {
		t.Fatalf("resolve.dns attempts = %d, want 1", n)
	}
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	if len(f.calls["resolve.dns"]) != n {
		t.Error("a paused capability was retried on the next pass")
	}
}

// One target whose scan windows never open must not stall the capability:
// its pair is blocked, the other targets of the same batch run in the same
// pass, and no pair of any capability is paused.
func TestAssetCoverage_NeverOpensTargetDoesNotStallCapability(t *testing.T) {
	g := newCovRig(t)
	ctx := context.Background()
	a := g.r.newTenant()
	g.exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern) VALUES ($1, 'domain', '*.never.test')`, a.tenant)
	bad := g.asset(a, "closed.never.test", "subdomain", "", "")
	good := g.asset(a, "open.never.test", "subdomain", "", "")
	ip := g.asset(a, "203.0.113.31", "ip_address", "", "")
	g.rel(a, bad, ip, "resolves_to")
	g.rel(a, good, ip, "resolves_to")
	f := &fakeStarter{t: t, calls: map[string][]string{}, runs: map[string]shared.ID{}, busy: map[string]bool{},
		never: map[string]bool{"closed.never.test": true}}
	f.execRun = func(shared.ID) {}
	g.svc.EnablePlanning(g.repo, f, coverageapp.GovernanceSwitch{Modes: fixedMode{m: scangov.ModeOff}}, coverageapp.Config{})
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	if got := g.states(a, bad)["probe.http"]; got != "blocked:scan_window_never_opens" {
		t.Errorf("never-open target probe.http = %q", got)
	}
	if got := g.states(a, good)["probe.http"]; got != "queued:" {
		t.Errorf("other target probe.http = %q, want queued in the same pass", got)
	}
	for id, name := range map[shared.ID]string{bad: "bad", good: "good"} {
		for cap, st := range g.states(a, id) {
			if strings.HasPrefix(st, "paused") {
				t.Errorf("%s %s = %q: a target-specific refusal must not pause a capability", name, cap, st)
			}
		}
	}
}

// A run step that ended with more tasks than chunks (a claim-time split and
// a follow-up of an unfinished target) settles each pair from its own
// target: done anywhere covers it (a follow-up finishing what an earlier
// task left unfinished), a failure keeps its class (a target-side one,
// unreachable or timeout, pauses the pair for a recheck), a skip blocks, a
// task that failed whole fails its targets with its error, a target the
// sensor called done but reported unreached is paused as unreachable, the
// run's own unfinished
// targets fail, and a target no task carried fails as not dispatched.
func TestAssetCoverage_SettlesPerTargetAcrossSplitTasks(t *testing.T) {
	g := newCovRig(t)
	ctx := context.Background()
	a := g.r.newTenant()

	names := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}
	ids := map[string]shared.ID{}
	for _, n := range names {
		ids[n] = g.asset(a, n+".split.test", "subdomain", "",
			`{"dns_records": [{"type": "A", "value": "203.0.113.40"}]}`)
	}
	run, wf, step, stepRun := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	g.exec(`INSERT INTO scan_workflows (id, tenant_id, name) VALUES ($1, $2, $3)`, wf, a.tenant, "split "+wf.String())
	g.exec(`INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, step_order, capabilities)
		VALUES ($1, $2, 'probe', 'probe', 1, ARRAY['http'])`, step, wf)
	g.exec(`INSERT INTO scan_runs (id, scan_workflow_id, tenant_id, trigger_type, status, unfinished_targets)
		VALUES ($1, $2, $3, 'manual', 'partial', '["h.split.test"]')`, run, wf, a.tenant)
	g.exec(`INSERT INTO scan_run_steps (id, scan_run_id, step_id, step_key, step_order, status) VALUES ($1, $2, $3, 'probe', 1, 'completed')`,
		stepRun, run, step)
	for _, n := range names {
		g.exec(`INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, queued_at, last_run_id)
			VALUES ($1, $2, 'probe.http', 'queued', now(), $3)`, a.tenant, ids[n], run)
	}
	task := func(status, errMsg string, targets []string, result string) {
		t.Helper()
		tj, _ := json.Marshal(targets)
		var res any
		if result != "" {
			res = result
		}
		g.exec(`INSERT INTO commands (id, tenant_id, type, status, error_message, payload, result, scan_run_step_id)
			VALUES ($1, $2, 'scan', $3, NULLIF($4, ''), jsonb_build_object('targets', $5::jsonb, 'scanner', 'httpx'), $6::jsonb, $7)`,
			shared.NewID(), a.tenant, status, errMsg, string(tj), res, stepRun)
	}
	// The started part of a split chunk: a done; b left unfinished; c done
	// but reported unreached.
	task("completed", "", []string{"a.split.test", "b.split.test", "c.split.test"},
		`{"target_outcomes": [{"target": "a.split.test", "state": "done"}, {"target": "b.split.test", "state": "unfinished"},
		  {"target": "c.split.test", "state": "done"}], "metadata": {"unreached_targets": [{"target": "c.split.test", "class": "timeout"}]}}`)
	// The waiting part, split off at claim time: d failed (timeout), e refused.
	task("completed", "", []string{"d.split.test", "e.split.test"},
		`{"target_outcomes": [{"target": "d.split.test", "state": "failed", "class": "timeout"},
		  {"target": "e.split.test", "state": "skipped", "class": "refused"}]}`)
	// The follow-up of b: done.
	task("completed", "", []string{"b.split.test"}, `{"target_outcomes": [{"target": "b.split.test", "state": "done"}]}`)
	// A chunk that failed whole, no outcomes.
	task("failed", "sensor lost", []string{"f.split.test"}, "")
	// An old sensor: completed without outcomes covers its targets.
	task("completed", "", []string{"g.split.test"}, `{"status": "completed"}`)
	// h: only in the run's unfinished targets; i: in no task.

	f := &fakeStarter{t: t, calls: map[string][]string{}, runs: map[string]shared.ID{}, busy: map[string]bool{}}
	f.execRun = func(shared.ID) {}
	g.svc.EnablePlanning(g.repo, f, coverageapp.GovernanceSwitch{Modes: fixedMode{m: scangov.ModeStrict}}, coverageapp.Config{})
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		// probe.http expects a web origin; none exists here, so covered pairs
		// are covered with no output.
		"a": "covered/no_output", "b": "covered/no_output", "c": "paused/unreachable", "d": "paused/timeout",
		"e": "blocked/", "f": "failed/failed", "g": "covered/no_output", "h": "failed/unfinished", "i": "failed/not_dispatched",
	}
	for n, w := range want {
		rows, _ := g.repo.ListForAsset(ctx, a.tenant, ids[n])
		got := "missing"
		for _, r := range rows {
			if r.Capability == "probe.http" {
				got = string(r.State) + "/" + r.LastOutcome
				if r.State == "blocked" {
					got = "blocked/"
					if r.Reason != "refused" {
						t.Errorf("%s blocked reason = %q", n, r.Reason)
					}
				}
				if n == "f" && r.LastError != "sensor lost" {
					t.Errorf("f error = %q", r.LastError)
				}
			}
		}
		if got != w {
			t.Errorf("%s: %s, want %s", n, got, w)
		}
	}
}
