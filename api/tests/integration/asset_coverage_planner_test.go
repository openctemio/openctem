package integration

// The coverage planner (RFC-093) on a migrated database with a recording run
// starter: due pairs go out in one batch per capability, the gate's refusals
// become blocked pairs with its code, a capability whose run is still active
// waits, a finished run settles its pairs (covered with the output check, or
// failed with a back-off), and a Strict tenant gets nothing started.

import (
	"context"
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
	execRun func(id shared.ID)
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
	// The port scan fails.
	if _, err := g.r.db.Exec(`UPDATE scan_runs SET status = 'failed', error_message = 'sensor unreachable' WHERE id = $1`, f.runs["scan.ports"].String()); err != nil {
		t.Fatal(err)
	}
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

// A refusal of the whole batch (here the trigger's zone coverage refusal)
// blocks the batch's pairs with the code instead of leaving them due to be
// retried every pass; any other error leaves them due.
func TestAssetCoverage_WholeBatchRefusalBlocks(t *testing.T) {
	g := newCovRig(t)
	ctx := context.Background()
	a := g.r.newTenant()
	name := g.asset(a, "nozone.batch.test", "subdomain", "", "")
	addr := g.asset(a, "203.0.113.77", "ip_address", "", "")
	f := &fakeStarter{t: t, calls: map[string][]string{}, runs: map[string]shared.ID{}, busy: map[string]bool{},
		fail: map[string]error{
			"resolve.dns": fmt.Errorf("failed to trigger coverage: %w", shared.NewDomainError("NO_ZONE_COVERAGE", "outside every zone", shared.ErrValidation)),
			"lookup.asn":  errors.New("connection reset"),
		}}
	f.execRun = func(shared.ID) {}
	g.svc.EnablePlanning(g.repo, f, coverageapp.GovernanceSwitch{Modes: fixedMode{m: scangov.ModeOff}}, coverageapp.Config{})
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	rows, _ := g.repo.ListForAsset(ctx, a.tenant, name)
	for _, r := range rows {
		if r.Capability == "resolve.dns" && (r.State != "blocked" || r.Reason != "no_zone_coverage" || r.NextDueAt == nil || !r.NextDueAt.After(time.Now().Add(time.Hour))) {
			t.Errorf("refused batch pair = %+v, want blocked no_zone_coverage, rechecked later", r)
		}
	}
	rows, _ = g.repo.ListForAsset(ctx, a.tenant, addr)
	for _, r := range rows {
		if r.Capability == "lookup.asn" && r.State != "due" {
			t.Errorf("a database-style error must leave the pair due: %+v", r)
		}
	}
	// The blocked pair is not offered again on the next pass.
	n := len(f.calls["resolve.dns"])
	if n != 1 {
		t.Fatalf("resolve.dns attempts = %d, want 1", n)
	}
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	if len(f.calls["resolve.dns"]) != n {
		t.Error("a blocked pair was retried on the next pass")
	}
}
