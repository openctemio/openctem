package integration

// The coverage ledger's full cycle (RFC-093) on a migrated database: a
// covered pair is planned again once its cadence has elapsed, a blocked pair
// once its recheck time has passed, due times carry the pair's jitter, a
// queued pair is never planned twice, a batch takes pairs falling due
// shortly after (only when one is due now), and one tenant's due pairs never
// reach another tenant's batch.

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	coverageapp "github.com/openctemio/openctem/api/internal/app/coverage"
	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type cycleRig struct {
	*covRig
	f *fakeStarter
}

func newCycleRig(t *testing.T) *cycleRig {
	g := &cycleRig{covRig: newCovRig(t)}
	g.f = &fakeStarter{t: t, calls: map[string][]string{}, runs: map[string]shared.ID{},
		refuse: map[string]string{}, busy: map[string]bool{}}
	g.svc.EnablePlanning(g.repo, g.f, coverageapp.GovernanceSwitch{Modes: fixedMode{m: scangov.ModeOff}}, coverageapp.Config{})
	return g
}

// bindTenant makes the fake starter's runs and tasks rows of tn.
func (g *cycleRig) bindTenant(tn v2Tenant) {
	g.f.execRun = func(id shared.ID) {
		g.exec(`INSERT INTO scan_runs (id, tenant_id, trigger_type, status, kind) VALUES ($1, $2, 'manual', 'running', 'system')`, id, tn.tenant)
	}
	g.f.execTask = func(id shared.ID, targets []string) {
		tj, _ := json.Marshal(targets)
		g.exec(`INSERT INTO commands (id, tenant_id, type, status, payload)
			VALUES ($1, $2, 'scan', 'running', jsonb_build_object('scan_run_id', $3::text, 'targets', $4::jsonb))`,
			shared.NewID(), tn.tenant, id.String(), string(tj))
	}
}

// pass runs one planner pass for tn and returns the targets started per
// capability in that pass.
func (g *cycleRig) pass(tn v2Tenant) map[string][]string {
	g.t.Helper()
	g.bindTenant(tn)
	g.f.calls = map[string][]string{}
	if _, err := g.svc.RunTenant(context.Background(), tn.tenant); err != nil {
		g.t.Fatal(err)
	}
	out := map[string][]string{}
	for c, ts := range g.f.calls {
		s := append([]string(nil), ts...)
		sort.Strings(s)
		out[c] = s
	}
	return out
}

// complete finishes the capability's last run with every task done.
func (g *cycleRig) complete(capability string) {
	g.t.Helper()
	run := g.f.runs[capability].String()
	g.exec(`UPDATE commands SET status = 'completed' WHERE payload->>'scan_run_id' = $1`, run)
	g.exec(`UPDATE scan_runs SET status = 'completed' WHERE id = $1`, run)
}

func (g *cycleRig) row(tn v2Tenant, id shared.ID, capability string) covdom.Row {
	g.t.Helper()
	rows, err := g.repo.ListForAsset(context.Background(), tn.tenant, id)
	if err != nil {
		g.t.Fatal(err)
	}
	for _, r := range rows {
		if r.Capability == capability {
			return r
		}
	}
	g.t.Fatalf("no %s row", capability)
	return covdom.Row{}
}

// dueIn moves the pair's next due time to now + d (the DB clock).
func (g *cycleRig) dueIn(tn v2Tenant, id shared.ID, capability string, d time.Duration) {
	g.t.Helper()
	g.exec(`UPDATE asset_coverage SET next_due_at = now() + make_interval(secs => $4)
		WHERE tenant_id = $1 AND asset_id = $2 AND capability = $3`, tn.tenant, id, capability, d.Seconds())
}

func TestAssetCoverageCycle_CoveredIsPlannedAgainAfterItsCadence(t *testing.T) {
	g := newCycleRig(t)
	a := g.r.newTenant()
	name := g.asset(a, "www.cycle.test", "subdomain", "", "")

	// New pair: due at once.
	if got := g.pass(a)["resolve.dns"]; strings.Join(got, ",") != "www.cycle.test" {
		t.Fatalf("first pass resolve.dns = %v", got)
	}
	if r := g.row(a, name, "resolve.dns"); r.State != covdom.StateQueued {
		t.Fatalf("after dispatch = %s", r.State)
	}
	// Queued and still running: never planned twice, even when its due
	// time is in the past.
	g.dueIn(a, name, "resolve.dns", -time.Hour)
	if got := g.pass(a)["resolve.dns"]; len(got) != 0 {
		t.Fatalf("queued pair planned again: %v", got)
	}

	g.complete("resolve.dns")
	g.pass(a)
	r := g.row(a, name, "resolve.dns")
	if r.State != covdom.StateCovered || r.NextDueAt == nil || r.LastSuccessAt == nil {
		t.Fatalf("after settle = %+v", r)
	}
	// Next due = success + cadence stretched by the pair's own jitter (the
	// SQL and Go jitter agree).
	want := covdom.Jittered(24*time.Hour, name.String(), "resolve.dns")
	if got := r.NextDueAt.Sub(*r.LastSuccessAt); got < want-2*time.Second || got > want+2*time.Second {
		t.Fatalf("next due after %v, want %v (cadence + jitter)", got, want)
	}

	// Within the cadence: not planned.
	if got := g.pass(a)["resolve.dns"]; len(got) != 0 {
		t.Fatalf("covered pair within its cadence planned: %v", got)
	}
	// The cadence elapsed: planned again, queued, then covered again.
	g.dueIn(a, name, "resolve.dns", -time.Minute)
	if got := g.pass(a)["resolve.dns"]; strings.Join(got, ",") != "www.cycle.test" {
		t.Fatalf("covered pair past its cadence not planned: %v", got)
	}
	if r := g.row(a, name, "resolve.dns"); r.State != covdom.StateQueued {
		t.Fatalf("re-planned pair = %s", r.State)
	}
	g.complete("resolve.dns")
	g.pass(a)
	if r := g.row(a, name, "resolve.dns"); r.State != covdom.StateCovered || !r.NextDueAt.After(time.Now().Add(23*time.Hour)) {
		t.Fatalf("second cycle = %+v", r)
	}
}

func TestAssetCoverageCycle_BlockedIsRecheckedAfterItsRecheckTime(t *testing.T) {
	g := newCycleRig(t)
	a := g.r.newTenant()
	name := g.asset(a, "blocked.cycle.test", "subdomain", "", "")
	g.f.refuse["blocked.cycle.test"] = "no_entry"

	g.pass(a)
	r := g.row(a, name, "resolve.dns")
	if r.State != covdom.StateBlocked || r.Reason != "no_entry" || r.NextDueAt == nil {
		t.Fatalf("refused pair = %+v", r)
	}
	want := covdom.Jittered(coverageapp.BlockedRecheck, name.String(), "resolve.dns")
	if got := time.Until(*r.NextDueAt); got < want-time.Minute || got > want+time.Second {
		t.Fatalf("recheck in %v, want about %v", got, want)
	}
	// Before the recheck time: not offered.
	if got := g.pass(a)["resolve.dns"]; len(got) != 0 {
		t.Fatalf("blocked pair offered before its recheck: %v", got)
	}
	// Scope changed (the gate now admits it) and the recheck time passed:
	// offered again and queued.
	delete(g.f.refuse, "blocked.cycle.test")
	g.dueIn(a, name, "resolve.dns", -time.Minute)
	if got := g.pass(a)["resolve.dns"]; strings.Join(got, ",") != "blocked.cycle.test" {
		t.Fatalf("blocked pair past its recheck not offered: %v", got)
	}
	if r := g.row(a, name, "resolve.dns"); r.State != covdom.StateQueued || r.Reason != "" {
		t.Fatalf("rechecked pair = %+v", r)
	}
}

// A blocked pair whose precondition stops holding becomes not applicable
// (it is not rechecked for ever).
func TestAssetCoverageCycle_BlockedFollowsPreconditions(t *testing.T) {
	g := newCycleRig(t)
	a := g.r.newTenant()
	name := g.asset(a, "pre.cycle.test", "subdomain", "", `{"dns_records": [{"type": "A", "value": "203.0.113.50"}]}`)
	g.f.refuse["pre.cycle.test"] = "guardrailed"
	g.pass(a)
	if r := g.row(a, name, "probe.http"); r.State != covdom.StateBlocked {
		t.Fatalf("probe.http = %s", r.State)
	}
	g.exec(`UPDATE assets SET properties = '{}' WHERE id = $1`, name)
	g.pass(a)
	if r := g.row(a, name, "probe.http"); r.State != covdom.StateNotApplicable || r.Reason != covdom.RequiresResolves {
		t.Fatalf("blocked pair without its precondition = %s:%s", r.State, r.Reason)
	}
}

// A batch also carries pairs due within the capability's lookahead, but
// only when one pair is due now.
func TestAssetCoverageCycle_CoalescesPairsDueSoon(t *testing.T) {
	g := newCycleRig(t)
	a := g.r.newTenant()
	one := g.asset(a, "one.cycle.test", "subdomain", "", "")
	two := g.asset(a, "two.cycle.test", "subdomain", "", "")
	three := g.asset(a, "three.cycle.test", "subdomain", "", "")
	g.pass(a)
	g.complete("resolve.dns")
	g.pass(a)

	// Nothing due now; two pairs inside the 1 h lookahead of resolve.dns.
	g.dueIn(a, one, "resolve.dns", 20*time.Minute)
	g.dueIn(a, two, "resolve.dns", 40*time.Minute)
	g.dueIn(a, three, "resolve.dns", 5*time.Hour)
	if got := g.pass(a)["resolve.dns"]; len(got) != 0 {
		t.Fatalf("batch started with no pair due now: %v", got)
	}
	// One pair due now: the batch takes it and the ones due within the
	// lookahead, not the one due later.
	g.dueIn(a, one, "resolve.dns", -time.Minute)
	if got := g.pass(a)["resolve.dns"]; strings.Join(got, ",") != "one.cycle.test,two.cycle.test" {
		t.Fatalf("coalesced batch = %v", got)
	}
}

// Tenant isolation: one tenant's pass never plans another tenant's pairs.
func TestAssetCoverageCycle_TenantScoped(t *testing.T) {
	g := newCycleRig(t)
	a := g.r.newTenant()
	b := g.r.newTenant()
	g.asset(a, "a.iso.test", "subdomain", "", "")
	bName := g.asset(b, "b.iso.test", "subdomain", "", "")
	got := g.pass(a)["resolve.dns"]
	if strings.Join(got, ",") != "a.iso.test" {
		t.Fatalf("tenant a batch = %v", got)
	}
	// b's ledger exists only after b's own pass; a's pass left it untouched.
	rows, err := g.repo.ListForAsset(context.Background(), b.tenant, bName)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("tenant a's pass wrote tenant b's ledger: %+v", rows)
	}
}
