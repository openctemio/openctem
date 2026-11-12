package integration

// Dead names (research/331 D4, D6, D9; RFC-093): a name that does not
// resolve is a DNS answer, not a failure. The resolve.dns pair is covered
// with outcome no_answer and the name is parked: its active capabilities
// turn not applicable (reason resolves) and are never dispatched, and it is
// rechecked at 1 day, 3 days, 7 days, then weekly. Another capability whose
// target the sensor could not resolve is blocked as unresolvable on the same
// schedule. Nothing of it is a failure streak or a gap. A parked name that
// resolves again goes through the full gate.

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	coverageapp "github.com/openctemio/openctem/api/internal/app/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type deadRig struct {
	*covRig
	a v2Tenant
	f *fakeStarter
}

func newDeadRig(t *testing.T) *deadRig {
	t.Helper()
	g := newCovRig(t)
	a := g.r.newTenant()
	g.exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern) VALUES ($1, 'domain', '*.dead.test')`, a.tenant)
	f := &fakeStarter{t: t, calls: map[string][]string{}, runs: map[string]shared.ID{}, refuse: map[string]string{}, busy: map[string]bool{}}
	f.execRun = func(id shared.ID) {
		g.exec(`INSERT INTO scan_runs (id, tenant_id, trigger_type, status, kind) VALUES ($1, $2, 'manual', 'running', 'system')`, id, a.tenant)
	}
	f.execTask = func(id shared.ID, targets []string) {
		tj, _ := json.Marshal(targets)
		g.exec(`INSERT INTO commands (id, tenant_id, type, status, payload)
			VALUES ($1, $2, 'scan', 'running', jsonb_build_object('scan_run_id', $3::text, 'targets', $4::jsonb))`,
			shared.NewID(), a.tenant, id.String(), string(tj))
	}
	g.svc.EnablePlanning(g.repo, f, coverageapp.GovernanceSwitch{Modes: fixedMode{m: scangov.ModeOff}}, coverageapp.Config{})
	return &deadRig{covRig: g, a: a, f: f}
}

// finish completes a capability's latest run with result on its task.
func (d *deadRig) finish(capability, result string) {
	d.t.Helper()
	run := d.f.runs[capability]
	if run.IsZero() {
		d.t.Fatalf("no %s run was started", capability)
	}
	d.exec(`UPDATE scan_runs SET status = 'completed' WHERE id = $1`, run)
	d.exec(`UPDATE commands SET status = 'completed', result = $2::jsonb WHERE payload->>'scan_run_id' = $1`, run.String(), result)
}

func (d *deadRig) pass() {
	d.t.Helper()
	if _, err := d.svc.RunTenant(context.Background(), d.a.tenant); err != nil {
		d.t.Fatal(err)
	}
}

type pairRow struct {
	state, reason, outcome string
	streak                 int
	dueIn                  time.Duration
}

func (d *deadRig) pair(asset shared.ID, capability string) pairRow {
	d.t.Helper()
	var (
		p    pairRow
		secs float64
	)
	if err := d.r.db.QueryRow(`SELECT state, reason, last_outcome, fail_streak, COALESCE(extract(epoch FROM next_due_at - now()), 0)
		FROM asset_coverage WHERE tenant_id = $1 AND asset_id = $2 AND capability = $3 AND vantage = ''`,
		d.a.tenant.String(), asset.String(), capability).Scan(&p.state, &p.reason, &p.outcome, &p.streak, &secs); err != nil {
		d.t.Fatalf("%s: %v", capability, err)
	}
	p.dueIn = time.Duration(secs * float64(time.Second))
	return p
}

// within reports whether got is the recheck want stretched by at most the
// 10 % jitter (and a little slack for the test's own clock).
func within(got, want time.Duration) bool {
	return got > want-time.Minute && got < want+want/10+time.Minute
}

const noAnswerResult = `{"metadata": {"refused_targets": [{"target": "gone.dead.test", "reason": "unresolvable", "rule": "targets", "dns": "name_gone"}], "refused_targets_total": 1, "partial": true},
	"target_outcomes": [{"target": "gone.dead.test", "state": "skipped", "class": "refused"}]}`

func TestAssetCoverage_DeadNameIsParkedNotFailed(t *testing.T) {
	d := newDeadRig(t)
	gone := d.asset(d.a, "gone.dead.test", "subdomain", "", "")
	ip := d.asset(d.a, "203.0.113.41", "ip_address", "", "")
	// A stale fact: the name resolved once.
	d.rel(d.a, gone, ip, "resolves_to")
	d.f.busy["scan.ports"], d.f.busy["probe.http"] = true, true

	d.pass()
	if got := d.pair(gone, "resolve.dns").state; got != "queued" {
		t.Fatalf("resolve.dns = %s, want queued", got)
	}
	d.finish("resolve.dns", noAnswerResult)
	d.f.busy = map[string]bool{}
	d.pass()

	dns := d.pair(gone, "resolve.dns")
	if dns.state != "covered" || dns.outcome != "no_answer" || dns.streak != 1 || !within(dns.dueIn, 24*time.Hour) {
		t.Fatalf("resolve.dns after no answer = %+v, want covered no_answer, streak 1, recheck in 1 d", dns)
	}
	// Parked: the active capabilities are not applicable and were never
	// dispatched, though a stale resolves_to edge is still there.
	for _, c := range []string{"scan.ports", "probe.http"} {
		if p := d.pair(gone, c); p.state != "not_applicable" || p.reason != "resolves" {
			t.Errorf("%s of a parked name = %+v, want not_applicable:resolves", c, p)
		}
		if slices.Contains(d.f.calls[c], "gone.dead.test") {
			t.Errorf("%s was dispatched to a parked name", c)
		}
	}

	// Never a gap, however long the name stays dead.
	d.exec(`UPDATE asset_coverage SET last_success_at = now() - interval '10 days' WHERE tenant_id = $1 AND asset_id = $2 AND capability = 'resolve.dns'`, d.a.tenant, gone)
	health, err := d.repo.Health(context.Background(), d.a.tenant, map[string]time.Duration{"resolve.dns": 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range health {
		if h.Capability == "resolve.dns" && (h.Gaps != 0 || h.Failing != 0) {
			t.Errorf("resolve.dns health = %+v, want no gap and no failing pair for a dead name", h)
		}
	}

	// The second consecutive no answer widens the recheck to 3 days.
	d.exec(`UPDATE asset_coverage SET next_due_at = now() - interval '1 minute' WHERE tenant_id = $1 AND asset_id = $2 AND capability = 'resolve.dns'`, d.a.tenant, gone)
	d.pass()
	d.finish("resolve.dns", noAnswerResult)
	d.pass()
	if dns := d.pair(gone, "resolve.dns"); dns.outcome != "no_answer" || dns.streak != 2 || !within(dns.dueIn, 72*time.Hour) {
		t.Fatalf("second no answer = %+v, want streak 2 and a 3 d recheck", dns)
	}
}

// Security: a parked name that resolves again (re-registered, maybe by
// someone else) re-enters through the full gate: its active pairs become
// due and the trigger's gate decides; a refusal blocks them.
func TestAssetCoverage_UnparkedNameGoesThroughTheGate(t *testing.T) {
	d := newDeadRig(t)
	gone := d.asset(d.a, "gone.dead.test", "subdomain", "", "")
	ip := d.asset(d.a, "203.0.113.42", "ip_address", "", "")
	d.rel(d.a, gone, ip, "resolves_to")
	d.f.busy["scan.ports"], d.f.busy["probe.http"] = true, true
	d.pass()
	d.finish("resolve.dns", noAnswerResult)
	d.f.busy = map[string]bool{}
	d.pass()
	if p := d.pair(gone, "scan.ports"); p.state != "not_applicable" {
		t.Fatalf("scan.ports of a parked name = %+v", p)
	}

	// The recheck answers: the name resolves again, now to an address the
	// gate refuses.
	d.exec(`UPDATE asset_coverage SET next_due_at = now() - interval '1 minute' WHERE tenant_id = $1 AND asset_id = $2 AND capability = 'resolve.dns'`, d.a.tenant, gone)
	d.f.busy["scan.ports"], d.f.busy["probe.http"] = true, true
	d.pass()
	d.finish("resolve.dns", `{"target_outcomes": [{"target": "gone.dead.test", "state": "done"}]}`)
	d.f.busy = map[string]bool{}
	d.f.refuse["gone.dead.test"] = "denied_range"
	d.pass() // settles the answer: un-parked
	d.pass() // reconcile makes the active pairs due; the gate refuses them

	if dns := d.pair(gone, "resolve.dns"); dns.outcome != "ok" || dns.streak != 0 {
		t.Fatalf("resolve.dns after an answer = %+v", dns)
	}
	if !slices.Contains(d.f.calls["scan.ports"], "gone.dead.test") {
		t.Fatal("the un-parked name never reached the gate")
	}
	if p := d.pair(gone, "scan.ports"); p.state != "blocked" || p.reason != "denied_range" {
		t.Errorf("scan.ports after the gate refused = %+v, want blocked:denied_range", p)
	}
}

// Security: a sensor that reports every name of its task as gone can only
// park those names: the assets stay, their pairs stay (rechecked on a
// bounded, widening schedule), and nothing outside the task is touched.
func TestAssetCoverage_SensorClaimingEveryNameDeadOnlyParks(t *testing.T) {
	d := newDeadRig(t)
	names := []string{"a.dead.test", "b.dead.test", "c.dead.test"}
	ids := map[string]shared.ID{}
	for _, n := range names {
		ids[n] = d.asset(d.a, n, "subdomain", "", `{"dns_records": [{"type": "A", "value": "203.0.113.43"}]}`)
	}
	other := d.asset(d.a, "other.dead.test", "subdomain", "", `{"dns_records": [{"type": "A", "value": "203.0.113.44"}]}`)
	d.f.busy["scan.ports"], d.f.busy["probe.http"] = true, true
	d.f.later = map[string]bool{"other.dead.test": true}
	d.pass()
	d.finish("resolve.dns", `{"target_outcomes": [
		{"target": "a.dead.test", "state": "failed", "class": "name_gone", "cause": "target"},
		{"target": "b.dead.test", "state": "failed", "class": "name_gone", "cause": "target"},
		{"target": "c.dead.test", "state": "failed", "class": "name_gone", "cause": "target"},
		{"target": "other.dead.test", "state": "failed", "class": "name_gone", "cause": "target"}]}`)
	d.pass()

	for _, n := range names {
		dns := d.pair(ids[n], "resolve.dns")
		if dns.state != "covered" || dns.outcome != "no_answer" || dns.dueIn > 27*time.Hour {
			t.Errorf("%s resolve.dns = %+v, want parked with a recheck within a day", n, dns)
		}
		var active int
		if err := d.r.db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND id = $2 AND status = 'active' AND deleted_at IS NULL`,
			d.a.tenant.String(), ids[n].String()).Scan(&active); err != nil || active != 1 {
			t.Errorf("%s asset no longer active (%d, %v)", n, active, err)
		}
		if p := d.pair(ids[n], "scan.ports"); p.state != "not_applicable" {
			t.Errorf("%s scan.ports = %+v", n, p)
		}
	}
	// A name the task did not carry is not touched by its outcomes.
	if dns := d.pair(other, "resolve.dns"); dns.outcome == "no_answer" {
		t.Errorf("a name outside the task was parked: %+v", dns)
	}
}

// D9: another capability whose target the sensor could not resolve is
// blocked as unresolvable on the dead-name schedule; never failed.
func TestAssetCoverage_UnresolvableTargetOfAnotherCapabilityIsBlocked(t *testing.T) {
	d := newDeadRig(t)
	stale := d.asset(d.a, "stale.dead.test", "subdomain", "", `{"dns_records": [{"type": "A", "value": "203.0.113.45"}]}`)
	d.f.busy["resolve.dns"], d.f.busy["probe.http"] = true, true
	d.pass()
	if p := d.pair(stale, "scan.ports"); p.state != "queued" {
		t.Fatalf("scan.ports = %+v, want queued", p)
	}
	d.finish("scan.ports", `{"metadata": {"refused_targets": [{"target": "stale.dead.test", "reason": "unresolvable", "dns": "name_gone"}]},
		"target_outcomes": [{"target": "stale.dead.test", "state": "skipped", "class": "refused"}]}`)
	d.pass()
	p := d.pair(stale, "scan.ports")
	if p.state != "blocked" || p.reason != "unresolvable" || p.streak != 1 || !within(p.dueIn, 24*time.Hour) {
		t.Fatalf("scan.ports of an unresolvable name = %+v, want blocked:unresolvable, streak 1, recheck in 1 d", p)
	}
}

// Tenant isolation: a run of one tenant cannot settle another tenant's
// pairs, whatever asset ids it names.
func TestAssetCoverage_DeadNameSettlementIsTenantScoped(t *testing.T) {
	d := newDeadRig(t)
	ctx := context.Background()
	b := d.r.newTenant()
	victim := d.asset(b, "victim.dead.test", "subdomain", "", "")
	runB := shared.NewID()
	d.exec(`INSERT INTO scan_runs (id, tenant_id, trigger_type, status, kind) VALUES ($1, $2, 'manual', 'completed', 'system')`, runB, b.tenant)
	d.exec(`INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, queued_at, last_run_id)
		VALUES ($1, $2, 'resolve.dns', 'queued', now(), $3)
		ON CONFLICT (tenant_id, asset_id, capability, vantage) DO UPDATE SET state = 'queued', last_run_id = $3`, b.tenant, victim, runB)

	n, err := d.repo.SettleNoAnswer(ctx, d.a.tenant, runB, "resolve.dns", []shared.ID{victim})
	if err != nil || n != 0 {
		t.Fatalf("tenant A settled %d of tenant B's pairs (err %v)", n, err)
	}
	n, err = d.repo.SettleUnresolved(ctx, d.a.tenant, runB, "resolve.dns", nil)
	if err != nil || n != 0 {
		t.Fatalf("empty settle = %d, %v", n, err)
	}
	var state string
	if err := d.r.db.QueryRow(`SELECT state FROM asset_coverage WHERE tenant_id = $1 AND asset_id = $2 AND capability = 'resolve.dns'`,
		b.tenant.String(), victim.String()).Scan(&state); err != nil || state != "queued" {
		t.Fatalf("tenant B's pair = %q (%v), want untouched", state, err)
	}
}
