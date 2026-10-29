package integration

// Target-side outcomes of continuous coverage (RFC-093) on a migrated
// database: an HTTP probe applies to a name only when a web port or web
// origin was seen on it, or its ports are still unknown; a pair whose target
// did not answer is paused with the outcome and rechecked after 1 day, 3
// days, then weekly, instead of failing and retrying every few hours.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestAssetCoverage_HTTPProbeNeedsWebPortOrUnknownPorts(t *testing.T) {
	g := newCycleRig(t)
	ctx := context.Background()
	a := g.r.newTenant()
	b := g.r.newTenant()
	g.scope(a)

	// name -> address, with the address's open ports linked by exposes.
	host := func(tn v2Tenant, name, ip string, ports ...int) (shared.ID, shared.ID) {
		n := g.asset(tn, name, "subdomain", "", "")
		addr := g.asset(tn, ip, "ip_address", "", "")
		g.rel(tn, n, addr, "resolves_to")
		for _, p := range ports {
			port := g.asset(tn, ip+":"+itoa(p)+":tcp", "service", "open_port", `{"port": `+itoa(p)+`}`)
			g.rel(tn, addr, port, "exposes")
		}
		return n, addr
	}
	scanned := func(tn v2Tenant, id shared.ID) {
		g.exec(`INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, last_success_at, next_due_at)
			VALUES ($1, $2, 'scan.ports', 'covered', now(), now() + interval '7 days')
			ON CONFLICT (tenant_id, asset_id, capability, vantage) DO UPDATE SET last_success_at = now(), state = 'covered'`, tn.tenant, id)
	}

	web, _ := host(a, "web.tside.test", "203.0.113.61", 22, 443)
	mail, _ := host(a, "mail.tside.test", "203.0.113.62", 25)
	unknown, _ := host(a, "new.tside.test", "203.0.113.63")
	empty, _ := host(a, "empty.tside.test", "203.0.113.64")
	scanned(a, empty)
	viaAddr, viaAddrIP := host(a, "addr.tside.test", "203.0.113.65")
	scanned(a, viaAddrIP)
	origin, _ := host(a, "origin.tside.test", "203.0.113.66")
	scanned(a, origin)
	g.asset(a, "https://origin.tside.test", "service", "http", "")
	closed, _ := host(a, "closed.tside.test", "203.0.113.67", 8443)
	g.exec(`UPDATE assets SET status = 'inactive' WHERE tenant_id = $1 AND name = '203.0.113.67:8443:tcp'`, a.tenant)
	// Tenant isolation: tenant b's web port and origin of the same name
	// never make tenant a's name applicable.
	iso, _ := host(a, "iso.tside.test", "203.0.113.68")
	scanned(a, iso)
	host(b, "iso.tside.test", "203.0.113.68", 443)
	g.asset(b, "https://iso.tside.test", "service", "http", "")

	if _, _, err := g.repo.Reconcile(ctx, a.tenant, covdom.Rules()); err != nil {
		t.Fatal(err)
	}
	const na = "not_applicable:" + covdom.RequiresWebPortOrUnscanned
	for _, c := range []struct {
		name string
		id   shared.ID
		want string
	}{
		{"web port on its address", web, "due:"},
		{"only a mail port (ports known from the address)", mail, na},
		{"ports unknown", unknown, "due:"},
		{"port scan of the name found nothing", empty, na},
		{"port scan of its address found nothing", viaAddr, na},
		{"a web origin of the name was seen", origin, "due:"},
		{"the web port closed", closed, na},
		{"another tenant's port and origin", iso, na},
	} {
		if got := g.states(a, c.id)["probe.http"]; got != c.want {
			t.Errorf("%s: probe.http = %q, want %q", c.name, got, c.want)
		}
	}

	// A web port appears on the mail host: the probe applies again.
	addr := g.asset(a, "203.0.113.62:8080:tcp", "service", "open_port", `{"port": 8080}`)
	var mailIP string
	if err := g.r.db.QueryRow(`SELECT id FROM assets WHERE tenant_id = $1 AND name = '203.0.113.62'`, a.tenant.String()).Scan(&mailIP); err != nil {
		t.Fatal(err)
	}
	ip, _ := shared.IDFromString(mailIP)
	g.rel(a, ip, addr, "exposes")
	if _, _, err := g.repo.Reconcile(ctx, a.tenant, covdom.Rules()); err != nil {
		t.Fatal(err)
	}
	if got := g.states(a, mail)["probe.http"]; got != "due:" {
		t.Errorf("after a web port appeared: probe.http = %q, want due", got)
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// unreachableTask records the run's one task with the target failed as
// unreachable, and finishes the run.
func (g *cycleRig) finishUnreachable(capability, target string) {
	g.t.Helper()
	run := g.f.runs[capability].String()
	g.exec(`UPDATE commands SET status = 'completed', result = jsonb_build_object('target_outcomes',
		jsonb_build_array(jsonb_build_object('target', $2::text, 'state', 'failed', 'class', 'unreachable')))
		WHERE payload->>'scan_run_id' = $1`, run, target)
	g.exec(`UPDATE scan_runs SET status = 'completed' WHERE id = $1`, run)
}

func TestAssetCoverage_TargetSideOutcomeRecheckSchedule(t *testing.T) {
	g := newCycleRig(t)
	a := g.r.newTenant()
	g.scope(a)
	name := g.asset(a, "down.tside.test", "subdomain", "", "")
	day := 24 * time.Hour

	g.pass(a)
	for i, wantAfter := range []time.Duration{day, 3 * day, 7 * day, 7 * day} {
		g.finishUnreachable("resolve.dns", "down.tside.test")
		g.pass(a)
		r := g.row(a, name, "resolve.dns")
		if r.State != covdom.StatePaused || r.Reason != "unreachable" || r.LastOutcome != "unreachable" || r.FailStreak != i+1 {
			t.Fatalf("observation %d: %s:%s outcome %s streak %d", i+1, r.State, r.Reason, r.LastOutcome, r.FailStreak)
		}
		want := covdom.Jittered(wantAfter, name.String(), "resolve.dns")
		if got := time.Until(*r.NextDueAt); got < want-time.Minute || got > want+time.Second {
			t.Fatalf("observation %d: recheck in %v, want about %v", i+1, got, want)
		}
		// Not retried before its recheck.
		if got := g.pass(a)["resolve.dns"]; len(got) != 0 {
			t.Fatalf("observation %d: retried before the recheck: %v", i+1, got)
		}
		// The recheck is due: planned again.
		g.dueIn(a, name, "resolve.dns", -time.Minute)
		if got := g.pass(a)["resolve.dns"]; len(got) != 1 {
			t.Fatalf("observation %d: recheck not planned: %v", i+1, got)
		}
	}
	// The host answers again: covered, the streak cleared.
	g.complete("resolve.dns")
	g.pass(a)
	if r := g.row(a, name, "resolve.dns"); r.State != covdom.StateCovered || r.FailStreak != 0 {
		t.Fatalf("after recovery = %s streak %d", r.State, r.FailStreak)
	}

	// A paused target-side pair is not a "keeps failing" pair.
	health, err := g.repo.Health(context.Background(), a.tenant, map[string]time.Duration{"resolve.dns": day})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range health {
		if h.Failing != 0 {
			t.Fatalf("%s failing = %d", h.Capability, h.Failing)
		}
	}
}

// A sensor-side failure keeps the back-off, and a target-side streak starts
// at one after it.
func TestAssetCoverage_SensorSideFailureKeepsBackoff(t *testing.T) {
	g := newCycleRig(t)
	a := g.r.newTenant()
	g.scope(a)
	name := g.asset(a, "flaky.tside.test", "subdomain", "", "")
	g.pass(a)
	run := g.f.runs["resolve.dns"].String()
	g.exec(`UPDATE commands SET status = 'failed', error_message = 'sensor lost' WHERE payload->>'scan_run_id' = $1`, run)
	g.exec(`UPDATE scan_runs SET status = 'failed' WHERE id = $1`, run)
	g.pass(a)
	r := g.row(a, name, "resolve.dns")
	if r.State != covdom.StateFailed || r.FailStreak != 1 || time.Until(*r.NextDueAt) > 61*time.Minute {
		t.Fatalf("sensor-side failure = %s streak %d next in %v", r.State, r.FailStreak, time.Until(*r.NextDueAt))
	}
	g.dueIn(a, name, "resolve.dns", -time.Minute)
	g.pass(a)
	g.finishUnreachable("resolve.dns", "flaky.tside.test")
	g.pass(a)
	if r := g.row(a, name, "resolve.dns"); r.State != covdom.StatePaused || r.FailStreak != 1 {
		t.Fatalf("target-side after a sensor failure = %s streak %d, want paused streak 1", r.State, r.FailStreak)
	}
}

// A host that stopped answering stays visible: its pair counts as
// applicable and as unreachable (the input of the "targets unreachable"
// alert), not as a plain gap, so the same pairs never raise two alerts.
func TestAssetCoverage_TargetSidePausedIsUnreachable(t *testing.T) {
	g := newCycleRig(t)
	a := g.r.newTenant()
	g.scope(a)
	name := g.asset(a, "dark.tside.test", "subdomain", "", "")
	day := 24 * time.Hour
	g.pass(a)
	g.finishUnreachable("resolve.dns", "dark.tside.test")
	g.pass(a)
	if r := g.row(a, name, "resolve.dns"); r.State != covdom.StatePaused || r.Reason != "unreachable" {
		t.Fatalf("pair = %s:%s, want paused:unreachable", r.State, r.Reason)
	}
	health := func() covdom.CapabilityHealth {
		t.Helper()
		hs, err := g.repo.Health(context.Background(), a.tenant, map[string]time.Duration{"resolve.dns": day})
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hs {
			if h.Capability == "resolve.dns" {
				return h
			}
		}
		t.Fatal("no resolve.dns health")
		return covdom.CapabilityHealth{}
	}
	if h := health(); h.Applicable != 1 || h.Gaps != 0 || h.Paused != 0 || h.Unreachable != 1 {
		t.Fatalf("fresh dark host: %+v, want applicable 1, unreachable 1, no gap, not readiness-paused", h)
	}
	g.exec(`UPDATE asset_coverage SET last_success_at = now() - interval '3 days', created_at = now() - interval '3 days'
		WHERE tenant_id = $1 AND asset_id = $2 AND capability = 'resolve.dns'`, a.tenant.String(), name.String())
	if h := health(); h.Applicable != 1 || h.Gaps != 0 || h.Unreachable != 1 || h.Failing != 0 {
		t.Fatalf("host dark for 3 days: %+v, want applicable 1, unreachable 1 and no second (gap) count, not failing", h)
	}
	if conds := covdom.Conditions([]covdom.CapabilityHealth{health()}); len(conds) != 1 || conds[0].Kind != covdom.AlertUnreachable {
		t.Fatalf("conditions %+v, want only the unreachable alert", conds)
	}
}

// finishUnreachableFrom is finishUnreachable from the given scan zone.
func (g *cycleRig) finishUnreachableFrom(capability, target string, zone shared.ID) {
	g.t.Helper()
	g.exec(`UPDATE commands SET scan_zone_id = $2 WHERE payload->>'scan_run_id' = $1`, g.f.runs[capability].String(), zone.String())
	g.finishUnreachable(capability, target)
}

// The observer is recorded: the streak (and the widening wait) goes on
// while the same zone sees the target silent, starts over when another
// zone does, and a success clears it. Another tenant's pairs are untouched.
func TestAssetCoverage_UnreachableKeyedByObserver(t *testing.T) {
	g := newCycleRig(t)
	a := g.r.newTenant()
	b := g.r.newTenant()
	g.scope(a)
	g.scope(b)
	name := g.asset(a, "far.tside.test", "subdomain", "", "")
	other := g.asset(b, "far.tside.test", "subdomain", "", "")
	zoneA, zoneB := shared.NewID(), shared.NewID()
	day := 24 * time.Hour
	g.pass(b) // b's pair is queued in its own run; a's runs below never settle it
	from := func() string {
		t.Helper()
		var s string
		if err := g.r.db.QueryRow(`SELECT unreached_from FROM asset_coverage WHERE tenant_id = $1 AND asset_id = $2 AND capability = 'resolve.dns'`,
			a.tenant.String(), name.String()).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	step := func(zone shared.ID, wantStreak int, wantAfter time.Duration) {
		t.Helper()
		g.bindTenant(a)
		g.pass(a)
		g.finishUnreachableFrom("resolve.dns", "far.tside.test", zone)
		g.pass(a)
		r := g.row(a, name, "resolve.dns")
		if r.State != covdom.StatePaused || r.FailStreak != wantStreak || from() != "zone:"+zone.String() {
			t.Fatalf("%s:%s streak %d from %q, want paused streak %d from zone:%s", r.State, r.Reason, r.FailStreak, from(), wantStreak, zone)
		}
		want := covdom.Jittered(wantAfter, name.String(), "resolve.dns")
		if got := time.Until(*r.NextDueAt); got < want-time.Minute || got > want+time.Second {
			t.Fatalf("recheck in %v, want about %v", got, want)
		}
		g.dueIn(a, name, "resolve.dns", -time.Minute)
	}
	step(zoneA, 1, day)
	step(zoneA, 2, 3*day) // same zone: the wait widens
	step(zoneB, 1, day)   // another zone gets the short recheck again
	g.pass(a)
	g.complete("resolve.dns") // it answers: covered, observer cleared
	g.pass(a)
	if r := g.row(a, name, "resolve.dns"); r.State != covdom.StateCovered || from() != "" {
		t.Fatalf("after success: %s from %q", r.State, from())
	}
	if r := g.row(b, other, "resolve.dns"); r.State == covdom.StatePaused {
		t.Fatalf("another tenant's pair was paused: %+v", r)
	}
}

// The asset read names the observer only when it is the tenant's own scan
// zone; another tenant's zone or an unknown (platform) sensor stays unnamed.
func TestAssetCoverage_UnreachedFromNamedForOwnZoneOnly(t *testing.T) {
	g := newCycleRig(t)
	a := g.r.newTenant()
	b := g.r.newTenant()
	g.scope(a)
	name := g.asset(a, "named.tside.test", "subdomain", "", "")
	g.pass(a)
	g.finishUnreachable("resolve.dns", "named.tside.test")
	g.pass(a)
	own, foreign := shared.NewID(), shared.NewID()
	g.exec(`INSERT INTO scan_zones (id, tenant_id, name, ranges) VALUES ($1, $2, 'dmz-own', '{10.9.0.0/16}')`, own, a.tenant)
	g.exec(`INSERT INTO scan_zones (id, tenant_id, name, ranges) VALUES ($1, $2, 'dmz-foreign', '{10.8.0.0/16}')`, foreign, b.tenant)
	read := func(key string) string {
		t.Helper()
		g.exec(`UPDATE asset_coverage SET unreached_from = $3 WHERE tenant_id = $1 AND asset_id = $2 AND capability = 'resolve.dns'`,
			a.tenant, name, key)
		rows, err := g.repo.ListForAsset(context.Background(), a.tenant, name)
		if err != nil {
			t.Fatal(err)
		}
		v := covdom.View(name, covdom.RulesFor("subdomain", ""), rows, time.Now())
		for _, e := range v.Entries {
			if e.Capability == "resolve.dns" {
				return e.UnreachedFrom
			}
		}
		t.Fatal("no resolve.dns entry")
		return ""
	}
	if got := read("zone:" + own.String()); got != "dmz-own" {
		t.Fatalf("own zone named %q", got)
	}
	if got := read("zone:" + foreign.String()); got != "" {
		t.Fatalf("another tenant's zone named %q", got)
	}
	if got := read("sensor:" + shared.NewID().String()); got != "" {
		t.Fatalf("a sensor that is not the tenant's named %q", got)
	}
}
