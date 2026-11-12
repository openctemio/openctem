package integration

// Platform-side failures of continuous coverage (RFC-093) on a migrated
// database: a check that did not run (no task carried the target, the task
// or tool failed) never grows the target's fail streak nor its "keeps
// failing" count; it grows its own platform streak (the back-off and the
// operator's fleet-wide count). Observations of the target (edge answers,
// target-side outcomes) keep their streaks across it. Other organizations'
// pairs are never touched and the fleet count carries no identity.

import (
	"context"
	"testing"
	"time"

	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// notDispatched finishes the capability's last run with no task carrying
// any target (a run no sensor took).
func (g *cycleRig) notDispatched(capability string) {
	g.t.Helper()
	run := g.f.runs[capability].String()
	g.exec(`DELETE FROM commands WHERE payload->>'scan_run_id' = $1`, run)
	g.exec(`UPDATE scan_runs SET status = 'failed', error_message = 'no eligible sensor' WHERE id = $1`, run)
}

// finishClass finishes the capability's last run with the target failed
// with the given class.
func (g *cycleRig) finishClass(capability, target, class string) {
	g.t.Helper()
	run := g.f.runs[capability].String()
	g.exec(`UPDATE commands SET status = 'completed', result = jsonb_build_object('target_outcomes',
		jsonb_build_array(jsonb_build_object('target', $2::text, 'state', 'failed', 'class', $3::text)))
		WHERE payload->>'scan_run_id' = $1`, run, target, class)
	g.exec(`UPDATE scan_runs SET status = 'completed' WHERE id = $1`, run)
}

func (g *cycleRig) health(tn v2Tenant, capability string) covdom.CapabilityHealth {
	g.t.Helper()
	hs, err := g.repo.Health(context.Background(), tn.tenant, map[string]time.Duration{capability: 24 * time.Hour})
	if err != nil {
		g.t.Fatal(err)
	}
	for _, h := range hs {
		if h.Capability == capability {
			return h
		}
	}
	return covdom.CapabilityHealth{Capability: capability}
}

func (g *cycleRig) entry(tn v2Tenant, id shared.ID, capability string) covdom.Entry {
	g.t.Helper()
	rows, err := g.repo.ListForAsset(context.Background(), tn.tenant, id)
	if err != nil {
		g.t.Fatal(err)
	}
	for _, e := range covdom.View(id, covdom.RulesFor("subdomain", ""), rows, time.Now()).Entries {
		if e.Capability == capability {
			return e
		}
	}
	g.t.Fatalf("no %s entry", capability)
	return covdom.Entry{}
}

func TestAssetCoverage_PlatformSideFailuresAreNotTheTargets(t *testing.T) {
	g := newCycleRig(t)
	a := g.r.newTenant()
	b := g.r.newTenant()
	g.scope(a)
	g.scope(b)
	name := g.asset(a, "quiet.pside.test", "subdomain", "", "")
	other := g.asset(b, "quiet.pside.test", "subdomain", "", "")
	const capability = "resolve.dns"

	// Tenant b's pair is queued in its own run; a's runs never settle it.
	g.pass(b)
	g.pass(a)
	// Five runs in a row that no sensor took.
	for i := 1; i <= 5; i++ {
		g.notDispatched(capability)
		g.pass(a)
		r := g.row(a, name, capability)
		if r.State != covdom.StateFailed || r.LastOutcome != covdom.OutcomeNotDispatched || r.FailStreak != 0 || r.PlatformFailStreak != i {
			t.Fatalf("run %d: %s/%s streak %d platform %d", i, r.State, r.LastOutcome, r.FailStreak, r.PlatformFailStreak)
		}
		// Back-off on the platform streak: 1 h, 2 h, 4 h, ...
		want := time.Hour << (i - 1)
		if got := time.Until(*r.NextDueAt); got < want-time.Minute || got > want+time.Minute {
			t.Fatalf("run %d: next in %v, want about %v", i, got, want)
		}
		if i < 5 {
			g.dueIn(a, name, capability, -time.Minute)
			g.pass(a)
		}
	}
	if h := g.health(a, capability); h.Failing != 0 {
		t.Fatalf("platform-side failures counted as failing: %+v", h)
	}
	if e := g.entry(a, name, capability); !e.PlatformSide || e.FailStreak != 0 {
		t.Fatalf("asset entry %+v, want platform_side and no fail streak", e)
	}
	if conds := covdom.Conditions([]covdom.CapabilityHealth{g.health(a, capability)}); hasKind(conds, covdom.AlertFailing) {
		t.Fatalf("conditions %+v raise a failing alert", conds)
	}

	// The fleet-wide operator count: counts only, this tenant's pair in it.
	counts, err := g.repo.PlatformFailures(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range counts {
		if c.Capability == capability && c.Outcome == covdom.OutcomeNotDispatched && c.Pairs >= 1 && c.Tenants >= 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("platform failures %+v miss the not-dispatched pair", counts)
	}

	// Edge answers are observations of the target: they count, three in a
	// row raise failing, and they reset the platform streak.
	g.dueIn(a, name, capability, -time.Minute)
	g.pass(a)
	for i := 1; i <= 3; i++ {
		g.finishClass(capability, "quiet.pside.test", "edge_blocked")
		g.pass(a)
		r := g.row(a, name, capability)
		if r.State != covdom.StateFailed || r.FailStreak != i || r.PlatformFailStreak != 0 {
			t.Fatalf("edge %d: %s streak %d platform %d", i, r.State, r.FailStreak, r.PlatformFailStreak)
		}
		g.dueIn(a, name, capability, -time.Minute)
		g.pass(a)
	}
	// A platform-side failure in between keeps the target's streak.
	g.notDispatched(capability)
	g.pass(a)
	if r := g.row(a, name, capability); r.FailStreak != 3 || r.PlatformFailStreak != 1 {
		t.Fatalf("platform failure after edge answers: streak %d platform %d, want 3 and 1", r.FailStreak, r.PlatformFailStreak)
	}
	if h := g.health(a, capability); h.Failing != 0 {
		t.Fatalf("last outcome platform side but counted failing: %+v", h)
	}
	g.dueIn(a, name, capability, -time.Minute)
	g.pass(a)
	g.finishClass(capability, "quiet.pside.test", "edge_blocked")
	g.pass(a)
	if r := g.row(a, name, capability); r.FailStreak != 4 || r.PlatformFailStreak != 0 {
		t.Fatalf("edge after a platform failure: streak %d platform %d, want 4 and 0", r.FailStreak, r.PlatformFailStreak)
	}
	if h := g.health(a, capability); h.Failing != 1 {
		t.Fatalf("edge-blocked pair not failing: %+v", h)
	}
	if e := g.entry(a, name, capability); e.PlatformSide {
		t.Fatalf("edge-blocked entry marked platform side: %+v", e)
	}

	// Tenant isolation: b's pair is still queued from its own run, never
	// settled by a's runs; b's health counts nothing failing.
	if r := g.row(b, other, capability); r.State != covdom.StateQueued || r.FailStreak != 0 || r.PlatformFailStreak != 0 {
		t.Fatalf("another tenant's pair was touched: %+v", r)
	}
	if h := g.health(b, capability); h.Failing != 0 {
		t.Fatalf("another tenant's health counts a's failures: %+v", h)
	}
}

// A platform-side failure between two target-side observations from the
// same scan zone neither breaks nor grows the target-side streak.
func TestAssetCoverage_PlatformFailureKeepsTargetSideStreak(t *testing.T) {
	g := newCycleRig(t)
	a := g.r.newTenant()
	g.scope(a)
	name := g.asset(a, "dim.pside.test", "subdomain", "", "")
	zone := shared.NewID()
	const capability = "resolve.dns"
	day := 24 * time.Hour

	g.pass(a)
	g.finishUnreachableFrom(capability, "dim.pside.test", zone)
	g.pass(a)
	if r := g.row(a, name, capability); r.State != covdom.StatePaused || r.FailStreak != 1 {
		t.Fatalf("first observation: %s streak %d", r.State, r.FailStreak)
	}
	g.dueIn(a, name, capability, -time.Minute)
	g.pass(a)
	g.notDispatched(capability)
	g.pass(a)
	if r := g.row(a, name, capability); r.State != covdom.StateFailed || r.FailStreak != 1 || r.PlatformFailStreak != 1 {
		t.Fatalf("platform failure: %s streak %d platform %d", r.State, r.FailStreak, r.PlatformFailStreak)
	}
	if h := g.health(a, capability); h.Failing != 0 || h.Unreachable != 0 {
		t.Fatalf("health after a platform failure: %+v", h)
	}
	g.dueIn(a, name, capability, -time.Minute)
	g.pass(a)
	g.finishUnreachableFrom(capability, "dim.pside.test", zone)
	g.pass(a)
	r := g.row(a, name, capability)
	if r.State != covdom.StatePaused || r.FailStreak != 2 || r.PlatformFailStreak != 0 {
		t.Fatalf("second observation: %s streak %d platform %d, want paused streak 2", r.State, r.FailStreak, r.PlatformFailStreak)
	}
	want := covdom.Jittered(3*day, name.String(), capability)
	if got := time.Until(*r.NextDueAt); got < want-time.Minute || got > want+time.Second {
		t.Fatalf("recheck in %v, want about %v", got, want)
	}
}

func hasKind(conds []covdom.AlertCondition, kind string) bool {
	for _, c := range conds {
		if c.Kind == kind {
			return true
		}
	}
	return false
}
