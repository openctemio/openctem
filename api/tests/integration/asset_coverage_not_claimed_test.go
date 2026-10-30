package integration

// The not_claimed pause (RFC-093): coverage runs that no sensor takes
// (NO_SENSOR) three times in a row pause the capability instead of being
// started again every back-off; a change of the tenant's sensor fleet or
// the probe time lets one run through, and a run a sensor takes lifts the
// hold. The fleet fingerprint ignores heartbeats and another tenant.

import (
	"context"
	"testing"
	"time"

	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
)

// unclaimed ends the capability's last run as no sensor took it: its task
// failed, the run failed and a step NO_SENSOR, as the unclaimed reaper does.
func (g *cycleRig) unclaimed(capability string) {
	g.t.Helper()
	run := g.f.runs[capability]
	g.exec(`UPDATE commands SET status = 'failed', error_message = 'no sensor picked up this run''s work within 1h'
		WHERE payload->>'scan_run_id' = $1`, run.String())
	g.exec(`UPDATE scan_runs SET status = 'failed', error_message = 'no sensor picked up this run''s work within 1h' WHERE id = $1`, run)
	g.exec(`INSERT INTO scan_run_steps (scan_run_id, step_key, step_order, status, error_code)
		VALUES ($1, 'coverage', 1, 'failed', 'NO_SENSOR')`, run)
}

func (g *cycleRig) hold(tn v2Tenant, capability string) covdom.Hold {
	g.t.Helper()
	hs, err := g.repo.Holds(context.Background(), tn.tenant)
	if err != nil {
		g.t.Fatal(err)
	}
	return hs[capability]
}

func TestAssetCoverage_NotClaimedPausesAndResumes(t *testing.T) {
	const capability = "resolve.dns"
	g := newCycleRig(t)
	a := g.r.newTenant()
	g.scope(a)
	name := g.asset(a, "www.nc.test", "subdomain", "", "")

	// Three runs in a row that no sensor takes.
	for i := 1; i <= covdom.NotClaimedStreak; i++ {
		if got := g.pass(a)[capability]; len(got) != 1 {
			t.Fatalf("run %d: started %v, want the pair", i, got)
		}
		g.unclaimed(capability)
		g.pass(a) // settles it
		if h := g.hold(a, capability); h.Streak != i {
			t.Fatalf("after run %d streak = %d", i, h.Streak)
		}
		if i < covdom.NotClaimedStreak {
			if r := g.row(a, name, capability); r.State != covdom.StateFailed {
				t.Fatalf("after run %d state = %s, want failed (back-off)", i, r.State)
			}
			g.dueIn(a, name, capability, -time.Minute)
		}
	}
	r := g.row(a, name, capability)
	if r.State != covdom.StatePaused || r.Reason != covdom.ReadyNotClaimed {
		t.Fatalf("after %d unclaimed runs: %s/%s, want paused/not_claimed", covdom.NotClaimedStreak, r.State, r.Reason)
	}
	h := g.hold(a, capability)
	if h.Fingerprint == "" || h.ProbeAt == nil || time.Until(*h.ProbeAt) < 90*time.Minute {
		t.Fatalf("hold %+v, want a fingerprint and a probe about 2h away", h)
	}

	// Paused: nothing starts, even when the pair's time has come again.
	g.dueIn(a, name, capability, -time.Minute)
	if got := g.pass(a)[capability]; len(got) != 0 {
		t.Fatalf("a held capability started %v", got)
	}

	// The fleet changes (a grant is widened): one run goes.
	g.exec(`UPDATE sensor_grants SET version = version + 1 WHERE tenant_id = $1`, a.tenant)
	if got := g.pass(a)[capability]; len(got) != 1 {
		t.Fatalf("after a grant change started %v, want the pair", got)
	}
	// It is not claimed either: paused again with a doubled wait.
	g.unclaimed(capability)
	g.pass(a)
	h = g.hold(a, capability)
	if h.Streak != covdom.NotClaimedStreak+1 || h.ProbeAt == nil || time.Until(*h.ProbeAt) < 3*time.Hour+30*time.Minute {
		t.Fatalf("hold %+v, want streak %d and a probe about 4h away", h, covdom.NotClaimedStreak+1)
	}
	if r := g.row(a, name, capability); r.State != covdom.StatePaused || r.Reason != covdom.ReadyNotClaimed {
		t.Fatalf("after the failed retry: %s/%s", r.State, r.Reason)
	}

	// The probe time comes: one run goes; a sensor takes it and the hold
	// lifts.
	g.exec(`UPDATE asset_coverage_holds SET probe_at = now() - interval '1 minute' WHERE tenant_id = $1`, a.tenant)
	if got := g.pass(a)[capability]; len(got) != 1 {
		t.Fatalf("at the probe started %v, want the pair", got)
	}
	g.complete(capability)
	g.pass(a)
	if h := g.hold(a, capability); h.Streak != 0 || h.Active() {
		t.Fatalf("after a claimed run hold = %+v, want reset", h)
	}
	if r := g.row(a, name, capability); r.State != covdom.StateCovered {
		t.Fatalf("after a claimed run state = %s", r.State)
	}
}

// The alert that a capability is paused carries the not_claimed reason.
func TestAssetCoverage_NotClaimedHealthAndCondition(t *testing.T) {
	g := newCycleRig(t)
	a := g.r.newTenant()
	g.scope(a)
	name := g.asset(a, "api.nc.test", "subdomain", "", "")
	if _, _, err := g.repo.Reconcile(context.Background(), a.tenant, covdom.Rules()); err != nil {
		t.Fatal(err)
	}
	if _, err := g.repo.HoldCapability(context.Background(), a.tenant, "resolve.dns", "fp", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r := g.row(a, name, "resolve.dns"); r.State != covdom.StatePaused || r.Reason != covdom.ReadyNotClaimed {
		t.Fatalf("held due pair: %s/%s", r.State, r.Reason)
	}
	health, err := g.repo.Health(context.Background(), a.tenant, map[string]time.Duration{"resolve.dns": time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range covdom.Conditions(health) {
		if c.Capability == "resolve.dns" && c.Kind == covdom.AlertReadiness && c.Reason == covdom.ReadyNotClaimed && c.Count == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("no not_claimed readiness condition in %+v", covdom.Conditions(health))
	}
}

// The fingerprint changes with what decides a claim (a grant, a new
// sensor, a zone assignment, the shared-fleet setting), not with
// heartbeats, and never with another tenant's fleet. Holds are tenant
// rows.
func TestAssetCoverage_FleetFingerprint(t *testing.T) {
	g := newCycleRig(t)
	ctx := context.Background()
	a, b := g.r.newTenant(), g.r.newTenant()
	fp := func() string {
		t.Helper()
		s, err := g.repo.FleetFingerprint(ctx, a.tenant)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	base := fp()
	g.exec(`UPDATE sensors SET last_seen_at = now(), load_reported_at = now(), metrics_updated_at = now(), updated_at = now() WHERE id = $1`, a.sensor)
	if fp() != base {
		t.Fatal("a heartbeat changed the fingerprint")
	}
	// Another tenant's sensor and grant change: not this tenant's fleet.
	g.exec(`UPDATE sensor_grants SET version = version + 5 WHERE tenant_id = $1`, b.tenant)
	g.exec(`UPDATE sensors SET status = 'disabled' WHERE id = $1`, b.sensor)
	if fp() != base {
		t.Fatal("another tenant's fleet changed this tenant's fingerprint")
	}
	g.exec(`UPDATE sensor_grants SET version = version + 1 WHERE tenant_id = $1`, a.tenant)
	afterGrant := fp()
	if afterGrant == base {
		t.Fatal("a grant change did not change the fingerprint")
	}
	g.exec(`INSERT INTO sensors (tenant_id, name, status, api_key_hash, api_key_prefix) VALUES ($1, 'second', 'active', md5(random()::text), 'k2')`, a.tenant)
	if fp() == afterGrant {
		t.Fatal("a new sensor did not change the fingerprint")
	}
	afterSensor := fp()
	g.exec(`UPDATE tenants SET shared_sensors_access = 'allow' WHERE id = $1`, a.tenant)
	if fp() == afterSensor {
		t.Fatal("the shared-fleet setting did not change the fingerprint")
	}

	// Holds: one tenant's streak is not another's.
	if _, err := g.repo.RecordRunClaim(ctx, a.tenant, "resolve.dns", true); err != nil {
		t.Fatal(err)
	}
	if hs, err := g.repo.Holds(ctx, b.tenant); err != nil || len(hs) != 0 {
		t.Fatalf("tenant b holds %v (%v), want none", hs, err)
	}
	if n, err := g.repo.RecordRunClaim(ctx, a.tenant, "resolve.dns", true); err != nil || n != 2 {
		t.Fatalf("streak %d (%v), want 2", n, err)
	}
	if n, err := g.repo.RecordRunClaim(ctx, a.tenant, "resolve.dns", false); err != nil || n != 0 {
		t.Fatalf("a claimed run left streak %d (%v)", n, err)
	}
}
