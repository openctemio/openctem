package integration

// Deep onboarding of new roots (docs/architecture/asset-coverage.md): on a
// migrated database, the first subdomain enumeration of a new root domain
// starts at deep depth, alone; once it settles covered the root's next pass
// is standard (once only, recorded by the ledger); a root whose deep pass
// keeps failing falls back to standard; one tenant's onboarding state never
// changes another's.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	coverageapp "github.com/openctemio/openctem/api/internal/app/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const enumCapability = "enumerate.subdomains"

type onboardingRig struct {
	g *covRig
	f *fakeStarter
	t *testing.T
}

func newOnboardingRig(t *testing.T) *onboardingRig {
	g := newCovRig(t)
	o := &onboardingRig{g: g, t: t}
	o.f = &fakeStarter{t: t, calls: map[string][]string{}, runs: map[string]shared.ID{}, depths: map[string][]string{}}
	o.f.execRun = func(id shared.ID) {}
	g.svc.EnablePlanning(g.repo, o.f, coverageapp.GovernanceSwitch{Modes: &fixedMode{m: scangov.ModeOff}}, coverageapp.Config{})
	return o
}

// tenant seeds a tenant with an active scope entry for the root and its
// names, and the root domain asset.
func (o *onboardingRig) tenant(rootName string) (v2Tenant, shared.ID) {
	tn := o.g.r.newTenant()
	o.g.exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern) VALUES ($1, 'domain', $2), ($1, 'domain', $3)`,
		tn.tenant, rootName, "*."+rootName)
	return tn, o.g.asset(tn, rootName, "domain", "", "")
}

// pass runs one planner pass for the tenant and returns the enumeration
// call it made (targets and depth), if any. Runs are recorded as running
// scan runs with one task carrying their targets.
func (o *onboardingRig) pass(tn v2Tenant) (targets []string, depth string, run shared.ID) {
	o.t.Helper()
	before, beforeDepths := len(o.f.calls[enumCapability]), len(o.f.depths[enumCapability])
	o.f.execRun = func(id shared.ID) {
		o.g.exec(`INSERT INTO scan_runs (id, tenant_id, trigger_type, status, kind) VALUES ($1, $2, 'manual', 'running', 'system')`, id, tn.tenant)
	}
	o.f.execTask = func(id shared.ID, kept []string) {
		tj, _ := json.Marshal(kept)
		o.g.exec(`INSERT INTO commands (id, tenant_id, type, status, payload)
			VALUES ($1, $2, 'scan', 'running', jsonb_build_object('scan_run_id', $3::text, 'targets', $4::jsonb))`,
			shared.NewID(), tn.tenant, id.String(), string(tj))
	}
	if _, err := o.g.svc.RunTenant(context.Background(), tn.tenant); err != nil {
		o.t.Fatal(err)
	}
	if len(o.f.depths[enumCapability]) == beforeDepths {
		return nil, "", shared.ID{}
	}
	return o.f.calls[enumCapability][before:], o.f.depths[enumCapability][beforeDepths], o.f.runs[enumCapability]
}

// finish ends a run: every task and the run complete or fail.
func (o *onboardingRig) finish(run shared.ID, status string) {
	o.t.Helper()
	msg := ""
	if status == "failed" {
		msg = "sensor lost"
	}
	o.g.exec(`UPDATE commands SET status = $2, error_message = NULLIF($3, '') WHERE payload->>'scan_run_id' = $1`, run.String(), status, msg)
	o.g.exec(`UPDATE scan_runs SET status = $2, error_message = NULLIF($3, '') WHERE id = $1`, run, status, msg)
}

// due makes the root's enumeration pair due now (the cadence or back-off
// has passed).
func (o *onboardingRig) due(tn v2Tenant, id shared.ID) {
	o.g.exec(`UPDATE asset_coverage SET next_due_at = now() - interval '1 minute'
		WHERE tenant_id = $1 AND asset_id = $2 AND capability = $3`, tn.tenant, id, enumCapability)
}

func TestAssetCoverage_DeepOnboardingOnceThenStandard(t *testing.T) {
	o := newOnboardingRig(t)
	a, root := o.tenant("onboard.test")
	b, rootB := o.tenant("onboard.test") // the same root in another tenant

	// A root enumerated before (its pair succeeded once) stays steady.
	o.g.exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern) VALUES ($1, 'domain', 'steady.test')`, a.tenant)
	steady := o.g.asset(a, "steady.test", "domain", "", "")
	o.g.exec(`INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, last_success_at, next_due_at)
		VALUES ($1, $2, $3, 'covered', now() - interval '8 days', now() - interval '1 day')`, a.tenant, steady, enumCapability)

	// Pass 1: the new root goes alone at deep depth; the steady root waits.
	targets, depth, run := o.pass(a)
	if depth != "deep" || strings.Join(targets, ",") != "onboard.test" {
		t.Fatalf("first pass = %v at %q, want the new root alone at deep depth", targets, depth)
	}
	if got := o.g.states(a, steady)[enumCapability]; got == "queued:" {
		t.Fatalf("steady root during the deep run = %q, want it left for a later pass", got)
	}

	// Cross-tenant: tenant B's same-named root was not touched by A's pass.
	if got := o.g.states(b, rootB)[enumCapability]; got == "queued:" || got == "covered:" {
		t.Fatalf("tenant B's root changed by tenant A's pass: %q", got)
	}

	// The deep run completes: the root is onboarded.
	o.finish(run, "completed")
	targets, depth, run = o.pass(a)
	if got := o.g.states(a, root)[enumCapability]; got != "covered:" {
		t.Fatalf("new root after its deep run = %q, want covered", got)
	}
	// Pass 2 (same pass, after settling): the steady root at standard.
	if depth != "standard" || strings.Join(targets, ",") != "steady.test" {
		t.Fatalf("second pass = %v at %q, want the steady root at standard", targets, depth)
	}
	o.finish(run, "completed")

	// The onboarded root comes due again: standard, never deep again.
	o.due(a, root)
	targets, depth, run = o.pass(a)
	if depth != "standard" || strings.Join(targets, ",") != "onboard.test" {
		t.Fatalf("onboarded root's next pass = %v at %q, want standard (once only)", targets, depth)
	}
	o.finish(run, "completed")

	// Tenant B still onboards its own root deep: A's state is A's alone.
	targets, depth, _ = o.pass(b)
	if depth != "deep" || strings.Join(targets, ",") != "onboard.test" {
		t.Fatalf("tenant B's first pass = %v at %q, want its root deep", targets, depth)
	}
}

func TestAssetCoverage_DeepOnboardingFallsBackAfterFailures(t *testing.T) {
	o := newOnboardingRig(t)
	c, root := o.tenant("flaky.test")
	for i := range coverageapp.OnboardingDeepAttempts {
		targets, depth, run := o.pass(c)
		if depth != "deep" || strings.Join(targets, ",") != "flaky.test" {
			t.Fatalf("attempt %d = %v at %q, want deep", i+1, targets, depth)
		}
		o.finish(run, "failed")
		// The next pass settles the failure; make the back-off pass.
		if _, err := o.g.svc.RunTenant(context.Background(), c.tenant); err != nil {
			t.Fatal(err)
		}
		if got := o.g.states(c, root)[enumCapability]; !strings.HasPrefix(got, "failed:") {
			t.Fatalf("attempt %d settled as %q, want failed", i+1, got)
		}
		o.due(c, root)
	}
	targets, depth, _ := o.pass(c)
	if depth != "standard" || strings.Join(targets, ",") != "flaky.test" {
		t.Fatalf("after %d failed deep passes = %v at %q, want standard", coverageapp.OnboardingDeepAttempts, targets, depth)
	}
}
