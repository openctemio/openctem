package integration

// The info pass of vuln.templates (docs/architecture/asset-coverage.md, "Info
// pass") on a migrated database: its own ledger key next to the regular
// pass, run on the asset's first coverage, then on the organization's
// interval, early when the asset's technologies changed, never when the
// organization turned it off, and per tenant only.

import (
	"context"
	"testing"
	"time"

	coverageapp "github.com/openctemio/openctem/server/internal/app/coverage"
	covdom "github.com/openctemio/openctem/server/pkg/domain/coverage"
	"github.com/openctemio/openctem/server/pkg/domain/scangov"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

const (
	capRegular = "vuln.templates"
	capInfo    = covdom.CapabilityVulnTemplatesInfo
)

// infoPolicies is a per-tenant info pass setting (missing: the default).
type infoPolicies map[shared.ID]covdom.InfoPolicy

func (p infoPolicies) InfoPolicy(_ context.Context, id shared.ID) (covdom.InfoPolicy, error) {
	if v, ok := p[id]; ok {
		return v, nil
	}
	return covdom.DefaultInfoPolicy(), nil
}

func TestAssetCoverage_InfoPass(t *testing.T) {
	g := newCovRig(t)
	ctx := context.Background()
	a, b := g.r.newTenant(), g.r.newTenant()
	day := 24 * time.Hour
	pol := infoPolicies{b.tenant: {On: false, Every: 30 * day}}

	for _, tn := range []v2Tenant{a, b} {
		g.exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern) VALUES ($1, 'domain', '*.test')`, tn.tenant)
	}
	aSvc := g.asset(a, "https://info-a.test", "service", "http", "")
	bSvc := g.asset(b, "https://info-b.test", "service", "http", "")

	f := &fakeStarter{t: t, calls: map[string][]string{}, runs: map[string]shared.ID{}}
	f.execRun = func(id shared.ID) {
		g.exec(`INSERT INTO scan_runs (id, tenant_id, trigger_type, status, kind) VALUES ($1, $2, 'manual', 'running', 'system')`,
			id, a.tenant)
	}
	g.svc.EnablePlanning(g.repo, f, coverageapp.GovernanceSwitch{Modes: fixedMode{m: scangov.ModeOff}}, coverageapp.Config{})
	g.svc.EnableInfoPass(pol)

	// First coverage: both passes, each under its own key.
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	if len(f.calls[capRegular]) != 1 || len(f.calls[capInfo]) != 1 {
		t.Fatalf("states %v; first coverage: regular %v, info %v; want one target each", g.states(a, aSvc), f.calls[capRegular], f.calls[capInfo])
	}
	if s := g.states(a, aSvc); s[capRegular] != "queued:" || s[capInfo] != "queued:" {
		t.Fatalf("states after first pass = %v", s)
	}

	// Off for tenant b: no info row is even created, nothing is planned, the regular pass runs.
	if _, err := g.svc.RunTenant(ctx, b.tenant); err != nil {
		t.Fatal(err)
	}
	if s := g.states(b, bSvc); s[capInfo] != "" {
		t.Fatalf("tenant b has an info row while the pass is off: %q", s[capInfo])
	}
	if len(f.calls[capInfo]) != 1 {
		t.Fatalf("the info pass ran for a tenant that turned it off: %v", f.calls[capInfo])
	}
	if s := g.states(b, bSvc); s[capRegular] != "queued:" {
		t.Fatalf("tenant b regular pass = %q", s[capRegular])
	}

	// The info pass settled 8 days ago, due again in 22: nothing to do at 30 days.
	f.calls = map[string][]string{}
	cover := func(tn v2Tenant, id shared.ID, success, due string) {
		g.exec(`UPDATE asset_coverage SET state = 'covered', reason = '', last_success_at = now() - $4::interval,
			last_attempt_at = now() - $4::interval, next_due_at = now() + $5::interval
			WHERE tenant_id = $1 AND asset_id = $2 AND capability = $3`, tn.tenant, id, capInfo, success, due)
	}
	cover(a, aSvc, "8 days", "22 days")
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	if len(f.calls[capInfo]) != 0 {
		t.Fatalf("info pass ran before its interval: %v", f.calls[capInfo])
	}

	// A shorter interval pulls the next pass in: 8 days ago + 7 days is past.
	pol[a.tenant] = covdom.InfoPolicy{On: true, Every: 7 * day}
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	if len(f.calls[capInfo]) != 1 {
		t.Fatalf("info pass at a 7 day interval: %v", f.calls[capInfo])
	}
	if len(f.calls[capRegular]) != 0 {
		t.Fatalf("the regular pass ran again: %v", f.calls[capRegular])
	}

	// Technologies changed: due early, but only for the tenant that has the event.
	pol[a.tenant] = covdom.DefaultInfoPolicy()
	pol[b.tenant] = covdom.DefaultInfoPolicy()
	f.calls = map[string][]string{}
	cover(a, aSvc, "10 days", "20 days")
	g.exec(`UPDATE asset_coverage SET state = 'covered', reason = '', last_success_at = now() - interval '10 days',
		last_attempt_at = now() - interval '10 days', next_due_at = now() + interval '20 days'
		WHERE tenant_id = $1 AND asset_id = $2 AND capability = $3`, b.tenant, bSvc, capInfo)
	g.exec(`INSERT INTO asset_change_events (id, tenant_id, asset_id, at, attribute, source_kind, reason)
		VALUES ($1, $2, $3, now() - interval '1 day', 'technologies', 'sensor', 'newer_observation')`, shared.NewID(), b.tenant, bSvc)
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	if len(f.calls[capInfo]) != 0 {
		t.Fatalf("tenant a ran the info pass because of tenant b's change: %v", f.calls[capInfo])
	}
	if _, err := g.svc.RunTenant(ctx, b.tenant); err != nil {
		t.Fatal(err)
	}
	if len(f.calls[capInfo]) != 1 || f.calls[capInfo][0] != "https://info-b.test" {
		t.Fatalf("tenant b info pass after a technologies change: %v", f.calls[capInfo])
	}

	// Turned off again: parked, never planned.
	pol[a.tenant] = covdom.InfoPolicy{On: false, Every: 30 * day}
	f.calls = map[string][]string{}
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	if s := g.states(a, aSvc); s[capInfo] != "not_applicable:"+covdom.ReasonInfoPassOff || len(f.calls[capInfo]) != 0 {
		t.Fatalf("off: state %q, calls %v", s[capInfo], f.calls[capInfo])
	}
}
