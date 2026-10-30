package integration

// The coverage batch rule (research/331 D3, RFC-093): a due batch starts
// when it fills one task of the capability's tool, or when its oldest pair
// has waited a tenth of the cadence (at most 6 h). Until then it stays due
// and collects the pairs that fall due meanwhile.

import (
	"context"
	"fmt"
	"testing"

	coverageapp "github.com/openctemio/openctem/api/internal/app/coverage"
	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func newBatchingRig(t *testing.T) (*covRig, v2Tenant, *fakeStarter) {
	t.Helper()
	g := newCovRig(t)
	a := g.r.newTenant()
	g.exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern) VALUES ($1, 'domain', '*.batch.test')`, a.tenant)
	f := &fakeStarter{t: t, calls: map[string][]string{}, runs: map[string]shared.ID{}}
	f.execRun = func(id shared.ID) {
		g.exec(`INSERT INTO scan_runs (id, tenant_id, trigger_type, status, kind) VALUES ($1, $2, 'manual', 'running', 'system')`, id, a.tenant)
	}
	g.svc.EnablePlanning(g.repo, f, coverageapp.GovernanceSwitch{Modes: fixedMode{m: scangov.ModeOff}},
		coverageapp.Config{FillBatches: true})
	return g, a, f
}

func TestAssetCoverage_SmallBatchWaitsForTheBound(t *testing.T) {
	g, a, f := newBatchingRig(t)
	ctx := context.Background()
	for i := range 3 {
		g.asset(a, fmt.Sprintf("n%d.batch.test", i), "subdomain", "", "")
	}
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	if n := len(f.calls["resolve.dns"]); n != 0 {
		t.Fatalf("3 fresh pairs started a run of %d targets; want the batch to wait", n)
	}
	var due int
	if err := g.r.db.QueryRow(`SELECT count(*) FROM asset_coverage WHERE tenant_id = $1 AND capability = 'resolve.dns' AND state = 'due'`,
		a.tenant.String()).Scan(&due); err != nil {
		t.Fatal(err)
	}
	if due != 3 {
		t.Fatalf("held pairs: %d due, want 3 (held, not blocked or paused)", due)
	}

	// Daily DNS: the bound is a tenth of a day. Once the oldest pair has
	// waited that long, the batch goes with every pair it has.
	g.exec(`UPDATE asset_coverage SET next_due_at = now() - interval '2 hours 30 minutes'
		WHERE tenant_id = $1 AND capability = 'resolve.dns' AND asset_id = (
			SELECT asset_id FROM asset_coverage WHERE tenant_id = $1 AND capability = 'resolve.dns' ORDER BY asset_id LIMIT 1)`, a.tenant)
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	if n := len(f.calls["resolve.dns"]); n != 3 {
		t.Fatalf("after the bound the run carried %d targets, want 3", n)
	}
}

func TestAssetCoverage_BatchThatFillsATaskStartsAtOnce(t *testing.T) {
	g, a, f := newBatchingRig(t)
	ctx := context.Background()
	chunk := scanapp.CoverageChunkSize("resolve.dns")
	if chunk < 2 {
		t.Fatalf("resolve.dns chunk size %d; the test needs a list tool", chunk)
	}
	for i := range chunk {
		g.asset(a, fmt.Sprintf("f%d.batch.test", i), "subdomain", "", "")
	}
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	if n := len(f.calls["resolve.dns"]); n != chunk {
		t.Fatalf("a batch of %d (one full task) started %d targets, want all at once", chunk, n)
	}
}

// Without FillBatches (the default of the planner's Config) a single due
// pair starts at once, as before.
func TestAssetCoverage_WithoutFillBatchesStartsAtOnce(t *testing.T) {
	g := newCovRig(t)
	ctx := context.Background()
	a := g.r.newTenant()
	g.exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern) VALUES ($1, 'domain', '*.batch.test')`, a.tenant)
	f := &fakeStarter{t: t, calls: map[string][]string{}, runs: map[string]shared.ID{}}
	f.execRun = func(id shared.ID) {
		g.exec(`INSERT INTO scan_runs (id, tenant_id, trigger_type, status, kind) VALUES ($1, $2, 'manual', 'running', 'system')`, id, a.tenant)
	}
	g.svc.EnablePlanning(g.repo, f, coverageapp.GovernanceSwitch{Modes: fixedMode{m: scangov.ModeOff}}, coverageapp.Config{})
	g.asset(a, "one.batch.test", "subdomain", "", "")
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	if n := len(f.calls["resolve.dns"]); n != 1 {
		t.Fatalf("started %d targets, want 1", n)
	}
}
