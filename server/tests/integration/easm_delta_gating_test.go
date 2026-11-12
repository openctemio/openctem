package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The delta baseline on a real database: an asset is done only when it is
// old, unchanged since the previous run, and that run's completed step
// planned it (or the coverage ledger says covered and not due). A partial
// baseline step is never done, a change event makes the asset due, and
// another tenant's rows never count.
func TestDeltaBaseline_UnchangedSince(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	tenantA := createTestTenant(t, db, "delta-a")
	tenantB := createTestTenant(t, db, "delta-b")
	t.Cleanup(func() {
		for _, tn := range []shared.ID{tenantA, tenantB} {
			_, _ = db.Exec(`DELETE FROM scan_runs WHERE tenant_id=$1`, tn.String())
			_, _ = db.Exec(`DELETE FROM assets WHERE tenant_id=$1`, tn.String())
			_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tn.String())
		}
	})
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	old := time.Now().Add(-48 * time.Hour)
	asset := func(tn shared.ID, name string, firstSeen time.Time) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, first_seen) VALUES ($1, $2, $3, 'subdomain', $4)`, id.String(), tn.String(), name, firstSeen)
		return id
	}
	run := func(tn shared.ID, started time.Time, stepStatus string, planned ...shared.ID) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO scan_runs (id, tenant_id, trigger_type, status, kind, started_at) VALUES ($1, $2, 'manual', 'completed', 'system', $3)`, id.String(), tn.String(), started)
		exec(`INSERT INTO scan_run_steps (id, scan_run_id, step_key, step_order, status) VALUES ($1, $2, 'templates', 1, $3)`, shared.NewID().String(), id.String(), stepStatus)
		for _, a := range planned {
			exec(`INSERT INTO scan_run_targets (tenant_id, run_id, stage_key, target_key, asset_id, origin, decision) VALUES ($1, $2, 'templates', $3, $4, 'derived', 'planned')`,
				tn.String(), id.String(), a.String()+".acme.com", a.String())
		}
		return id
	}

	unchanged := asset(tenantA, "same.acme.com", old)
	changed := asset(tenantA, "changed.acme.com", old)
	newer := asset(tenantA, "new.acme.com", time.Now())
	notPlanned := asset(tenantA, "skipped.acme.com", old)
	ledger := asset(tenantA, "ledger.acme.com", old)
	baseStart := time.Now().Add(-24 * time.Hour)
	prev := run(tenantA, baseStart, "completed", unchanged, changed, newer)
	exec(`INSERT INTO asset_change_events (id, tenant_id, asset_id, at, attribute, source_kind, reason) VALUES ($1, $2, $3, now(), 'title', 'scan', 'newer_observation')`,
		shared.NewID().String(), tenantA.String(), changed.String())
	exec(`INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, next_due_at) VALUES ($1, $2, 'vuln.templates', 'covered', now() + interval '1 day')`,
		tenantA.String(), ledger.String())

	repo := postgres.NewScanHopRepository(&postgres.DB{DB: db})
	all := []shared.ID{unchanged, changed, newer, notPlanned, ledger}
	done, err := repo.UnchangedSince(ctx, tenantA, prev, "templates", "vuln.templates", all, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	want := map[shared.ID]bool{unchanged: true, ledger: true}
	if len(done) != len(want) || !done[unchanged] || !done[ledger] {
		t.Fatalf("done = %v, want only the unchanged and the ledger-covered asset", done)
	}

	// The baseline is older than the stage's max age: only the ledger counts.
	done, _ = repo.UnchangedSince(ctx, tenantA, prev, "templates", "vuln.templates", all, time.Hour)
	if done[unchanged] || !done[ledger] {
		t.Fatalf("max age: done = %v", done)
	}

	// A partial baseline step is never done.
	partial := run(tenantA, baseStart, "partial", unchanged)
	if done, _ := repo.UnchangedSince(ctx, tenantA, partial, "templates", "vuln.templates", []shared.ID{unchanged}, 7*24*time.Hour); done[unchanged] {
		t.Fatal("a partial step's target counted as done")
	}

	// Cross-tenant: tenant B asking with tenant A's run and assets gets
	// nothing; tenant B's own run does not make tenant A's asset done.
	if done, _ := repo.UnchangedSince(ctx, tenantB, prev, "templates", "vuln.templates", all, 7*24*time.Hour); len(done) != 0 {
		t.Fatalf("tenant B read tenant A's baseline: %v", done)
	}
	prevB := run(tenantB, baseStart, "completed")
	// The database refuses a run target of tenant B naming tenant A's asset.
	if _, err := db.ExecContext(ctx, `INSERT INTO scan_run_targets (tenant_id, run_id, stage_key, target_key, asset_id, origin, decision) VALUES ($1, $2, 'templates', 'x.acme.com', $3, 'derived', 'planned')`,
		tenantB.String(), prevB.String(), notPlanned.String()); err == nil {
		t.Fatal("a cross-tenant run target was stored")
	}
	if done, _ := repo.UnchangedSince(ctx, tenantA, prevB, "templates", "vuln.templates", []shared.ID{notPlanned}, 7*24*time.Hour); len(done) != 0 {
		t.Fatalf("tenant B's run made tenant A's asset done: %v", done)
	}
}
