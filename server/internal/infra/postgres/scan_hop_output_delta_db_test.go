package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The run map compares each step's outputs with the previous finished run
// of the same scan, and a step's outputs are previewed new ones first. All
// of it stays in the tenant and, for a member, in their data scope.
func TestScanHops_PreviousRunDeltaAndPreview(t *testing.T) {
	db := openHopDB(t)
	ctx := context.Background()
	repo := NewScanHopRepository(&DB{DB: db})
	a := newHopTenant(t, db, 4) // a.run is the current run: subs produced assets 0..2
	b := newHopTenant(t, db, 1)

	var wf string
	if err := db.QueryRowContext(ctx, `SELECT scan_workflow_id FROM scan_runs WHERE id = $1`, a.run.String()).Scan(&wf); err != nil {
		t.Fatal(err)
	}
	scan := shared.NewID()
	hopExec(t, db, `INSERT INTO scans (id, tenant_id, name, scan_type, scan_workflow_id) VALUES ($1, $2, $3, 'workflow', $4)`,
		scan, a.tenant, "delta "+scan.String(), wf)
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM scans WHERE id = $1`, scan.String()) })
	hopExec(t, db, `UPDATE scan_runs SET scan_id = $1 WHERE id = $2`, scan, a.run)

	// No earlier finished run yet.
	if prev, err := repo.PreviousRun(ctx, a.tenant, a.run); err != nil || !prev.IsZero() {
		t.Fatalf("previous = %s, %v; want none", prev, err)
	}

	// Two earlier runs of the scan: a failed one (ignored) and a completed
	// one whose subs step produced assets 2 and 3.
	addRun := func(status, age string) (shared.ID, shared.ID) {
		run, sr := shared.NewID(), shared.NewID()
		hopExec(t, db, `INSERT INTO scan_runs (id, scan_workflow_id, tenant_id, scan_id, trigger_type, status, created_at)
			VALUES ($1, $2, $3, $4, 'manual', $5, now() - $6::interval)`, run, wf, a.tenant, scan, status, age)
		hopExec(t, db, `INSERT INTO scan_run_steps (id, scan_run_id, step_key, step_order, status) VALUES ($1, $2, 'subs', 1, 'completed')`, sr, run)
		return run, sr
	}
	prevRun, prevStep := addRun("completed", "2 days")
	failedRun, failedStep := addRun("failed", "1 day")
	out := func(run, step, asset shared.ID) {
		hopExec(t, db, `INSERT INTO scan_step_outputs (tenant_id, run_id, scan_run_step_id, asset_id) VALUES ($1, $2, $3, $4)`,
			a.tenant, run, step, asset)
	}
	for _, i := range []int{0, 1, 2} {
		out(a.run, a.stepRun, a.assets[i])
	}
	out(prevRun, prevStep, a.assets[2])
	out(prevRun, prevStep, a.assets[3])
	out(failedRun, failedStep, a.assets[3])
	// Another tenant's outputs never count.
	hopExec(t, db, `INSERT INTO scan_step_outputs (tenant_id, run_id, scan_run_step_id, asset_id) VALUES ($1, $2, $3, $4)`,
		b.tenant, b.run, b.stepRun, b.assets[0])

	prev, err := repo.PreviousRun(ctx, a.tenant, a.run)
	if err != nil || prev != prevRun {
		t.Fatalf("previous = %s, %v; want the completed run %s (not the failed one)", prev, err, prevRun)
	}
	// Cross-tenant: B's id finds no previous run of A's run.
	if p, _ := repo.PreviousRun(ctx, b.tenant, a.run); !p.IsZero() {
		t.Fatal("another tenant found A's previous run")
	}

	deltas, err := repo.CompareStepOutputs(ctx, a.tenant, a.run, prev, nil)
	if err != nil || len(deltas) != 1 {
		t.Fatalf("deltas = %+v, %v", deltas, err)
	}
	if d := deltas[0]; d.StepKey != "subs" || d.Previous != 2 || d.Added != 2 || d.Gone != 1 {
		t.Fatalf("delta = %+v, want previous 2, added 2 (0, 1), gone 1 (3)", d)
	}
	if d, _ := repo.CompareStepOutputs(ctx, b.tenant, a.run, prev, nil); len(d) != 0 {
		t.Fatalf("another tenant compared A's runs: %+v", d)
	}

	got, total, err := repo.PreviewStepOutputs(ctx, a.tenant, a.run, prev, "subs", nil, 10)
	if err != nil || total != 3 || len(got) != 3 {
		t.Fatalf("preview = %+v total %d, %v", got, total, err)
	}
	if !got[0].New || !got[1].New || got[2].New || got[2].AssetID != a.assets[2] {
		t.Fatalf("preview must list the new outputs first, then asset 2: %+v", got)
	}
	if got, total, _ := repo.PreviewStepOutputs(ctx, a.tenant, a.run, prev, "subs", nil, 1); len(got) != 1 || total != 3 {
		t.Fatalf("limited preview = %d of %d", len(got), total)
	}
	if got, _, _ := repo.PreviewStepOutputs(ctx, a.tenant, a.run, shared.ID{}, "subs", nil, 10); len(got) != 3 || got[0].New {
		t.Fatalf("without a previous run nothing is new: %+v", got)
	}
	if got, total, _ := repo.PreviewStepOutputs(ctx, b.tenant, a.run, prev, "subs", nil, 10); len(got) != 0 || total != 0 {
		t.Fatal("another tenant previewed A's outputs")
	}

	// A member who may see asset 0 and asset 3 only.
	user := seedGroupsUser(ctx, t, db, "run-delta.test")
	addTenantMember(ctx, t, db, a.tenant, user)
	for _, i := range []int{0, 3} {
		hopExec(t, db, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
			user, a.tenant, a.assets[i])
	}
	scope := &shared.DataScope{TenantID: a.tenant, UserID: user}
	deltas, _ = repo.CompareStepOutputs(ctx, a.tenant, a.run, prev, scope)
	if len(deltas) != 1 || deltas[0].Previous != 1 || deltas[0].Added != 1 || deltas[0].Gone != 1 {
		t.Fatalf("scoped delta = %+v, want previous 1 (3), added 1 (0), gone 1 (3)", deltas)
	}
	got, total, _ = repo.PreviewStepOutputs(ctx, a.tenant, a.run, prev, "subs", scope, 10)
	if total != 1 || len(got) != 1 || got[0].AssetID != a.assets[0] {
		t.Fatalf("scoped preview = %+v total %d, want asset 0 only", got, total)
	}
}
