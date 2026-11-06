package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// research/122: a run's deadline is a policy cap and records which policy
// set it. A scan without a max duration (NULL) gets the workflow's timeout
// or the platform's 24 h cap, never a silent 1 h default.
func TestRunDeadline_ReasonFollowsThePolicy(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	tenant := seedScanTriggerTenant(ctx, t, db)
	runs := NewScanRunRepository(&DB{DB: db})

	newWorkflow := func(settings string) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO scan_workflows (id, tenant_id, name, settings) VALUES ($1, $2, $3, $4::jsonb)`,
			id.String(), tenant.String(), "policy "+id.String(), settings); err != nil {
			t.Fatal(err)
		}
		return id
	}
	newScan := func(wf shared.ID, timeout sql.NullInt64) *shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO scans (id, tenant_id, name, scan_type, scan_workflow_id, timeout_seconds) VALUES ($1, $2, $3, 'workflow', $4, $5)`,
			id.String(), tenant.String(), "policy scan "+id.String(), wf.String(), timeout); err != nil {
			t.Fatal(err)
		}
		return &id
	}
	check := func(name string, wf shared.ID, scanID *shared.ID, wantAfter time.Duration, wantReason string) {
		t.Helper()
		run, err := scanrun.NewRun(wf, tenant, nil, scanworkflow.TriggerTypeManual, "", map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		run.ScanID = scanID
		run.Start()
		if err := runs.Create(ctx, run); err != nil {
			t.Fatal(err)
		}
		got, err := runs.GetByTenantAndID(ctx, tenant, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.DeadlineAt == nil || got.StartedAt == nil {
			t.Fatalf("%s: no deadline", name)
		}
		if after := got.DeadlineAt.Sub(*got.StartedAt).Round(time.Second); after != wantAfter {
			t.Errorf("%s: deadline after %s, want %s", name, after, wantAfter)
		}
		if got.DeadlineReason != wantReason {
			t.Errorf("%s: reason %q, want %q", name, got.DeadlineReason, wantReason)
		}
	}

	none := newWorkflow(`{}`)
	check("no scan, no workflow timeout", none, nil, AbsoluteRunTimeoutSeconds*time.Second, scanrun.DeadlineReasonPlatformCap)
	check("scan without max duration", none, newScan(none, sql.NullInt64{}), AbsoluteRunTimeoutSeconds*time.Second, scanrun.DeadlineReasonPlatformCap)
	wf := newWorkflow(`{"timeout_seconds": 600}`)
	check("workflow timeout", wf, newScan(wf, sql.NullInt64{}), 600*time.Second, scanrun.DeadlineReasonWorkflowMaxDuration)
	check("scan max duration wins", wf, newScan(wf, sql.NullInt64{Int64: 1200, Valid: true}), 1200*time.Second, scanrun.DeadlineReasonScanMaxDuration)

	// A run started later through Update gets its deadline and reason then.
	run, err := scanrun.NewRun(none, tenant, nil, scanworkflow.TriggerTypeManual, "", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if err := runs.Create(ctx, run); err != nil {
		t.Fatal(err)
	}
	run.Start()
	if err := runs.Update(ctx, run); err != nil {
		t.Fatal(err)
	}
	got, err := runs.GetByTenantAndID(ctx, tenant, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeadlineAt == nil || got.DeadlineReason != scanrun.DeadlineReasonPlatformCap {
		t.Errorf("started via Update: deadline %v reason %q", got.DeadlineAt, got.DeadlineReason)
	}
}

// A scan's max duration is optional: 0 is stored as NULL and read back as 0.
func TestScanMaxDuration_ZeroIsNone(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	tenant := seedScanTriggerTenant(ctx, t, db)
	repo := NewScanRepository(&DB{DB: db})

	sc, err := scan.NewScanWithTargets(tenant, "no max "+shared.NewID().String(), []string{"example.com"}, scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	sc.ScannerName = "nuclei"
	if sc.TimeoutSeconds != 0 {
		t.Fatalf("a new scan has max duration %d, want none", sc.TimeoutSeconds)
	}
	if err := repo.Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	var stored sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT timeout_seconds FROM scans WHERE id = $1`, sc.ID.String()).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored.Valid {
		t.Fatalf("stored timeout_seconds = %d, want NULL", stored.Int64)
	}
	got, err := repo.GetByTenantAndID(ctx, tenant, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TimeoutSeconds != 0 {
		t.Fatalf("read back %d, want 0", got.TimeoutSeconds)
	}

	got.SetTimeoutSeconds(7200)
	if err := repo.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT timeout_seconds FROM scans WHERE id = $1`, sc.ID.String()).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !stored.Valid || stored.Int64 != 7200 {
		t.Fatalf("stored %v, want 7200", stored)
	}
}

// AddUnfinishedTargets appends in order, deduplicated, only to an open run of
// the tenant; the reaper then keeps them and adds its own.
func TestAddUnfinishedTargets_MergesAndIsTenantScoped(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	tenant := seedScanTriggerTenant(ctx, t, db)
	other := seedScanTriggerTenant(ctx, t, db)
	runs := NewScanRunRepository(&DB{DB: db})

	wf := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO scan_workflows (id, tenant_id, name, settings) VALUES ($1, $2, $3, '{}'::jsonb)`,
		wf.String(), tenant.String(), "unfinished "+wf.String()); err != nil {
		t.Fatal(err)
	}
	run, err := scanrun.NewRun(wf, tenant, nil, scanworkflow.TriggerTypeManual, "", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	run.Start()
	if err := runs.Create(ctx, run); err != nil {
		t.Fatal(err)
	}

	if err := runs.AddUnfinishedTargets(ctx, tenant, run.ID, []string{"a.example", "b.example", ""}); err != nil {
		t.Fatal(err)
	}
	if err := runs.AddUnfinishedTargets(ctx, tenant, run.ID, []string{"b.example", "c.example"}); err != nil {
		t.Fatal(err)
	}
	// Another tenant cannot write to this run.
	if err := runs.AddUnfinishedTargets(ctx, other, run.ID, []string{"evil.example"}); err != nil {
		t.Fatal(err)
	}
	got, err := runs.GetUnfinishedTargets(ctx, tenant, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.example", "b.example", "c.example"}
	if len(got) != len(want) {
		t.Fatalf("unfinished = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unfinished = %v, want %v", got, want)
		}
	}

	// The reaper keeps what was recorded before it.
	if _, err := db.ExecContext(ctx, `UPDATE scan_runs SET deadline_at = NOW() - interval '1 minute' WHERE id = $1`, run.ID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := runs.MarkTimedOutRuns(ctx); err != nil {
		t.Fatal(err)
	}
	got, err = runs.GetUnfinishedTargets(ctx, tenant, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != "a.example" {
		t.Fatalf("after the reaper: unfinished = %v, want the 3 recorded targets", got)
	}

	// A settled run is not touched.
	if err := runs.AddUnfinishedTargets(ctx, tenant, run.ID, []string{"late.example"}); err != nil {
		t.Fatal(err)
	}
	got, _ = runs.GetUnfinishedTargets(ctx, tenant, run.ID)
	for _, g := range got {
		if g == "late.example" {
			t.Fatalf("a settled run got a new unfinished target: %v", got)
		}
	}
}
