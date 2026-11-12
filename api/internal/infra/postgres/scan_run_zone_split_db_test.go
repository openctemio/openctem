package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A workflow run split over scan zones (zone_split.go): the parent settles
// from its children, only within its own tenant, the scan's summary counts
// the parent alone, and children never use the scan's concurrency slots.
// Against the real SQL.

func seedSplitRun(ctx context.Context, t *testing.T, repo *ScanRunRepository, tenant, scan shared.ID, parent *shared.ID) *scanrun.Run {
	t.Helper()
	tpl, _ := shared.IDFromString(quickScanTemplate)
	run, err := scanrun.NewRun(tpl, tenant, nil, scanworkflow.TriggerTypeManual, "", map[string]any{})
	if err != nil {
		t.Fatalf("new run: %v", err)
	}
	run.ScanID = &scan
	run.ParentRunID = parent
	run.Start()
	if err := repo.CreateRunIfUnderLimit(ctx, run, 1, 1000); err != nil {
		t.Fatalf("create run: %v", err)
	}
	if err := repo.Update(ctx, run); err != nil {
		t.Fatalf("start run: %v", err)
	}
	return run
}

func finishSplitRun(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID, status string, findings int) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `UPDATE scan_runs SET status = $2, total_findings = $3, completed_at = NOW() WHERE id = $1`,
		id.String(), status, findings); err != nil {
		t.Fatalf("finish run: %v", err)
	}
}

func splitRunStatus(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) (string, int) {
	t.Helper()
	var st string
	var n int
	if err := db.QueryRowContext(ctx, `SELECT status, total_findings FROM scan_runs WHERE id = $1`, id.String()).Scan(&st, &n); err != nil {
		t.Fatalf("read run: %v", err)
	}
	return st, n
}

func TestZoneSplit_ParentSettlesFromChildren(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRunRepository(&DB{DB: db})
	tenant, scan := seedCounterScan(ctx, t, db)
	other, _ := seedCounterScan(ctx, t, db)

	// The per-scan limit is 1: the parent takes it, the children do not.
	parent := seedSplitRun(ctx, t, repo, tenant, scan, nil)
	a := seedSplitRun(ctx, t, repo, tenant, scan, &parent.ID)
	b := seedSplitRun(ctx, t, repo, tenant, scan, &parent.ID)

	kids, err := repo.ListChildRuns(ctx, tenant, parent.ID)
	if err != nil || len(kids) != 2 {
		t.Fatalf("children = %d, %v", len(kids), err)
	}
	if kids, _ := repo.ListChildRuns(ctx, other, parent.ID); len(kids) != 0 {
		t.Fatal("another tenant listed the children of a split run")
	}
	if got, err := repo.GetByTenantAndID(ctx, tenant, a.ID); err != nil || got.ParentRunID == nil || *got.ParentRunID != parent.ID {
		t.Fatalf("child parent_run_id = %v, %v", got, err)
	}

	finishSplitRun(ctx, t, db, a.ID, "completed", 3)
	if _, settled, err := repo.SettleSplitParent(ctx, tenant, parent.ID); err != nil || settled {
		t.Fatalf("settled with a child still running: %v %v", settled, err)
	}
	finishSplitRun(ctx, t, db, b.ID, "failed", 0)
	// Another tenant cannot settle it.
	if _, settled, _ := repo.SettleSplitParent(ctx, other, parent.ID); settled {
		t.Fatal("another tenant settled a split run")
	}
	status, settled, err := repo.SettleSplitParent(ctx, tenant, parent.ID)
	if err != nil || !settled || status != scanrun.RunStatusPartial {
		t.Fatalf("settle = %s %v %v, want partial", status, settled, err)
	}
	if st, n := splitRunStatus(ctx, t, db, parent.ID); st != "partial" || n != 3 {
		t.Errorf("parent = %s with %d findings, want partial with 3", st, n)
	}
	if _, settled, _ := repo.SettleSplitParent(ctx, tenant, parent.ID); settled {
		t.Error("a settled parent settled again")
	}

	// The scan's summary counts the parent only.
	total, _, _, last, lastRun := readCounters(ctx, t, db, scan)
	if total != 1 || last != "partial" || lastRun.String != parent.ID.String() {
		t.Errorf("summary total=%d last=%s run=%s, want the parent alone", total, last, lastRun.String)
	}
	runs, n, err := repo.ListByScanID(ctx, scan, 1, 20)
	if err != nil || n != 1 || len(runs) != 1 || runs[0].ID != parent.ID {
		t.Errorf("scan runs = %d (%v), want the parent alone", n, err)
	}
}

func TestZoneSplit_SweepSettlesReapedChildren(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRunRepository(&DB{DB: db})
	tenant, scan := seedCounterScan(ctx, t, db)

	parent := seedSplitRun(ctx, t, repo, tenant, scan, nil)
	a := seedSplitRun(ctx, t, repo, tenant, scan, &parent.ID)
	b := seedSplitRun(ctx, t, repo, tenant, scan, &parent.ID)
	finishSplitRun(ctx, t, db, a.ID, "completed", 1)
	finishSplitRun(ctx, t, db, b.ID, "completed", 2)

	if _, err := repo.SettleSplitParents(ctx); err != nil {
		t.Fatal(err)
	}
	if st, n := splitRunStatus(ctx, t, db, parent.ID); st != "completed" || n != 3 {
		t.Errorf("parent = %s with %d findings, want completed with 3", st, n)
	}
}

// A child cannot point at a parent of another tenant: the composite
// foreign key refuses it.
func TestZoneSplit_ParentMustBeSameTenant(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRunRepository(&DB{DB: db})
	tenant, scan := seedCounterScan(ctx, t, db)
	other, otherScan := seedCounterScan(ctx, t, db)
	parent := seedSplitRun(ctx, t, repo, tenant, scan, nil)

	tpl, _ := shared.IDFromString(quickScanTemplate)
	run, _ := scanrun.NewRun(tpl, other, nil, scanworkflow.TriggerTypeManual, "", map[string]any{})
	run.ScanID = &otherScan
	run.ParentRunID = &parent.ID
	if err := repo.Create(ctx, run); err == nil {
		t.Fatal("a run was linked to another tenant's parent")
	}
}
