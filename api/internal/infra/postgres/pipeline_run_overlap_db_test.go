package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Overlap policy skip in the run-insert transaction (RFC-046 D4, §6.2).

func newOverlapRun(t *testing.T, tenantID, scanID shared.ID, scheduled bool) *pipeline.Run {
	t.Helper()
	tpl, _ := shared.IDFromString(quickScanTemplate)
	trig := pipeline.TriggerTypeManual
	if scheduled {
		trig = pipeline.TriggerTypeSchedule
	}
	run, err := pipeline.NewRun(tpl, tenantID, nil, trig, "", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	run.ScanID = &scanID
	if scheduled {
		at := time.Now().UTC().Add(time.Duration(time.Now().UnixNano() % int64(time.Hour)))
		run.ScheduledFor = &at
	}
	return run
}

func TestCreateRunIfUnderLimit_ScheduledRunSkipsWhileAnotherIsActive(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewPipelineRunRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)

	// A manual run is active; the per-scan limit (5) would allow more.
	if err := repo.CreateRunIfUnderLimit(ctx, newOverlapRun(t, tenantID, scanID, false), 5, 50); err != nil {
		t.Fatalf("manual run: %v", err)
	}
	err := repo.CreateRunIfUnderLimit(ctx, newOverlapRun(t, tenantID, scanID, true), 5, 50)
	if !errors.Is(err, pipeline.ErrScanRunActive) {
		t.Fatalf("scheduled run while one is active: err = %v, want ErrScanRunActive", err)
	}
	// A manual trigger is not subject to the overlap skip (only the limit).
	if err := repo.CreateRunIfUnderLimit(ctx, newOverlapRun(t, tenantID, scanID, false), 5, 50); err != nil {
		t.Fatalf("second manual run: %v", err)
	}
	// Another scan of the same tenant is unaffected.
	otherScan := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name)
		VALUES ($1, $2, 'overlap other', 'single', 'nuclei')`, otherScan.String(), tenantID.String()); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateRunIfUnderLimit(ctx, newOverlapRun(t, tenantID, otherScan, true), 5, 50); err != nil {
		t.Fatalf("scheduled run of another scan: %v", err)
	}
}

// The race the transaction closes: a manual trigger commits while the
// scheduler waits on the scan row lock; the scheduler then sees it.
func TestCreateRunIfUnderLimit_ScheduledRunSeesAManualRunCommittedMeanwhile(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewPipelineRunRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)

	// The manual trigger holds the scan row lock and has inserted its run,
	// not committed yet.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT id FROM scans WHERE id = $1 FOR UPDATE`, scanID.String()); err != nil {
		t.Fatal(err)
	}
	manual := newOverlapRun(t, tenantID, scanID, false)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO pipeline_runs (id, pipeline_id, tenant_id, scan_id, trigger_type, status, context, created_at)
		VALUES ($1, $2, $3, $4, 'manual', 'pending', '{}', NOW())`,
		manual.ID.String(), manual.PipelineID.String(), tenantID.String(), scanID.String()); err != nil {
		t.Fatalf("manual insert: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- repo.CreateRunIfUnderLimit(ctx, newOverlapRun(t, tenantID, scanID, true), 5, 50)
	}()
	select {
	case err := <-done:
		t.Fatalf("the scheduled insert did not wait for the scan row lock: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, pipeline.ErrScanRunActive) {
		t.Fatalf("scheduled run after the manual run committed: err = %v, want ErrScanRunActive", err)
	}
	var active int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pipeline_runs WHERE scan_id = $1 AND status IN ('pending','running')`,
		scanID.String()).Scan(&active); err != nil || active != 1 {
		t.Fatalf("active runs = %d (%v), want 1", active, err)
	}
}
