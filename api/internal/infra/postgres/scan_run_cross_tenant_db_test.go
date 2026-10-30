package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A run id given with another tenant's id changes nothing: the status
// transition and the retry-claim release both carry the tenant predicate.

func TestUpdateStatus_OtherTenantRunIsNotTouched(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	runs := NewScanRunRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)
	run := seedCounterRun(ctx, t, runs, tenantID, scanID)
	other := shared.NewID()

	if err := runs.UpdateStatus(ctx, other, run.ID, scanrun.RunStatusCanceled, "x"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("UpdateStatus with another tenant = %v, want ErrNotFound", err)
	}
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM scan_runs WHERE id = $1`, run.ID.String()).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != string(run.Status) {
		t.Fatalf("status = %q after a cross-tenant update, want unchanged %q", status, run.Status)
	}
	if err := runs.UpdateStatus(ctx, tenantID, run.ID, scanrun.RunStatusCanceled, "x"); err != nil {
		t.Fatalf("UpdateStatus with the owning tenant: %v", err)
	}
}

func TestReleaseFailedRetryDispatch_OtherTenantRunIsNotTouched(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	repo := NewScanRunRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	runID := seedFinishedRun(ctx, t, db, tenantID, seedRetryScan(ctx, t, db, tenantID, 2), "failed", 1, "failed", "COMMAND_FAILED")
	if !listedRuns(ctx, t, repo)[runID] {
		t.Fatal("run not claimed")
	}

	if err := repo.ReleaseFailedRetryDispatch(ctx, shared.NewID(), runID); err != nil {
		t.Fatal(err)
	}
	var attempt int
	var claimed bool
	if err := db.QueryRowContext(ctx, `SELECT retry_attempt, retry_dispatched_at IS NOT NULL FROM scan_runs WHERE id = $1`, runID.String()).
		Scan(&attempt, &claimed); err != nil {
		t.Fatal(err)
	}
	if attempt != 1 || !claimed {
		t.Fatalf("attempt=%d claimed=%v after a cross-tenant release, want 1 and still claimed", attempt, claimed)
	}
}
