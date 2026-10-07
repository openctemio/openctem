package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Retry classes (D7), poison commands and unclaimed runs (D8), against the
// real SQL.

const (
	retryQuickScanTemplate = "00000000-0000-0000-0000-000000000001"
	quickScanStepID        = "00000000-0000-0000-0000-000000000002"
)

func seedRetryScan(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID, maxRetries int) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, targets, max_retries, retry_backoff_seconds, timeout_seconds)
		 VALUES ($1, $2, $3, 'single', 'nuclei', ARRAY['example.test'], $4, 10, 86400)`,
		id.String(), tenantID.String(), "retry probe "+id.String(), maxRetries); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	return id
}

// seedFinishedRun inserts a finished run (completed long enough ago for any
// backoff) with one step run carrying errCode.
func seedFinishedRun(ctx context.Context, t *testing.T, db *sql.DB, tenantID, scanID shared.ID, status string, attempt int, stepStatus, errCode string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scan_runs (id, scan_workflow_id, tenant_id, scan_id, trigger_type, status, started_at, completed_at, retry_attempt)
		 VALUES ($1, $2, $3, $4, 'manual', $5, NOW() - interval '2 days', NOW() - interval '1 day', $6)`,
		id.String(), retryQuickScanTemplate, tenantID.String(), scanID.String(), status, attempt); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scan_run_steps (id, scan_run_id, step_id, step_key, step_order, status, error_code)
		 VALUES ($1, $2, $3, 'quick_scan', 1, $4, NULLIF($5, ''))`,
		shared.NewID().String(), id.String(), quickScanStepID, stepStatus, errCode); err != nil {
		t.Fatalf("seed step run: %v", err)
	}
	return id
}

func listedRuns(ctx context.Context, t *testing.T, repo *ScanRunRepository) map[shared.ID]bool {
	t.Helper()
	cands, err := repo.ListPendingRetries(ctx, 1000)
	if err != nil {
		t.Fatalf("ListPendingRetries: %v", err)
	}
	out := map[shared.ID]bool{}
	for _, c := range cands {
		out[c.RunID] = true
	}
	return out
}

func TestListPendingRetries_Classes(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	repo := NewScanRunRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)

	transient := seedFinishedRun(ctx, t, db, tenantID, seedRetryScan(ctx, t, db, tenantID, 5), "failed", 0, "failed", "COMMAND_FAILED")
	permanent := seedFinishedRun(ctx, t, db, tenantID, seedRetryScan(ctx, t, db, tenantID, 5), "failed", 0, "failed", scanrun.FailureScannerNotFound)
	timeoutFresh := seedFinishedRun(ctx, t, db, tenantID, seedRetryScan(ctx, t, db, tenantID, 5), "timeout", 1, "timeout", "")
	timeoutSpent := seedFinishedRun(ctx, t, db, tenantID, seedRetryScan(ctx, t, db, tenantID, 5), "timeout", 2, "timeout", "")

	got := listedRuns(ctx, t, repo)
	if !got[transient] {
		t.Error("a transient failure with budget left must be retried")
	}
	if got[permanent] {
		t.Error("SCANNER_NOT_FOUND was offered for retry; a retry cannot fix it")
	}
	if !got[timeoutFresh] {
		t.Error("a timed-out run (attempt 1 of 2) must be retried; timeouts were never retried")
	}
	if got[timeoutSpent] {
		t.Error("a timed-out run past 2 retries was offered again (timeouts retry at most twice)")
	}
}

func TestReleaseFailedRetryDispatch_SpendsTheAttempt(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	repo := NewScanRunRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	runID := seedFinishedRun(ctx, t, db, tenantID, seedRetryScan(ctx, t, db, tenantID, 2), "failed", 1, "failed", "COMMAND_FAILED")

	if !listedRuns(ctx, t, repo)[runID] {
		t.Fatal("run not claimed")
	}
	if err := repo.ReleaseFailedRetryDispatch(ctx, runID); err != nil {
		t.Fatal(err)
	}
	var attempt int
	var claimed sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT retry_attempt, retry_dispatched_at FROM scan_runs WHERE id = $1`, runID.String()).
		Scan(&attempt, &claimed); err != nil {
		t.Fatal(err)
	}
	if attempt != 2 || claimed.Valid {
		t.Fatalf("retry_attempt=%d claimed=%v, want 2 and released", attempt, claimed.Valid)
	}
	// Budget (2) is spent now: no more retries.
	if listedRuns(ctx, t, repo)[runID] {
		t.Fatal("run offered again after its budget was spent by failed dispatches")
	}
}

func seedRunCommand(ctx context.Context, t *testing.T, db *sql.DB, tenantID, runID shared.ID, status string, acknowledged bool, attempts int) shared.ID {
	t.Helper()
	id := shared.NewID()
	ack := "NULL"
	if acknowledged {
		ack = "NOW() - interval '30 minutes'"
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO commands (id, tenant_id, type, priority, payload, status, acknowledged_at, dispatch_attempts)
		 VALUES ($1, $2, 'scan', 'normal', jsonb_build_object('scan_run_id', $3::text, 'step_key', 'quick_scan'), $4, `+ack+`, $5)`,
		id.String(), tenantID.String(), runID.String(), status, attempts); err != nil {
		t.Fatalf("seed command: %v", err)
	}
	return id
}

func seedActiveRun(ctx context.Context, t *testing.T, db *sql.DB, tenantID, scanID shared.ID, trigger string, startedAgo time.Duration) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scan_runs (id, scan_workflow_id, tenant_id, scan_id, trigger_type, status, started_at)
		 VALUES ($1, $2, $3, $4, $5, 'running', NOW() - make_interval(secs => $6))`,
		id.String(), retryQuickScanTemplate, tenantID.String(), scanID.String(), trigger, startedAgo.Seconds()); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scan_run_steps (id, scan_run_id, step_id, step_key, step_order, status)
		 VALUES ($1, $2, $3, 'quick_scan', 1, 'queued')`,
		shared.NewID().String(), id.String(), quickScanStepID); err != nil {
		t.Fatalf("seed step run: %v", err)
	}
	return id
}

func TestAbortUnclaimedRuns(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	repo := NewScanRunRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	scanID := seedRetryScan(ctx, t, db, tenantID, 0)

	// Interactive, 2h, never claimed: aborted (threshold 1h).
	unclaimed := seedActiveRun(ctx, t, db, tenantID, scanID, "manual", 2*time.Hour)
	unclaimedCmd := seedRunCommand(ctx, t, db, tenantID, unclaimed, "pending", false, 0)
	// Interactive, 2h, a sensor acknowledged it: not this reaper's business.
	claimed := seedActiveRun(ctx, t, db, tenantID, scanID, "manual", 2*time.Hour)
	seedRunCommand(ctx, t, db, tenantID, claimed, "acknowledged", true, 1)
	// Scheduled, 2h, never claimed: still inside its 4h.
	scheduled := seedActiveRun(ctx, t, db, tenantID, scanID, "schedule", 2*time.Hour)
	seedRunCommand(ctx, t, db, tenantID, scheduled, "pending", false, 0)

	n, err := repo.AbortUnclaimedRuns(ctx, 4*time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("aborted %d runs, want 1", n)
	}
	status, msg := runStatus(ctx, t, db, unclaimed)
	if status != "failed" || !msg.Valid || msg.String == "" {
		t.Fatalf("unclaimed run: status=%s msg=%q, want failed with the reason", status, msg.String)
	}
	var code, cmdStatus string
	if err := db.QueryRowContext(ctx, `SELECT error_code FROM scan_run_steps WHERE scan_run_id = $1`, unclaimed.String()).Scan(&code); err != nil {
		t.Fatal(err)
	}
	if code != scanrun.FailureNoSensor {
		t.Fatalf("step error_code=%s, want NO_SENSOR (never retried)", code)
	}
	if err := db.QueryRowContext(ctx, `SELECT status FROM commands WHERE id = $1`, unclaimedCmd.String()).Scan(&cmdStatus); err != nil {
		t.Fatal(err)
	}
	if cmdStatus != "failed" {
		t.Fatalf("command status=%s, want failed (a late sensor must not pick it up)", cmdStatus)
	}
	if s, _ := runStatus(ctx, t, db, claimed); s != "running" {
		t.Fatalf("claimed run status=%s, want running", s)
	}
	if s, _ := runStatus(ctx, t, db, scheduled); s != "running" {
		t.Fatalf("scheduled run status=%s, want running (4h threshold)", s)
	}
	// And the aborted run is not offered for retry.
	if listedRuns(ctx, t, repo)[unclaimed] {
		t.Fatal("an unclaimed (no sensor) run was offered for retry")
	}
}

func TestFailExhaustedCommandsReturning(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	cmds := NewCommandRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	scanID := seedRetryScan(ctx, t, db, tenantID, 0)
	runID := seedActiveRun(ctx, t, db, tenantID, scanID, "manual", time.Minute)
	poison := seedRunCommand(ctx, t, db, tenantID, runID, "pending", false, 3)
	fresh := seedRunCommand(ctx, t, db, tenantID, runID, "pending", false, 1)

	failed, err := cmds.FailExhaustedCommandsReturning(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range failed {
		if c.ID == fresh {
			t.Fatal("a command with attempts left was failed")
		}
		if c.ID == poison {
			found = true
			if len(c.Payload) == 0 {
				t.Fatal("payload not returned: the pipeline cannot be told")
			}
		}
	}
	if !found {
		t.Fatal("exhausted command not returned")
	}
}
