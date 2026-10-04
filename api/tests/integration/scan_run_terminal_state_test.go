package integration

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "github.com/lib/pq"

	pipelinesvc "github.com/openctemio/openctem/api/internal/app/pipeline"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Terminal states of a scan run, as a user sees them.
//
// Found by running real sensors against a v0.9.0 candidate (2026-10-01):
//
//  1. A run that FAILED left its scan reading "never run": last_run_status
//     empty, total_runs 0, failed_runs 0. Only the success path wrote the
//     outcome back onto the scan, so two failed runs in a row were invisible
//     on the scan itself.
//  2. Canceling a running scan did not stop the sensor: the cancel looked the
//     run's commands up through commands.step_run_id, which the scan dispatcher
//     never sets, so the command stayed 'running' and the scanner kept going.
//  3. When that sensor then reported its result, the canceled run flipped to
//     'completed' and was counted as a successful run on the scan.

// newRecordingPipelineService is newPipelineService with the scan-run recorder
// wired, exactly as cmd/server does.
func newRecordingPipelineService(db *sql.DB) *pipelinesvc.Service {
	pg := &postgres.DB{DB: db}
	return pipelinesvc.NewService(
		postgres.NewPipelineTemplateRepository(pg),
		postgres.NewPipelineStepRepository(pg),
		postgres.NewPipelineRunRepository(pg),
		postgres.NewStepRunRepository(pg),
		nil, // sensorRepo
		postgres.NewCommandRepository(pg),
		nil, // securityValidator
		logger.New(logger.Config{Level: "error"}),
		pipelinesvc.WithScanRunRecorder(postgres.NewScanRepository(pg)),
	)
}

type scanSummary struct {
	lastStatus sql.NullString
	total      int
	succeeded  int
	failed     int
}

func readScanSummary(ctx context.Context, t *testing.T, db *sql.DB, scanID string) scanSummary {
	t.Helper()
	var s scanSummary
	if err := db.QueryRowContext(ctx,
		`SELECT last_run_status, total_runs, successful_runs, failed_runs FROM scans WHERE id = $1`, scanID).
		Scan(&s.lastStatus, &s.total, &s.succeeded, &s.failed); err != nil {
		t.Fatalf("read scan summary: %v", err)
	}
	return s
}

func commandStatusForRun(ctx context.Context, t *testing.T, db *sql.DB, runID string) string {
	t.Helper()
	var status string
	if err := db.QueryRowContext(ctx,
		`SELECT status FROM commands WHERE payload->>'pipeline_run_id' = $1`, runID).Scan(&status); err != nil {
		t.Fatalf("read command status: %v", err)
	}
	return status
}

func TestScanRun_FailedRunIsRecordedOnTheScan(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	svc := newTriggerService(db)
	pipeSvc := newRecordingPipelineService(db)

	tenantID := seedLifecycleTenant(ctx, t, db)
	scanID := seedLifecycleScan(ctx, t, db, tenantID)

	run, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenantID.String(), ScanID: scanID.String()})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	p := routingFromCommand(ctx, t, db, tenantID.String())

	if err := pipeSvc.OnStepFailed(ctx, p.PipelineRunID, p.StepKey, "scan target refused by guard", "COMMAND_FAILED"); err != nil {
		t.Fatalf("OnStepFailed: %v", err)
	}

	if status, _, _ := runState(ctx, t, db, run.ID.String()); status != "failed" {
		t.Fatalf("precondition: run status = %q, want failed", status)
	}
	got := readScanSummary(ctx, t, db, scanID.String())
	if got.lastStatus.String != "failed" || got.total != 1 || got.failed != 1 || got.succeeded != 0 {
		t.Errorf("scan summary after a failed run = {last=%q total=%d ok=%d failed=%d}, want {failed 1 0 1} — "+
			"a failed run must not leave the scan reading \"never run\"",
			got.lastStatus.String, got.total, got.succeeded, got.failed)
	}
}

func TestScanRun_CancelStopsTheDispatchedCommand(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	svc := newTriggerService(db)
	pipeSvc := newRecordingPipelineService(db)

	tenantID := seedLifecycleTenant(ctx, t, db)
	scanID := seedLifecycleScan(ctx, t, db, tenantID)

	run, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenantID.String(), ScanID: scanID.String()})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	// The sensor has claimed and started it.
	if _, err := db.ExecContext(ctx,
		`UPDATE commands SET status = 'running', started_at = NOW() WHERE payload->>'pipeline_run_id' = $1`,
		run.ID.String()); err != nil {
		t.Fatalf("mark command running: %v", err)
	}

	if err := pipeSvc.CancelRun(ctx, tenantID.String(), run.ID.String()); err != nil {
		t.Fatalf("CancelRun: %v", err)
	}

	if got := commandStatusForRun(ctx, t, db, run.ID.String()); got != "canceled" {
		t.Errorf("command status after canceling its run = %q, want canceled — the sensor keeps scanning "+
			"something the user stopped", got)
	}
	got := readScanSummary(ctx, t, db, scanID.String())
	if got.lastStatus.String != "canceled" || got.total != 1 || got.succeeded != 0 || got.failed != 0 {
		t.Errorf("scan summary after cancel = {last=%q total=%d ok=%d failed=%d}, want {canceled 1 0 0}",
			got.lastStatus.String, got.total, got.succeeded, got.failed)
	}
}

// Canceling twice is the same as canceling once: the second call succeeds,
// the scan counts the run once, and the run's open step ends canceled. A user
// of another tenant cannot cancel it: not found, nothing changes.
func TestScanRun_CancelIsIdempotentTenantScopedAndClosesSteps(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	svc := newTriggerService(db)
	pipeSvc := newRecordingPipelineService(db)

	tenantID := seedLifecycleTenant(ctx, t, db)
	scanID := seedLifecycleScan(ctx, t, db, tenantID)
	stranger := seedLifecycleTenant(ctx, t, db)

	run, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenantID.String(), ScanID: scanID.String()})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}

	err = pipeSvc.CancelRun(ctx, stranger.String(), run.ID.String())
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant CancelRun err = %v, want not found", err)
	}
	if status, _, _ := runState(ctx, t, db, run.ID.String()); status == "canceled" {
		t.Fatalf("another tenant canceled the run")
	}
	if got := commandStatusForRun(ctx, t, db, run.ID.String()); got == "canceled" {
		t.Fatalf("another tenant canceled the command")
	}

	for i := 0; i < 2; i++ {
		if err := pipeSvc.CancelRun(ctx, tenantID.String(), run.ID.String()); err != nil {
			t.Fatalf("CancelRun #%d: %v", i+1, err)
		}
	}
	if got := commandStatusForRun(ctx, t, db, run.ID.String()); got != "canceled" {
		t.Errorf("command = %q, want canceled", got)
	}
	var openSteps int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM step_runs
		WHERE pipeline_run_id = $1 AND status NOT IN ('canceled', 'completed', 'partial', 'failed', 'skipped', 'timeout')`,
		run.ID.String()).Scan(&openSteps); err != nil {
		t.Fatal(err)
	}
	if openSteps != 0 {
		t.Errorf("%d step run(s) still open after the cancel, want 0", openSteps)
	}
	if got := readScanSummary(ctx, t, db, scanID.String()); got.total != 1 || got.lastStatus.String != "canceled" {
		t.Errorf("scan summary = {last=%q total=%d}, want {canceled 1}: a second cancel must not count again",
			got.lastStatus.String, got.total)
	}
}

func TestScanRun_LateResultDoesNotReviveACanceledRun(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	svc := newTriggerService(db)
	pipeSvc := newRecordingPipelineService(db)

	tenantID := seedLifecycleTenant(ctx, t, db)
	scanID := seedLifecycleScan(ctx, t, db, tenantID)

	run, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenantID.String(), ScanID: scanID.String()})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	p := routingFromCommand(ctx, t, db, tenantID.String())

	if err := pipeSvc.CancelRun(ctx, tenantID.String(), run.ID.String()); err != nil {
		t.Fatalf("CancelRun: %v", err)
	}
	// The sensor finishes anyway and reports.
	if err := pipeSvc.OnStepCompleted(ctx, p.PipelineRunID, p.StepKey, 1, nil); err != nil {
		t.Fatalf("OnStepCompleted: %v", err)
	}

	if status, _, _ := runState(ctx, t, db, run.ID.String()); status != "canceled" {
		t.Errorf("run status after a late result = %q, want canceled — a finished run must stay finished", status)
	}
	if got := readScanSummary(ctx, t, db, scanID.String()); got.succeeded != 0 {
		t.Errorf("successful_runs = %d after a canceled run, want 0", got.succeeded)
	}
}

func TestScanRun_LateFailureDoesNotOverwriteATimedOutRun(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	svc := newTriggerService(db)
	pipeSvc := newRecordingPipelineService(db)

	tenantID := seedLifecycleTenant(ctx, t, db)
	scanID := seedLifecycleScan(ctx, t, db, tenantID)

	run, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenantID.String(), ScanID: scanID.String()})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	p := routingFromCommand(ctx, t, db, tenantID.String())

	// The reaper got there first.
	if _, err := db.ExecContext(ctx,
		`UPDATE pipeline_runs SET status = 'timeout', completed_at = NOW() WHERE id = $1`, run.ID.String()); err != nil {
		t.Fatalf("mark run timed out: %v", err)
	}
	if err := pipeSvc.OnStepFailed(ctx, p.PipelineRunID, p.StepKey, "late error", "COMMAND_FAILED"); err != nil {
		t.Fatalf("OnStepFailed: %v", err)
	}

	if status, _, _ := runState(ctx, t, db, run.ID.String()); status != "timeout" {
		t.Errorf("run status = %q, want timeout to stay — a finished run must stay finished", status)
	}
}

// A sensor that dies mid-scan never reports. The reaper ends the run as a
// timeout, but it used to touch only the run: the command stayed 'running'
// forever (a zombie in the command list and in the sensor's job count), and
// the scan still read "never run".
func TestScanRun_TimeoutClosesTheCommandAndRecordsTheScan(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	svc := newTriggerService(db)

	tenantID := seedLifecycleTenant(ctx, t, db)
	scanID := seedLifecycleScan(ctx, t, db, tenantID)

	run, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenantID.String(), ScanID: scanID.String()})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	// The sensor claimed and started the command, then died; the run is now
	// older than the scan's timeout.
	if _, err := db.ExecContext(ctx,
		`UPDATE commands SET status = 'running', started_at = NOW() - INTERVAL '2 hours'
		 WHERE payload->>'pipeline_run_id' = $1`, run.ID.String()); err != nil {
		t.Fatalf("mark command running: %v", err)
	}
	// The deadline is fixed when the run starts (RFC-046 §6.3), so aging the
	// run means moving its stored deadline along with its start.
	if _, err := db.ExecContext(ctx,
		`UPDATE pipeline_runs SET started_at = NOW() - INTERVAL '2 hours',
		        deadline_at = NOW() - INTERVAL '1 hour' WHERE id = $1`, run.ID.String()); err != nil {
		t.Fatalf("age run: %v", err)
	}

	if _, err := postgres.NewPipelineRunRepository(&postgres.DB{DB: db}).MarkTimedOutRuns(ctx); err != nil {
		t.Fatalf("MarkTimedOutRuns: %v", err)
	}

	if status, _, _ := runState(ctx, t, db, run.ID.String()); status != "timeout" {
		t.Fatalf("precondition: run status = %q, want timeout", status)
	}
	if got := commandStatusForRun(ctx, t, db, run.ID.String()); got != "failed" {
		t.Errorf("command status after its run timed out = %q, want failed — a dead sensor's command "+
			"must not stay 'running' forever", got)
	}
	var stepStatus string
	if err := db.QueryRowContext(ctx,
		`SELECT status FROM step_runs WHERE pipeline_run_id = $1`, run.ID.String()).Scan(&stepStatus); err != nil {
		t.Fatalf("read step run: %v", err)
	}
	if stepStatus != "timeout" {
		t.Errorf("step run status = %q, want timeout", stepStatus)
	}
	got := readScanSummary(ctx, t, db, scanID.String())
	if got.lastStatus.String != "timeout" || got.total != 1 || got.failed != 1 {
		t.Errorf("scan summary after a timeout = {last=%q total=%d ok=%d failed=%d}, want {timeout 1 0 1}",
			got.lastStatus.String, got.total, got.succeeded, got.failed)
	}
}
