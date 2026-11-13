package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/scanrun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// A sensor away across schedule occurrences must not find the same work
// twice when it comes back (research 511): one live run per scan (a retry
// never starts next to an active run, and a run a newer run superseded is
// not retried), and the work of a run that ended is never handed out.
// Requires DATABASE_URL.

// claimableRunCommands counts the tenant's commands of runs that a sensor
// with no identity would be offered now (the poll's predicate).
func claimableRunCommands(ctx context.Context, t *testing.T, cmds *CommandRepository, tenantID shared.ID, runs ...shared.ID) int {
	t.Helper()
	got, err := cmds.GetPendingForSensor(ctx, tenantID, nil, nil, 100)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	want := map[string]bool{}
	for _, r := range runs {
		want[r.String()] = true
	}
	n := 0
	for _, c := range got {
		if want[runIDOf(c.Payload)] {
			n++
		}
	}
	return n
}

// runIDOf is the scan_run_id of a command payload ("" when none).
func runIDOf(payload json.RawMessage) string {
	var p struct {
		RunID string `json:"scan_run_id"`
	}
	_ = json.Unmarshal(payload, &p)
	return p.RunID
}

func commandStatus(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) (status string, msg sql.NullString) {
	t.Helper()
	if err := db.QueryRowContext(ctx, `SELECT status, error_message FROM commands WHERE id = $1`, id.String()).Scan(&status, &msg); err != nil {
		t.Fatal(err)
	}
	return status, msg
}

func TestSensorAwayAcrossTwoOccurrences_OneSetOfWorkIsClaimable(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	runs := NewScanRunRepository(&DB{DB: db})
	cmds := NewCommandRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	scanID := seedRetryScan(ctx, t, db, tenantID, 2)

	// Occurrence 1: queued, then the sensor went away; the run ended at its
	// deadline (a past run that failed, retry budget left).
	first := seedFinishedRun(ctx, t, db, tenantID, scanID, "timeout", 0, "timeout", "")

	// Occurrence 2: the schedule came round and queued the work again.
	second := newOverlapRun(t, tenantID, scanID, true)
	if err := runs.CreateRunIfUnderLimit(ctx, second, 3, 50); err != nil {
		t.Fatalf("second occurrence: %v", err)
	}
	seedRunCommand(ctx, t, db, tenantID, second.ID, "pending", false, 0)

	// The retry of occurrence 1 is not dispatched: a newer run superseded it.
	if listedRuns(ctx, t, runs)[first] {
		t.Fatal("a run a newer run of the scan superseded was listed for retry")
	}
	// And a retry that reaches the insert anyway (dispatched before the
	// newer run, or by another path) is refused while that run is active.
	retry := newOverlapRun(t, tenantID, scanID, false)
	retry.RetryAttempt = 1
	err := runs.CreateRunIfUnderLimit(ctx, retry, 3, 50)
	if err == nil {
		seedRunCommand(ctx, t, db, tenantID, retry.ID, "pending", false, 0)
	} else if !errors.Is(err, scanrun.ErrScanRunActive) {
		t.Fatalf("retry next to an active run: err = %v, want ErrScanRunActive", err)
	}

	// The sensor comes back: exactly one set of work.
	if n := claimableRunCommands(ctx, t, cmds, tenantID, first, second.ID, retry.ID); n != 1 {
		t.Fatalf("claimable commands after the outage = %d, want 1 (one live run per scan)", n)
	}
}

func TestRunEnded_ItsUnclaimedCommandsCannotBeClaimed(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	defer lockGlobalSweep(ctx, t, db)()
	runs := NewScanRunRepository(&DB{DB: db})
	cmds := NewCommandRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	scanID := seedRetryScan(ctx, t, db, tenantID, 0)
	sensor := seedZoneSensor(ctx, t, db, &tenantID, "dup", zoneSensorOpts{tools: []string{"nuclei"}})

	// Settled through the run service (fail fast, a failed start, any
	// settle): the pending command is canceled in the same statement, with
	// the reason; a claimed one is left to its own path.
	failed := seedActiveRun(ctx, t, db, tenantID, scanID, "schedule", time.Minute)
	pending := seedRunCommand(ctx, t, db, tenantID, failed, "pending", false, 0)
	held := seedRunCommand(ctx, t, db, tenantID, failed, "acknowledged", true, 1)
	if err := runs.UpdateStatus(ctx, tenantID, failed, scanrun.RunStatusFailed, "Scan workflow failed: step x failed"); err != nil {
		t.Fatal(err)
	}
	if st, msg := commandStatus(ctx, t, db, pending); st != "canceled" || !msg.Valid || msg.String == "" {
		t.Fatalf("pending command of the ended run: status=%s msg=%q, want canceled with the reason", st, msg.String)
	}
	if st, _ := commandStatus(ctx, t, db, held); st != "acknowledged" {
		t.Fatalf("held command status=%s, want acknowledged (not the settle's business)", st)
	}

	// Settled by a path that leaves its commands as they are: still never
	// handed out, by poll, by id or in a batch.
	done := seedActiveRun(ctx, t, db, tenantID, scanID, "manual", time.Minute)
	left := seedRunCommand(ctx, t, db, tenantID, done, "pending", false, 0)
	if _, err := db.ExecContext(ctx, `UPDATE scan_runs SET status = 'completed', completed_at = NOW() WHERE id = $1`, done.String()); err != nil {
		t.Fatal(err)
	}
	// A live run of the same scan: its work stays claimable.
	live := seedActiveRun(ctx, t, db, tenantID, scanID, "manual", time.Minute)
	liveCmd := seedRunCommand(ctx, t, db, tenantID, live, "pending", false, 0)

	if n := claimableRunCommands(ctx, t, cmds, tenantID, failed, done); n != 0 {
		t.Fatalf("poll offered %d commands of ended runs, want 0", n)
	}
	if n := claimableRunCommands(ctx, t, cmds, tenantID, live); n != 1 {
		t.Fatalf("poll offered %d commands of the live run, want 1", n)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenantID, left, sensor.String()); err != nil || ok {
		t.Fatalf("claim by id of an ended run's command: ok=%v err=%v, want refused", ok, err)
	}
	got, err := cmds.ClaimManyForSensor(ctx, tenantID, sensor, nil, []shared.ID{left})
	if err != nil || len(got) != 0 {
		t.Fatalf("batch claim of an ended run's command: %v %v, want none", got, err)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenantID, liveCmd, sensor.String()); err != nil || !ok {
		t.Fatalf("claim of the live run's command: ok=%v err=%v, want claimed", ok, err)
	}

	// Tenant isolation: another organization's command naming this run id
	// is judged by its own organization's runs only (none ended there).
	other := seedTestTenant(ctx, t, db)
	seedRunCommand(ctx, t, db, other, done, "pending", false, 0)
	if n := claimableRunCommands(ctx, t, cmds, other, done); n != 1 {
		t.Fatalf("another organization's command was judged by this organization's run: offered %d, want 1", n)
	}
	foreignLive := seedRunCommand(ctx, t, db, other, live, "pending", false, 0)
	if err := runs.UpdateStatus(ctx, tenantID, live, scanrun.RunStatusFailed, "Scan workflow failed"); err != nil {
		t.Fatal(err)
	}
	if st, _ := commandStatus(ctx, t, db, foreignLive); st != "pending" {
		t.Fatalf("ending a run canceled another organization's command: status=%s", st)
	}
}
