package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A run's deadline counts active work, not queue wait
// (scan_run_deadline_work.go). Requires DATABASE_URL.

// seedDeadlineRun seeds an open run of the quick-scan template (timeout
// 7200 s) that started ago and has deadline in from now, with reason.
func seedDeadlineRun(ctx context.Context, t *testing.T, db *sql.DB, tenant shared.ID, ago, in time.Duration, reason string) string {
	t.Helper()
	stepRun := seedChunkStepRun(ctx, t, db, tenant)
	var runID string
	if err := db.QueryRowContext(ctx, `SELECT scan_run_id FROM scan_run_steps WHERE id = $1`, stepRun.String()).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE scan_runs SET status = 'running',
		started_at = NOW() - make_interval(secs => $2), deadline_at = NOW() + make_interval(secs => $3), deadline_reason = $4
		WHERE id = $1`, runID, ago.Seconds(), in.Seconds(), reason); err != nil {
		t.Fatal(err)
	}
	return runID
}

// createRunCommand queues a scan task of runID for tool on n targets, with
// the run's deadline in its payload as the dispatcher writes it.
func createRunCommand(ctx context.Context, t *testing.T, repo *CommandRepository, tenant shared.ID, runID, tool string, n int) shared.ID {
	t.Helper()
	targets := make([]string, n)
	for i := range targets {
		targets[i] = fmt.Sprintf("https://h%03d-%s.example.test/", i, shared.NewID().String()[:8])
	}
	raw, _ := json.Marshal(map[string]any{"scan_run_id": runID, "scanner": tool, "targets": targets,
		"deadline": time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)})
	cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	return cmd.ID
}

func runDeadline(ctx context.Context, t *testing.T, db *sql.DB, runID string) (time.Time, string) {
	t.Helper()
	var at time.Time
	var reason sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT deadline_at, deadline_reason FROM scan_runs WHERE id = $1`, runID).Scan(&at, &reason); err != nil {
		t.Fatal(err)
	}
	return at, reason.String
}

func setSensorSpeed(ctx context.Context, t *testing.T, db *sql.DB, sensor shared.ID, tool string, perMin float64) {
	t.Helper()
	capacity, _ := json.Marshal(map[string]any{"per_tool": map[string]any{tool: map[string]any{"throughput_targets_per_min": perMin}}})
	if _, err := db.ExecContext(ctx, `UPDATE sensors SET reported_capacity = $2, load_reported_at = NOW() WHERE id = $1`,
		sensor.String(), string(capacity)); err != nil {
		t.Fatal(err)
	}
}

// The live case: a coverage run's template scan of 25 targets was claimed
// with 10 minutes left of its 2 h timeout (the rest spent waiting) and was
// ended part-way. At the claim the run now gets the time 25 targets need at
// the sensor's measured speed, and the task's payload deadline follows.
func TestExtendRunDeadlinesAtClaim(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	sensor := seedZoneSensor(ctx, t, db, &tenant, "s", zoneSensorOpts{tools: []string{"nuclei"}})
	theirs := seedZoneSensor(ctx, t, db, &other, "o", zoneSensorOpts{tools: []string{"nuclei"}})
	setSensorSpeed(ctx, t, db, sensor, "nuclei", 0.5)

	claim := func(tn, s, id shared.ID) {
		t.Helper()
		if ok, err := repo.ClaimForSensor(ctx, tn, id, s.String()); err != nil || !ok {
			t.Fatalf("claim: %v %v", ok, err)
		}
		if err := repo.ExtendRunDeadlinesAtClaim(ctx, tn, s, []shared.ID{id}); err != nil {
			t.Fatal(err)
		}
		// Free the slot for the next case.
		if _, err := db.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE id = $1`, id.String()); err != nil {
			t.Fatal(err)
		}
	}

	// Measured speed: 25 targets at 0.5 a minute, twice over plus 5 min.
	run := seedDeadlineRun(ctx, t, db, tenant, 110*time.Minute, 10*time.Minute, scanrun.DeadlineReasonWorkflowMaxDuration)
	cmd := createRunCommand(ctx, t, repo, tenant, run, "nuclei", 25)
	before := time.Now()
	claim(tenant, sensor, cmd)
	at, reason := runDeadline(ctx, t, db, run)
	want := before.Add(6300 * time.Second)
	if reason != scanrun.DeadlineReasonWorkEstimate || at.Before(want.Add(-time.Minute)) || at.After(want.Add(2*time.Minute)) {
		t.Fatalf("deadline %v (%s), want about %v (%s)", at, reason, want, scanrun.DeadlineReasonWorkEstimate)
	}
	var sent string
	if err := db.QueryRowContext(ctx, `SELECT payload->>'deadline' FROM commands WHERE id = $1`, cmd.String()).Scan(&sent); err != nil {
		t.Fatal(err)
	}
	if got, err := time.Parse(time.RFC3339, sent); err != nil || got.Unix() != at.Truncate(time.Second).Unix() {
		t.Fatalf("payload deadline %q, want the run's %v", sent, at)
	}

	// A later claim never moves it back, and the claimed task's payload
	// still gets the run's deadline: a task created before an earlier claim
	// moved the run carries the old one (prod 2026-11-01: a task queued for
	// hours was handed a deadline already past and ran 30 s).
	small := createRunCommand(ctx, t, repo, tenant, run, "nuclei", 1)
	if _, err := db.ExecContext(ctx, `UPDATE commands SET payload = jsonb_set(payload, '{deadline}', to_jsonb($2::text)) WHERE id = $1`,
		small.String(), time.Now().Add(-2*time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	claim(tenant, sensor, small)
	if again, _ := runDeadline(ctx, t, db, run); !again.Equal(at) {
		t.Fatalf("a shorter estimate moved the deadline from %v to %v", at, again)
	}
	if err := db.QueryRowContext(ctx, `SELECT payload->>'deadline' FROM commands WHERE id = $1`, small.String()).Scan(&sent); err != nil {
		t.Fatal(err)
	}
	if got, err := time.Parse(time.RFC3339, sent); err != nil || got.Unix() != at.Truncate(time.Second).Unix() {
		t.Fatalf("a claim that moved nothing left payload deadline %q, want the run's %v", sent, at)
	}

	// No measured speed: the run's configured timeout from the claim.
	setSensorSpeed(ctx, t, db, sensor, "httpx", 10)
	run2 := seedDeadlineRun(ctx, t, db, tenant, 110*time.Minute, 10*time.Minute, scanrun.DeadlineReasonWorkflowMaxDuration)
	before = time.Now()
	claim(tenant, sensor, createRunCommand(ctx, t, repo, tenant, run2, "nuclei", 3))
	if at2, _ := runDeadline(ctx, t, db, run2); at2.Before(before.Add(7200*time.Second-time.Minute)) || at2.After(before.Add(7200*time.Second+2*time.Minute)) {
		t.Fatalf("no speed: deadline %v, want the 2 h timeout from the claim", at2)
	}

	// Never past the platform cap.
	run3 := seedDeadlineRun(ctx, t, db, tenant, 23*time.Hour+50*time.Minute, 5*time.Minute, scanrun.DeadlineReasonWorkflowMaxDuration)
	setSensorSpeed(ctx, t, db, sensor, "nuclei", 0.5)
	claim(tenant, sensor, createRunCommand(ctx, t, repo, tenant, run3, "nuclei", 25))
	var overCap bool
	if err := db.QueryRowContext(ctx, `SELECT deadline_at > started_at + interval '24 hours' FROM scan_runs WHERE id = $1`, run3).Scan(&overCap); err != nil || overCap {
		t.Fatalf("deadline past the platform cap (%v)", err)
	}

	// The scan owner's max duration is a hard cap.
	owned := seedDeadlineRun(ctx, t, db, tenant, 50*time.Minute, 10*time.Minute, scanrun.DeadlineReasonScanMaxDuration)
	ownedAt, _ := runDeadline(ctx, t, db, owned)
	claim(tenant, sensor, createRunCommand(ctx, t, repo, tenant, owned, "nuclei", 25))
	if got, reason := runDeadline(ctx, t, db, owned); !got.Equal(ownedAt) || reason != scanrun.DeadlineReasonScanMaxDuration {
		t.Fatalf("owner-capped run moved to %v (%s)", got, reason)
	}

	// Tenant isolation: another organization's sensor and tenant id never
	// move this tenant's run, even naming its task.
	iso := seedDeadlineRun(ctx, t, db, tenant, 110*time.Minute, 10*time.Minute, scanrun.DeadlineReasonWorkflowMaxDuration)
	isoAt, _ := runDeadline(ctx, t, db, iso)
	isoCmd := createRunCommand(ctx, t, repo, tenant, iso, "nuclei", 25)
	isoStale := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if _, err := db.ExecContext(ctx, `UPDATE commands SET status = 'acknowledged', sensor_id = $2,
		payload = jsonb_set(payload, '{deadline}', to_jsonb($3::text)) WHERE id = $1`, isoCmd.String(), sensor.String(), isoStale); err != nil {
		t.Fatal(err)
	}
	if err := repo.ExtendRunDeadlinesAtClaim(ctx, other, theirs, []shared.ID{isoCmd}); err != nil {
		t.Fatal(err)
	}
	if err := repo.ExtendRunDeadlinesAtClaim(ctx, tenant, theirs, []shared.ID{isoCmd}); err != nil {
		t.Fatal(err)
	}
	if got, _ := runDeadline(ctx, t, db, iso); !got.Equal(isoAt) {
		t.Fatalf("a foreign sensor moved the run's deadline to %v", got)
	}
	// Nor rewrites the task's payload deadline.
	var isoSent string
	if err := db.QueryRowContext(ctx, `SELECT payload->>'deadline' FROM commands WHERE id = $1`, isoCmd.String()).Scan(&isoSent); err != nil {
		t.Fatal(err)
	}
	if isoSent != isoStale {
		t.Fatalf("a foreign sensor rewrote the payload deadline to %q", isoSent)
	}
}

// A run past its deadline whose task waits for a busy sensor of the tenant
// is not timed out, and is not "no sensor picked up this run's work"; once
// the sensor is free and still nobody takes it, it is. A busy sensor of
// another tenant never counts, and the owner's cap still applies.
func TestQueueWaitDoesNotCount(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	runs := NewScanRunRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	sensor := seedZoneSensor(ctx, t, db, &tenant, "s", zoneSensorOpts{tools: []string{"nuclei"}})
	theirs := seedZoneSensor(ctx, t, db, &other, "o", zoneSensorOpts{tools: []string{"nuclei"}})
	for _, s := range []shared.ID{sensor, theirs} {
		if _, err := db.ExecContext(ctx, `UPDATE sensors SET max_concurrent_jobs = 1 WHERE id = $1`, s.String()); err != nil {
			t.Fatal(err)
		}
	}

	// The tenant's only slot runs another run's task.
	busyRun := seedDeadlineRun(ctx, t, db, tenant, time.Minute, 2*time.Hour, scanrun.DeadlineReasonWorkflowMaxDuration)
	holder := createRunCommand(ctx, t, repo, tenant, busyRun, "nuclei", 1)
	if ok, err := repo.ClaimForSensor(ctx, tenant, holder, sensor.String()); err != nil || !ok {
		t.Fatalf("holder not claimed: %v %v", ok, err)
	}

	waiting := seedDeadlineRun(ctx, t, db, tenant, 3*time.Hour, -time.Minute, scanrun.DeadlineReasonWorkflowMaxDuration)
	createRunCommand(ctx, t, repo, tenant, waiting, "nuclei", 5)
	owned := seedDeadlineRun(ctx, t, db, tenant, 3*time.Hour, -time.Minute, scanrun.DeadlineReasonScanMaxDuration)
	createRunCommand(ctx, t, repo, tenant, owned, "nuclei", 5)

	status := func(runID string) string {
		t.Helper()
		var s string
		if err := db.QueryRowContext(ctx, `SELECT status FROM scan_runs WHERE id = $1`, runID).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	settle := func() {
		t.Helper()
		if _, err := runs.AbortUnclaimedRunsReporting(ctx, time.Minute, time.Minute); err != nil {
			t.Fatal(err)
		}
		if _, err := runs.MarkTimedOutRunsReporting(ctx); err != nil {
			t.Fatal(err)
		}
	}

	settle()
	if got := status(waiting); got != "running" {
		t.Fatalf("a run waiting for a busy sensor ended %q", got)
	}
	if got := status(owned); got == "running" {
		t.Fatal("a run past the owner's max duration was kept open")
	}

	// The tenant's sensor frees up but the other tenant's stays busy: that
	// never counts, and with a free slot left idle the run is unclaimed.
	theirRun := seedDeadlineRun(ctx, t, db, other, time.Minute, 2*time.Hour, scanrun.DeadlineReasonWorkflowMaxDuration)
	theirHolder := createRunCommand(ctx, t, repo, other, theirRun, "nuclei", 1)
	if ok, err := repo.ClaimForSensor(ctx, other, theirHolder, theirs.String()); err != nil || !ok {
		t.Fatalf("foreign holder not claimed: %v %v", ok, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE id = $1`, holder.String()); err != nil {
		t.Fatal(err)
	}
	settle()
	if got := status(waiting); got == "running" {
		t.Fatal("a run nobody took with a free sensor was kept open")
	}
}
