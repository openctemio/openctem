package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/toolbudget"
)

// Per-command progress and stall detection (research/122). Requires
// DATABASE_URL (CI applies every migration first).

// newBudgetTestCommand creates a command over n targets carrying budget
// (nil: none), claimed and started by sensor.
func newBudgetTestCommand(ctx context.Context, t *testing.T, cmds *CommandRepository, tenant, sensor shared.ID, n int, budget *toolbudget.Task) shared.ID {
	t.Helper()
	targets := make([]string, n)
	host := uniqueTestHost()
	for i := range targets {
		targets[i] = fmt.Sprintf("t%d.%s", i%9, host)
	}
	p := map[string]any{"scanner": "nuclei", "targets": targets}
	if budget != nil {
		p["budget"] = budget
	}
	raw, _ := json.Marshal(p)
	cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmds.Create(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, cmd.ID, sensor.String()); err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	if _, err := cmds.db.ExecContext(ctx, `UPDATE commands SET status = 'running', started_at = NOW() WHERE id = $1`, cmd.ID.String()); err != nil {
		t.Fatal(err)
	}
	return cmd.ID
}

type progressRow struct {
	done, total sql.NullInt64
	at          sql.NullTime
}

func readProgress(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) progressRow {
	t.Helper()
	var p progressRow
	if err := db.QueryRowContext(ctx, `SELECT progress_done, progress_total, last_progress_at FROM commands WHERE id = $1`, id.String()).
		Scan(&p.done, &p.total, &p.at); err != nil {
		t.Fatal(err)
	}
	return p
}

// Progress is recorded only for commands the reporting sensor holds in its
// tenant, is bounded by the command's own target count, never goes down, and
// moves the stall clock only when it grows.
func TestRecordProgress_ScopedBoundedMonotonic(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	b := seedZoneSensor(ctx, t, sqlDB, &tenant, "b", zoneSensorOpts{tools: []string{"nuclei"}})
	x := seedZoneSensor(ctx, t, sqlDB, &other, "x", zoneSensorOpts{tools: []string{"nuclei"}})

	id := newBudgetTestCommand(ctx, t, cmds, tenant, a, 4, nil)

	// Another sensor of the tenant and a sensor of another tenant are ignored.
	for _, w := range []struct{ tenant, sensor shared.ID }{{tenant, b}, {other, x}} {
		if n, err := cmds.RecordProgress(ctx, w.tenant, w.sensor, map[string]command.Progress{id.String(): {Done: 3, Total: 4}}); err != nil || n != 0 {
			t.Fatalf("non-holder recorded progress: %d %v", n, err)
		}
	}
	if p := readProgress(ctx, t, sqlDB, id); p.total.Valid {
		t.Fatalf("progress recorded from a non-holder: %+v", p)
	}

	// The holder's report: a total above the command's 4 targets is bounded.
	if n, err := cmds.RecordProgress(ctx, tenant, a, map[string]command.Progress{id.String(): {Done: 999, Total: 1000}, "not-an-id": {Done: 1, Total: 1}}); err != nil || n != 1 {
		t.Fatalf("record: %d %v", n, err)
	}
	p := readProgress(ctx, t, sqlDB, id)
	if p.done.Int64 != 4 || p.total.Int64 != 4 || !p.at.Valid {
		t.Fatalf("bounded progress: %+v", p)
	}

	// Lower done never goes down; an unchanged count keeps the stall clock.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET progress_done = 2, last_progress_at = NOW() - interval '1 hour' WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := cmds.RecordProgress(ctx, tenant, a, map[string]command.Progress{id.String(): {Done: 1, Total: 4}}); err != nil {
		t.Fatal(err)
	}
	p = readProgress(ctx, t, sqlDB, id)
	if p.done.Int64 != 2 || time.Since(p.at.Time) < 50*time.Minute {
		t.Fatalf("progress went down or the clock moved without progress: %+v", p)
	}
	if _, err := cmds.RecordProgress(ctx, tenant, a, map[string]command.Progress{id.String(): {Done: 3, Total: 4}}); err != nil {
		t.Fatal(err)
	}
	if p = readProgress(ctx, t, sqlDB, id); p.done.Int64 != 3 || time.Since(p.at.Time) > time.Minute {
		t.Fatalf("growth did not move the clock: %+v", p)
	}

	// The same progress again writes nothing: a heartbeat repeats it until
	// the task advances.
	if n, err := cmds.RecordProgress(ctx, tenant, a, map[string]command.Progress{id.String(): {Done: 3, Total: 4}}); err != nil || n != 0 {
		t.Fatalf("unchanged progress wrote %d rows (want 0): %v", n, err)
	}

	// A completed command is not touched.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}
	if n, err := cmds.RecordProgress(ctx, tenant, a, map[string]command.Progress{id.String(): {Done: 4, Total: 4}}); err != nil || n != 0 {
		t.Fatalf("a completed command recorded progress: %d %v", n, err)
	}
}

// A running task that finished no target for its stall window is asked to
// stop and hand back what it finished, and re-queued when no answer comes
// within the grace; one past twice its budget plus the grace is re-queued
// at once. A slow but progressing task, a finished count, a task without a
// budget and a fresh task are left alone. A new claim starts with no
// progress.
func TestRequeueStalledCommands(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	budget := &toolbudget.Task{TargetSeconds: 60, TaskSeconds: 600, StallSeconds: 300}

	set := func(id shared.ID, sql string) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET `+sql+` WHERE id = $1`, id.String()); err != nil {
			t.Fatal(err)
		}
	}
	stalled := newBudgetTestCommand(ctx, t, cmds, tenant, a, 10, budget)
	set(stalled, `progress_done = 3, progress_total = 10, last_progress_at = NOW() - interval '6 minutes', started_at = NOW() - interval '7 minutes'`)
	slow := newBudgetTestCommand(ctx, t, cmds, tenant, a, 10, budget)
	set(slow, `progress_done = 3, progress_total = 10, last_progress_at = NOW() - interval '1 minute', started_at = NOW() - interval '15 minutes'`)
	finished := newBudgetTestCommand(ctx, t, cmds, tenant, a, 10, budget)
	set(finished, `progress_done = 10, progress_total = 10, last_progress_at = NOW() - interval '9 minutes', started_at = NOW() - interval '10 minutes'`)
	overrun := newBudgetTestCommand(ctx, t, cmds, tenant, a, 10, budget)
	set(overrun, `progress_done = 9, progress_total = 10, last_progress_at = NOW(), started_at = NOW() - interval '26 minutes'`)
	noBudget := newBudgetTestCommand(ctx, t, cmds, tenant, a, 10, nil)
	set(noBudget, `progress_done = 1, progress_total = 10, last_progress_at = NOW() - interval '5 hours', started_at = NOW() - interval '5 hours'`)
	// An older sensor reports no progress: never cut here, even far past
	// twice its budget (its lease and the run's cap bound it).
	silent := newBudgetTestCommand(ctx, t, cmds, tenant, a, 10, budget)
	set(silent, `started_at = NOW() - interval '3 hours'`)
	// A batch tool (httpx, naabu) reports its total but finishes no target
	// until it exits: no finished target yet is not a stall, only the
	// overrun limit bounds it (live, 2026-10-14: httpx re-queued three
	// times at the stall window and exhausted).
	batch := newBudgetTestCommand(ctx, t, cmds, tenant, a, 10, budget)
	set(batch, `progress_done = 0, progress_total = 10, last_progress_at = NOW() - interval '9 minutes', started_at = NOW() - interval '9 minutes'`)

	// A stalled task is first asked to stop and hand back what it
	// finished; only the stalled one is asked.
	stops, err := cmds.RequestStopForStalled(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ids := tenantRequeued(stops, tenant); len(ids) != 1 || ids[stalled.String()].SensorID == nil {
		t.Fatalf("stop requested for %v, want only %s", ids, stalled)
	}
	if ids, err := cmds.CommandsToStop(ctx, tenant, a, []string{stalled.String(), slow.String(), "not-an-id"}); err != nil || len(ids) != 1 || ids[0] != stalled.String() {
		t.Fatalf("commands to stop %v %v", ids, err)
	}
	// Within the grace it is not re-queued; the overrun is at once.
	rq, err := cmds.RequeueStalledCommands(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := requeuedIDs(rq)[stalled.String()]; ok {
		t.Fatal("a stalled task was re-queued before its sensor could hand it back")
	}
	// No answer within the grace: re-queued.
	set(stalled, `stop_requested_at = NOW() - interval '6 minutes'`)
	more, err := cmds.RequeueStalledCommands(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rq = append(rq, more...)
	got := requeuedIDs(rq)
	for _, keep := range []shared.ID{slow, finished, noBudget, silent, batch} {
		if _, ok := got[keep.String()]; ok {
			t.Errorf("command %s re-queued, want it left running", keep)
		}
	}
	for id, msg := range map[shared.ID]string{stalled: command.StalledMessage, overrun: command.OverrunMessage} {
		r, ok := got[id.String()]
		if !ok || r.SensorID == nil || *r.SensorID != a {
			t.Fatalf("command %s not re-queued with its holder: %+v", id, r)
		}
		c, err := cmds.GetByTenantAndID(ctx, tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		if c.Status != command.CommandStatusPending || c.SensorID != nil || c.DispatchAttempts != 1 || c.ErrorMessage != msg {
			t.Fatalf("re-queued %s: status %s sensor %v attempts %d msg %q", id, c.Status, c.SensorID, c.DispatchAttempts, c.ErrorMessage)
		}
		if p := readProgress(ctx, t, sqlDB, id); p.done.Valid || p.total.Valid || p.at.Valid {
			t.Fatalf("progress kept after the re-queue: %+v", p)
		}
	}

	// The next claim starts a clean count.
	set(slow, `status = 'pending', sensor_id = NULL`)
	if ok, err := cmds.ClaimForSensor(ctx, tenant, slow, a.String()); err != nil || !ok {
		t.Fatalf("re-claim: %v %v", ok, err)
	}
	if p := readProgress(ctx, t, sqlDB, slow); p.done.Valid || p.total.Valid {
		t.Fatalf("a new claim kept the old progress: %+v", p)
	}
}

// tenantRequeued is requeuedIDs limited to one tenant (the sweeps are
// global; other tests' rows are not this test's business).
func tenantRequeued(rq []command.RequeuedCommand, tenant shared.ID) map[string]command.RequeuedCommand {
	out := map[string]command.RequeuedCommand{}
	for _, r := range rq {
		if r.TenantID == tenant {
			out[r.ID.String()] = r
		}
	}
	return out
}
