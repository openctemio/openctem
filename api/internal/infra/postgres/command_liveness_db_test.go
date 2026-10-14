package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/toolbudget"
)

// Stall decided on liveness (research/125). Requires DATABASE_URL.

type livenessRow struct {
	records, bytes, cpu, mark sql.NullInt64
	at, stop                  sql.NullTime
}

func readLiveness(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) livenessRow {
	t.Helper()
	var r livenessRow
	if err := db.QueryRowContext(ctx, `SELECT progress_records, progress_output_bytes, progress_cpu_ms, progress_cpu_mark,
		last_progress_at, stop_requested_at FROM commands WHERE id = $1`, id.String()).
		Scan(&r.records, &r.bytes, &r.cpu, &r.mark, &r.at, &r.stop); err != nil {
		t.Fatal(err)
	}
	return r
}

// Records, output bytes and CPU time are recorded only for the holder, never
// go down, are bounded, and move the stall clock when they grow (CPU by at
// least command.CPUMoveMs since it last counted).
func TestRecordProgress_Liveness(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	x := seedZoneSensor(ctx, t, sqlDB, &other, "x", zoneSensorOpts{tools: []string{"nuclei"}})
	id := newBudgetTestCommand(ctx, t, cmds, tenant, a, 72, nil)
	rec := func(sensorTenant, sensor shared.ID, p command.Progress) int64 {
		t.Helper()
		p.Total = 72
		n, err := cmds.RecordProgress(ctx, sensorTenant, sensor, map[string]command.Progress{id.String(): p})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	stale := func() {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET last_progress_at = NOW() - interval '1 hour', stop_requested_at = NOW() WHERE id = $1`, id.String()); err != nil {
			t.Fatal(err)
		}
	}
	moved := func() bool { return time.Since(readLiveness(ctx, t, sqlDB, id).at.Time) < time.Minute }

	if rec(other, x, command.Progress{Records: 5, CPUMs: 9000}) != 0 {
		t.Fatal("another tenant's sensor recorded liveness")
	}
	rec(tenant, a, command.Progress{CPUMs: 100})
	if l := readLiveness(ctx, t, sqlDB, id); l.cpu.Int64 != 100 || l.mark.Int64 != 100 || !l.at.Valid {
		t.Fatalf("first report %+v", l)
	}

	// CPU below the threshold since the mark: not movement.
	stale()
	rec(tenant, a, command.Progress{CPUMs: 100 + command.CPUMoveMs - 1})
	if moved() || readLiveness(ctx, t, sqlDB, id).mark.Int64 != 100 {
		t.Fatalf("an idle process's CPU counted as movement: %+v", readLiveness(ctx, t, sqlDB, id))
	}
	// At the threshold: movement, the mark moves, the stop request is dropped.
	rec(tenant, a, command.Progress{CPUMs: 100 + command.CPUMoveMs})
	if l := readLiveness(ctx, t, sqlDB, id); !moved() || l.mark.Int64 != 100+command.CPUMoveMs || l.stop.Valid {
		t.Fatalf("CPU growth did not count: %+v", l)
	}

	// Records and bytes: any growth counts; never down; bounded.
	stale()
	rec(tenant, a, command.Progress{Records: 3, OutputBytes: 400, CPUMs: 50})
	if l := readLiveness(ctx, t, sqlDB, id); !moved() || l.records.Int64 != 3 || l.bytes.Int64 != 400 || l.cpu.Int64 != 100+command.CPUMoveMs {
		t.Fatalf("records did not count, or CPU went down: %+v", l)
	}
	stale()
	rec(tenant, a, command.Progress{Records: 1, OutputBytes: 10})
	if moved() || readLiveness(ctx, t, sqlDB, id).records.Int64 != 3 {
		t.Fatal("a lower count moved the clock or went down")
	}
	rec(tenant, a, command.Progress{Records: 1 << 62})
	if l := readLiveness(ctx, t, sqlDB, id); l.records.Int64 != command.MaxLivenessCounter {
		t.Fatalf("records not bounded: %d", l.records.Int64)
	}
}

// The 2026-10-14 incident on liveness: an httpx batch over 72 targets that
// finishes targets rarely is never stalled while its records or CPU time
// move, even with 0 targets done; one whose signals all stop is asked to
// stop. Faked liveness never passes the overrun cap. A sensor that reports
// neither progress nor liveness is bounded by the overrun only.
func TestStall_DecidedOnLiveness(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	b := seedZoneSensor(ctx, t, sqlDB, &tenant, "b", zoneSensorOpts{tools: []string{"nuclei"}})
	budget := &toolbudget.Task{TargetSeconds: 30, TaskSeconds: 600, StallSeconds: 300}
	set := func(id shared.ID, q string) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET `+q+` WHERE id = $1`, id.String()); err != nil {
			t.Fatal(err)
		}
	}
	const old = `progress_total = 72, started_at = NOW() - interval '9 minutes', last_progress_at = NOW() - interval '6 minutes'`

	alive := newBudgetTestCommand(ctx, t, cmds, tenant, a, 72, budget)
	set(alive, old+`, progress_done = 0, progress_cpu_ms = 4000, progress_cpu_mark = 4000`)
	// A heartbeat now: 0 done, but CPU grew by more than the threshold.
	if _, err := cmds.RecordProgress(ctx, tenant, a, map[string]command.Progress{alive.String(): {Done: 0, Total: 72, CPUMs: 4000 + command.CPUMoveMs}}); err != nil {
		t.Fatal(err)
	}
	hung := newBudgetTestCommand(ctx, t, cmds, tenant, a, 72, budget)
	set(hung, old+`, progress_done = 0, progress_cpu_ms = 900, progress_cpu_mark = 900`)
	silentOld := newBudgetTestCommand(ctx, t, cmds, tenant, a, 72, budget)
	set(silentOld, old+`, progress_done = 0`)
	faker := newBudgetTestCommand(ctx, t, cmds, tenant, a, 72, budget)
	set(faker, `progress_total = 72, progress_done = 0, progress_records = 1, started_at = NOW() - interval '26 minutes', last_progress_at = NOW()`)

	stops, err := cmds.RequestStopForStalled(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := tenantRequeued(stops, tenant)
	if _, ok := got[hung.String()]; !ok || len(got) != 1 {
		t.Fatalf("stops requested %v: want only the hung task (alive, silent and faker left)", got)
	}
	// Only the holder is told; another sensor of the tenant is not.
	if ids, _ := cmds.CommandsToStop(ctx, tenant, b, []string{hung.String()}); len(ids) != 0 {
		t.Fatalf("another sensor was told to stop %v", ids)
	}
	if ids, _ := cmds.CommandsToStop(ctx, tenant, a, []string{hung.String(), alive.String()}); len(ids) != 1 || ids[0] != hung.String() {
		t.Fatalf("holder told to stop %v", ids)
	}
	rq, err := cmds.RequeueStalledCommands(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got = tenantRequeued(rq, tenant)
	if r, ok := got[faker.String()]; !ok || len(got) != 1 || r.SensorID == nil {
		t.Fatalf("re-queued %v: want only the faker, past its overrun cap", got)
	}
	c, err := cmds.GetByTenantAndID(ctx, tenant, faker)
	if err != nil || c.ErrorMessage != command.OverrunMessage {
		t.Fatalf("faker %+v %v", c, err)
	}
}

// A stop-requested task its sensor reports failed (it stopped with nothing
// finished) is re-queued with one more attempt, only under the holder's
// fence, and only when a stop was requested.
func TestRequeueStopped(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	id := newBudgetTestCommand(ctx, t, cmds, tenant, a, 3, &toolbudget.Task{TargetSeconds: 30, TaskSeconds: 600, StallSeconds: 300})
	cmd, err := cmds.GetByTenantAndID(ctx, tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	fence := command.Fence{SensorID: a.String(), Status: command.CommandStatusRunning, Epoch: cmd.LeaseEpoch}
	if ok, err := cmds.RequeueStopped(ctx, cmd, fence, "x"); err != nil || ok {
		t.Fatalf("re-queued without a stop request: %v %v", ok, err)
	}
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET stop_requested_at = NOW() WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}
	stale := fence
	stale.Epoch++
	if ok, err := cmds.RequeueStopped(ctx, cmd, stale, "x"); err != nil || ok {
		t.Fatalf("re-queued under a stale fence: %v %v", ok, err)
	}
	if ok, err := cmds.RequeueStopped(ctx, cmd, fence, "stopped empty"); err != nil || !ok {
		t.Fatalf("not re-queued: %v %v", ok, err)
	}
	c, _ := cmds.GetByTenantAndID(ctx, tenant, id)
	if c.Status != command.CommandStatusPending || c.SensorID != nil || c.DispatchAttempts != 1 || c.ErrorMessage != "stopped empty" {
		t.Fatalf("after: %+v", c)
	}
	if l := readLiveness(ctx, t, sqlDB, id); l.stop.Valid {
		t.Fatal("the stop request outlived the re-queue")
	}
}
