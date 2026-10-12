package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Canceling a run reaches the sensors (RFC-046 §8): its open step runs and
// commands end canceled in one statement, the commands lose their lease so
// the expired-lease sweep never re-queues them, the sensor holding one is told
// to stop on its next heartbeat and asked to ring again soon. Only the run's
// own tenant can close it. Against the real SQL.

type cancelFixture struct {
	ctx    context.Context
	db     *sql.DB
	runs   *ScanRunRepository
	steps  *StepRunRepository
	cmds   *CommandRepository
	tenant shared.ID
	scan   shared.ID
}

func newCancelFixture(t *testing.T) *cancelFixture {
	t.Helper()
	ctx := context.Background()
	db := openScanDB(t)
	tenant, scan := seedCounterScan(ctx, t, db)
	return &cancelFixture{
		ctx: ctx, db: db, tenant: tenant, scan: scan,
		runs:  NewScanRunRepository(&DB{DB: db}),
		steps: NewStepRunRepository(&DB{DB: db}),
		cmds:  NewCommandRepository(&DB{DB: db}),
	}
}

func (f *cancelFixture) sensor(t *testing.T, tenant shared.ID) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status)
		VALUES ($1, $2, $3, $4, 'p', 'active')`, id.String(), tenant.String(), "cancel-"+id.String(), "h-"+id.String()); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}
	return id
}

// command seeds a scan command of run in status; a claimed status gets the
// sensor, an acknowledgement and a live lease.
func (f *cancelFixture) command(t *testing.T, tenant shared.ID, run shared.ID, sensor *shared.ID, status string) shared.ID {
	t.Helper()
	id := shared.NewID()
	payload, _ := json.Marshal(map[string]any{"scan_run_id": run.String(), "target": "h.example"})
	var sensorArg any
	if sensor != nil {
		sensorArg = sensor.String()
	}
	if _, err := f.db.ExecContext(f.ctx, `
		INSERT INTO commands (id, tenant_id, sensor_id, type, status, payload, acknowledged_at, lease_expires_at)
		VALUES ($1, $2, $3, 'scan', $4::text, $5,
		        CASE WHEN $4::text IN ('acknowledged', 'running', 'completed') THEN NOW() END,
		        CASE WHEN $4::text IN ('acknowledged', 'running') THEN NOW() + interval '5 minutes' END)`,
		id.String(), tenant.String(), sensorArg, status, payload); err != nil {
		t.Fatalf("seed command: %v", err)
	}
	return id
}

func (f *cancelFixture) commandState(t *testing.T, id shared.ID) (status string, leased bool) {
	t.Helper()
	if err := f.db.QueryRowContext(f.ctx,
		`SELECT status, lease_expires_at IS NOT NULL FROM commands WHERE id = $1`, id.String()).Scan(&status, &leased); err != nil {
		t.Fatalf("read command: %v", err)
	}
	return status, leased
}

func (f *cancelFixture) cancelRun(t *testing.T, run shared.ID) {
	t.Helper()
	if err := f.runs.UpdateStatus(f.ctx, run, scanrun.RunStatusCanceled, "Canceled by user"); err != nil {
		t.Fatalf("cancel run: %v", err)
	}
}

func TestCloseCanceledRun_ClosesStepsAndCommandsOnce(t *testing.T) {
	f := newCancelFixture(t)
	s1, s2 := f.sensor(t, f.tenant), f.sensor(t, f.tenant)

	run := seedCounterRun(f.ctx, t, f.runs, f.tenant, f.scan)
	openStep := seedStepRun(f.ctx, t, f.steps, run.ID)
	doneStep := seedStepRun(f.ctx, t, f.steps, run.ID)
	if err := f.steps.Complete(f.ctx, doneStep.ID, 0, nil); err != nil {
		t.Fatalf("complete step: %v", err)
	}
	running := f.command(t, f.tenant, run.ID, &s1, "running")
	pinned := f.command(t, f.tenant, run.ID, &s2, "pending")
	queued := f.command(t, f.tenant, run.ID, nil, "pending")
	done := f.command(t, f.tenant, run.ID, &s1, "completed")

	// Another run of the same tenant and scan is left alone.
	other := seedCounterRun(f.ctx, t, f.runs, f.tenant, f.scan)
	otherCmd := f.command(t, f.tenant, other.ID, &s1, "running")

	// An open run is not closed: the run must be canceled first.
	if c, err := f.runs.CloseCanceledRun(f.ctx, f.tenant, run.ID); err != nil || c.Commands != 0 || c.Steps != 0 {
		t.Fatalf("open run closure = %+v, %v; want nothing", c, err)
	}

	f.cancelRun(t, run.ID)

	// Another tenant cannot close it, even knowing the id.
	stranger, _ := seedCounterScan(f.ctx, t, f.db)
	if c, err := f.runs.CloseCanceledRun(f.ctx, stranger, run.ID); err != nil || c.Commands != 0 || c.Steps != 0 {
		t.Fatalf("cross-tenant closure = %+v, %v; want nothing", c, err)
	}
	if st, _ := f.commandState(t, running); st != "running" {
		t.Fatalf("cross-tenant close changed a command to %q", st)
	}

	c, err := f.runs.CloseCanceledRun(f.ctx, f.tenant, run.ID)
	if err != nil {
		t.Fatalf("CloseCanceledRun: %v", err)
	}
	if c.Steps != 1 || c.Commands != 3 {
		t.Fatalf("closure = %+v, want 1 step and 3 commands", c)
	}
	got := []string{}
	for _, s := range c.Sensors {
		got = append(got, s.String())
	}
	want := []string{s1.String(), s2.String()}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sensors = %v, want the two holders %v", got, want)
	}

	for _, id := range []shared.ID{running, pinned, queued} {
		if st, leased := f.commandState(t, id); st != "canceled" || leased {
			t.Fatalf("command %s: status=%q leased=%v, want canceled without a lease", id, st, leased)
		}
	}
	if st, _ := f.commandState(t, done); st != "completed" {
		t.Fatalf("completed command became %q", st)
	}
	if st, _ := f.commandState(t, otherCmd); st != "running" {
		t.Fatalf("another run's command became %q", st)
	}
	if st := readStepRun(f.ctx, t, f.steps, openStep.ID).Status; st != scanrun.StepRunStatusCanceled {
		t.Fatalf("open step = %q, want canceled", st)
	}
	if st := readStepRun(f.ctx, t, f.steps, doneStep.ID).Status; st != scanrun.StepRunStatusCompleted {
		t.Fatalf("completed step became %q", st)
	}

	// The sensor still running it is told to stop; the other run's command,
	// which it still holds, is not.
	ids, err := f.cmds.CommandsToCancel(f.ctx, f.tenant, s1, []string{running.String(), otherCmd.String()})
	if err != nil || !reflect.DeepEqual(ids, []string{running.String()}) {
		t.Fatalf("cancel ids = %v (%v), want only the canceled command", ids, err)
	}

	// Repeating is a no-op.
	if c, err := f.runs.CloseCanceledRun(f.ctx, f.tenant, run.ID); err != nil || c.Commands != 0 || c.Steps != 0 {
		t.Fatalf("second closure = %+v, %v; want nothing", c, err)
	}
}

// A sensor that went offline holding a command: its lease runs out after the
// cancel. The sweep must not re-queue the canceled command (another sensor
// would then scan what the user stopped), and when the sensor comes back and
// reports it, it is told to stop.
func TestCloseCanceledRun_OfflineSensorAndLeaseExpiry(t *testing.T) {
	f := newCancelFixture(t)
	s := f.sensor(t, f.tenant)
	run := seedCounterRun(f.ctx, t, f.runs, f.tenant, f.scan)
	held := f.command(t, f.tenant, run.ID, &s, "running")
	// The lease ran out while the sensor was offline, before the cancel.
	if _, err := f.db.ExecContext(f.ctx,
		`UPDATE commands SET lease_expires_at = NOW() - interval '1 minute' WHERE id = $1`, held.String()); err != nil {
		t.Fatal(err)
	}
	f.cancelRun(t, run.ID)
	if _, err := f.runs.CloseCanceledRun(f.ctx, f.tenant, run.ID); err != nil {
		t.Fatalf("CloseCanceledRun: %v", err)
	}

	requeued, err := f.cmds.RequeueExpiredLeases(f.ctx)
	if err != nil {
		t.Fatalf("RequeueExpiredLeases: %v", err)
	}
	for _, rq := range requeued {
		if rq.ID == held {
			t.Fatalf("the canceled command was re-queued")
		}
	}
	if st, _ := f.commandState(t, held); st != "canceled" {
		t.Fatalf("command = %q after the sweep, want canceled", st)
	}
	if ids, err := f.cmds.CommandsToCancel(f.ctx, f.tenant, s, []string{held.String()}); err != nil || len(ids) != 1 {
		t.Fatalf("back online: cancel ids = %v (%v), want the canceled command", ids, err)
	}
}

// The doorbell asks a sensor to ring again soon while a command it claimed was
// canceled recently; only its own commands count.
func TestPendingWorkForSensor_RecentlyCanceled(t *testing.T) {
	f := newCancelFixture(t)
	s, peer := f.sensor(t, f.tenant), f.sensor(t, f.tenant)
	run := seedCounterRun(f.ctx, t, f.runs, f.tenant, f.scan)

	recentlyCanceled := func(sensor shared.ID, tenant shared.ID) int {
		t.Helper()
		w, err := f.cmds.PendingWorkForSensor(f.ctx, tenant, sensor, nil, 100)
		if err != nil {
			t.Fatalf("PendingWorkForSensor: %v", err)
		}
		return w.RecentlyCanceled
	}

	held := f.command(t, f.tenant, run.ID, &s, "running")
	f.command(t, f.tenant, run.ID, nil, "pending") // never claimed
	if n := recentlyCanceled(s, f.tenant); n != 0 {
		t.Fatalf("before the cancel: %d, want 0", n)
	}
	f.cancelRun(t, run.ID)
	if _, err := f.runs.CloseCanceledRun(f.ctx, f.tenant, run.ID); err != nil {
		t.Fatal(err)
	}
	if n := recentlyCanceled(s, f.tenant); n != 1 {
		t.Fatalf("holder: %d, want 1 (the pending one was never claimed)", n)
	}
	if n := recentlyCanceled(peer, f.tenant); n != 0 {
		t.Fatalf("another sensor: %d, want 0", n)
	}
	// The same sensor id asked under another tenant sees nothing.
	stranger, _ := seedCounterScan(f.ctx, t, f.db)
	if n := recentlyCanceled(s, stranger); n != 0 {
		t.Fatalf("another tenant: %d, want 0", n)
	}
	// Once the lease period has passed, it is no longer news.
	if _, err := f.db.ExecContext(f.ctx,
		`UPDATE commands SET completed_at = NOW() - interval '1 hour' WHERE id = $1`, held.String()); err != nil {
		t.Fatal(err)
	}
	if n := recentlyCanceled(s, f.tenant); n != 0 {
		t.Fatalf("an hour later: %d, want 0", n)
	}
}
