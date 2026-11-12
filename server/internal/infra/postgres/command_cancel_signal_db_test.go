package postgres

import (
	"context"
	"errors"
	"slices"
	"testing"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The heartbeat answers a sensor with the commands it reports holding but
// must stop (cancel_command_ids, which sdk-go's poller acts on): canceled,
// closed by the platform (a run timeout fails them), re-queued after the
// lease ran out, held by another sensor, or gone. Before, nothing told the
// sensor: a canceled or timed-out scan kept running to the end. A command
// the sensor still holds, or one it already completed, is never in the list.
// Requires DATABASE_URL.
func TestCommandsToCancel(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	db := &DB{DB: sqlDB}
	cmds := NewCommandRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	b := seedZoneSensor(ctx, t, sqlDB, &tenant, "b", zoneSensorOpts{tools: []string{"nuclei"}})

	claim := func(sensor shared.ID) shared.ID {
		id := newLeaseTestCommand(ctx, t, cmds, tenant)
		if ok, err := cmds.ClaimForSensor(ctx, tenant, id, sensor.String()); err != nil || !ok {
			t.Fatalf("claim: %v %v", ok, err)
		}
		return id
	}
	set := func(id shared.ID, sql string) {
		if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET `+sql+` WHERE id = $1`, id.String()); err != nil {
			t.Fatal(err)
		}
	}

	held := claim(a)
	running := claim(a)
	set(running, `status = 'running', started_at = NOW()`)
	completed := claim(a)
	set(completed, `status = 'completed', completed_at = NOW()`)
	canceled := claim(a)
	set(canceled, `status = 'canceled', completed_at = NOW()`)
	timedOut := claim(a)
	set(timedOut, `status = 'failed', completed_at = NOW(), error_message = 'scan run timed out before this command reported a result'`)
	requeued := claim(a)
	set(requeued, `status = 'pending', sensor_id = NULL, acknowledged_at = NULL, lease_expires_at = NULL`)
	elsewhere := claim(b)
	pinned := newLeaseTestCommand(ctx, t, cmds, tenant)
	set(pinned, `sensor_id = '`+a.String()+`'`)
	gone := shared.NewID()
	otherTenant := seedTestTenant(ctx, t, sqlDB)
	foreign := newLeaseTestCommand(ctx, t, cmds, otherTenant)

	reported := []string{
		held.String(), running.String(), pinned.String(), completed.String(), canceled.String(), timedOut.String(),
		requeued.String(), elsewhere.String(), gone.String(), foreign.String(), "not-a-uuid",
	}
	got, err := cmds.CommandsToCancel(ctx, tenant, a, reported)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	want := []string{canceled.String(), timedOut.String(), requeued.String(), elsewhere.String(), gone.String(), foreign.String()}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("CommandsToCancel = %v\nwant %v", got, want)
	}

	if got, err := cmds.CommandsToCancel(ctx, tenant, a, nil); err != nil || len(got) != 0 {
		t.Fatalf("empty running list: %v %v", got, err)
	}
}

// Canceling a command touches only an open one (pending, acknowledged,
// running); a second cancel is a no-op. Before, CancelCommand read the
// command, refused only "completed", and wrote it back unconditionally: a
// failed or expired
// command became canceled, and a sensor completing the command between the
// read and the write had its accepted result overwritten.
func TestCancelCommand_OnlyOpenCommands(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	cmds := NewCommandRepository(db)
	svc := commandapp.NewService(cmds, logger.NewNop())
	tenant := seedTestTenant(ctx, t, sqlDB)
	set := func(id shared.ID, sql string) {
		if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET `+sql+` WHERE id = $1`, id.String()); err != nil {
			t.Fatal(err)
		}
	}
	status := func(id shared.ID) command.CommandStatus {
		c, err := cmds.GetByTenantAndID(ctx, tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		return c.Status
	}

	for _, closed := range []string{"failed", "expired", "completed"} {
		id := newLeaseTestCommand(ctx, t, cmds, tenant)
		set(id, `status = '`+closed+`', completed_at = NOW()`)
		if _, err := svc.CancelCommand(ctx, tenant.String(), id.String()); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("cancel a %s command: err %v, want a validation error", closed, err)
		}
		if got := status(id); string(got) != closed {
			t.Errorf("a %s command became %s", closed, got)
		}
	}

	// Canceling twice is a no-op, not an error.
	again := newLeaseTestCommand(ctx, t, cmds, tenant)
	set(again, `status = 'canceled', completed_at = NOW()`)
	if c, err := svc.CancelCommand(ctx, tenant.String(), again.String()); err != nil || c.Status != command.CommandStatusCanceled {
		t.Fatalf("cancel a canceled command: %v %v", c, err)
	}

	open := newLeaseTestCommand(ctx, t, cmds, tenant)
	set(open, `status = 'running', started_at = NOW()`)
	if c, err := svc.CancelCommand(ctx, tenant.String(), open.String()); err != nil || c.Status != command.CommandStatusCanceled {
		t.Fatalf("cancel a running command: %v %v", c, err)
	}
	if got := status(open); got != command.CommandStatusCanceled {
		t.Fatalf("stored status %s", got)
	}

	// The write itself is conditional: a command that finished after the
	// read is left as it is.
	raced := newLeaseTestCommand(ctx, t, cmds, tenant)
	stale, err := cmds.GetByTenantAndID(ctx, tenant, raced)
	if err != nil {
		t.Fatal(err)
	}
	set(raced, `status = 'completed', completed_at = NOW()`)
	stale.Cancel()
	if ok, err := cmds.CancelIfOpen(ctx, stale); err != nil || ok {
		t.Fatalf("CancelIfOpen on a command completed meanwhile: %v %v", ok, err)
	}
	if got := status(raced); got != command.CommandStatusCompleted {
		t.Fatalf("a completed command became %s", got)
	}
}
