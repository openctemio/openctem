package postgres

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/toolbudget"
)

// Dispatch attempts count work a sensor took and lost (a lease that ran
// out, a stall, an overrun, a refusal), never a "not now": a command a
// sensor hands back because its hosts are busy there or it has no free
// slot, and a command that waits for its hosts, must never be failed as
// exhausted. Requires DATABASE_URL.

// exhaustLimit is the dispatch attempts limit the job recovery controller
// uses by default.
const exhaustLimit = 3

func readAttempts(ctx context.Context, t *testing.T, cmds *CommandRepository, tenant, id shared.ID) *command.Command {
	t.Helper()
	c, err := cmds.GetByTenantAndID(ctx, tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// failsExhausted runs the exhaustion sweep and reports whether it failed id.
func failsExhausted(ctx context.Context, t *testing.T, cmds *CommandRepository, id shared.ID) bool {
	t.Helper()
	failed, err := cmds.FailExhaustedCommandsReturning(ctx, exhaustLimit)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range failed {
		if c.ID == id {
			return true
		}
	}
	return false
}

// A sensor that hands a claimed command back ("hosts busy here", "no free
// slot") many times does not use up its dispatch attempts.
func TestDispatchAttempts_HandBackIsNotAnAttempt(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})

	raw, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": []string{uniqueTestHost()}})
	cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmds.Create(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	reasons := []string{
		command.ReleasedBySensorPrefix + command.ReleaseReasonHostsBusy,
		command.ReleasedBySensorPrefix + "no free slot",
	}
	for i := range 6 {
		// The back-off between returns is not under test here.
		if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET scheduled_at = NULL WHERE id = $1`, cmd.ID.String()); err != nil {
			t.Fatal(err)
		}
		if ok, err := cmds.ClaimForSensor(ctx, tenant, cmd.ID, a.String()); err != nil || !ok {
			t.Fatalf("claim %d: %v %v", i, ok, err)
		}
		if ok, err := cmds.ReleaseForSensor(ctx, tenant, cmd.ID, a.String(), reasons[i%len(reasons)]); err != nil || !ok {
			t.Fatalf("release %d: %v %v", i, ok, err)
		}
		if failsExhausted(ctx, t, cmds, cmd.ID) {
			t.Fatalf("a command handed back %d times was failed as exhausted", i+1)
		}
	}
	c := readAttempts(ctx, t, cmds, tenant, cmd.ID)
	if c.DispatchAttempts != 0 || c.Status != command.CommandStatusPending || c.SensorID != nil {
		t.Fatalf("after six hand-backs: attempts %d status %s sensor %v", c.DispatchAttempts, c.Status, c.SensorID)
	}
}

// A command that waits for hosts another command of its tenant holds is
// neither claimable nor charged while it waits, whatever the sweeps do.
func TestDispatchAttempts_WaitingForHostsNeverExhausts(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	host := uniqueTestHost()

	newCmd := func() *command.Command {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": []string{host}})
		c, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := cmds.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	holder := newCmd()
	if ok, err := cmds.ClaimForSensor(ctx, tenant, holder.ID, a.String()); err != nil || !ok {
		t.Fatalf("claim holder: %v %v", ok, err)
	}
	waiter := newCmd()
	for i := range 5 {
		if ok, err := cmds.ClaimForSensor(ctx, tenant, waiter.ID, a.String()); err != nil || ok {
			t.Fatalf("round %d: a command whose host is held was claimed: %v %v", i, ok, err)
		}
		if _, err := cmds.RequeueExpiredLeases(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := cmds.RequeueStalledCommands(ctx); err != nil {
			t.Fatal(err)
		}
		if failsExhausted(ctx, t, cmds, waiter.ID) {
			t.Fatalf("round %d: a command waiting for its hosts was failed as exhausted", i)
		}
	}
	c := readAttempts(ctx, t, cmds, tenant, waiter.ID)
	if c.DispatchAttempts != 0 || c.Status != command.CommandStatusPending {
		t.Fatalf("waiting command: attempts %d status %s", c.DispatchAttempts, c.Status)
	}
}

// Live replay (2026-10-14): a step with a one-hour timeout whose task budget
// estimate is five minutes, running and reporting progress for sixteen
// minutes, is within the time its sensor was given: it is not re-queued
// and keeps its attempts. Past the timeout plus the grace it is taken back.
// Without a timeout the overrun stays twice the budget.
func TestRequeueStalledCommands_HonoursStepTimeout(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	budget := &toolbudget.Task{TargetSeconds: 15, TaskSeconds: 300, StallSeconds: 300}

	set := func(id shared.ID, sql string) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET `+sql+` WHERE id = $1`, id.String()); err != nil {
			t.Fatal(err)
		}
	}
	withTimeout := func(seconds any) shared.ID {
		t.Helper()
		id := newBudgetTestCommand(ctx, t, cmds, tenant, a, 71, budget)
		b, _ := json.Marshal(seconds)
		set(id, `payload = jsonb_set(payload, '{timeout_seconds}', '`+string(b)+`'::jsonb)`)
		return id
	}
	// Progressing: the progress clock moved a minute ago.
	const progressing = `progress_done = 40, progress_total = 71, last_progress_at = NOW() - interval '1 minute', `

	live := withTimeout(3600)
	set(live, progressing+`started_at = NOW() - interval '16 minutes'`)
	pastTimeout := withTimeout(3600)
	set(pastTimeout, progressing+`started_at = NOW() - interval '66 minutes'`)
	noTimeout := withTimeout(0)
	set(noTimeout, progressing+`started_at = NOW() - interval '16 minutes'`)
	// A timeout that is not a whole number is ignored: twice the budget.
	badTimeout := withTimeout("3600; DROP TABLE commands")
	set(badTimeout, progressing+`started_at = NOW() - interval '16 minutes'`)
	// Capped at 24 h, whatever the payload says.
	huge := withTimeout(999999999)
	set(huge, progressing+`started_at = NOW() - interval '24 hours 6 minutes'`)

	rq, err := cmds.RequeueStalledCommands(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := tenantRequeued(rq, tenant)
	if _, ok := got[live.String()]; ok {
		t.Fatal("a task within its step timeout was re-queued at twice its budget")
	}
	if c := readAttempts(ctx, t, cmds, tenant, live); c.DispatchAttempts != 0 || c.Status != command.CommandStatusRunning {
		t.Fatalf("live task: attempts %d status %s", c.DispatchAttempts, c.Status)
	}
	for _, id := range []shared.ID{pastTimeout, noTimeout, badTimeout, huge} {
		if _, ok := got[id.String()]; !ok {
			t.Errorf("command %s past its deadline was not re-queued", id)
			continue
		}
		c := readAttempts(ctx, t, cmds, tenant, id)
		if c.DispatchAttempts != 1 || c.ErrorMessage != command.OverrunMessage {
			t.Errorf("command %s: attempts %d msg %q", id, c.DispatchAttempts, c.ErrorMessage)
		}
	}
}
