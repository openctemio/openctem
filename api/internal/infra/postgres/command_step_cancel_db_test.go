package postgres

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CancelOpenByStepRun stops a streamed step whose source failed: only the
// open commands of that step run, only for the step run's own tenant.
// Against the real SQL (DATABASE_URL).
func TestCancelOpenByStepRun(t *testing.T) {
	f := newCancelFixture(t)
	s1 := f.sensor(t, f.tenant)
	run := seedCounterRun(f.ctx, t, f.runs, f.tenant, f.scan)
	step := seedStepRun(f.ctx, t, f.steps, run.ID)
	other := seedStepRun(f.ctx, t, f.steps, run.ID)

	stepCmd := func(stepRun shared.ID, sensor *shared.ID, status string) shared.ID {
		id := f.command(t, f.tenant, run.ID, sensor, status)
		if _, err := f.db.ExecContext(f.ctx, `UPDATE commands SET scan_run_step_id = $2 WHERE id = $1`, id.String(), stepRun.String()); err != nil {
			t.Fatalf("link command to step: %v", err)
		}
		return id
	}
	running := stepCmd(step.ID, &s1, "running")
	queued := stepCmd(step.ID, nil, "pending")
	done := stepCmd(step.ID, &s1, "completed")
	otherStep := stepCmd(other.ID, &s1, "running")

	// Another tenant, knowing the step run id, cancels nothing.
	stranger, _ := seedCounterScan(f.ctx, t, f.db)
	if n, err := f.cmds.CancelOpenByStepRun(f.ctx, stranger, step.ID); err != nil || n != 0 {
		t.Fatalf("cross-tenant cancel = %d, %v; want 0", n, err)
	}
	if st, _ := f.commandState(t, running); st != "running" {
		t.Fatalf("cross-tenant cancel changed a command to %q", st)
	}

	n, err := f.cmds.CancelOpenByStepRun(f.ctx, f.tenant, step.ID)
	if err != nil || n != 2 {
		t.Fatalf("cancel = %d, %v; want the 2 open commands", n, err)
	}
	for _, id := range []shared.ID{running, queued} {
		if st, leased := f.commandState(t, id); st != "canceled" || leased {
			t.Fatalf("command %s: status=%q leased=%v, want canceled without a lease", id, st, leased)
		}
	}
	if st, _ := f.commandState(t, done); st != "completed" {
		t.Fatalf("completed command became %q", st)
	}
	if st, _ := f.commandState(t, otherStep); st != "running" {
		t.Fatalf("another step's command became %q", st)
	}
	// The holder is told to stop.
	ids, err := f.cmds.CommandsToCancel(f.ctx, f.tenant, s1, []string{running.String(), otherStep.String()})
	if err != nil || len(ids) != 1 || ids[0] != running.String() {
		t.Fatalf("cancel ids = %v (%v), want only the canceled command", ids, err)
	}
}
