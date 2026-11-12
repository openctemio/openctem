package postgres

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func (f *deadlineFixture) commandError(t *testing.T, id shared.ID) string {
	t.Helper()
	var msg string
	if err := f.db.QueryRowContext(f.ctx, `SELECT COALESCE(error_message, '') FROM commands WHERE id = $1`, id.String()).Scan(&msg); err != nil {
		t.Fatalf("read command: %v", err)
	}
	return msg
}

// A command closed at its run's deadline says what is known about it: never
// picked up, finished every target on the sensor without a result arriving
// (live 2026-10-25: progress 7/7, then nothing), or no result at all.
func TestRunDeadline_CommandMessageSaysWhatIsKnown(t *testing.T) {
	f := newDeadlineFixture(t)
	run, sr := f.newRun(t, scanworkflow.TriggerTypeSchedule, 0)
	pending := f.command(t, run, sr, "pending", "a.example")
	finished := f.command(t, run, sr, "running", "b.example", "c.example")
	f.exec(t, `UPDATE commands SET progress_done = 2, progress_total = 2, last_progress_at = NOW() WHERE id = $1`, finished)
	halfway := f.command(t, run, sr, "running", "d.example", "e.example")
	f.exec(t, `UPDATE commands SET progress_done = 1, progress_total = 2 WHERE id = $1`, halfway)
	silent := f.command(t, run, sr, "running", "f.example")
	f.pastDeadline(t, run)

	if _, err := f.runs.MarkTimedOutRuns(f.ctx); err != nil {
		t.Fatalf("MarkTimedOutRuns: %v", err)
	}
	for id, want := range map[shared.ID]string{
		pending:  DeadlineMsgNotPickedUp,
		finished: DeadlineMsgToolFinished,
		halfway:  DeadlineMsgNoResult,
		silent:   DeadlineMsgNoResult,
	} {
		if st, _ := f.commandStatus(t, id); st != "failed" {
			t.Fatalf("command %s = %q, want failed", id, st)
		}
		if got := f.commandError(t, id); got != want {
			t.Errorf("command %s message %q, want %q", id, got, want)
		}
	}
}

// The deadline the database fixes when a run starts is put back on the
// run, so its commands can carry it to the sensor: on create (a run
// started before it is stored) and on the update that starts a stored run.
func TestRunDeadline_ReturnedToTheRun(t *testing.T) {
	f := newDeadlineFixture(t)
	run, _ := f.newRun(t, scanworkflow.TriggerTypeManual, 0)
	if run.DeadlineAt == nil {
		t.Fatal("create did not return the run's deadline")
	}
	stored, _ := f.runs.GetByTenantAndID(f.ctx, f.tenant, run.ID)
	if stored.DeadlineAt == nil || !stored.DeadlineAt.Equal(*run.DeadlineAt) {
		t.Fatalf("returned %v, stored %v", run.DeadlineAt, stored.DeadlineAt)
	}

	tpl, _ := shared.IDFromString(quickScanTemplate)
	later, _ := scanrun.NewRun(tpl, f.tenant, nil, scanworkflow.TriggerTypeManual, "", map[string]any{})
	later.ScanID = &f.scan
	if err := f.runs.Create(f.ctx, later); err != nil {
		t.Fatalf("create run: %v", err)
	}
	if later.DeadlineAt != nil {
		t.Fatalf("a run that has not started has deadline %v", later.DeadlineAt)
	}
	later.Start()
	if err := f.runs.Update(f.ctx, later); err != nil {
		t.Fatalf("start run: %v", err)
	}
	if later.DeadlineAt == nil || later.DeadlineAt.Sub(*later.StartedAt) < 899*time.Second {
		t.Fatalf("deadline after start = %v (started %v), want started + 900s", later.DeadlineAt, later.StartedAt)
	}

	// The run counts toward the concurrency limits: the guarded create
	// returns the deadline too.
	limited, _ := scanrun.NewRun(tpl, f.tenant, nil, scanworkflow.TriggerTypeManual, "", map[string]any{})
	limited.ScanID = &f.scan
	limited.Start()
	if err := f.runs.CreateRunIfUnderLimit(f.ctx, limited, 100, 100); err != nil {
		t.Fatalf("create run under limit: %v", err)
	}
	if limited.DeadlineAt == nil {
		t.Fatal("CreateRunIfUnderLimit did not return the run's deadline")
	}
}
