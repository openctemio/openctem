package postgres

// Per-task sensor logs (command_logs, RFC-029 §4.4.1) against the real SQL:
// only the holding sensor of the tenant writes, a replay is stored once, the
// per-command caps count dropped lines, a finished command closes after the
// window, reads are scoped to the run and tenant, and retention deletes.

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/commandlog"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func logBatch(tenant, sensor, cmd shared.ID, seq int, msgs ...string) commandlog.Batch {
	lines := make([]commandlog.Line, len(msgs))
	for i, m := range msgs {
		lines[i] = commandlog.Line{TS: time.Now().UTC(), Level: "info", Msg: m}
	}
	raw, _ := json.Marshal(lines)
	return commandlog.Batch{TenantID: tenant, SensorID: sensor, CommandID: cmd, Seq: seq, Lines: lines, JSON: raw}
}

func TestCommandLogs_AppendOwnershipReplayCapsAndRead_DB(t *testing.T) {
	f := newRunTasksFixture(t)
	repo := NewCommandLogRepository(&DB{DB: f.db})
	s1 := f.sensor(t, f.tenant, "edge")
	s2 := f.sensor(t, f.tenant, "other")
	run := seedCounterRun(f.ctx, t, f.runs, f.tenant, f.scan)
	cmd := f.command(t, f.tenant, run.ID, &s1, "running", map[string]any{"scanner": "nuclei"})
	const day = 24 * time.Hour

	res, err := repo.Append(f.ctx, logBatch(f.tenant, s1, cmd, 0, "a", "b"), day, 3, 1<<20)
	if err != nil || res.Stored != 2 || res.Truncated {
		t.Fatalf("first batch: %+v %v", res, err)
	}
	// A replay answers what was stored and stores nothing new.
	res, err = repo.Append(f.ctx, logBatch(f.tenant, s1, cmd, 0, "different"), day, 3, 1<<20)
	if err != nil || res.Stored != 2 {
		t.Fatalf("replay: %+v %v", res, err)
	}

	// Another sensor of the tenant, and another tenant's sensor, are not
	// the holder: not found, nothing stored.
	if _, err := repo.Append(f.ctx, logBatch(f.tenant, s2, cmd, 1, "x"), day, 3, 1<<20); !errors.Is(err, commandlog.ErrNotFound) {
		t.Fatalf("other sensor: %v", err)
	}
	stranger, _ := seedCounterScan(f.ctx, t, f.db)
	ss := f.sensor(t, stranger, "stranger")
	if _, err := repo.Append(f.ctx, logBatch(stranger, ss, cmd, 1, "x"), day, 3, 1<<20); !errors.Is(err, commandlog.ErrNotFound) {
		t.Fatalf("other tenant: %v", err)
	}
	if _, err := repo.Append(f.ctx, logBatch(stranger, s1, cmd, 1, "x"), day, 3, 1<<20); !errors.Is(err, commandlog.ErrNotFound) {
		t.Fatalf("holder's id under another tenant: %v", err)
	}

	// Caps: 3 batches; the 4th is dropped and counted, never stored.
	for seq := 1; seq <= 2; seq++ {
		if res, err := repo.Append(f.ctx, logBatch(f.tenant, s1, cmd, seq, "c"), day, 3, 1<<20); err != nil || res.Stored != 1 {
			t.Fatalf("batch %d: %+v %v", seq, res, err)
		}
	}
	res, err = repo.Append(f.ctx, logBatch(f.tenant, s1, cmd, 3, "d", "e"), day, 3, 1<<20)
	if err != nil || !res.Truncated || res.Dropped != 2 || res.Stored != 0 {
		t.Fatalf("over the batch cap: %+v %v", res, err)
	}

	page, err := repo.ListForRunTask(f.ctx, f.tenant, run.ID, cmd, 100)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range page.Lines {
		got = append(got, l.Msg)
	}
	if len(got) != 4 || got[0] != "a" || got[1] != "b" || !page.Truncated {
		t.Fatalf("read %v truncated=%v", got, page.Truncated)
	}
	// The read limit cuts too.
	if page, err := repo.ListForRunTask(f.ctx, f.tenant, run.ID, cmd, 3); err != nil || len(page.Lines) != 3 || !page.Truncated {
		t.Fatalf("read limit: %d lines truncated=%v %v", len(page.Lines), page.Truncated, err)
	}
	// Another tenant, or another run of the tenant: not found.
	if _, err := repo.ListForRunTask(f.ctx, stranger, run.ID, cmd, 100); !errors.Is(err, commandlog.ErrNotFound) {
		t.Fatalf("other tenant read: %v", err)
	}
	other := seedCounterRun(f.ctx, t, f.runs, f.tenant, f.scan)
	if _, err := repo.ListForRunTask(f.ctx, f.tenant, other.ID, cmd, 100); !errors.Is(err, commandlog.ErrNotFound) {
		t.Fatalf("other run read: %v", err)
	}

	// The byte cap.
	cmd2 := f.command(t, f.tenant, run.ID, &s1, "running", map[string]any{"scanner": "nuclei"})
	big := logBatch(f.tenant, s1, cmd2, 0, string(make([]byte, 600)))
	if res, err := repo.Append(f.ctx, big, day, 10, 500); err != nil || !res.Truncated {
		t.Fatalf("over the byte cap: %+v %v", res, err)
	}
}

func TestCommandLogs_FinishedCommandClosesAfterWindow_DB(t *testing.T) {
	f := newRunTasksFixture(t)
	repo := NewCommandLogRepository(&DB{DB: f.db})
	s1 := f.sensor(t, f.tenant, "edge")
	run := seedCounterRun(f.ctx, t, f.runs, f.tenant, f.scan)
	cmd := f.command(t, f.tenant, run.ID, &s1, "completed", map[string]any{"scanner": "nuclei"})

	// Just finished: an outbox replay is still accepted.
	if res, err := repo.Append(f.ctx, logBatch(f.tenant, s1, cmd, 0, "late"), 24*time.Hour, 10, 1<<20); err != nil || res.Stored != 1 {
		t.Fatalf("within the window: %+v %v", res, err)
	}
	if _, err := f.db.ExecContext(f.ctx, `UPDATE commands SET completed_at = NOW() - INTERVAL '25 hours' WHERE id = $1`, cmd.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Append(f.ctx, logBatch(f.tenant, s1, cmd, 1, "too late"), 24*time.Hour, 10, 1<<20); !errors.Is(err, commandlog.ErrClosed) {
		t.Fatalf("after the window: %v", err)
	}
}

func TestCommandLogs_RetentionDeletesOldBatches_DB(t *testing.T) {
	f := newRunTasksFixture(t)
	repo := NewCommandLogRepository(&DB{DB: f.db})
	s1 := f.sensor(t, f.tenant, "edge")
	run := seedCounterRun(f.ctx, t, f.runs, f.tenant, f.scan)
	cmd := f.command(t, f.tenant, run.ID, &s1, "running", map[string]any{"scanner": "nuclei"})
	for seq := 0; seq < 2; seq++ {
		if _, err := repo.Append(f.ctx, logBatch(f.tenant, s1, cmd, seq, "m"), time.Hour, 10, 1<<20); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.db.ExecContext(f.ctx, `UPDATE command_logs SET created_at = NOW() - INTERVAL '15 days' WHERE command_id = $1 AND seq = 0`, cmd.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DeleteOlderThan(f.ctx, time.Now().Add(-commandlog.Retention), 100); err != nil {
		t.Fatal(err)
	}
	page, err := repo.ListForRunTask(f.ctx, f.tenant, run.ID, cmd, 100)
	if err != nil || len(page.Lines) != 1 {
		t.Fatalf("after retention: %d lines %v", len(page.Lines), err)
	}
	// Deleted with the command.
	if _, err := f.db.ExecContext(f.ctx, `DELETE FROM commands WHERE id = $1`, cmd.String()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM command_logs WHERE command_id = $1`, cmd.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d rows left after the command was deleted (%v)", n, err)
	}
}
