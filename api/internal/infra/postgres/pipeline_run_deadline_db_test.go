package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RFC-046 P1.3 (D5): a run that reaches its deadline keeps what came back,
// ends partial, records what it did not finish, and tells the sensors still
// working on it to stop. Against the real SQL and migration 000430.

type deadlineFixture struct {
	db     *sql.DB
	runs   *PipelineRunRepository
	steps  *StepRunRepository
	cmds   *CommandRepository
	tenant shared.ID
	scan   shared.ID
	sensor shared.ID
	ctx    context.Context
}

func newDeadlineFixture(t *testing.T) *deadlineFixture {
	t.Helper()
	ctx := context.Background()
	db := openScanDB(t)
	tenantID, scanID := seedCounterScan(ctx, t, db)
	f := &deadlineFixture{
		db: db, ctx: ctx,
		runs:   NewPipelineRunRepository(&DB{DB: db}),
		steps:  NewStepRunRepository(&DB{DB: db}),
		cmds:   NewCommandRepository(&DB{DB: db}),
		tenant: tenantID, scan: scanID, sensor: shared.NewID(),
	}
	f.exec(t, `INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status)
		VALUES ($1, $2, $3, $4, 'p', 'active')`, f.sensor, f.tenant, "deadline-"+f.sensor.String(), "h-"+f.sensor.String())
	f.exec(t, `UPDATE scans SET timeout_seconds = 900 WHERE id = $1`, f.scan)
	return f
}

func (f *deadlineFixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	for i, a := range args {
		if id, ok := a.(shared.ID); ok {
			args[i] = id.String()
		}
	}
	if _, err := f.db.ExecContext(f.ctx, q, args...); err != nil {
		t.Fatalf("fixture: %v\n%s", err, q)
	}
}

// newRun creates a started run of the fixture scan; startedAgo moves its start
// into the past before it is stored, so its deadline is computed from there.
func (f *deadlineFixture) newRun(t *testing.T, trigger pipeline.TriggerType, startedAgo time.Duration) (*pipeline.Run, *pipeline.StepRun) {
	t.Helper()
	tpl, _ := shared.IDFromString(quickScanTemplate)
	run, err := pipeline.NewRun(tpl, f.tenant, nil, trigger, "", map[string]any{})
	if err != nil {
		t.Fatalf("new run: %v", err)
	}
	run.ScanID = &f.scan
	run.SetTotalSteps(1)
	run.Start()
	started := time.Now().Add(-startedAgo)
	run.StartedAt = &started
	if err := f.runs.Create(f.ctx, run); err != nil {
		t.Fatalf("create run: %v", err)
	}
	sr := seedStepRun(f.ctx, t, f.steps, run.ID)
	return run, sr
}

// command stores a scan command of run/step with the given targets; a
// non-pending command is held by the fixture sensor.
func (f *deadlineFixture) command(t *testing.T, run *pipeline.Run, sr *pipeline.StepRun, status string, targets ...string) shared.ID {
	t.Helper()
	id := shared.NewID()
	payload, _ := json.Marshal(map[string]any{
		"pipeline_run_id": run.ID.String(),
		"step_run_id":     sr.ID.String(),
		"scanner":         "nuclei",
		"targets":         targets,
	})
	var sensor any
	if status != "pending" {
		sensor = f.sensor.String()
	}
	f.exec(t, `INSERT INTO commands (id, tenant_id, sensor_id, type, status, payload, lease_expires_at)
		VALUES ($1, $2, $3, 'scan', $4::text, $5, CASE WHEN $4::text IN ('acknowledged', 'running') THEN NOW() + interval '5 minutes' END)`,
		id, f.tenant, sensor, status, payload)
	return id
}

func (f *deadlineFixture) pastDeadline(t *testing.T, run *pipeline.Run) {
	t.Helper()
	f.exec(t, `UPDATE pipeline_runs SET deadline_at = NOW() - interval '1 second' WHERE id = $1`, run.ID)
}

func (f *deadlineFixture) commandStatus(t *testing.T, id shared.ID) (string, bool) {
	t.Helper()
	var status string
	var leased bool
	if err := f.db.QueryRowContext(f.ctx,
		`SELECT status, lease_expires_at IS NOT NULL FROM commands WHERE id = $1`, id.String()).Scan(&status, &leased); err != nil {
		t.Fatalf("read command: %v", err)
	}
	return status, leased
}

func (f *deadlineFixture) partialRuns(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.db.QueryRowContext(f.ctx, `SELECT partial_runs FROM scans WHERE id = $1`, f.scan.String()).Scan(&n); err != nil {
		t.Fatalf("read partial_runs: %v", err)
	}
	return n
}

func TestRunDeadline_FixedAtStartFromTheScanTimeout(t *testing.T) {
	f := newDeadlineFixture(t)
	run, _ := f.newRun(t, pipeline.TriggerTypeManual, 0)

	got, err := f.runs.GetByTenantAndID(f.ctx, f.tenant, run.ID)
	if err != nil {
		t.Fatalf("read run: %v", err)
	}
	if got.DeadlineAt == nil {
		t.Fatal("a started run must get a deadline")
	}
	if d := got.DeadlineAt.Sub(*got.StartedAt); d < 899*time.Second || d > 901*time.Second {
		t.Fatalf("deadline = started + %v, want the scan timeout 900s", d)
	}

	// Editing the scan does not move the deadline of a run in flight.
	f.exec(t, `UPDATE scans SET timeout_seconds = 7200 WHERE id = $1`, f.scan)
	again, _ := f.runs.GetByTenantAndID(f.ctx, f.tenant, run.ID)
	if !again.DeadlineAt.Equal(*got.DeadlineAt) {
		t.Fatalf("deadline moved from %v to %v after a scan edit", got.DeadlineAt, again.DeadlineAt)
	}
}

func TestRunDeadline_SetWhenARunStartsLater(t *testing.T) {
	// The workflow path stores the run first and starts it with Update.
	f := newDeadlineFixture(t)
	tpl, _ := shared.IDFromString(quickScanTemplate)
	run, _ := pipeline.NewRun(tpl, f.tenant, nil, pipeline.TriggerTypeManual, "", map[string]any{})
	run.ScanID = &f.scan
	if err := f.runs.Create(f.ctx, run); err != nil {
		t.Fatalf("create run: %v", err)
	}
	got, _ := f.runs.GetByTenantAndID(f.ctx, f.tenant, run.ID)
	if got.DeadlineAt != nil {
		t.Fatalf("a run that has not started has no deadline, got %v", got.DeadlineAt)
	}
	run.Start()
	if err := f.runs.Update(f.ctx, run); err != nil {
		t.Fatalf("start run: %v", err)
	}
	got, _ = f.runs.GetByTenantAndID(f.ctx, f.tenant, run.ID)
	if got.DeadlineAt == nil || got.DeadlineAt.Sub(*got.StartedAt) < 899*time.Second {
		t.Fatalf("deadline after start = %v (started %v), want started + 900s", got.DeadlineAt, got.StartedAt)
	}
}

func TestRunDeadline_KeptResultsEndPartialWithUnfinishedTargets(t *testing.T) {
	f := newDeadlineFixture(t)
	run, sr := f.newRun(t, pipeline.TriggerTypeSchedule, 0)
	done := f.command(t, run, sr, "completed", "a.example", "b.example")
	running := f.command(t, run, sr, "running", "c.example", "d.example")
	queued := f.command(t, run, sr, "pending", "e.example", "c.example")

	// Control: before the deadline the sensor still holds its command.
	if ids, err := f.cmds.CommandsToCancel(f.ctx, f.tenant, f.sensor, []string{running.String()}); err != nil || len(ids) != 0 {
		t.Fatalf("before the deadline: cancel=%v err=%v, want none", ids, err)
	}
	if n, err := f.runs.MarkTimedOutRuns(f.ctx); err != nil || n != 0 {
		t.Fatalf("before the deadline: settled=%d err=%v, want 0", n, err)
	}

	f.pastDeadline(t, run)
	n, err := f.runs.MarkTimedOutRuns(f.ctx)
	if err != nil || n != 1 {
		t.Fatalf("MarkTimedOutRuns = %d, %v; want 1 run settled", n, err)
	}

	got, _ := f.runs.GetByTenantAndID(f.ctx, f.tenant, run.ID)
	if got.Status != pipeline.RunStatusPartial {
		t.Fatalf("run status = %q, want partial (one command came back)", got.Status)
	}
	if got.UnfinishedTargetCount != 3 || !strings.Contains(got.ErrorMessage, "3 target(s) unfinished") {
		t.Fatalf("unfinished count=%d message=%q, want 3", got.UnfinishedTargetCount, got.ErrorMessage)
	}
	targets, err := f.runs.GetUnfinishedTargets(f.ctx, f.tenant, run.ID)
	if err != nil {
		t.Fatalf("GetUnfinishedTargets: %v", err)
	}
	if want := []string{"c.example", "d.example", "e.example"}; !reflect.DeepEqual(targets, want) {
		t.Fatalf("unfinished = %v, want %v (dispatch order, deduplicated)", targets, want)
	}

	// The open commands are closed; the running one loses its lease and the
	// sensor is told to stop it on its next heartbeat.
	if st, _ := f.commandStatus(t, done); st != "completed" {
		t.Fatalf("completed command became %q", st)
	}
	for _, id := range []shared.ID{running, queued} {
		if st, leased := f.commandStatus(t, id); st != "failed" || leased {
			t.Fatalf("open command %s: status=%q leased=%v, want failed with no lease", id, st, leased)
		}
	}
	ids, err := f.cmds.CommandsToCancel(f.ctx, f.tenant, f.sensor, []string{running.String(), done.String()})
	if err != nil || !reflect.DeepEqual(ids, []string{running.String()}) {
		t.Fatalf("cancel ids = %v (err %v), want only the running command", ids, err)
	}

	if step := readStepRun(f.ctx, t, f.steps, sr.ID); step.Status != pipeline.StepRunStatusPartial {
		t.Fatalf("step status = %q, want partial (one of its commands completed)", step.Status)
	}
	total, ok, failed, status, _ := readCounters(f.ctx, t, f.db, f.scan)
	if total != 1 || ok != 0 || failed != 0 || f.partialRuns(t) != 1 || status != "partial" {
		t.Fatalf("counters total=%d ok=%d failed=%d partial=%d status=%q, want 1 0 0 1 partial",
			total, ok, failed, f.partialRuns(t), status)
	}

	// Settled once: a second pass changes nothing.
	if n, _ := f.runs.MarkTimedOutRuns(f.ctx); n != 0 {
		t.Fatalf("second pass settled %d runs", n)
	}
	if total, _, _, _, _ := readCounters(f.ctx, t, f.db, f.scan); total != 1 {
		t.Fatalf("run counted twice: total=%d", total)
	}
}

func TestRunDeadline_NothingKeptEndsTimeout(t *testing.T) {
	f := newDeadlineFixture(t)
	run, sr := f.newRun(t, pipeline.TriggerTypeSchedule, 0)
	running := f.command(t, run, sr, "running", "x.example")
	f.pastDeadline(t, run)

	if _, err := f.runs.MarkTimedOutRuns(f.ctx); err != nil {
		t.Fatalf("MarkTimedOutRuns: %v", err)
	}
	got, _ := f.runs.GetByTenantAndID(f.ctx, f.tenant, run.ID)
	if got.Status != pipeline.RunStatusTimeout || got.UnfinishedTargetCount != 1 {
		t.Fatalf("status=%q unfinished=%d, want timeout with 1 unfinished", got.Status, got.UnfinishedTargetCount)
	}
	if step := readStepRun(f.ctx, t, f.steps, sr.ID); step.Status != pipeline.StepRunStatusTimeout {
		t.Fatalf("step status = %q, want timeout", step.Status)
	}
	if st, _ := f.commandStatus(t, running); st != "failed" {
		t.Fatalf("running command = %q, want failed", st)
	}
	total, _, failed, status, _ := readCounters(f.ctx, t, f.db, f.scan)
	if total != 1 || failed != 1 || f.partialRuns(t) != 0 || status != "timeout" {
		t.Fatalf("counters total=%d failed=%d partial=%d status=%q, want 1 1 0 timeout", total, failed, f.partialRuns(t), status)
	}
	// A timeout run is not a rollover source (only partial runs are).
	if ro, err := f.runs.LatestRollover(f.ctx, f.tenant, f.scan); err != nil || ro != nil {
		t.Fatalf("LatestRollover after a timeout = %+v, %v; want nil", ro, err)
	}
}

func TestRunDeadline_StoredDeadlineWinsOverAScanEdit(t *testing.T) {
	f := newDeadlineFixture(t)
	// Started 30 min ago under a 15 min timeout: its deadline passed.
	run, sr := f.newRun(t, pipeline.TriggerTypeManual, 30*time.Minute)
	f.command(t, run, sr, "running", "y.example")
	// Raising the scan timeout afterwards does not rescue it.
	f.exec(t, `UPDATE scans SET timeout_seconds = 7200 WHERE id = $1`, f.scan)

	if _, err := f.runs.MarkTimedOutRuns(f.ctx); err != nil {
		t.Fatalf("MarkTimedOutRuns: %v", err)
	}
	if st, _ := runStatus(f.ctx, t, f.db, run.ID); st != "timeout" {
		t.Fatalf("status = %q, want timeout at the deadline fixed when it started", st)
	}
}

func TestRunRollover_LatestScheduledPartialOnlyAndTenantScoped(t *testing.T) {
	f := newDeadlineFixture(t)

	if ro, err := f.runs.LatestRollover(f.ctx, f.tenant, f.scan); err != nil || ro != nil {
		t.Fatalf("no settled run: %+v, %v; want nil", ro, err)
	}

	// A manual run that ends partial does not roll over.
	manual, msr := f.newRun(t, pipeline.TriggerTypeManual, 0)
	f.command(t, manual, msr, "completed", "m1.example")
	f.command(t, manual, msr, "running", "m2.example")
	f.pastDeadline(t, manual)
	if _, err := f.runs.MarkTimedOutRuns(f.ctx); err != nil {
		t.Fatalf("reap manual: %v", err)
	}
	if ro, err := f.runs.LatestRollover(f.ctx, f.tenant, f.scan); err != nil || ro != nil {
		t.Fatalf("manual partial: %+v, %v; want nil", ro, err)
	}

	// A scheduled one does.
	sched, ssr := f.newRun(t, pipeline.TriggerTypeSchedule, 0)
	f.command(t, sched, ssr, "completed", "s1.example")
	f.command(t, sched, ssr, "running", "s2.example", "s3.example")
	f.pastDeadline(t, sched)
	if _, err := f.runs.MarkTimedOutRuns(f.ctx); err != nil {
		t.Fatalf("reap scheduled: %v", err)
	}
	ro, err := f.runs.LatestRollover(f.ctx, f.tenant, f.scan)
	if err != nil || ro == nil {
		t.Fatalf("scheduled partial: %+v, %v; want its leftovers", ro, err)
	}
	if ro.FromRunID != sched.ID || !reflect.DeepEqual(ro.Targets, []string{"s2.example", "s3.example"}) {
		t.Fatalf("rollover = %+v, want run %s with [s2 s3]", ro, sched.ID)
	}

	// Another tenant sees nothing: not the rollover, not the run's targets.
	other, _ := seedCounterScan(f.ctx, t, f.db)
	if ro, err := f.runs.LatestRollover(f.ctx, other, f.scan); err != nil || ro != nil {
		t.Fatalf("other tenant LatestRollover = %+v, %v; want nil", ro, err)
	}
	if _, err := f.runs.GetUnfinishedTargets(f.ctx, other, sched.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("other tenant GetUnfinishedTargets err = %v, want ErrNotFound", err)
	}

	// Once a later run settles, the leftovers are its business.
	later, _ := f.newRun(t, pipeline.TriggerTypeSchedule, 0)
	if err := f.runs.UpdateStatus(f.ctx, later.ID, pipeline.RunStatusCompleted, ""); err != nil {
		t.Fatalf("complete later run: %v", err)
	}
	if ro, err := f.runs.LatestRollover(f.ctx, f.tenant, f.scan); err != nil || ro != nil {
		t.Fatalf("after a later completed run: %+v, %v; want nil", ro, err)
	}
}

// A command of another tenant that names the run in its payload neither makes
// the run look as if it kept results nor is recorded or closed by the reaper.
func TestRunDeadline_OtherTenantsCommandIsIgnored(t *testing.T) {
	f := newDeadlineFixture(t)
	run, sr := f.newRun(t, pipeline.TriggerTypeSchedule, 0)
	f.command(t, run, sr, "running", "a.example")

	other, _ := seedCounterScan(f.ctx, t, f.db)
	payload, _ := json.Marshal(map[string]any{"pipeline_run_id": run.ID.String(), "targets": []string{"victim.example"}})
	foreignDone, foreignOpen := shared.NewID(), shared.NewID()
	f.exec(t, `INSERT INTO commands (id, tenant_id, type, status, payload) VALUES ($1, $2, 'scan', 'completed', $3)`,
		foreignDone, other, payload)
	f.exec(t, `INSERT INTO commands (id, tenant_id, type, status, payload) VALUES ($1, $2, 'scan', 'running', $3)`,
		foreignOpen, other, payload)

	f.pastDeadline(t, run)
	if _, err := f.runs.MarkTimedOutRuns(f.ctx); err != nil {
		t.Fatalf("MarkTimedOutRuns: %v", err)
	}
	got, _ := f.runs.GetByTenantAndID(f.ctx, f.tenant, run.ID)
	if got.Status != pipeline.RunStatusTimeout {
		t.Fatalf("run status = %q, want timeout (the completed command belongs to another tenant)", got.Status)
	}
	targets, err := f.runs.GetUnfinishedTargets(f.ctx, f.tenant, run.ID)
	if err != nil || !reflect.DeepEqual(targets, []string{"a.example"}) {
		t.Fatalf("unfinished = %v (%v), want only this tenant's target", targets, err)
	}
	if st, _ := f.commandStatus(t, foreignOpen); st != "running" {
		t.Fatalf("another tenant's command became %q; the reaper must not touch it", st)
	}
}

// The recorded leftovers are bounded; the run still settles.
func TestRunDeadline_UnfinishedTargetsAreCapped(t *testing.T) {
	f := newDeadlineFixture(t)
	run, sr := f.newRun(t, pipeline.TriggerTypeSchedule, 0)
	f.command(t, run, sr, "completed", "done.example")
	targets := make([]string, MaxUnfinishedTargets+50)
	for i := range targets {
		targets[i] = fmt.Sprintf("host-%05d.example", i)
	}
	f.command(t, run, sr, "running", targets...)

	f.pastDeadline(t, run)
	if _, err := f.runs.MarkTimedOutRuns(f.ctx); err != nil {
		t.Fatalf("MarkTimedOutRuns: %v", err)
	}
	got, _ := f.runs.GetByTenantAndID(f.ctx, f.tenant, run.ID)
	if got.Status != pipeline.RunStatusPartial || got.UnfinishedTargetCount != MaxUnfinishedTargets {
		t.Fatalf("status=%q unfinished=%d, want partial with %d", got.Status, got.UnfinishedTargetCount, MaxUnfinishedTargets)
	}
	recorded, _ := f.runs.GetUnfinishedTargets(f.ctx, f.tenant, run.ID)
	if len(recorded) == 0 || recorded[0] != "host-00000.example" {
		t.Fatalf("first recorded target = %v, want the first dispatched", recorded[:min(1, len(recorded))])
	}
}
