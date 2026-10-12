package scanrun

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// memStepRuns is a tiny step-run store: Update writes, GetByScanRunID
// reads what was written (the database view, not a handler's stale copy).
type memStepRuns struct {
	scanrun.StepRunRepository
	rows map[string]scanrun.StepRun
}

func (m *memStepRuns) Update(_ context.Context, sr *scanrun.StepRun) error {
	m.rows[sr.StepKey] = *sr
	return nil
}

func (m *memStepRuns) GetByScanRunID(context.Context, shared.ID) ([]*scanrun.StepRun, error) {
	out := make([]*scanrun.StepRun, 0, len(m.rows))
	for _, r := range m.rows {
		cp := r
		out = append(out, &cp)
	}
	return out, nil
}

func (m *memStepRuns) GetByStepKey(_ context.Context, _ shared.ID, key string) (*scanrun.StepRun, error) {
	r, ok := m.rows[key]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return &r, nil
}

// statusRuns records terminal transitions; GetWithStepRuns returns the copy
// the test hands it (possibly stale).
type statusRuns struct {
	scanrun.RunRepository
	run      *scanrun.Run
	statuses []scanrun.RunStatus
}

func (r *statusRuns) GetWithStepRuns(context.Context, shared.ID) (*scanrun.Run, error) {
	return r.run, nil
}
func (r *statusRuns) UpdateStats(context.Context, shared.ID, int, int, int, int) error { return nil }
func (r *statusRuns) UpdateStatus(_ context.Context, _ shared.ID, st scanrun.RunStatus, _ string) error {
	if len(r.statuses) > 0 {
		return scanrun.ErrRunAlreadyFinished
	}
	r.statuses = append(r.statuses, st)
	return nil
}

type fixedTemplate struct {
	scanworkflow.Repository
	tpl *scanworkflow.Workflow
}

func (f fixedTemplate) GetWithSteps(context.Context, shared.ID) (*scanworkflow.Workflow, error) {
	return f.tpl, nil
}

type countingCommands struct {
	command.Repository
	created []string
}

func (c *countingCommands) Create(_ context.Context, cmd *command.Command) error {
	c.created = append(c.created, string(cmd.Payload))
	return nil
}

func gatingFixture(statuses map[string]scanrun.StepRunStatus, deps map[string][]string) (*Service, *scanrun.Run, *memStepRuns, *statusRuns, *countingCommands) {
	run := &scanrun.Run{ID: shared.NewID(), TenantID: shared.NewID(), ScanWorkflowID: shared.NewID(),
		Status: scanrun.RunStatusRunning, TotalSteps: len(statuses), Context: map[string]any{}}
	tpl := &scanworkflow.Workflow{}
	store := &memStepRuns{rows: map[string]scanrun.StepRun{}}
	order := 1
	for _, key := range []string{"a", "b", "c"} {
		st, ok := statuses[key]
		if !ok {
			continue
		}
		step := &scanworkflow.Step{ID: shared.NewID(), StepKey: key, StepOrder: order, DependsOn: deps[key],
			Condition: scanworkflow.AlwaysCondition()}
		order++
		tpl.Steps = append(tpl.Steps, step)
		sr := scanrun.NewStepRun(run.ID, step.ID, key, step.StepOrder, 0)
		sr.Status = st
		store.rows[key] = *sr
		cp := *sr
		run.StepRuns = append(run.StepRuns, &cp)
	}
	runs := &statusRuns{run: run}
	cmds := &countingCommands{}
	s := &Service{stepRunRepo: store, runRepo: runs, templateRepo: fixedTemplate{tpl: tpl},
		commandRepo: cmds, webScope: &fakeWebScope{}, logger: logger.NewNop()}
	return s, run, store, runs, cmds
}

// b depends on a. a fails: b used to be queued anyway (every terminal step
// counted as "completed" for dependency purposes). Now b is skipped and the
// run ends as failed instead of running b.
func TestFailedDependencyGatesItsDependents(t *testing.T) {
	s, run, store, runs, cmds := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusRunning, "b": scanrun.StepRunStatusPending},
		map[string][]string{"b": {"a"}})

	if err := s.failStep(context.Background(), run, run.GetStepRun("a"), "boom", "COMMAND_FAILED"); err != nil {
		t.Fatal(err)
	}
	if len(cmds.created) != 0 {
		t.Fatalf("queued %d command(s) for a step whose dependency failed", len(cmds.created))
	}
	if b := store.rows["b"]; b.Status != scanrun.StepRunStatusSkipped {
		t.Fatalf("b is %s, want skipped", b.Status)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusFailed {
		t.Fatalf("run transitions = %v, want [failed] (the run must be able to end)", runs.statuses)
	}
}

// a and b run in parallel and are the last steps. b's result was saved while
// a's handler held a copy of the run in which b was still running: neither
// handler finished the run, which hung until the run timeout.
func TestParallelFinalSteps_RunCompletes(t *testing.T) {
	s, run, store, runs, _ := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusRunning, "b": scanrun.StepRunStatusRunning},
		nil)
	// b finished meanwhile (saved), but a's handler loads the stale run.
	b := store.rows["b"]
	b.Complete(0, nil)
	store.rows["b"] = b

	if err := s.OnStepCompleted(context.Background(), run.ID.String(), "a", 0, nil); err != nil {
		t.Fatal(err)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusCompleted {
		t.Fatalf("run transitions = %v, want [completed]", runs.statuses)
	}
}
