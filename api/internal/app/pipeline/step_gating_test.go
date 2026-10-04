package pipeline

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	pipelinedom "github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// memStepRuns is a tiny step-run store: Update writes, GetByPipelineRunID
// reads what was written (the database view, not a handler's stale copy).
type memStepRuns struct {
	pipelinedom.StepRunRepository
	rows map[string]pipelinedom.StepRun
}

func (m *memStepRuns) Update(_ context.Context, sr *pipelinedom.StepRun) error {
	m.rows[sr.StepKey] = *sr
	return nil
}

func (m *memStepRuns) GetByPipelineRunID(context.Context, shared.ID) ([]*pipelinedom.StepRun, error) {
	out := make([]*pipelinedom.StepRun, 0, len(m.rows))
	for _, r := range m.rows {
		cp := r
		out = append(out, &cp)
	}
	return out, nil
}

func (m *memStepRuns) GetByStepKey(_ context.Context, _ shared.ID, key string) (*pipelinedom.StepRun, error) {
	r, ok := m.rows[key]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return &r, nil
}

// statusRuns records terminal transitions; GetWithStepRuns returns the copy
// the test hands it (possibly stale).
type statusRuns struct {
	pipelinedom.RunRepository
	run      *pipelinedom.Run
	statuses []pipelinedom.RunStatus
}

func (r *statusRuns) GetWithStepRuns(context.Context, shared.ID) (*pipelinedom.Run, error) {
	return r.run, nil
}
func (r *statusRuns) UpdateStats(context.Context, shared.ID, int, int, int, int) error { return nil }
func (r *statusRuns) UpdateStatus(_ context.Context, _ shared.ID, st pipelinedom.RunStatus, _ string) error {
	if len(r.statuses) > 0 {
		return pipelinedom.ErrRunAlreadyFinished
	}
	r.statuses = append(r.statuses, st)
	return nil
}

type fixedTemplate struct {
	pipelinedom.TemplateRepository
	tpl *pipelinedom.Template
}

func (f fixedTemplate) GetWithSteps(context.Context, shared.ID) (*pipelinedom.Template, error) {
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

func gatingFixture(statuses map[string]pipelinedom.StepRunStatus, deps map[string][]string) (*Service, *pipelinedom.Run, *memStepRuns, *statusRuns, *countingCommands) {
	run := &pipelinedom.Run{ID: shared.NewID(), TenantID: shared.NewID(), PipelineID: shared.NewID(),
		Status: pipelinedom.RunStatusRunning, TotalSteps: len(statuses), Context: map[string]any{}}
	tpl := &pipelinedom.Template{}
	store := &memStepRuns{rows: map[string]pipelinedom.StepRun{}}
	order := 1
	for _, key := range []string{"a", "b", "c"} {
		st, ok := statuses[key]
		if !ok {
			continue
		}
		step := &pipelinedom.Step{ID: shared.NewID(), StepKey: key, StepOrder: order, DependsOn: deps[key],
			Condition: pipelinedom.AlwaysCondition()}
		order++
		tpl.Steps = append(tpl.Steps, step)
		sr := pipelinedom.NewStepRun(run.ID, step.ID, key, step.StepOrder, 0)
		sr.Status = st
		store.rows[key] = *sr
		cp := *sr
		run.StepRuns = append(run.StepRuns, &cp)
	}
	runs := &statusRuns{run: run}
	cmds := &countingCommands{}
	s := &Service{stepRunRepo: store, runRepo: runs, templateRepo: fixedTemplate{tpl: tpl},
		commandRepo: cmds, logger: logger.NewNop()}
	return s, run, store, runs, cmds
}

// b depends on a. a fails: b used to be queued anyway (every terminal step
// counted as "completed" for dependency purposes). Now b is skipped and the
// run ends as failed instead of running b.
func TestFailedDependencyGatesItsDependents(t *testing.T) {
	s, run, store, runs, cmds := gatingFixture(
		map[string]pipelinedom.StepRunStatus{"a": pipelinedom.StepRunStatusRunning, "b": pipelinedom.StepRunStatusPending},
		map[string][]string{"b": {"a"}})

	if err := s.failStep(context.Background(), run, run.GetStepRun("a"), "boom", "COMMAND_FAILED"); err != nil {
		t.Fatal(err)
	}
	if len(cmds.created) != 0 {
		t.Fatalf("queued %d command(s) for a step whose dependency failed", len(cmds.created))
	}
	if b := store.rows["b"]; b.Status != pipelinedom.StepRunStatusSkipped {
		t.Fatalf("b is %s, want skipped", b.Status)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != pipelinedom.RunStatusFailed {
		t.Fatalf("run transitions = %v, want [failed] (the run must be able to end)", runs.statuses)
	}
}

// a and b run in parallel and are the last steps. b's result was saved while
// a's handler held a copy of the run in which b was still running: neither
// handler finished the run, which hung until the run timeout.
func TestParallelFinalSteps_RunCompletes(t *testing.T) {
	s, run, store, runs, _ := gatingFixture(
		map[string]pipelinedom.StepRunStatus{"a": pipelinedom.StepRunStatusRunning, "b": pipelinedom.StepRunStatusRunning},
		nil)
	// b finished meanwhile (saved), but a's handler loads the stale run.
	b := store.rows["b"]
	b.Complete(0, nil)
	store.rows["b"] = b

	if err := s.OnStepCompleted(context.Background(), run.ID.String(), "a", 0, nil); err != nil {
		t.Fatal(err)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != pipelinedom.RunStatusCompleted {
		t.Fatalf("run transitions = %v, want [completed]", runs.statuses)
	}
}
