package scan

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// failingQueuer refuses some steps (as the scan run service does for a step
// with no tool or no compatible target) and records the run it was asked to
// re-evaluate.
type failingQueuer struct {
	refuse   map[string]bool
	queued   []string
	advanced []shared.ID
}

func (q *failingQueuer) QueueRunStep(_ context.Context, _ *scanrun.Run, step *scanworkflow.Step) error {
	if q.refuse[step.StepKey] {
		return shared.NewDomainError("NO_MATCHING_TOOL", "no tool can run this step", shared.ErrValidation)
	}
	q.queued = append(q.queued, step.StepKey)
	return nil
}

func (q *failingQueuer) AdvanceRun(_ context.Context, run *scanrun.Run) error {
	q.advanced = append(q.advanced, run.ID)
	return nil
}

// research/62 SG-4: a workflow whose first step cannot be queued used to
// answer 201 and stay "running" until the deadline (up to 24 h). The other
// first steps still start, and the run is re-evaluated at once so that it
// settles with the step's reason when nothing else can run.
func TestScheduleWorkflowSteps_QueueFailureSettlesTheRunAtOnce(t *testing.T) {
	steps := []*scanworkflow.Step{
		{ID: shared.NewID(), StepKey: "a", Tool: "subfinder", Condition: scanworkflow.AlwaysCondition()},
		{ID: shared.NewID(), StepKey: "b", Tool: "dnsx", DependsOn: []string{"a"}, Condition: scanworkflow.AlwaysCondition()},
		{ID: shared.NewID(), StepKey: "c", Tool: "httpx", Condition: scanworkflow.AlwaysCondition()},
	}
	newRun := func() *scanrun.Run {
		return &scanrun.Run{ID: shared.NewID(), TenantID: shared.NewID(), StartedAt: ptrTime(time.Now())}
	}

	// One first step refused: the other still starts; the run is re-evaluated.
	q := &failingQueuer{refuse: map[string]bool{"a": true}}
	s := &Service{tools: testTools, logger: logger.NewNop(), stepQueuer: q}
	run := newRun()
	if err := s.scheduleWorkflowSteps(context.Background(), run, steps, 3); err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if !reflect.DeepEqual(q.queued, []string{"c"}) {
		t.Fatalf("queued %v, want [c]", q.queued)
	}
	if !reflect.DeepEqual(q.advanced, []shared.ID{run.ID}) {
		t.Fatalf("advanced %v, want the run re-evaluated once", q.advanced)
	}

	// Every first step refused: nothing queued, and the run is re-evaluated
	// (it settles failed there) instead of waiting for its deadline.
	q = &failingQueuer{refuse: map[string]bool{"a": true, "c": true}}
	s.stepQueuer = q
	run = newRun()
	if err := s.scheduleWorkflowSteps(context.Background(), run, steps, 3); err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if len(q.queued) != 0 || len(q.advanced) != 1 {
		t.Fatalf("queued %v advanced %v, want nothing queued and one re-evaluation", q.queued, q.advanced)
	}

	// Nothing refused: no extra re-evaluation.
	q = &failingQueuer{}
	s.stepQueuer = q
	if err := s.scheduleWorkflowSteps(context.Background(), newRun(), steps, 3); err != nil {
		t.Fatal(err)
	}
	if len(q.advanced) != 0 {
		t.Fatalf("a clean start was re-evaluated %d times", len(q.advanced))
	}
}

// settlingQueuer settles one first step without a command (a host
// discovery step of a run of names).
type settlingQueuer struct{ failingQueuer }

func (q *settlingQueuer) QueueRunStep(_ context.Context, _ *scanrun.Run, step *scanworkflow.Step) error {
	if step.StepKey == "hosts" {
		return ErrStepSettled
	}
	q.queued = append(q.queued, step.StepKey)
	return nil
}

// A first step settled without a command is not a failure, and the run is
// advanced at once so the steps after it start (they would wait forever
// otherwise: nothing else completes to schedule them).
func TestScheduleWorkflowSteps_SettledStepAdvancesTheRun(t *testing.T) {
	steps := []*scanworkflow.Step{
		{ID: shared.NewID(), StepKey: "hosts", Capabilities: []string{"discover.hosts"}, Condition: scanworkflow.AlwaysCondition()},
		{ID: shared.NewID(), StepKey: "ports", Capabilities: []string{"scan.ports"}, DependsOn: []string{"hosts"}, Condition: scanworkflow.AlwaysCondition()},
	}
	q := &settlingQueuer{}
	s := &Service{tools: testTools, logger: logger.NewNop(), stepQueuer: q}
	run := &scanrun.Run{ID: shared.NewID(), TenantID: shared.NewID(), StartedAt: ptrTime(time.Now())}
	if err := s.scheduleWorkflowSteps(context.Background(), run, steps, 3); err != nil {
		t.Fatalf("schedule: %v (a settled step is not a failed start)", err)
	}
	if !reflect.DeepEqual(q.advanced, []shared.ID{run.ID}) {
		t.Fatalf("advanced %v, want the run advanced once", q.advanced)
	}
}
