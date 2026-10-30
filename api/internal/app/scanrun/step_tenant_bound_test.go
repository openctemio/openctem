package scanrun

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A step result names its run by the scan_run_id of the command payload. The
// run must belong to the command's tenant: a command of another organization
// (or one with no tenant) never settles, fails or advances the step.

func TestStepResult_ForeignTenant_LeavesTheStepAlone(t *testing.T) {
	foreign := shared.NewID()
	cases := map[string]func(s *Service, run *scanrun.Run) error{
		"completed": func(s *Service, run *scanrun.Run) error {
			return s.OnStepCompleted(context.Background(), foreign, run.ID.String(), "a", 7, map[string]any{"x": 1})
		},
		"partial": func(s *Service, run *scanrun.Run) error {
			return s.OnStepCompletedPartial(context.Background(), foreign, run.ID.String(), "a", 1, nil, Partial{Gaps: 2})
		},
		"failed": func(s *Service, run *scanrun.Run) error {
			return s.OnStepFailed(context.Background(), foreign, run.ID.String(), "a", "boom", "COMMAND_FAILED")
		},
		"no tenant": func(s *Service, run *scanrun.Run) error {
			return s.OnStepCompleted(context.Background(), shared.ID{}, run.ID.String(), "a", 0, nil)
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			s, run, store, runs, cmds := gatingFixture(
				map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusRunning, "b": scanrun.StepRunStatusPending},
				map[string][]string{"b": {"a"}})

			err := call(s, run)
			if !errors.Is(err, shared.ErrNotFound) {
				t.Fatalf("err = %v, want not found", err)
			}
			if got := store.rows["a"].Status; got != scanrun.StepRunStatusRunning {
				t.Fatalf("step a is %s, want it still running", got)
			}
			if len(cmds.created) != 0 {
				t.Fatalf("queued %d command(s) for the dependent step", len(cmds.created))
			}
			if len(runs.statuses) != 0 || runs.updated != nil {
				t.Fatalf("run changed: statuses %v, updated %v", runs.statuses, runs.updated != nil)
			}
		})
	}
}

// The run's own tenant still settles the step (the check does not refuse the
// normal path).
func TestStepResult_OwnTenant_Settles(t *testing.T) {
	s, run, store, _, _ := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusRunning}, nil)

	if err := s.OnStepCompleted(context.Background(), run.TenantID, run.ID.String(), "a", 3, nil); err != nil {
		t.Fatal(err)
	}
	if got := store.rows["a"].Status; got != scanrun.StepRunStatusCompleted {
		t.Fatalf("step a is %s, want completed", got)
	}
}

// tenantBoundRuns answers GetByTenantAndID the way the repository does: a run of
// another tenant is not found.
type tenantBoundRuns struct {
	*statusRuns
}

func (r tenantBoundRuns) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*scanrun.Run, error) {
	if r.run.TenantID != tenantID || r.run.ID != id {
		return nil, shared.ErrNotFound
	}
	return r.run, nil
}

func TestStepStarted_ForeignTenant_AssignsNoSensor(t *testing.T) {
	s, run, store, runs, _ := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusQueued}, nil)
	s.runRepo = tenantBoundRuns{runs}

	err := s.OnStepStarted(context.Background(), shared.NewID(), run.ID.String(), "a", shared.NewID(), shared.NewID())
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("err = %v, want not found", err)
	}
	if got := store.rows["a"]; got.Status != scanrun.StepRunStatusQueued || got.SensorID != nil {
		t.Fatalf("step a = %s with sensor %v, want queued with none", got.Status, got.SensorID)
	}
}
