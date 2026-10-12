package scanrun

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type recordingNotifier struct{ runs []shared.ID }

func (r *recordingNotifier) RunChanged(_, runID shared.ID) { r.runs = append(r.runs, runID) }

// Advancing a run (a step finished, the next one queued) tells the live run
// map; without a notifier nothing happens.
func TestAdvanceRun_NotifiesTheRunMap(t *testing.T) {
	s, run, _, _, _ := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusCompleted, "b": scanrun.StepRunStatusPending},
		map[string][]string{"b": {"a"}})
	s.sensorRepo = tenantSensors{id: shared.NewID()}
	run.Context = map[string]any{"targets": []string{"example.com"}}
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.ScanWorkflowID)
	tpl.Steps[1].Tool = "nuclei"

	n := &recordingNotifier{}
	s.SetRunNotifier(n)
	if err := s.AdvanceRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if len(n.runs) == 0 || n.runs[len(n.runs)-1] != run.ID {
		t.Fatalf("notified runs = %v, want the run %s", n.runs, run.ID)
	}

	s.SetRunNotifier(nil)
	if err := s.AdvanceRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
}
