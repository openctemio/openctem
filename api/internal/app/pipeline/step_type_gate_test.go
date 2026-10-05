package pipeline

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	pipelinedom "github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// fakeStepGate is a target gate that also filters step targets.
type fakeStepGate struct {
	TargetGate
	out *scanapp.StepTargets
	err error
}

func (f *fakeStepGate) FilterStepTargets(context.Context, shared.ID, string, map[string]any) (*scanapp.StepTargets, error) {
	return f.out, f.err
}

func typeGateFixture(gate TargetGate) (*Service, *pipelinedom.Run, *memStepRuns, *countingCommands) {
	s, run, store, _, cmds := gatingFixture(
		map[string]pipelinedom.StepRunStatus{"a": pipelinedom.StepRunStatusPending}, nil)
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.PipelineID)
	tpl.Steps[0].Tool = "zap"
	run.Context = map[string]any{
		"targets":                        []string{"https://app.example.com", "github.com/acme/app"},
		scanapp.RunContextKeyTargetTypes: map[string]string{"https://app.example.com": "application/website", "github.com/acme/app": "repository"},
		// zone-routed, so the fixture needs no sensor routing
		pipelinedom.RunContextKeyScanZoneID: shared.NewID().String(),
	}
	s.targetGate = gate
	return s, run, store, cmds
}

// RFC-042 §6.3.8 O6 on the sensor dispatch path: a step whose tool can scan
// none of the run's targets fails with INCOMPATIBLE_TARGETS and no command
// is created for a sensor.
func TestStepDispatch_RefusesIncompatibleTargets(t *testing.T) {
	gate := &fakeStepGate{err: shared.NewDomainError("INCOMPATIBLE_TARGETS", "No target of this step can be scanned: zap cannot scan 1 repository", shared.ErrValidation)}
	s, run, store, cmds := typeGateFixture(gate)
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.PipelineID)

	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	if len(cmds.created) != 0 {
		t.Fatalf("a command reached the sensor queue: %v", cmds.created)
	}
	a := store.rows["a"]
	if a.Status != pipelinedom.StepRunStatusFailed || a.ErrorCode != "INCOMPATIBLE_TARGETS" {
		t.Fatalf("step a = %s/%s (%s), want failed/INCOMPATIBLE_TARGETS", a.Status, a.ErrorCode, a.ErrorMessage)
	}
}

// A step is handed only the targets its tool can scan, and the sensor never
// sees the platform's type bookkeeping.
func TestStepDispatch_SendsOnlyCompatibleTargets(t *testing.T) {
	gate := &fakeStepGate{out: &scanapp.StepTargets{Targets: []string{"https://app.example.com"}, Refused: 1, Reason: "zap cannot scan 1 repository"}}
	s, run, _, cmds := typeGateFixture(gate)
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.PipelineID)

	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	if len(cmds.created) != 1 {
		t.Fatalf("commands = %d, want 1", len(cmds.created))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(cmds.created[0]), &payload); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(payload["targets"], []any{"https://app.example.com"}) {
		t.Fatalf("targets = %v", payload["targets"])
	}
	ctx, _ := payload["context"].(map[string]any)
	if _, leaked := ctx[scanapp.RunContextKeyTargetTypes]; leaked {
		t.Fatal("target_types reached the sensor")
	}
	if !reflect.DeepEqual(ctx["targets"], []any{"https://app.example.com"}) {
		t.Fatalf("context targets = %v", ctx["targets"])
	}
}

// The fake must keep satisfying the interface the dispatcher type-asserts,
// or the gate is silently skipped and these tests prove nothing.
var _ StepTargetFilter = (*fakeStepGate)(nil)
