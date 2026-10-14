package scanrun

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
)

// kindFixture is a one-step run whose step runs tool on typed-in targets.
func kindFixture(t *testing.T, tool string, targets ...string) (*Service, *scanrun.Run, *memStepRuns, *countingCommands) {
	t.Helper()
	s, run, store, cmds := typeGateFixture(&fakeStepGate{})
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.ScanWorkflowID)
	tpl.Steps[0].Tool = tool
	run.Context["targets"] = targets
	delete(run.Context, scanapp.RunContextKeyTargetTypes)
	return s, run, store, cmds
}

func commandTargets(t *testing.T, cmds *countingCommands) []any {
	t.Helper()
	if len(cmds.created) != 1 {
		t.Fatalf("commands = %d, want 1", len(cmds.created))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(cmds.created[0]), &payload); err != nil {
		t.Fatal(err)
	}
	ts, _ := payload["targets"].([]any)
	return ts
}

// A typed-in network range used to reach every step of a workflow, HTTP
// probing and vulnerability templates included (only asset-group members
// were type-gated). A template step now gets the names and addresses only.
func TestStepDispatch_RangeNeverReachesTemplates(t *testing.T) {
	s, run, _, cmds := kindFixture(t, "nuclei", "203.0.113.0/24", "app.example.com", "203.0.113.9", "198.51.100.0-198.51.100.20")
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.ScanWorkflowID)
	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	if got, want := commandTargets(t, cmds), []any{"app.example.com", "203.0.113.9"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("nuclei targets = %v, want %v", got, want)
	}
}

func TestStepDispatch_RangeOnlyTemplateStepFails(t *testing.T) {
	s, run, store, cmds := kindFixture(t, "httpx", "203.0.113.0/24")
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.ScanWorkflowID)
	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	if len(cmds.created) != 0 {
		t.Fatalf("a command reached the sensor queue: %v", cmds.created)
	}
	if a := store.rows["a"]; a.Status != scanrun.StepRunStatusFailed || a.ErrorCode != "INCOMPATIBLE_TARGETS" {
		t.Fatalf("step a = %s/%s (%s), want failed/INCOMPATIBLE_TARGETS", a.Status, a.ErrorCode, a.ErrorMessage)
	}
}

// The port scan still takes the range (it expands it itself until host
// discovery ships); a URL does not go to it.
func TestStepDispatch_PortScanTakesRange(t *testing.T) {
	s, run, _, cmds := kindFixture(t, "naabu", "203.0.113.0/24", "https://app.example.com/login", "app.example.com")
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.ScanWorkflowID)
	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	if got, want := commandTargets(t, cmds), []any{"203.0.113.0/24", "app.example.com"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("naabu targets = %v, want %v", got, want)
	}
}

func TestGateStepKinds_ChainedStepKeepsEmptySeeds(t *testing.T) {
	st, ok := testCat.ForStep("nuclei", nil)
	if !ok {
		t.Fatal("nuclei has no stage")
	}
	resolved := scanapp.StepTool{Catalog: testCat, Name: "nuclei", Stage: st, HasStage: true}
	got, err := gateStepKinds(resolved, &scanapp.StepTargets{Targets: []string{"203.0.113.0/24"}}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Targets == nil || len(got.Targets) != 0 || got.Refused != 1 {
		t.Fatalf("chained = %+v, want an empty seed list with 1 refused", got)
	}
}
