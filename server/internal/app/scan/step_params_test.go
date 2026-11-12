package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/scan"
	"github.com/openctemio/openctem/server/pkg/domain/scanrun"
	"github.com/openctemio/openctem/server/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

type fakeSteps struct {
	scanworkflow.StepRepository
	steps []*scanworkflow.Step
}

func (f fakeSteps) GetByScanWorkflowID(context.Context, shared.ID) ([]*scanworkflow.Step, error) {
	return f.steps, nil
}

func stepParamsFixture() (*Service, *scan.Scan) {
	steps := []*scanworkflow.Step{
		{StepKey: "ports", Capabilities: []string{"scan.ports"}},
		{StepKey: "vulns", Capabilities: []string{"vuln.templates"}},
		{StepKey: "vulns_pinned", Tool: "nuclei", Capabilities: []string{"vuln.templates"}},
	}
	wf := shared.NewID()
	sc, _ := scan.NewScanWithTargets(shared.NewID(), "n", []string{"example.com"}, scan.ScanTypeWorkflow)
	sc.ScanWorkflowID = &wf
	return &Service{stepRepo: fakeSteps{steps: steps}}, sc
}

func TestApplyStepParams_Accepts(t *testing.T) {
	s, sc := stepParamsFixture()
	in := scan.StepParams{
		"*:vuln.templates": {"severity": []any{"info", "low"}, "tags": []any{"cve", "exposure"}, "exclude_tags": []any{"dos"}},
		"ports":            {"ports": "80,443", "rate": float64(100)},
	}
	if err := s.applyStepParams(context.Background(), sc, in); err != nil {
		t.Fatal(err)
	}
	if len(sc.StepParams) != 2 {
		t.Fatalf("not stored: %v", sc.StepParams)
	}
	// nil leaves, {} clears.
	if err := s.applyStepParams(context.Background(), sc, nil); err != nil || len(sc.StepParams) != 2 {
		t.Fatalf("nil must leave: %v %v", err, sc.StepParams)
	}
	if err := s.applyStepParams(context.Background(), sc, scan.StepParams{}); err != nil || sc.StepParams != nil {
		t.Fatalf("{} must clear: %v %v", err, sc.StepParams)
	}
}

func TestApplyStepParams_Refuses(t *testing.T) {
	cases := map[string]scan.StepParams{
		"unknown step":           {"nope": {"tags": []any{"cve"}}},
		"unknown capability":     {"*:nope.cap": {"tags": []any{"cve"}}},
		"capability not in flow": {"*:crawl.web": {"depth": 2}},
		"unknown param":          {"vulns": {"templates": []any{"x.yaml"}}},
		"tool extras":            {"vulns_pinned": {"x": map[string]any{"nuclei": map[string]any{"tags": []any{"cve"}}}}},
		"executor key":           {"ports": {"exclude": []any{"10.0.0.1"}}},
		"wrong type":             {"ports": {"rate": "fast"}},
		"out of bounds":          {"ports": {"rate": float64(-5)}},
		"bad severity":           {"vulns": {"severity": []any{"urgent"}}},
		"intrusive tag":          {"vulns": {"tags": []any{"intrusive"}}},
		"default-login tag":      {"*:vuln.templates": {"tags": []any{"cve", "default-login"}}},
		"brute-force tag":        {"vulns": {"tags": []any{"brute-force"}}},
		"bruteforce tag":         {"vulns": {"tags": []any{"BruteForce"}}},
		"fuzz tag":               {"vulns": {"tags": []any{"fuzz"}}},
		"dos tag":                {"vulns": {"tags": "dos"}},
		"fuzzing tag":            {"vulns": {"tags": []any{"fuzzing"}}},
		"flag-like tag":          {"vulns": {"tags": []any{"-severity"}}},
	}
	for name, in := range cases {
		s, sc := stepParamsFixture()
		err := s.applyStepParams(context.Background(), sc, in)
		var de *shared.DomainError
		if err == nil || !errors.Is(err, shared.ErrValidation) || !errors.As(err, &de) || de.Code != scan.CodeInvalidStepParams {
			t.Errorf("%s: err = %v, want INVALID_STEP_PARAMS", name, err)
		}
		if sc.StepParams != nil {
			t.Errorf("%s: a refused map was stored", name)
		}
	}
}

func TestApplyStepParams_SingleScanRefused(t *testing.T) {
	s, sc := stepParamsFixture()
	sc.ScanType = scan.ScanTypeSingle
	if err := s.applyStepParams(context.Background(), sc, scan.StepParams{"vulns": {"tags": []any{"cve"}}}); err == nil {
		t.Fatal("a single scan has no steps")
	}
}

func TestStepWithScanParams_MergesOverConfigWithoutMutating(t *testing.T) {
	step := &scanworkflow.Step{StepKey: "vulns", Capabilities: []string{"vuln.templates"},
		Config: map[string]any{"severity": []any{"critical"}, "tags": []any{"cve"}}}
	run := &scanrun.Run{Context: map[string]any{scanrun.RunContextKeyStepParams: map[string]any{
		"*:vuln.templates": map[string]any{"severity": []any{"high"}},
		"vulns":            map[string]any{"tags": []any{"exposure"}},
	}}}
	got := StepWithScanParams(run, step)
	if got.Config["severity"].([]any)[0] != "high" || got.Config["tags"].([]any)[0] != "exposure" {
		t.Fatalf("config = %v", got.Config)
	}
	if step.Config["severity"].([]any)[0] != "critical" {
		t.Fatal("the workflow step was changed")
	}
	if StepWithScanParams(&scanrun.Run{}, step) != step {
		t.Fatal("no params must return the step as is")
	}
}

func TestSetRunStepParams(t *testing.T) {
	_, sc := stepParamsFixture()
	ctx := map[string]any{scanrun.RunContextKeyStepParams: "stale"}
	setRunStepParams(ctx, sc)
	if _, ok := ctx[scanrun.RunContextKeyStepParams]; ok {
		t.Fatal("stale entry kept")
	}
	sc.StepParams = scan.StepParams{"vulns": {"tags": []any{"cve"}}}
	setRunStepParams(ctx, sc)
	if len(scan.StepParamsFromAny(ctx[scanrun.RunContextKeyStepParams])) != 1 {
		t.Fatal("not copied")
	}
}

// The override is checked on top of the step's own settings: a step whose
// settings are not valid as a whole refuses the entry that would run on it.
func TestApplyStepParams_RefusesWhenMergedConfigIsInvalid(t *testing.T) {
	s, sc := stepParamsFixture()
	steps := s.stepRepo.(fakeSteps).steps
	steps[0].Config = map[string]any{"not_a_setting": 1} // an auto step with a key no capability takes
	err := s.applyStepParams(context.Background(), sc, scan.StepParams{"ports": {"ports": "80"}})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want a validation refusal", err)
	}
	if sc.StepParams != nil {
		t.Fatal("refused params were stored")
	}
}
