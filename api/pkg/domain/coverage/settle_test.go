package coverage

import (
	"encoding/json"
	"testing"
)

// The sensor's per-target outcomes are read against each task's own
// targets: an outcome for a target the task does not carry is ignored, so
// a sensor cannot cover a target it was never given.
func TestVerdicts_SensorCannotAddTargets(t *testing.T) {
	v := Verdicts([]TaskResult{{
		Status: "completed", Targets: []string{"a.example.test"},
		Result: json.RawMessage(`{"target_outcomes": [{"target": "a.example.test", "state": "done"}, {"target": "other.example.test", "state": "done"}]}`),
	}}, nil)
	if v["a.example.test"].Kind != VerdictCovered {
		t.Errorf("a = %+v", v["a.example.test"])
	}
	if _, ok := v["other.example.test"]; ok {
		t.Error("an outcome for a target the task did not carry was taken")
	}
}

// Across tasks the best verdict wins, and a target missing from the
// outcomes of a task that has outcomes is unfinished.
func TestVerdicts_BestAcrossTasks(t *testing.T) {
	v := Verdicts([]TaskResult{
		{Status: "completed", Targets: []string{"x", "y"}, Result: json.RawMessage(`{"target_outcomes": [{"target": "x", "state": "failed", "class": "timeout"}]}`)},
		{Status: "completed", Targets: []string{"x"}, Result: json.RawMessage(`{"target_outcomes": [{"target": "x", "state": "done"}]}`)},
		{Status: "expired", Targets: []string{"z"}, Error: "lease expired"},
	}, []string{"x", "w"})
	if v["x"].Kind != VerdictCovered {
		t.Errorf("x = %+v (a later done must win over an earlier failure and the run's unfinished list)", v["x"])
	}
	if v["y"].Kind != VerdictFailed || v["y"].Outcome != OutcomeUnfinished {
		t.Errorf("y = %+v", v["y"])
	}
	if v["z"].Kind != VerdictFailed || v["z"].Error != "lease expired" {
		t.Errorf("z = %+v", v["z"])
	}
	if v["w"].Outcome != OutcomeUnfinished {
		t.Errorf("w = %+v", v["w"])
	}
	if TargetKey("  A.Example.TEST ") != "a.example.test" {
		t.Error("target keys are not case-insensitive")
	}
}

// A target the sensor could not reach is never settled as covered, with or
// without per-target outcomes, even though the run it belongs to completes
// (an unreachable target does not make a run partial).
func TestVerdicts_UnreachedTargetIsNotCovered(t *testing.T) {
	withOutcomes := json.RawMessage(`{"target_outcomes": [{"target": "a", "state": "done"}, {"target": "b", "state": "done"}],
		"metadata": {"unreached_targets": [{"target": "B", "class": "timeout"}]}}`)
	withoutOutcomes := json.RawMessage(`{"metadata": {"unreached_targets": [{"target": "B", "class": "timeout"}]}}`)
	for name, result := range map[string]json.RawMessage{"with outcomes": withOutcomes, "without outcomes": withoutOutcomes} {
		v := Verdicts([]TaskResult{{Status: "completed", Targets: []string{"a", "b"}, Result: result}}, nil)
		if v["a"].Kind != VerdictCovered {
			t.Errorf("%s: a = %+v, want covered", name, v["a"])
		}
		if v["b"].Kind != VerdictFailed || v["b"].Outcome != "unreachable" {
			t.Errorf("%s: b = %+v, want failed unreachable", name, v["b"])
		}
	}
}
