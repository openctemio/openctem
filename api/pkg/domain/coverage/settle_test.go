package coverage

import (
	"encoding/json"
	"testing"
	"time"
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

func TestTargetSide(t *testing.T) {
	for o, want := range map[string]bool{"unreachable": true, "timeout": true, "tool_error": false, "egress_refused": false,
		"failed": false, "unfinished": false, "not_dispatched": false, "stalled": false} {
		if IsTargetSide(o) != want {
			t.Errorf("IsTargetSide(%q) = %v", o, !want)
		}
	}
	day := 24 * time.Hour
	for n, want := range map[int]time.Duration{0: day, 1: day, 2: 3 * day, 3: 7 * day, 4: 7 * day, 50: 7 * day} {
		if got := TargetSideRecheck(n); got != want {
			t.Errorf("TargetSideRecheck(%d) = %v, want %v", n, got, want)
		}
	}
}

// A task whose every target failed the same target-side way points at the
// sensor, not at the targets: the verdicts are plain failures (back-off),
// not target-side pauses. A lone target, or a mixed task, keeps its class.
func TestVerdicts_UniformTargetSideFailureIsSensorFailure(t *testing.T) {
	task := func(targets []string, outcomes string) []TaskResult {
		return []TaskResult{{Status: "completed", Targets: targets, Result: json.RawMessage(`{"target_outcomes": ` + outcomes + `}`)}}
	}
	all := task([]string{"a", "b"}, `[{"target":"a","state":"failed","class":"timeout"},{"target":"b","state":"failed","class":"timeout"}]`)
	for k, v := range Verdicts(all, nil) {
		if v.Kind != VerdictFailed || v.Outcome != OutcomeFailed || IsTargetSide(v.Outcome) {
			t.Errorf("all timeouts, %s = %+v, want a sensor failure", k, v)
		}
	}
	mixed := task([]string{"a", "b"}, `[{"target":"a","state":"failed","class":"timeout"},{"target":"b","state":"done"}]`)
	if v := Verdicts(mixed, nil)["a"]; v.Outcome != "timeout" || !IsTargetSide(v.Outcome) {
		t.Errorf("one timeout among answers = %+v, want target-side", v)
	}
	lone := task([]string{"a"}, `[{"target":"a","state":"failed","class":"timeout"}]`)
	if v := Verdicts(lone, nil)["a"]; v.Outcome != "timeout" {
		t.Errorf("lone timeout = %+v, want target-side", v)
	}
	differing := task([]string{"a", "b"}, `[{"target":"a","state":"failed","class":"timeout"},{"target":"b","state":"failed","class":"unreachable"}]`)
	if v := Verdicts(differing, nil)["a"]; v.Outcome != "timeout" {
		t.Errorf("different classes = %+v, want each its own", v)
	}
}
