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

// A truncated result (cut short by a deadline, disk or cap) covers nothing:
// its done targets are unfinished, with or without per-target outcomes, and
// a later complete task still decides them.
func TestVerdicts_TruncatedResultNeverCovers(t *testing.T) {
	for name, result := range map[string]string{
		"no outcomes":   `{"metadata": {"truncated": true}}`,
		"top-level":     `{"truncated": true}`,
		"with outcomes": `{"metadata": {"truncated": true}, "target_outcomes": [{"target": "a", "state": "done"}, {"target": "b", "state": "done"}]}`,
	} {
		v := Verdicts([]TaskResult{{Status: "completed", Targets: []string{"a", "b"}, Result: json.RawMessage(result)}}, nil)
		for _, k := range []string{"a", "b"} {
			if v[k].Kind != VerdictFailed || v[k].Outcome != OutcomeUnfinished {
				t.Errorf("%s: %s = %+v, want unfinished", name, k, v[k])
			}
		}
	}
	// A complete follow-up overrides the truncated task.
	v := Verdicts([]TaskResult{
		{Status: "completed", Targets: []string{"a", "b"}, Result: json.RawMessage(`{"metadata": {"truncated": true}}`)},
		{Status: "completed", Targets: []string{"a"}},
	}, nil)
	if v["a"].Kind != VerdictCovered || v["b"].Kind != VerdictFailed {
		t.Errorf("follow-up: a = %+v, b = %+v", v["a"], v["b"])
	}
	// Facts about a target stay: unreached is still unreached, a skip stays blocked.
	v = Verdicts([]TaskResult{{Status: "completed", Targets: []string{"a", "b"},
		Result: json.RawMessage(`{"metadata": {"truncated": true, "unreached_targets": [{"target": "a"}]}}`)}}, nil)
	if v["a"].Outcome != "unreachable" || v["b"].Outcome != OutcomeUnfinished {
		t.Errorf("unreached: a = %+v, b = %+v", v["a"], v["b"])
	}
	v = Verdicts([]TaskResult{{Status: "completed", Targets: []string{"a", "b"},
		Result: json.RawMessage(`{"metadata": {"truncated": true}, "target_outcomes": [{"target": "a", "state": "skipped", "class": "refused"}, {"target": "b", "state": "done"}]}`)}}, nil)
	if v["a"].Kind != VerdictBlocked || v["b"].Kind != VerdictFailed {
		t.Errorf("skip: a = %+v, b = %+v", v["a"], v["b"])
	}
	// An untruncated result is unchanged.
	v = Verdicts([]TaskResult{{Status: "completed", Targets: []string{"a"}, Result: json.RawMessage(`{"metadata": {"truncated": false}}`)}}, nil)
	if v["a"].Kind != VerdictCovered {
		t.Errorf("complete = %+v", v["a"])
	}
}

// A name that does not resolve is unresolved, never failed: from the
// result's refused_targets (a sensor whose platform accepts revision 1
// outcomes reports it skipped as refused), from a failed name_gone or
// resolver_failed outcome (revision 2), and from a completed task without
// per-target outcomes (an older sensor), where it must not be covered.
func TestVerdicts_DeadNamesAreUnresolved(t *testing.T) {
	v := Verdicts([]TaskResult{
		{Status: "completed", Targets: []string{"gone.example.test", "flaky.example.test", "old.example.test", "denied.example.test", "ok.example.test"},
			Result: json.RawMessage(`{
				"metadata": {"refused_targets": [
					{"target": "gone.example.test", "reason": "unresolvable", "dns": "name_gone"},
					{"target": "flaky.example.test", "reason": "unresolvable", "dns": "resolver_failed"},
					{"target": "old.example.test", "reason": "unresolvable"},
					{"target": "denied.example.test", "reason": "denied_by_policy"}]},
				"target_outcomes": [
					{"target": "gone.example.test", "state": "skipped", "class": "refused"},
					{"target": "flaky.example.test", "state": "skipped", "class": "refused"},
					{"target": "old.example.test", "state": "skipped", "class": "refused"},
					{"target": "denied.example.test", "state": "skipped", "class": "refused"},
					{"target": "ok.example.test", "state": "done"}]}`)},
		{Status: "completed", Targets: []string{"rev2.example.test", "rev2flaky.example.test"},
			Result: json.RawMessage(`{"target_outcomes": [
				{"target": "rev2.example.test", "state": "failed", "class": "name_gone", "cause": "target"},
				{"target": "rev2flaky.example.test", "state": "failed", "class": "resolver_failed", "cause": "target"}]}`)},
		{Status: "completed", Targets: []string{"nooutcomes.example.test", "ran.example.test"},
			Result: json.RawMessage(`{"metadata": {"refused_targets": [{"target": "nooutcomes.example.test", "reason": "unresolvable", "dns": "name_gone"}]}}`)},
	}, nil)
	want := map[string]Verdict{
		"gone.example.test":       {Kind: VerdictUnresolved, Outcome: OutcomeNoAnswer},
		"flaky.example.test":      {Kind: VerdictUnresolved, Outcome: ReasonResolverFailed},
		"old.example.test":        {Kind: VerdictUnresolved, Outcome: OutcomeNoAnswer},
		"denied.example.test":     {Kind: VerdictBlocked},
		"ok.example.test":         {Kind: VerdictCovered, Outcome: OutcomeOK},
		"rev2.example.test":       {Kind: VerdictUnresolved, Outcome: OutcomeNoAnswer},
		"rev2flaky.example.test":  {Kind: VerdictUnresolved, Outcome: ReasonResolverFailed},
		"nooutcomes.example.test": {Kind: VerdictUnresolved, Outcome: OutcomeNoAnswer},
		"ran.example.test":        {Kind: VerdictCovered, Outcome: OutcomeOK},
	}
	for target, w := range want {
		got := v[target]
		if got.Kind != w.Kind || (w.Outcome != "" && got.Outcome != w.Outcome) {
			t.Errorf("%s = %+v, want kind %s outcome %q", target, got, w.Kind, w.Outcome)
		}
	}
}

// refused_targets is sensor-supplied: an entry for a target the task does
// not carry settles nothing (a sensor can only speak for its own task's
// targets), and a later task that covered the name wins over an earlier
// refusal.
func TestVerdicts_RefusedTargetsReadAgainstTheTask(t *testing.T) {
	v := Verdicts([]TaskResult{
		{Status: "completed", Targets: []string{"mine.example.test"},
			Result: json.RawMessage(`{"metadata": {"refused_targets": [
				{"target": "mine.example.test", "reason": "unresolvable", "dns": "name_gone"},
				{"target": "someone-else.example.test", "reason": "unresolvable", "dns": "name_gone"}]}}`)},
		{Status: "completed", Targets: []string{"mine.example.test"},
			Result: json.RawMessage(`{"target_outcomes": [{"target": "mine.example.test", "state": "done"}]}`)},
	}, nil)
	if _, ok := v["someone-else.example.test"]; ok {
		t.Error("a refused entry for a target the task did not carry was taken")
	}
	if v["mine.example.test"].Kind != VerdictCovered {
		t.Errorf("mine = %+v, want the later done to win", v["mine.example.test"])
	}
}

// A whole task failed (an older sensor refused the job) still settles the
// names it listed as unresolvable one by one, not as one failure.
func TestVerdicts_FailedTaskWithRefusedNamesSettlesPerName(t *testing.T) {
	v := Verdicts([]TaskResult{{Status: "failed", Error: "local policy refused", Targets: []string{"a.example.test", "b.example.test"},
		Result: json.RawMessage(`{"metadata": {"refused_targets": [{"target": "a.example.test", "reason": "unresolvable", "dns": "name_gone"}]}}`)}}, nil)
	if v["a.example.test"].Kind != VerdictUnresolved {
		t.Errorf("a = %+v", v["a.example.test"])
	}
	if v["b.example.test"].Kind != VerdictFailed {
		t.Errorf("b = %+v (not listed: the task's failure)", v["b.example.test"])
	}
}

func TestDeadNameRechecks_WidenToWeekly(t *testing.T) {
	got := DeadNameRechecks()
	want := []time.Duration{24 * time.Hour, 72 * time.Hour, 7 * 24 * time.Hour}
	if len(got) != len(want) {
		t.Fatalf("schedule %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("recheck %d = %v, want %v", i+1, got[i], want[i])
		}
	}
	got[0] = time.Minute
	if DeadNameRechecks()[0] != 24*time.Hour {
		t.Error("the schedule can be changed through the returned slice")
	}
}
