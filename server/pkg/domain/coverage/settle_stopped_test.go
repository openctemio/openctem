package coverage

import (
	"encoding/json"
	"strings"
	"testing"
)

// A completed task whose result says the run did not finish by itself
// covers nothing (research/467 F6). The legacy shape is the one that
// matters: an older sensor reports a budget-killed scanner as "completed",
// exit -1, every target done. Its done targets are unfinished and are
// scanned again; a later clean task still decides them.
func TestVerdicts_StoppedRunNeverCovers(t *testing.T) {
	for name, result := range map[string]string{
		"legacy budget kill, every target done": `{"status": "completed", "exit_code": -1, "metadata": {"coverage_type": "full"}, "target_outcomes": [{"target": "a", "state": "done"}, {"target": "b", "state": "done"}]}`,
		"tool gave up, exit 1, no outcomes":     `{"status": "completed", "exit_code": 1}`,
		"partial result status":                 `{"status": "partial", "exit_code": 0}`,
		"sensor says it stopped":                `{"exit_code": 0, "stop_reason": "lease_lost"}`,
		"unreadable result":                     `{"exit_code": `,
	} {
		v := Verdicts([]TaskResult{{Status: "completed", Targets: []string{"a", "b"}, Result: json.RawMessage(result)}}, nil)
		for _, k := range []string{"a", "b"} {
			if v[k].Kind != VerdictFailed || v[k].Outcome != OutcomeUnfinished {
				t.Errorf("%s: %s = %+v, want unfinished", name, k, v[k])
			}
			if !strings.Contains(v[k].Error, "did not finish") {
				t.Errorf("%s: %s error = %q, want the stop named", name, k, v[k].Error)
			}
		}
	}
	// A clean follow-up decides the targets the stopped run left.
	v := Verdicts([]TaskResult{
		{Status: "completed", Targets: []string{"a", "b"}, Result: json.RawMessage(`{"status": "completed", "exit_code": -1}`)},
		{Status: "completed", Targets: []string{"a"}, Result: json.RawMessage(`{"status": "completed", "exit_code": 0}`)},
	}, nil)
	if v["a"].Kind != VerdictCovered || v["b"].Kind != VerdictFailed {
		t.Errorf("follow-up: a = %+v, b = %+v", v["a"], v["b"])
	}
	// A clean run with exit 0 still covers.
	v = Verdicts([]TaskResult{{Status: "completed", Targets: []string{"a"}, Result: json.RawMessage(`{"status": "completed", "exit_code": 0}`)}}, nil)
	if v["a"].Kind != VerdictCovered {
		t.Errorf("clean = %+v", v["a"])
	}
}
