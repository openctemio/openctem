package coverage

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestObserverKey(t *testing.T) {
	if got := ObserverKey("z1", "s1"); got != "zone:z1" {
		t.Fatalf("zone first: %q", got)
	}
	if got := ObserverKey("", "s1"); got != "sensor:s1" {
		t.Fatalf("sensor: %q", got)
	}
	if got := ObserverKey("", ""); got != "" {
		t.Fatalf("unknown: %q", got)
	}
}

// A target-side failure carries the task's observer; a covered target
// does not (nothing to key).
func TestVerdicts_CarryObserver(t *testing.T) {
	res := json.RawMessage(`{"target_outcomes":[{"target":"down.example.com","state":"failed","class":"unreachable"},{"target":"up.example.com","state":"done"}]}`)
	v := Verdicts([]TaskResult{{Status: "completed", Targets: []string{"down.example.com", "up.example.com"},
		Result: res, Observer: "zone:z1"}}, nil)
	down := v[TargetKey("down.example.com")]
	if down.Outcome != "unreachable" || down.Observer != "zone:z1" {
		t.Fatalf("down = %+v, want unreachable observed by zone:z1", down)
	}
	if up := v[TargetKey("up.example.com")]; up.Kind != VerdictCovered || up.Observer != "" {
		t.Fatalf("up = %+v", up)
	}
}

// Unreachable pairs raise their own alert, with counts and the capability
// only, and an action that says what to check.
func TestConditions_Unreachable(t *testing.T) {
	conds := Conditions([]CapabilityHealth{{Capability: "probe.http", Applicable: 4, Unreachable: 3}})
	if len(conds) != 1 || conds[0].Kind != AlertUnreachable || conds[0].Count != 3 {
		t.Fatalf("conditions %+v, want one unreachable alert of 3", conds)
	}
	act := ActionFor(conds[0])
	if act.URL != "/assets" || act.Text == "" {
		t.Fatalf("action %+v", act)
	}
	if conds := Conditions([]CapabilityHealth{{Capability: "probe.http", Applicable: 4}}); len(conds) != 0 {
		t.Fatalf("no unreachable pair, no alert: %+v", conds)
	}
}

// The asset view names the observer only on a pair paused for a
// target-side outcome.
func TestView_UnreachedFrom(t *testing.T) {
	id := shared.NewID()
	rows := []Row{
		{Pair: Pair{Capability: "resolve.dns"}, State: StatePaused, Reason: "timeout", UnreachedFromName: "dmz"},
		{Pair: Pair{Capability: "probe.http"}, State: StateCovered, UnreachedFromName: "dmz"},
	}
	v := View(id, nil, rows, time.Now())
	got := map[string]string{}
	for _, e := range v.Entries {
		got[e.Capability] = e.UnreachedFrom
	}
	if got["resolve.dns"] != "dmz" || got["probe.http"] != "" {
		t.Fatalf("unreached_from = %v", got)
	}
}
