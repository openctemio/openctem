package handler

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Every run says who or what started it in one shape (research/62 P0-3):
// the old trigger_type + free-text triggered_by left "manual" on a run an
// automation started and nothing on a retest the platform started.
func TestRunTrigger(t *testing.T) {
	user, auto, autoRun, scan := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	cases := []struct {
		name string
		run  scanrun.Run
		want RunTrigger
	}{
		{"a person", scanrun.Run{TriggerType: scanworkflow.TriggerTypeManual, TriggeredBy: user.String()},
			RunTrigger{Type: "user", ID: user.String()}},
		{"an automation step (cause in the run context)", scanrun.Run{TriggerType: scanworkflow.TriggerTypeManual,
			TriggeredBy: "workflow:" + auto.String(),
			Context:     map[string]any{"automation_cause": map[string]any{"workflow_id": auto.String(), "run_id": autoRun.String(), "node_key": "rescan", "chain_depth": 1}}},
			RunTrigger{Type: "automation", ID: auto.String(), RunID: autoRun.String(), NodeKey: "rescan"}},
		{"an automation (triggered_by only)", scanrun.Run{TriggerType: scanworkflow.TriggerTypeManual, TriggeredBy: "workflow:" + auto.String()},
			RunTrigger{Type: "automation", ID: auto.String()}},
		{"an automation run without a cause", scanrun.Run{TriggerType: scanworkflow.TriggerTypeAutomation},
			RunTrigger{Type: "automation"}},
		{"a schedule", scanrun.Run{TriggerType: scanworkflow.TriggerTypeSchedule, ScanID: &scan},
			RunTrigger{Type: "schedule", ID: scan.String()}},
		{"the platform", scanrun.Run{TriggerType: scanworkflow.TriggerTypeSystem, TriggeredBy: "system"},
			RunTrigger{Type: "system"}},
		{"manual with no person", scanrun.Run{TriggerType: scanworkflow.TriggerTypeManual, TriggeredBy: "system"},
			RunTrigger{Type: "system"}},
		{"an API key", scanrun.Run{TriggerType: scanworkflow.TriggerTypeAPI, TriggeredBy: "api_key:abc"},
			RunTrigger{Type: "api"}},
		{"asset discovery", scanrun.Run{TriggerType: scanworkflow.TriggerTypeOnAssetDiscovery},
			RunTrigger{Type: "asset_discovery"}},
	}
	for _, c := range cases {
		if got := runTrigger(&c.run); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

// The user label is set only on a user trigger; an automation id that
// happens to be a known user id is not named.
func TestWithRunTriggerLabel(t *testing.T) {
	user := shared.NewID().String()
	names := map[string]string{user: "Ada"}
	resp := withRunTriggerLabel(&RunResponse{TriggeredBy: user, Trigger: &RunTrigger{Type: "user", ID: user}}, names)
	if resp.Trigger.Label != "Ada" || resp.TriggeredByName != "Ada" {
		t.Fatalf("user trigger = %+v / %q", resp.Trigger, resp.TriggeredByName)
	}
	auto := withRunTriggerLabel(&RunResponse{TriggeredBy: "workflow:" + user, Trigger: &RunTrigger{Type: "automation", ID: user}}, names)
	if auto.Trigger.Label != "" {
		t.Fatalf("automation trigger labeled with a user name: %+v", auto.Trigger)
	}
}

// The run response carries the counts the run recorded in its context (an int
// in memory, a float64 after the JSON round trip), never negative ones.
func TestToRunResponse_UnreachableAndSkippedCounts(t *testing.T) {
	r := scanrun.Run{TenantID: shared.NewID(), Context: map[string]any{
		"unreachable_target_count": 3, "skipped_target_count": float64(2),
	}}
	got := toRunResponse(&r)
	if got.UnreachableTargetCount != 3 || got.SkippedTargetCount != 2 {
		t.Fatalf("counts = %d / %d, want 3 / 2", got.UnreachableTargetCount, got.SkippedTargetCount)
	}
	neg := scanrun.Run{TenantID: shared.NewID(), Context: map[string]any{"unreachable_target_count": -4, "skipped_target_count": "7"}}
	if g := toRunResponse(&neg); g.UnreachableTargetCount != 0 || g.SkippedTargetCount != 0 {
		t.Fatalf("hostile counts = %d / %d, want 0 / 0", g.UnreachableTargetCount, g.SkippedTargetCount)
	}
	if g := toRunResponse(&scanrun.Run{TenantID: shared.NewID()}); g.UnreachableTargetCount != 0 || g.SkippedTargetCount != 0 {
		t.Fatalf("no context: %d / %d", g.UnreachableTargetCount, g.SkippedTargetCount)
	}
}
