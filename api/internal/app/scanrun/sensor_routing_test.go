package scanrun

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The scan trigger's routing decision wins over the workflow's preference
// (research/62 SG-11): a workflow that prefers platform sensors no longer
// sends the steps of an internal-target scan there.
func TestStepUsesPlatform_FollowsTheTriggerDecision(t *testing.T) {
	s := &Service{sensorSelector: platformSelector{}, logger: logger.NewNop()}
	step := &scanworkflow.Step{Tool: "nuclei"}
	cases := []struct {
		name    string
		routing any
		pref    scanworkflow.SensorPreference
		want    bool
	}{
		{"tenant decision beats a platform workflow", scanrun.SensorRoutingTenant, scanworkflow.SensorPreferencePlatform, false},
		{"platform decision", scanrun.SensorRoutingPlatform, scanworkflow.SensorPreferenceTenant, true},
		{"auto decision ignores a tenant workflow", scanrun.SensorRoutingAuto, scanworkflow.SensorPreferenceTenant, true},
		{"no decision: workflow preference", nil, scanworkflow.SensorPreferenceTenant, false},
		{"unknown decision is no decision", "everywhere", scanworkflow.SensorPreferenceTenant, false},
	}
	for _, tc := range cases {
		ctx := map[string]any{}
		if tc.routing != nil {
			ctx[scanrun.RunContextKeySensorRouting] = tc.routing
		}
		run := &scanrun.Run{TenantID: shared.NewID(), Context: ctx}
		if got := s.stepUsesPlatform(context.Background(), run, step, tc.pref); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A caller of a workflow run cannot hand itself a routing decision.
func TestGateRunContext_DropsCallerRouting(t *testing.T) {
	s := &Service{logger: logger.NewNop()}
	out, err := s.gateRunContext(context.Background(), shared.NewID(), "",
		map[string]any{scanrun.RunContextKeySensorRouting: scanrun.SensorRoutingPlatform, "note": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out[scanrun.RunContextKeySensorRouting]; ok || out["note"] != "x" {
		t.Fatalf("context after gate = %v", out)
	}
}
