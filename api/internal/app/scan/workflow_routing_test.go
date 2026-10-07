package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A workflow scan routes by the scan's own sensor preference, with the
// checks a single scan gets (research/62 SG-11). Before: the steps followed
// the workflow's preference, so a workflow preferring platform sensors sent
// an asset group or an internal target to shared infrastructure, and a
// scan set to 'platform' was not checked at all.
func TestDecideWorkflowRouting(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		sel      SensorSelector
		pref     scan.SensorPreference
		tenantRO bool
		group    bool
		targets  []string
		want     string
		wantErr  bool
	}{
		{"tenant", stubSelector{false, true}, scan.SensorPreferenceTenant, false, false, []string{"a.example.com"}, sensorRoutingTenant, false},
		{"tenant runner only beats platform", stubSelector{false, true}, scan.SensorPreferencePlatform, true, false, []string{"a.example.com"}, sensorRoutingTenant, false},
		{"platform + asset group refused", stubSelector{false, true}, scan.SensorPreferencePlatform, false, true, []string{"a.example.com"}, "", true},
		{"platform + internal target refused", stubSelector{false, true}, scan.SensorPreferencePlatform, false, false, []string{"10.0.0.5"}, "", true},
		{"platform not allowed refused", stubSelector{false, false}, scan.SensorPreferencePlatform, false, false, []string{"a.example.com"}, "", true},
		{"platform public allowed", stubSelector{false, true}, scan.SensorPreferencePlatform, false, false, []string{"a.example.com"}, sensorRoutingPlatform, false},
		{"auto public allowed: per step", stubSelector{false, true}, scan.SensorPreferenceAuto, false, false, []string{"a.example.com"}, sensorRoutingAuto, false},
		{"auto + internal target: tenant only", stubSelector{false, true}, scan.SensorPreferenceAuto, false, false, []string{"192.168.1.4"}, sensorRoutingTenant, false},
		{"auto + asset group: tenant only", stubSelector{false, true}, scan.SensorPreferenceAuto, false, true, []string{"a.example.com"}, sensorRoutingTenant, false},
		{"auto, platform not allowed: tenant only", stubSelector{false, false}, scan.SensorPreferenceAuto, false, false, []string{"a.example.com"}, sensorRoutingTenant, false},
		{"auto, no selector: tenant only", nil, scan.SensorPreferenceAuto, false, false, []string{"a.example.com"}, sensorRoutingTenant, false},
	}
	for _, tc := range cases {
		svc := &Service{sensorSelector: tc.sel, logger: logger.NewNop()}
		sc := testScan("")
		sc.SensorPreference = tc.pref
		sc.RunOnTenantRunner = tc.tenantRO
		if tc.group {
			sc.SetAssetGroupIDs([]shared.ID{shared.NewID()})
		}
		got, err := svc.decideWorkflowRouting(ctx, sc, tc.targets)
		if (err != nil) != tc.wantErr {
			t.Fatalf("%s: err = %v", tc.name, err)
		}
		if err != nil {
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%s: refusal must be a validation error, got %v", tc.name, err)
			}
			continue
		}
		if got.Routing != tc.want {
			t.Fatalf("%s: got %+v, want %s", tc.name, got, tc.want)
		}
	}
}

// unprovenTargets reports every target as unproven.
type unprovenTargets struct{ AttributionGate }

func (unprovenTargets) UnverifiedTargets(_ context.Context, _ shared.ID, targets []string) ([]string, error) {
	return targets, nil
}

// With the operator's proof requirement, 'auto' keeps unproven targets off
// platform sensors.
func TestDecideWorkflowRouting_UnprovenStaysOnTenant(t *testing.T) {
	svc := &Service{sensorSelector: stubSelector{false, true}, logger: logger.NewNop(),
		activeProof: ActiveProofPlatformSensors, attributionGate: unprovenTargets{}}
	sc := testScan("")
	sc.SensorPreference = scan.SensorPreferenceAuto
	got, err := svc.decideWorkflowRouting(context.Background(), sc, []string{"a.example.com"})
	if err != nil || got.Routing != sensorRoutingTenant {
		t.Fatalf("got %+v, %v; want tenant", got, err)
	}
}
