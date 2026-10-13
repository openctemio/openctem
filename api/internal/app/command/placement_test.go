package command

import (
	"slices"
	"testing"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
)

func TestGateReason(t *testing.T) {
	for _, tc := range []struct {
		r    sensordom.DispatchRefusal
		want string
	}{
		{sensordom.DispatchRefusal{Layer: RefusalLayerGrant, Rule: sensordom.DimTools}, "grant_tools"},
		{sensordom.DispatchRefusal{Layer: RefusalLayerGrant, Rule: sensordom.DimTier}, "grant_tier_ceiling"},
		{sensordom.DispatchRefusal{Layer: RefusalLayerGrant, Rule: RuleIntensity}, commanddom.PlacementIntensity},
		{sensordom.DispatchRefusal{Layer: sensordom.RefusalLayerManaged, Rule: "unavailable"}, commanddom.PlacementPolicyUnavailable},
		{sensordom.DispatchRefusal{Layer: sensordom.RefusalLayerManaged, Rule: sensordom.RulePrivateNeedsLocalPlcy}, commanddom.PlacementPrivateNeedsPolicy},
		{sensordom.DispatchRefusal{Layer: sensordom.RefusalLayerManaged, Rule: sensordom.RuleAllowInteractsh}, commanddom.PlacementOptInDisabled},
		{sensordom.DispatchRefusal{Layer: "local", Rule: "tools.allow"}, commanddom.PlacementLocalPolicy},
	} {
		if got := gateReason(&tc.r); got != tc.want {
			t.Errorf("%+v: %s, want %s", tc.r, got, tc.want)
		}
	}
}

func TestPlacementSummary(t *testing.T) {
	p := &Placement{Sensors: []SensorPlacement{
		{Eligible: true},
		{Eligible: true, Busy: true},
		{Reasons: []string{commanddom.PlacementOffline, commanddom.PlacementToolMissing}},
		{Reasons: []string{commanddom.PlacementToolMissing}},
	}}
	p.summarize()
	if p.Eligible != 2 || p.Busy != 1 {
		t.Fatalf("eligible %d busy %d", p.Eligible, p.Busy)
	}
	want := []ReasonCount{{commanddom.PlacementToolMissing, 2}, {commanddom.PlacementOffline, 1}}
	if !slices.Equal(p.Blocking, want) {
		t.Fatalf("blocking %v, want %v", p.Blocking, want)
	}
}

func TestJobReasons(t *testing.T) {
	got := jobReasons(commanddom.PlacementJob{NotExpired: true, Due: false, HostFree: false})
	if !slices.Equal(got, []string{commanddom.PlacementWindowClosed, commanddom.PlacementHostBusy}) {
		t.Fatalf("job reasons %v", got)
	}
	if got := jobReasons(commanddom.PlacementJob{NotExpired: true, Due: true, HostFree: true}); len(got) != 0 {
		t.Fatalf("ready job: %v", got)
	}
}
