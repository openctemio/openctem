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
	// The sensor's own per-host limit, only while the platform sees the
	// hosts free (else host_busy says it).
	got = jobReasons(commanddom.PlacementJob{NotExpired: true, Due: true, HostFree: true, SensorHostsBusy: true})
	if !slices.Equal(got, []string{commanddom.PlacementSensorHostsBusy}) {
		t.Fatalf("sensor hosts busy: %v", got)
	}
	got = jobReasons(commanddom.PlacementJob{NotExpired: true, Due: true, HostFree: false, SensorHostsBusy: true})
	if !slices.Equal(got, []string{commanddom.PlacementHostBusy}) {
		t.Fatalf("both: %v", got)
	}
}

func TestHostConflicts(t *testing.T) {
	if got := hostConflicts("203.0.113.7"); !slices.Contains(got, "net:203.0.113.0/24") || !slices.Contains(got, "203.0.113.7") {
		t.Fatalf("address: %v", got)
	}
	if got := hostConflicts("10.0.0.5#net-1"); !slices.Contains(got, "net:10.0.0.0/24#net-1") {
		t.Fatalf("scoped address: %v", got)
	}
	if got := hostConflicts("a.example.com"); !slices.Equal(got, []string{"a.example.com"}) {
		t.Fatalf("name: %v", got)
	}
	if got := hostConflicts("net:198.51.100.0/24"); !slices.Contains(got, "in:198.51.100.0/24") {
		t.Fatalf("range: %v", got)
	}
}

func TestIsHostsBusyRelease(t *testing.T) {
	for _, r := range []string{"hosts_busy", "its hosts are busy on this sensor", " Its hosts are busy on this sensor "} {
		if !commanddom.IsHostsBusyRelease(r) {
			t.Fatalf("%q not recognized", r)
		}
	}
	if commanddom.IsHostsBusyRelease("no free slot") {
		t.Fatal("another reason taken for hosts busy")
	}
}

// A sensor that is busy only because host pressure took its slots away is
// counted under sensor_overloaded; a plain busy one stays unexplained.
func TestPlacementSummary_OverloadedBusy(t *testing.T) {
	p := &Placement{Sensors: []SensorPlacement{
		{Eligible: true, Busy: true, Reasons: []string{commanddom.PlacementSensorOverloaded}},
		{Eligible: true, Busy: true},
	}}
	p.summarize()
	want := []ReasonCount{{commanddom.PlacementSensorOverloaded, 1}}
	if p.Eligible != 2 || p.Busy != 2 || !slices.Equal(p.Blocking, want) {
		t.Fatalf("eligible %d busy %d blocking %v", p.Eligible, p.Busy, p.Blocking)
	}
}

func TestWithheldText(t *testing.T) {
	for code, want := range map[string]string{
		"grant_credentials":                   "withheld by sensor permissions: credentials",
		"grant_tier_ceiling":                  "withheld by sensor permissions: tier ceiling",
		commanddom.PlacementIntensity:         "withheld: the job's tier is above the scan's intensity",
		commanddom.PlacementLocalPolicy:       "withheld: the sensor's local policy refuses it",
		commanddom.PlacementPolicyUnavailable: "withheld: the sensor's policy could not be read",
		"something_new":                       "withheld: something_new",
	} {
		if got := commanddom.WithheldText(code); got != want {
			t.Errorf("%s: %q, want %q", code, got, want)
		}
	}
}
