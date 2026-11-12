package scanzone

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func boolp(b bool) *bool { return &b }

func TestJudgeZoneSensors(t *testing.T) {
	z := mustZone(t, "dc", false, "10.0.0.0/16")
	noPrivate := &sensor.LocalPolicyReport{State: sensor.LocalPolicyAbsent, AllowPrivate: boolp(false)}
	private := &sensor.LocalPolicyReport{State: sensor.LocalPolicyAbsent, AllowPrivate: boolp(true)}
	strictFile := &sensor.LocalPolicyReport{State: sensor.LocalPolicyEnforced, Summary: &sensor.LocalPolicySummary{TargetsAllow: -1}}
	newS := ZoneSensorState{ID: shared.NewID(), Name: "edge-new", LocalPolicy: private}
	trusted := ZoneSensorState{ID: shared.NewID(), Name: "core", Trusted: true, LocalPolicy: private}
	trustedNoPriv := ZoneSensorState{ID: shared.NewID(), Name: "core-np", Trusted: true, LocalPolicy: noPrivate}
	trustedOld := ZoneSensorState{ID: shared.NewID(), Name: "core-old", Trusted: true} // never reported
	trustedFile := ZoneSensorState{ID: shared.NewID(), Name: "core-file", Trusted: true, LocalPolicy: strictFile}

	cases := []struct {
		name     string
		states   []ZoneSensorState
		need     SensorNeed
		kind     string
		sensor   shared.ID
		eligible []shared.ID
	}{
		{name: "no state decides nothing", need: SensorNeed{Tier: 1, Private: true}},
		{name: "only New, active job", states: []ZoneSensorState{newS}, need: SensorNeed{Tier: 1}, kind: KindZoneSensorNew, sensor: newS.ID},
		{name: "only New, intrusive job", states: []ZoneSensorState{newS}, need: SensorNeed{Tier: 2, Private: true}, kind: KindZoneSensorNew, sensor: newS.ID},
		{name: "only New, passive job still routes", states: []ZoneSensorState{newS}, need: SensorNeed{Tier: 0, Private: true}, eligible: []shared.ID{newS.ID}},
		{name: "only New, unknown tier left to the claim", states: []ZoneSensorState{newS}, need: SensorNeed{Tier: TierUnknown}, eligible: []shared.ID{newS.ID}},
		{name: "New and Trusted: the Trusted one only", states: []ZoneSensorState{newS, trusted}, need: SensorNeed{Tier: 1, Private: true}, eligible: []shared.ID{trusted.ID}},
		{name: "host refuses private", states: []ZoneSensorState{trustedNoPriv}, need: SensorNeed{Tier: 1, Private: true}, kind: KindZoneSensorNoPrivate, sensor: trustedNoPriv.ID},
		{name: "enforced file without allow_private", states: []ZoneSensorState{trustedFile}, need: SensorNeed{Tier: 1, Private: true}, kind: KindZoneSensorNoPrivate, sensor: trustedFile.ID},
		{name: "host refuses private, public target routes", states: []ZoneSensorState{trustedNoPriv}, need: SensorNeed{Tier: 1}, eligible: []shared.ID{trustedNoPriv.ID}},
		{name: "unreported sensor is left to the sensor", states: []ZoneSensorState{trustedOld}, need: SensorNeed{Tier: 1, Private: true}, eligible: []shared.ID{trustedOld.ID}},
		{name: "one refuses private, the other takes it", states: []ZoneSensorState{trustedNoPriv, trusted}, need: SensorNeed{Tier: 1, Private: true}, eligible: []shared.ID{trusted.ID}},
		// The trust check comes first: the New sensor that allows private
		// targets does not count while it is New.
		{name: "New allows private, Trusted refuses", states: []ZoneSensorState{newS, trustedNoPriv}, need: SensorNeed{Tier: 1, Private: true}, kind: KindZoneSensorNoPrivate, sensor: trustedNoPriv.ID},
		{name: "pinned to the New one", states: []ZoneSensorState{newS, trusted}, need: SensorNeed{Tier: 1, SensorID: &newS.ID}, kind: KindZoneSensorNew, sensor: newS.ID},
		{name: "pinned to a sensor outside the zone decides nothing", states: []ZoneSensorState{newS}, need: SensorNeed{Tier: 1, SensorID: &trusted.ID}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := JudgeZoneSensors(z, tc.states, tc.need)
			if v.Kind != tc.kind {
				t.Fatalf("kind = %q, want %q (%s)", v.Kind, tc.kind, v.Reason)
			}
			if tc.kind != "" {
				if v.SensorID != tc.sensor || v.Eligible != nil || !strings.Contains(v.Reason, `"dc"`) {
					t.Fatalf("verdict %+v", v)
				}
				return
			}
			if tc.eligible == nil {
				if v.Eligible != nil {
					t.Fatalf("decided %v with nothing to decide on", v.Eligible)
				}
				return
			}
			if len(v.Eligible) != len(tc.eligible) {
				t.Fatalf("eligible %v, want %v", v.Eligible, tc.eligible)
			}
			for _, id := range tc.eligible {
				if !v.Eligible[id] {
					t.Fatalf("eligible %v lacks %s", v.Eligible, id)
				}
			}
		})
	}
}

func TestJudgeZoneSensors_ReasonNamesSensorsAndRemedy(t *testing.T) {
	z := mustZone(t, "dc", false, "10.0.0.0/16")
	var states []ZoneSensorState
	for _, n := range []string{"a", "b", "c", "d"} {
		states = append(states, ZoneSensorState{ID: shared.NewID(), Name: n})
	}
	v := JudgeZoneSensors(z, states, SensorNeed{Tier: 1})
	if !strings.Contains(v.Reason, `sensors "a", "b", "c" and 1 more`) || !strings.Contains(v.Reason, "T1") {
		t.Errorf("reason %q", v.Reason)
	}
	off := &sensor.LocalPolicyReport{State: sensor.LocalPolicyAbsent, AllowPrivate: boolp(false)}
	v = JudgeZoneSensors(z, []ZoneSensorState{{ID: shared.NewID(), Name: "a", Trusted: true, LocalPolicy: off}}, SensorNeed{Tier: 1, Private: true})
	if !strings.Contains(v.Reason, `sensor "a"`) || !strings.Contains(v.Reason, "SENSOR_ALLOW_PRIVATE_TARGETS=1") {
		t.Errorf("reason %q", v.Reason)
	}
}

func TestRoutePrivate(t *testing.T) {
	for target, want := range map[string]bool{
		"10.0.0.5": true, "10.0.0.0/16": true, "192.168.1.1:8443": true, "https://172.16.3.4/x": true, "fd00::1": true,
		"203.0.113.7": false, "100.64.0.1": false, "app.example.com": false,
	} {
		if got := RoutePrivate(Route{Target: target}); got != want {
			t.Errorf("%s: %t, want %t", target, got, want)
		}
	}
	if !RoutePrivate(Route{Target: "intranet.example.com", Addrs: []netip.Addr{netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("10.1.2.3")}}) {
		t.Error("a name resolving to a private address is not private")
	}
	if RoutePrivate(Route{Target: "www.example.com", Addrs: []netip.Addr{netip.MustParseAddr("203.0.113.9")}}) {
		t.Error("a public name is private")
	}
}
