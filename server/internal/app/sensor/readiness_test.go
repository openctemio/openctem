package sensor

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	sensordom "github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func readySensor() *sensordom.Sensor {
	tid := shared.NewID()
	now := time.Now()
	return &sensordom.Sensor{ID: shared.NewID(), TenantID: &tid, Status: sensordom.SensorStatusActive,
		Health: sensordom.SensorHealthOnline, LastSeenAt: &now}
}

func internalGrant(s *sensordom.Sensor, trust sensordom.TrustLevel) *sensordom.Grant {
	g, _ := sensordom.NewGrantFromProfile(*s.TenantID, s.ID, sensordom.ProfileInternalScanner, nil)
	g.TrustLevel = trust
	return g
}

func zoneOf(s *sensordom.Sensor, ranges ...string) *scanzone.Zone {
	z := &scanzone.Zone{ID: shared.NewID(), TenantID: *s.TenantID, SensorIDs: []shared.ID{s.ID}}
	for _, r := range ranges {
		z.Ranges = append(z.Ranges, netip.MustParsePrefix(r))
	}
	return z
}

func target(t *testing.T, s *sensordom.Sensor, typ scopedom.TargetType, pattern string) *scopedom.Target {
	t.Helper()
	tg, err := scopedom.NewTarget(*s.TenantID, typ, pattern, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func items(r Readiness) map[string]ReadinessItem {
	out := map[string]ReadinessItem{}
	for _, it := range r.Items {
		out[it.Key] = it
	}
	return out
}

func TestBuildReadiness_FixOrderAndBlockers(t *testing.T) {
	s := readySensor()
	r := BuildReadiness(ReadinessInput{Sensor: s, Grant: internalGrant(s, sensordom.TrustNew), ZonesKnown: true, ScopeKnown: true}, nil)
	want := []string{ReadyOnline, ReadyTrusted, ReadyPrivate, ReadyKill, ReadyNetworks, ReadyScope, ReadySandbox}
	if len(r.Items) != len(want) {
		t.Fatalf("items %+v", r.Items)
	}
	for i, k := range want {
		if r.Items[i].Key != k {
			t.Fatalf("item %d = %s, want %s", i, r.Items[i].Key, k)
		}
	}
	got := items(r)
	if r.Ready || got[ReadyTrusted].State != ReadyStateBlocked || got[ReadyTrusted].Fix.Action != FixPromote ||
		got[ReadyTrusted].Fix.Permission != permGrantWiden || got[ReadyTrusted].Fix.Allowed {
		t.Fatalf("trusted %+v", got[ReadyTrusted])
	}
	if got[ReadyNetworks].State != ReadyStateBlocked || got[ReadyNetworks].Fix.Action != FixAddZone {
		t.Fatalf("networks %+v", got[ReadyNetworks])
	}
	if got[ReadyPrivate].State != ReadyStateUnknown || got[ReadyPrivate].Fix.HostLine != "SENSOR_ALLOW_PRIVATE_TARGETS=1" {
		t.Fatalf("private without a report %+v", got[ReadyPrivate])
	}
	if got[ReadyScope].State != ReadyStateNotApplicable {
		t.Fatalf("scope with no zone ranges %+v", got[ReadyScope])
	}
}

func TestBuildReadiness_AllClear(t *testing.T) {
	s := readySensor()
	s.LocalPolicy = &sensordom.LocalPolicyReport{State: "enforced", Summary: &sensordom.LocalPolicySummary{AllowPrivate: true}}
	in := ReadinessInput{Sensor: s, Grant: internalGrant(s, sensordom.TrustTrusted),
		Zones: []*scanzone.Zone{zoneOf(s, "10.0.0.0/16")}, ZonesKnown: true,
		ActiveScope: []*scopedom.Target{target(t, s, scopedom.TargetTypeCIDR, "10.0.0.0/8")}, ScopeKnown: true,
		ConfigKnown: true, ConfigChecks: []sensordom.ConfigCheck{{ID: "runtime.sandbox_network", Status: sensordom.CheckPass}}}
	r := BuildReadiness(in, func(string) bool { return true })
	if !r.Ready {
		t.Fatalf("not ready: %+v", r.Items)
	}
	for _, it := range r.Items {
		if it.State != ReadyStateOK {
			t.Errorf("%s = %s", it.Key, it.State)
		}
	}
}

func TestBuildReadiness_HostAndScopeStates(t *testing.T) {
	s := readySensor()
	s.LocalPolicy = &sensordom.LocalPolicyReport{State: "enforced", KillSwitch: true, Summary: &sensordom.LocalPolicySummary{AllowPrivate: false}}
	in := ReadinessInput{Sensor: s, Grant: internalGrant(s, sensordom.TrustTrusted),
		Zones: []*scanzone.Zone{zoneOf(s, "10.0.0.0/16", "192.168.4.0/24")}, ZonesKnown: true,
		PendingScope: []*scopedom.Target{target(t, s, scopedom.TargetTypeCIDR, "10.0.0.0/16")}, ScopeKnown: true,
		ConfigKnown: true, ConfigChecks: []sensordom.ConfigCheck{{ID: "runtime.sandbox_network", Status: sensordom.CheckWarn}}}
	got := items(BuildReadiness(in, func(p string) bool { return p == permScopeWrite || p == permZonesRead }))
	if got[ReadyPrivate].State != ReadyStateBlocked || got[ReadyKill].State != ReadyStateBlocked ||
		got[ReadyKill].Fix.HostLine != killSwitchHostLine || strings.Contains(got[ReadyKill].Fix.HostLine, "/etc/") {
		t.Fatalf("host items %+v %+v", got[ReadyPrivate], got[ReadyKill])
	}
	sc := got[ReadyScope]
	if sc.State != ReadyStateBlocked || sc.Count != 1 || sc.Fix.Patterns[0] != "192.168.4.0/24" || !sc.Fix.Allowed {
		t.Fatalf("scope %+v %+v", sc, sc.Fix)
	}
	if got[ReadySandbox].State != ReadyStateBlocked || got[ReadySandbox].Fix.Docs != HostRequirementsDocs {
		t.Fatalf("sandbox %+v", got[ReadySandbox])
	}

	// A caller who may write scope but not read zones gets the count, never
	// the zones' private ranges.
	noZones := items(BuildReadiness(in, func(p string) bool { return p == permScopeWrite }))[ReadyScope]
	if noZones.State != ReadyStateBlocked || noZones.Count != 1 || noZones.Fix == nil || !noZones.Fix.Allowed || len(noZones.Fix.Patterns) != 0 {
		t.Fatalf("scope without zones:read %+v %+v", noZones, noZones.Fix)
	}
	if b, err := json.Marshal(noZones); err != nil || strings.Contains(string(b), "192.168.4.0") {
		t.Fatalf("the answer leaks the zone range: %s %v", b, err)
	}

	// Only a pending entry left: waiting for someone else's approval.
	in.Zones = []*scanzone.Zone{zoneOf(s, "10.0.0.0/16")}
	if it := items(BuildReadiness(in, nil))[ReadyScope]; it.State != ReadyStateWaiting || it.Count != 1 || it.Fix != nil {
		t.Fatalf("waiting %+v", it)
	}
}

func TestBuildReadiness_InternetSensorNeedsNoNetworks(t *testing.T) {
	s := readySensor()
	g, _ := sensordom.NewGrantFromProfile(*s.TenantID, s.ID, sensordom.ProfileEASMExternal, nil)
	got := items(BuildReadiness(ReadinessInput{Sensor: s, Grant: g, ZonesKnown: true, ScopeKnown: true}, nil))
	for _, k := range []string{ReadyPrivate, ReadyNetworks, ReadyScope} {
		if got[k].State != ReadyStateNotApplicable {
			t.Errorf("%s = %s for an internet-only sensor", k, got[k].State)
		}
	}
}

func TestBuildReadiness_Online(t *testing.T) {
	s := readySensor()
	s.LastSeenAt = nil
	if it := items(BuildReadiness(ReadinessInput{Sensor: s}, nil))[ReadyOnline]; it.State != ReadyStateWaiting || it.Fix.Action != FixShowInstall {
		t.Fatalf("never seen %+v", it)
	}
	s = readySensor()
	s.Health = sensordom.SensorHealthOffline
	if it := items(BuildReadiness(ReadinessInput{Sensor: s}, nil))[ReadyOnline]; it.State != ReadyStateBlocked {
		t.Fatalf("offline %+v", it)
	}
	s = readySensor()
	s.Status = sensordom.SensorStatusDisabled
	if it := items(BuildReadiness(ReadinessInput{Sensor: s}, nil))[ReadyOnline]; it.State != ReadyStateBlocked || it.Fix != nil {
		t.Fatalf("disabled %+v", it)
	}
}
