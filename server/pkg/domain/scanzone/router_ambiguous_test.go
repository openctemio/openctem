package scanzone

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Overlapping zones (research 466 D9): two zones that hold the same range
// with different sensors are two sites reusing an address range. A target
// there is never routed by zone name; the scan must pick its zone.

func zoneWith(t *testing.T, name string, sensors []shared.ID, ranges ...string) *Zone {
	t.Helper()
	z := mustZone(t, name, false, ranges...)
	z.SensorIDs = sensors
	return z
}

func TestRouter_SameRangeDifferentSensorsIsAmbiguous(t *testing.T) {
	office := zoneWith(t, "office", []shared.ID{shared.NewID()}, "10.0.0.0/16")
	cloud := zoneWith(t, "cloud", []shared.ID{shared.NewID()}, "10.0.0.0/16")
	for _, order := range [][]*Zone{{office, cloud}, {cloud, office}} {
		r := NewRouter(order, nil)
		for _, target := range []string{"10.0.4.5", "10.0.4.0/24", "https://10.0.9.9:8443/x", "10.0.0.0/16"} {
			got := r.Route(context.Background(), target)
			if got.Zone != nil || got.Unzoned || got.Kind != KindAmbiguousZone {
				t.Fatalf("Route(%q) = zone %s kind %q, want ambiguous", target, zoneName(got.Zone), got.Kind)
			}
			if !strings.Contains(got.Reason, `"cloud", "office"`) || !strings.Contains(got.Reason, "pick the zone") {
				t.Errorf("reason %q", got.Reason)
			}
		}
	}
	// A zone with sensors and one without differ too.
	empty := zoneWith(t, "lab", nil, "10.0.0.0/16")
	if got := NewRouter([]*Zone{office, empty}, nil).Route(context.Background(), "10.0.1.1"); got.Kind != KindAmbiguousZone {
		t.Errorf("zone without sensors next to one with sensors: %+v", got)
	}
}

func TestRouter_SameRangeSameSensorsRoutes(t *testing.T) {
	s1, s2 := shared.NewID(), shared.NewID()
	a := zoneWith(t, "a-site", []shared.ID{s1, s2}, "10.0.0.0/16")
	b := zoneWith(t, "b-site", []shared.ID{s2, s1}, "10.0.0.0/16")
	for _, order := range [][]*Zone{{a, b}, {b, a}} {
		if got := NewRouter(order, nil).Route(context.Background(), "10.0.1.1"); got.Zone != a {
			t.Errorf("same sensors: zone %s kind %q, want a-site", zoneName(got.Zone), got.Kind)
		}
	}
}

func TestRouter_NestedOverlapNarrowestWins(t *testing.T) {
	wide := zoneWith(t, "corp", []shared.ID{shared.NewID()}, "10.0.0.0/8")
	site := zoneWith(t, "site", []shared.ID{shared.NewID()}, "10.5.0.0/16")
	r := NewRouter([]*Zone{wide, site}, nil)
	for target, want := range map[string]*Zone{"10.5.1.1": site, "10.6.1.1": wide, "10.5.0.0/24": site} {
		if got := r.Route(context.Background(), target); got.Zone != want {
			t.Errorf("Route(%q) = %s kind %q, want %s", target, zoneName(got.Zone), got.Kind, want.Name)
		}
	}
	// A tie below a narrower zone is no tie: the narrower one wins.
	other := zoneWith(t, "corp-2", []shared.ID{shared.NewID()}, "10.0.0.0/8")
	r = NewRouter([]*Zone{wide, other, site}, nil)
	if got := r.Route(context.Background(), "10.5.1.1"); got.Zone != site {
		t.Errorf("nested inside two tied wide zones: %s %q", zoneName(got.Zone), got.Kind)
	}
	if got := r.Route(context.Background(), "10.6.1.1"); got.Kind != KindAmbiguousZone {
		t.Errorf("outside the narrow zone, the wide tie is ambiguous: %+v", got)
	}
}

func TestRouter_DisjointZonesUnchanged(t *testing.T) {
	a := zoneWith(t, "a", []shared.ID{shared.NewID()}, "10.1.0.0/16")
	b := zoneWith(t, "b", []shared.ID{shared.NewID()}, "10.2.0.0/16")
	r := NewRouter([]*Zone{a, b}, nil)
	if got := r.Route(context.Background(), "10.1.0.1"); got.Zone != a {
		t.Errorf("10.1.0.1 -> %s", zoneName(got.Zone))
	}
	if got := r.Route(context.Background(), "10.2.0.1"); got.Zone != b {
		t.Errorf("10.2.0.1 -> %s", zoneName(got.Zone))
	}
}

// A scan pinned to one zone (the zone picker) routes there: the router is
// built over the selected zone only.
func TestRouter_PinnedZoneResolvesAmbiguity(t *testing.T) {
	office := zoneWith(t, "office", []shared.ID{shared.NewID()}, "10.0.0.0/16")
	cloud := zoneWith(t, "cloud", []shared.ID{shared.NewID()}, "10.0.0.0/16")
	plan := NewRouter([]*Zone{cloud}, nil).Plan(context.Background(), []string{"10.0.0.5"}).RestrictTo(cloud)
	if len(plan.ByZone[cloud.ID]) != 1 || len(plan.Uncovered) != 0 {
		t.Fatalf("pinned plan %+v", plan)
	}
	plan = NewRouter([]*Zone{office, cloud}, nil).Plan(context.Background(), []string{"10.0.0.5", "10.9.0.1"})
	if len(plan.Uncovered) != 2 || plan.Uncovered[0].Kind != KindAmbiguousZone || plan.Uncovered[1].Kind != KindOutsideZones {
		t.Fatalf("automatic plan %+v", plan.Uncovered)
	}
}

// A name resolving into a tie is ambiguous, and the reason does not quote
// the (private) address.
func TestRouter_HostnameInTieIsAmbiguous(t *testing.T) {
	office := zoneWith(t, "office", []shared.ID{shared.NewID()}, "10.0.0.0/16")
	cloud := zoneWith(t, "cloud", []shared.ID{shared.NewID()}, "10.0.0.0/16")
	res := fakeResolver{"intranet.example.com": {"10.0.3.3"}, "split.example.com": {"10.0.3.3", "10.0.3.4"}}
	r := NewRouter([]*Zone{office, cloud}, res)
	for _, name := range []string{"intranet.example.com", "split.example.com"} {
		got := r.Route(context.Background(), name)
		if got.Kind != KindAmbiguousZone || got.Zone != nil || strings.Contains(got.Reason, "10.0.3") {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

func TestSameRangeZones(t *testing.T) {
	z := zoneWith(t, "office", nil, "10.0.0.0/16", "192.168.1.0/24")
	same := zoneWith(t, "cloud", nil, "10.0.0.0/16")
	wider := zoneWith(t, "corp", nil, "10.0.0.0/8")
	narrower := zoneWith(t, "lab", nil, "10.0.5.0/24")
	other := zoneWith(t, "dc", nil, "172.16.0.0/16")
	got := SameRangeZones(z, []*Zone{z, same, wider, narrower, other})
	if len(got) != 1 || got[0] != same {
		names := make([]string, 0, len(got))
		for _, g := range got {
			names = append(names, g.Name)
		}
		t.Fatalf("same range zones = %v, want cloud", names)
	}
}
