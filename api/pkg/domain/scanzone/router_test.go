package scanzone

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// fakeResolver answers from a fixed table; anything else fails to resolve.
type fakeResolver map[string][]string

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	addrs, ok := f[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

func TestRouter_NarrowestZoneWins(t *testing.T) {
	wide := mustZone(t, "corp", false, "10.0.0.0/8")
	narrow := mustZone(t, "dc-230", false, "10.230.0.0/16")
	r := NewRouter([]*Zone{wide, narrow}, nil)

	cases := map[string]*Zone{
		"10.230.4.5":             narrow,
		"10.230.0.0/24":          narrow,
		"10.1.2.3":               wide,
		"http://10.230.9.9:8080": narrow,
		"10.230.1.1:443":         narrow,
	}
	for target, want := range cases {
		got := r.Route(context.Background(), target)
		if got.Zone != want {
			t.Errorf("Route(%q) zone = %v, want %s (reason %q)", target, zoneName(got.Zone), want.Name, got.Reason)
		}
	}
}

func TestRouter_TieBreakIsDeterministic(t *testing.T) {
	b := mustZone(t, "b-zone", false, "10.5.0.0/16")
	a := mustZone(t, "a-zone", false, "10.5.0.0/16")
	for _, order := range [][]*Zone{{a, b}, {b, a}} {
		got := NewRouter(order, nil).Route(context.Background(), "10.5.1.1")
		if got.Zone != a {
			t.Errorf("overlapping equal ranges: got %s, want a-zone", zoneName(got.Zone))
		}
	}
}

func TestRouter_IPv6(t *testing.T) {
	site := mustZone(t, "site-v6", false, "fd00:10::/48")
	r := NewRouter([]*Zone{site}, nil)
	for _, target := range []string{"fd00:10::5", "fd00:10:0:1::/64", "[fd00:10::7]:22", "https://[fd00:10::8]/login"} {
		if got := r.Route(context.Background(), target); got.Zone != site {
			t.Errorf("Route(%q) = %s (reason %q), want site-v6", target, zoneName(got.Zone), got.Reason)
		}
	}
	// An IPv6 ULA outside the zone is private and uncovered.
	got := r.Route(context.Background(), "fd99::1")
	if got.Zone != nil || got.Unzoned || got.Reason == "" {
		t.Errorf("uncovered ULA routed: %+v", got)
	}
}

func TestRouter_PrivateOutsideZonesIsUncovered(t *testing.T) {
	r := NewRouter([]*Zone{mustZone(t, "dc", false, "10.1.0.0/16")}, nil)
	got := r.Route(context.Background(), "192.168.7.7")
	if got.Zone != nil || got.Unzoned {
		t.Fatalf("private target outside every zone was routed: %+v", got)
	}
	if !strings.Contains(got.Reason, "private") {
		t.Errorf("reason %q does not say why", got.Reason)
	}
}

func TestRouter_RangeSpanningZonesIsUncovered(t *testing.T) {
	r := NewRouter([]*Zone{mustZone(t, "dc", false, "10.1.0.0/16")}, nil)
	got := r.Route(context.Background(), "10.0.0.0/15") // half inside, half outside
	if got.Zone != nil || got.Reason == "" {
		t.Errorf("range only partly inside a zone was routed: %+v", got)
	}
}

func TestRouter_PublicTargets(t *testing.T) {
	dmz := mustZone(t, "dmz", false, "198.51.100.0/24")
	def := mustZone(t, "internet", true)
	r := NewRouter([]*Zone{dmz, def}, fakeResolver{"www.example.com": {"93.184.215.14"}})

	if got := r.Route(context.Background(), "198.51.100.10"); got.Zone != dmz {
		t.Errorf("public address inside a zone range: %s", zoneName(got.Zone))
	}
	if got := r.Route(context.Background(), "8.8.8.8"); got.Zone != def {
		t.Errorf("public address outside every range: %s, want default zone", zoneName(got.Zone))
	}
	if got := r.Route(context.Background(), "https://www.example.com/a"); got.Zone != def {
		t.Errorf("public hostname: %s (reason %q), want default zone", zoneName(got.Zone), got.Reason)
	}

	// No default zone: public targets keep the pre-zone behavior.
	r = NewRouter([]*Zone{dmz}, fakeResolver{"www.example.com": {"93.184.215.14"}})
	if got := r.Route(context.Background(), "8.8.8.8"); !got.Unzoned || got.Zone != nil {
		t.Errorf("public target without a default zone: %+v, want unzoned", got)
	}
	if got := r.Route(context.Background(), "www.example.com"); !got.Unzoned {
		t.Errorf("public hostname without a default zone: %+v, want unzoned", got)
	}
}

func TestRouter_HostnamesRouteByResolvedAddress(t *testing.T) {
	dc := mustZone(t, "dc", false, "10.230.0.0/16")
	def := mustZone(t, "internet", true)
	res := fakeResolver{
		"db01.corp.example":  {"10.230.0.15"},
		"mixed.corp.example": {"10.1.0.1", "10.230.0.16"}, // one address in dc
		"leak.corp.example":  {"192.168.9.9"},             // private, no zone
		"loop.example":       {"127.0.0.1"},
	}
	r := NewRouter([]*Zone{dc, def}, res)

	got := r.Route(context.Background(), "db01.corp.example")
	if got.Zone != dc {
		t.Errorf("internal hostname: %s (reason %q), want dc", zoneName(got.Zone), got.Reason)
	}
	if len(got.Addrs) != 1 || got.Addrs[0].String() != "10.230.0.15" {
		t.Errorf("resolved addresses not reported: %v", got.Addrs)
	}
	if got := r.Route(context.Background(), "mixed.corp.example"); got.Zone != dc {
		t.Errorf("hostname with one in-zone address: %s, want dc", zoneName(got.Zone))
	}
	// A private resolution never falls back to the internet-facing default zone.
	if got := r.Route(context.Background(), "leak.corp.example"); got.Zone != nil || got.Unzoned {
		t.Errorf("hostname resolving to an unzoned private address was routed: %+v", got)
	}
	if got := r.Route(context.Background(), "loop.example"); got.Zone != nil || !strings.Contains(got.Reason, "deny") {
		t.Errorf("hostname resolving to loopback: %+v", got)
	}
	// Unresolvable: reported, never guessed.
	got = r.Route(context.Background(), "nope.corp.example")
	if got.Zone != nil || got.Unzoned || !strings.Contains(got.Reason, "resolve") {
		t.Errorf("unresolvable hostname: %+v", got)
	}
	// Without a resolver every hostname is unresolvable.
	if got := NewRouter([]*Zone{dc, def}, nil).Route(context.Background(), "db01.corp.example"); got.Zone != nil {
		t.Errorf("hostname routed without a resolver: %+v", got)
	}
}

func TestRouter_DeniedAddressIsUncovered(t *testing.T) {
	r := NewRouter([]*Zone{mustZone(t, "internet", true)}, nil)
	for _, target := range []string{"127.0.0.1", "169.254.169.254", "::1", "[::]:80"} {
		got := r.Route(context.Background(), target)
		if got.Zone != nil || got.Unzoned || !strings.Contains(got.Reason, "deny") {
			t.Errorf("Route(%q) = %+v, want uncovered (deny list)", target, got)
		}
	}
}

func TestRouter_Plan(t *testing.T) {
	a := mustZone(t, "a", false, "10.1.0.0/16")
	b := mustZone(t, "b", false, "10.2.0.0/16")
	r := NewRouter([]*Zone{a, b}, nil)
	plan := r.Plan(context.Background(), []string{"10.2.0.1", "10.1.0.1", "10.1.0.2", "192.168.1.1", "8.8.8.8"})

	if got := plan.ByZone[a.ID]; len(got) != 2 || got[0] != "10.1.0.1" || got[1] != "10.1.0.2" {
		t.Errorf("zone a targets = %v", got)
	}
	if got := plan.ByZone[b.ID]; len(got) != 1 || got[0] != "10.2.0.1" {
		t.Errorf("zone b targets = %v", got)
	}
	if len(plan.Unzoned) != 1 || plan.Unzoned[0] != "8.8.8.8" {
		t.Errorf("unzoned = %v", plan.Unzoned)
	}
	if len(plan.Uncovered) != 1 || plan.Uncovered[0].Target != "192.168.1.1" {
		t.Errorf("uncovered = %+v", plan.Uncovered)
	}
	// Zones appear in first-seen order so batches are deterministic.
	if len(plan.ZoneOrder) != 2 || plan.ZoneOrder[0] != b.ID || plan.ZoneOrder[1] != a.ID {
		t.Errorf("zone order = %v", plan.ZoneOrder)
	}
}

func TestParseTarget(t *testing.T) {
	cases := map[string]string{
		"10.0.0.1":                "10.0.0.1/32",
		"10.0.0.0/24":             "10.0.0.0/24",
		"10.0.0.1:8443":           "10.0.0.1/32",
		"https://10.0.0.1/x":      "10.0.0.1/32",
		"[fd00::1]:22":            "fd00::1/128",
		"::ffff:10.0.0.9":         "10.0.0.9/32",
		"Example.COM.":            "host:example.com",
		"*.corp.example":          "host:corp.example",
		"https://app.example/a?b": "host:app.example",
		"app.example:8080":        "host:app.example",
	}
	for in, want := range cases {
		pt := ParseTarget(in)
		got := "host:" + pt.Host
		if pt.IsAddr {
			got = pt.Prefix.String()
		}
		if got != want {
			t.Errorf("ParseTarget(%q) = %s, want %s", in, got, want)
		}
	}
}

func zoneName(z *Zone) string {
	if z == nil {
		return "<none>"
	}
	return z.Name
}

// A service on a private address routes to the zone of its address, in
// every name form, and never as a public target (research/63 PR0).
func TestRouter_ServiceNamesRouteByHost(t *testing.T) {
	dc := mustZone(t, "dc", false, "10.0.0.0/8")
	v6 := mustZone(t, "dc6", false, "fd00::/32")
	r := NewRouter([]*Zone{dc, v6}, nil)
	for target, want := range map[string]*Zone{
		"10.0.0.5:22:tcp":   dc,
		"10.0.0.5:22/tcp":   dc,
		"[fd00::5]:443/tcp": v6,
		"fd00::5:443:tcp":   v6,
	} {
		got := r.Route(context.Background(), target)
		if got.Zone != want {
			t.Errorf("Route(%q) zone = %v, want %s (reason %q)", target, zoneName(got.Zone), want.Name, got.Reason)
		}
	}
	// A private service outside every zone is refused, not routed as public.
	got := r.Route(context.Background(), "192.168.7.7:22:tcp")
	if got.Zone != nil || got.Unzoned {
		t.Fatalf("a private service outside every zone was routed: %+v", got)
	}
	if pt := ParseTarget("10.0.0.5:22:tcp"); !pt.IsAddr || pt.Prefix.String() != "10.0.0.5/32" {
		t.Fatalf("ParseTarget = %+v", pt)
	}
}
