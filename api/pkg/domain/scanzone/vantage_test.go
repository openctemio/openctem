package scanzone

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// The owner's case: one sensor inside the company network, split-horizon
// DNS. An internal-only name resolves only for the sensor; the platform has
// no answer.
func TestRouter_VantagePrivateAnswerRoutesToObserverZone(t *testing.T) {
	internal := mustZone(t, "Internal", false, "10.0.0.0/8")
	laptop := shared.NewID()
	internal.SensorIDs = []shared.ID{laptop}
	now := time.Now()
	r := NewRouter([]*Zone{internal}, fakeResolver{}).WithVantage(VantageAnswers{
		"intranet.example.com": {{Observer: laptop, Addrs: addrs("10.20.0.5"), ObservedAt: now}},
	})
	got := r.Route(context.Background(), "intranet.example.com")
	if got.Zone != internal || got.Vantage == nil || got.Vantage.Observer != laptop || got.Unresolved {
		t.Fatalf("internal-only name = %+v, want routed to Internal by the laptop's answer", got)
	}
	if got.Vantage.SplitHorizon {
		t.Errorf("no platform answer: not split-horizon")
	}
}

// A name that resolves publicly for the platform and privately inside:
// routed by the inside sensor's view, both views kept (split-horizon).
func TestRouter_VantageSplitHorizonIsReported(t *testing.T) {
	internal := mustZone(t, "Internal", false, "10.0.0.0/8")
	laptop := shared.NewID()
	internal.SensorIDs = []shared.ID{laptop}
	r := NewRouter([]*Zone{internal}, fakeResolver{"portal.example.com": {"192.0.2.10"}}).WithVantage(VantageAnswers{
		"portal.example.com": {{Observer: laptop, Addrs: addrs("10.1.1.1"), ObservedAt: time.Now()}},
	})
	got := r.Route(context.Background(), "portal.example.com")
	if got.Zone != internal || got.Vantage == nil || !got.Vantage.SplitHorizon {
		t.Fatalf("split-horizon name = %+v, want Internal with SplitHorizon", got)
	}
}

// A private answer from a sensor of another site (or of no zone) says
// nothing about the zone that holds the address: not routed by it.
func TestRouter_VantagePrivateAnswerFromOtherSiteIgnored(t *testing.T) {
	internal := mustZone(t, "Internal", false, "10.0.0.0/8")
	internal.SensorIDs = []shared.ID{shared.NewID()}
	stranger := shared.NewID()
	r := NewRouter([]*Zone{internal}, fakeResolver{}).WithVantage(VantageAnswers{
		"intranet.example.com": {{Observer: stranger, Addrs: addrs("10.20.0.5"), ObservedAt: time.Now()}},
	})
	got := r.Route(context.Background(), "intranet.example.com")
	if got.Zone != nil || got.Unzoned || !got.Unresolved || got.Kind != KindUnresolved {
		t.Fatalf("answer of a sensor outside the zone routed the name: %+v", got)
	}
}

// The command's zone stamp is the vantage when present, whatever zones the
// sensor is in now.
func TestRouter_VantageZoneStampWins(t *testing.T) {
	a := mustZone(t, "Site-A", false, "10.1.0.0/16")
	b := mustZone(t, "Site-B", false, "10.2.0.0/16")
	s := shared.NewID()
	a.SensorIDs, b.SensorIDs = []shared.ID{s}, []shared.ID{shared.NewID()}
	zid := b.ID
	r := NewRouter([]*Zone{a, b}, fakeResolver{}).WithVantage(VantageAnswers{
		// Observed under a Site-B command although the address is Site-A's.
		"x.example.com": {{Observer: s, ZoneID: &zid, Addrs: addrs("10.1.0.9"), ObservedAt: time.Now()}},
	})
	if got := r.Route(context.Background(), "x.example.com"); got.Zone != nil {
		t.Fatalf("answer from Site-B's vantage routed into Site-A: %+v", got)
	}
}

// A public answer from a sensor places a name the platform cannot resolve
// as a public target (unzoned, or the default zone).
func TestRouter_VantagePublicAnswerWhenPlatformHasNone(t *testing.T) {
	internal := mustZone(t, "Internal", false, "10.0.0.0/8")
	s := shared.NewID()
	internal.SensorIDs = []shared.ID{s}
	r := NewRouter([]*Zone{internal}, fakeResolver{}).WithVantage(VantageAnswers{
		"cdn.example.com": {{Observer: s, Addrs: addrs("198.51.100.7"), ObservedAt: time.Now()}},
	})
	got := r.Route(context.Background(), "cdn.example.com")
	if !got.Unzoned || got.Vantage == nil || got.Unresolved {
		t.Fatalf("public sensor answer = %+v, want unzoned via vantage", got)
	}
}

// Denied addresses in an answer never route anywhere.
func TestRouter_VantageDeniedAnswerIgnored(t *testing.T) {
	internal := mustZone(t, "Internal", false, "10.0.0.0/8")
	s := shared.NewID()
	internal.SensorIDs = []shared.ID{s}
	r := NewRouter([]*Zone{internal}, fakeResolver{}).WithVantage(VantageAnswers{
		"meta.example.com": {{Observer: s, Addrs: addrs("169.254.169.254", "127.0.0.1"), ObservedAt: time.Now()}},
	})
	if got := r.Route(context.Background(), "meta.example.com"); got.Zone != nil || got.Unzoned {
		t.Fatalf("denied answer routed: %+v", got)
	}
}

// Without vantage answers the router is unchanged.
func TestRouter_NoVantageUnchanged(t *testing.T) {
	internal := mustZone(t, "Internal", false, "10.0.0.0/8")
	got := NewRouter([]*Zone{internal}, fakeResolver{}).Route(context.Background(), "intranet.example.com")
	if !got.Unresolved || got.Kind != KindUnresolved || got.Vantage != nil {
		t.Fatalf("no vantage: %+v", got)
	}
}

func TestHostNames(t *testing.T) {
	got := HostNames([]string{"A.example.com", "a.example.com.", "10.0.0.1", "10.0.0.0/24", "https://b.example.com/x"}, 10)
	if len(got) != 2 || got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Fatalf("HostNames = %v", got)
	}
}
