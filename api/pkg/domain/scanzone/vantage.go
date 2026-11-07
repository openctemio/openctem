package scanzone

// Vantage resolution: what a host name resolves to from where a sensor of
// the organization sits. Design: docs/architecture/scan-zones.md "Vantage
// resolution".

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxAnswerAddrs bounds the addresses one stored answer keeps.
const MaxAnswerAddrs = 16

// Answer is one sensor's DNS answer for a name. Observer and ZoneID come
// from the command the answer was reported under, never from the report.
type Answer struct {
	Observer   shared.ID
	ZoneID     *shared.ID // the zone the command was routed to (nil: none)
	Addrs      []netip.Addr
	ObservedAt time.Time
}

// VantageAnswers are the stored answers of a tenant's sensors, keyed by the
// lower-case name.
type VantageAnswers map[string][]Answer

// VantageReader reads the fresh answers of names (lower-case) observed
// since a time, for one tenant only.
type VantageReader interface {
	VantageAnswers(ctx context.Context, tenantID shared.ID, names []string, since time.Time) (VantageAnswers, error)
}

// VantageWriter records one sensor's answers for names (lower-case name to
// addresses) under the tenant.
type VantageWriter interface {
	RecordAnswers(ctx context.Context, tenantID, sensorID shared.ID, zoneID *shared.ID, answers map[string][]netip.Addr, at time.Time) error
}

// WithVantage makes the router read the sensors' answers besides the
// platform's: a name whose sensor answer is a private address of the
// observing sensor's own zone routes to that zone; a name the platform
// cannot resolve routes by a sensor's public answer.
func (r *Router) WithVantage(v VantageAnswers) *Router {
	r.vantage = v
	return r
}

// observerZone reports whether zone z is the answer's vantage point: the
// zone the answer's command was routed to, or a zone its sensor is
// assigned to.
func (a Answer) observerZone(z *Zone) bool {
	if z == nil {
		return false
	}
	if a.ZoneID != nil {
		return *a.ZoneID == z.ID
	}
	return z.HasSensor(a.Observer)
}

// routeByVantage routes a name from the sensors' answers. A private
// address counts only when it routes to the observing sensor's own zone:
// a sensor elsewhere saying "10.0.0.5" says nothing about another site's
// network. It returns false when no answer places the name.
func (r *Router) routeByVantage(rt *Route, host string, platform []netip.Addr) bool {
	answers := r.vantage[strings.ToLower(strings.TrimSuffix(host, "."))]
	if len(answers) == 0 {
		return false
	}
	// Newest first: the freshest view of each vantage point wins.
	sorted := slices.Clone(answers)
	slices.SortStableFunc(sorted, func(a, b Answer) int { return b.ObservedAt.Compare(a.ObservedAt) })
	for i := range sorted {
		a := &sorted[i]
		var private []netip.Addr
		for _, ad := range a.Addrs {
			if ad = ad.Unmap(); IsPrivate(ad) && !IsDenied(ad) {
				private = append(private, ad)
			}
		}
		if len(private) == 0 {
			continue
		}
		try := Route{Target: rt.Target}
		r.routeAddrs(&try, private)
		if try.Zone == nil || !a.observerZone(try.Zone) {
			continue
		}
		*rt = try
		rt.Addrs = private
		rt.Vantage = &VantageRoute{Observer: a.Observer, Zone: try.Zone.ID, ObservedAt: a.ObservedAt,
			SplitHorizon: len(platform) > 0 && !sameAddrSet(platform, private)}
		return true
	}
	if len(platform) > 0 {
		return false
	}
	// The platform has no answer: a sensor's public answer places the name
	// as a public target.
	for i := range sorted {
		a := &sorted[i]
		var public []netip.Addr
		for _, ad := range a.Addrs {
			if ad = ad.Unmap(); !IsPrivate(ad) && !IsDenied(ad) {
				public = append(public, ad)
			}
		}
		if len(public) == 0 {
			continue
		}
		rt.Addrs = public
		r.routeAddrs(rt, public)
		if rt.Zone == nil && !rt.Unzoned {
			return true // routed to a reason (a tie, the deny list): stays uncovered
		}
		v := &VantageRoute{Observer: a.Observer, ObservedAt: a.ObservedAt}
		if rt.Zone != nil {
			v.Zone = rt.Zone.ID
		}
		rt.Vantage = v
		return true
	}
	return false
}

// VantageRoute says which sensor's answer placed a name.
type VantageRoute struct {
	Observer   shared.ID
	Zone       shared.ID // zero for an unzoned public target
	ObservedAt time.Time
	// SplitHorizon: the platform resolves the name to other addresses (the
	// name answers differently inside and outside the network). Both are
	// kept; the route follows the sensor's view.
	SplitHorizon bool
}

func sameAddrSet(a, b []netip.Addr) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.SortFunc(x, func(p, q netip.Addr) int { return p.Compare(q) })
	slices.SortFunc(y, func(p, q netip.Addr) int { return p.Compare(q) })
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

// HostNames are the distinct lower-case host names among targets (addresses
// and ranges left out), at most limit.
func HostNames(targets []string, limit int) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range targets {
		pt := ParseTarget(t)
		if pt.IsAddr || pt.Host == "" {
			continue
		}
		h := strings.ToLower(strings.TrimSuffix(pt.Host, "."))
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
		if len(out) >= limit {
			break
		}
	}
	return out
}
