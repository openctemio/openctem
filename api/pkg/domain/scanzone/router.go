package scanzone

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Resolver looks up the addresses of a hostname. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Resolution bounds for routing hostnames at trigger time.
const (
	lookupTimeout     = 3 * time.Second
	lookupConcurrency = 8
)

// Router assigns scan targets to zones (RFC-023 D4-D6):
//
//   - an address or CIDR goes to the zone with the narrowest range that holds
//     all of it (ties: zone name, then id);
//   - a hostname is routed by the addresses it resolves to from the platform
//     (RFC-023 §12 Q2): the narrowest zone holding any of them;
//   - a public target no range holds goes to the tenant's default zone, or,
//     when the tenant has none, is "unzoned" and dispatched as before zones;
//   - a private target no range holds, an address in the deny list, a range
//     spanning zones and a hostname that does not resolve are uncovered: they
//     are reported, never sent anywhere.
type Router struct {
	zones    []*Zone
	def      *Zone
	resolver Resolver
}

// NewRouter builds a router over a tenant's zones. resolver may be nil, in
// which case every hostname is uncovered.
func NewRouter(zones []*Zone, resolver Resolver) *Router {
	sorted := slices.Clone(zones)
	slices.SortFunc(sorted, func(a, b *Zone) int {
		if c := strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); c != 0 {
			return c
		}
		return strings.Compare(a.ID.String(), b.ID.String())
	})
	r := &Router{zones: sorted, resolver: resolver}
	for _, z := range sorted {
		if z.IsDefault {
			r.def = z
			break
		}
	}
	return r
}

// Route is the routing decision for one target. Exactly one of Zone,
// Unzoned and Reason is set.
type Route struct {
	Target  string
	Zone    *Zone
	Unzoned bool
	Reason  string
	Addrs   []netip.Addr // what a hostname resolved to
	// OutsideZones is set when the target is uncovered only because no
	// zone range holds it (as opposed to the deny list or failed DNS).
	OutsideZones bool
}

// Uncovered is a target that will not be scanned, with the reason.
type Uncovered struct {
	Target string `json:"target"`
	Reason string `json:"reason"`
}

// Plan is the routing of a whole target list.
type Plan struct {
	ByZone    map[shared.ID][]string
	Zones     map[shared.ID]*Zone
	ZoneOrder []shared.ID // zones in first-seen target order
	Unzoned   []string
	Uncovered []Uncovered
	Routes    []Route // one per input target, in input order
}

// Plan routes every target. Hostnames are resolved concurrently; the result
// keeps the input order.
func (r *Router) Plan(ctx context.Context, targets []string) *Plan {
	routes := make([]Route, len(targets))
	sem := make(chan struct{}, lookupConcurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		pt := ParseTarget(t)
		if pt.IsAddr {
			routes[i] = r.routeTarget(ctx, t, pt)
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t string, pt Target) {
			defer wg.Done()
			defer func() { <-sem }()
			routes[i] = r.routeTarget(ctx, t, pt)
		}(i, t, pt)
	}
	wg.Wait()

	return buildPlan(routes)
}

func buildPlan(routes []Route) *Plan {
	p := &Plan{ByZone: map[shared.ID][]string{}, Zones: map[shared.ID]*Zone{}, Routes: routes}
	for _, rt := range routes {
		switch {
		case rt.Zone != nil:
			if _, seen := p.Zones[rt.Zone.ID]; !seen {
				p.Zones[rt.Zone.ID] = rt.Zone
				p.ZoneOrder = append(p.ZoneOrder, rt.Zone.ID)
			}
			p.ByZone[rt.Zone.ID] = append(p.ByZone[rt.Zone.ID], rt.Target)
		case rt.Unzoned:
			p.Unzoned = append(p.Unzoned, rt.Target)
		default:
			p.Uncovered = append(p.Uncovered, Uncovered{Target: rt.Target, Reason: rt.Reason})
		}
	}
	return p
}

// Route decides where one target goes.
func (r *Router) Route(ctx context.Context, target string) Route {
	return r.routeTarget(ctx, target, ParseTarget(target))
}

func (r *Router) routeTarget(ctx context.Context, target string, pt Target) Route {
	rt := Route{Target: target}
	if pt.IsAddr {
		r.routePrefix(&rt, pt.Prefix)
		return rt
	}
	if pt.Host == "" {
		rt.Reason = "not an address, range or hostname"
		return rt
	}
	addrs := r.resolve(ctx, pt.Host)
	if len(addrs) == 0 {
		rt.Reason = "hostname did not resolve from the platform; zones route hostnames by resolved address, so add the address or fix DNS"
		return rt
	}
	rt.Addrs = addrs
	r.routeAddrs(&rt, addrs)
	return rt
}

func (r *Router) routePrefix(rt *Route, p netip.Prefix) {
	if IsDenied(p.Addr()) || (p.Bits() < p.Addr().BitLen() && overlapsDeny(p)) {
		rt.Reason = fmt.Sprintf("%s is in the built-in deny list (loopback, link-local/metadata, multicast, unspecified)", p)
		return
	}
	if z := r.narrowest(p); z != nil {
		rt.Zone = z
		return
	}
	if prefixIsPrivate(p) {
		rt.OutsideZones = true
		if p.Bits() < p.Addr().BitLen() && r.partlyCovered(p) {
			rt.Reason = fmt.Sprintf("range %s is only partly inside a zone; split it so each part lies in one zone", p)
			return
		}
		rt.Reason = fmt.Sprintf("%s is a private address outside every scan zone", p.Addr())
		return
	}
	r.routePublic(rt)
}

func (r *Router) routeAddrs(rt *Route, addrs []netip.Addr) {
	var (
		best     *Zone
		bestBits = -1
		private  netip.Addr
		denied   netip.Addr
	)
	for _, a := range addrs {
		a = a.Unmap()
		if IsDenied(a) {
			denied = a
			continue
		}
		p := netip.PrefixFrom(a, a.BitLen())
		for _, z := range r.zones {
			if bits := z.Covers(p); bits > bestBits {
				best, bestBits = z, bits
			}
		}
		if IsPrivate(a) && !private.IsValid() {
			private = a
		}
	}
	switch {
	case best != nil:
		rt.Zone = best
	// The reasons never quote a private or denied answer: the platform's
	// resolver may know internal names, and a reason is shown to whoever
	// asked (scan-zone preview).
	case private.IsValid():
		rt.OutsideZones = true
		rt.Reason = "resolves to a private address outside every scan zone"
	case denied.IsValid() && len(addrs) == 1:
		rt.Reason = "resolves to an address in the built-in deny list"
	case denied.IsValid() && !hasPublic(addrs):
		rt.Reason = "resolves only to addresses in the built-in deny list"
	default:
		r.routePublic(rt)
	}
}

func (r *Router) routePublic(rt *Route) {
	if r.def != nil {
		rt.Zone = r.def
		return
	}
	rt.Unzoned = true
}

// RestrictTo turns a plan made by a router over only the selected zone into
// the plan of a scan that pins its targets to that zone (RFC-023 D5: a
// selected zone's ranges are always enforced). Targets the zone does not hold
// are uncovered, including public targets when the zone is not the default
// zone; deny-list and DNS failures keep their own reason.
func (p *Plan) RestrictTo(selected *Zone) *Plan {
	routes := slices.Clone(p.Routes)
	reason := fmt.Sprintf("outside the selected scan zone %q", selected.Name)
	for i := range routes {
		rt := &routes[i]
		switch {
		case rt.Zone != nil && rt.Zone.ID != selected.ID:
			rt.Zone, rt.Reason = nil, reason
		case rt.Unzoned:
			rt.Unzoned, rt.Reason = false, reason
		case rt.Zone == nil && rt.OutsideZones:
			rt.Reason = reason
		}
	}
	return buildPlan(routes)
}

// narrowest returns the zone with the narrowest range holding all of p.
func (r *Router) narrowest(p netip.Prefix) *Zone {
	var best *Zone
	bestBits := -1
	for _, z := range r.zones { // sorted: the first of equal matches wins
		if bits := z.Covers(p); bits > bestBits {
			best, bestBits = z, bits
		}
	}
	return best
}

func (r *Router) partlyCovered(p netip.Prefix) bool {
	for _, z := range r.zones {
		for _, zr := range z.Ranges {
			if zr.Overlaps(p) {
				return true
			}
		}
	}
	return false
}

func (r *Router) resolve(ctx context.Context, host string) []netip.Addr {
	if r.resolver == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	addrs, err := r.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(addrs)
}

func overlapsDeny(p netip.Prefix) bool {
	for _, d := range denyRanges {
		if d.Overlaps(p) {
			return true
		}
	}
	return false
}

func hasPublic(addrs []netip.Addr) bool {
	for _, a := range addrs {
		if !IsDenied(a) && !IsPrivate(a) {
			return true
		}
	}
	return false
}

// Target is a parsed scan target: an address/range, or a hostname.
type Target struct {
	IsAddr bool
	Prefix netip.Prefix // set when IsAddr; a single address is a full-length prefix
	Host   string       // lower-case hostname otherwise (empty if unparseable)
}

// ParseTarget extracts what routing needs from a scan target: URLs give their
// host, host:port and [v6]:port lose the port, a wildcard domain routes by its
// base name, and IPv4-mapped IPv6 becomes IPv4.
func ParseTarget(raw string) Target {
	s := strings.TrimSpace(raw)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			s = u.Hostname()
		}
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return Target{IsAddr: true, Prefix: unmapPrefix(p).Masked()}
	}
	if h, _, _, ok := asset.SplitServiceName(s); ok {
		s = h // a service in any name form routes by its host
	} else if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.Trim(s, "[]")
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		a = a.Unmap()
		return Target{IsAddr: true, Prefix: netip.PrefixFrom(a, a.BitLen())}
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(s, "*."), "."))
	if strings.ContainsAny(host, "/ @") {
		host = ""
	}
	return Target{Host: host}
}
