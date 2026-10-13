package stage

// Target kinds: what a target string names, so each stage is handed only the
// kinds it accepts, whether the target was typed in or came from the
// inventory. Design: docs/rfcs/RFC-088-scope-aware-target-allocation.md.

import (
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// TargetKind is what a target names.
type TargetKind string

const (
	// KindName is a host name (an apex, a subdomain, a host).
	KindName TargetKind = "name"
	// KindAddr is one address.
	KindAddr TargetKind = "address"
	// KindRange is more than one address: a CIDR or an "a-b" range.
	KindRange TargetKind = "range"
	// KindURL is a URL.
	KindURL TargetKind = "url"
	// KindService is a host and a port ("host:port", "host:port/proto").
	KindService TargetKind = "service"
	// KindOther is anything else (a repository, an image, a cloud
	// account): not gated by kind.
	KindOther TargetKind = "other"
)

// ClassifyTarget reads the kind of a target string. It never resolves names.
func ClassifyTarget(target string) TargetKind {
	t := strings.TrimSpace(target)
	if t == "" {
		return KindOther
	}
	if strings.Contains(t, "://") {
		if u, err := url.Parse(t); err == nil && u.Host != "" {
			return KindURL
		}
		return KindOther
	}
	if strings.Contains(t, "/") {
		if p, err := netip.ParsePrefix(t); err == nil {
			if p.Bits() == p.Addr().BitLen() || (p.Addr().Is4In6() && p.Bits() == 128) {
				return KindAddr
			}
			return KindRange
		}
	}
	if lo, hi, ok := strings.Cut(t, "-"); ok {
		a, errA := netip.ParseAddr(strings.TrimSpace(lo))
		b, errB := netip.ParseAddr(strings.TrimSpace(hi))
		if errA == nil && errB == nil {
			if a.Unmap() == b.Unmap() {
				return KindAddr
			}
			return KindRange
		}
	}
	if _, err := netip.ParseAddr(strings.Trim(t, "[]")); err == nil {
		return KindAddr
	}
	if _, _, _, ok := asset.SplitServiceName(t); ok {
		return KindService
	}
	if looksLikeHostName(t) {
		return KindName
	}
	return KindOther
}

// looksLikeHostName: letters, digits, dots, hyphens, underscores and a
// leading "*." only, with at least one dot or no dot at all (a single-label
// internal host).
func looksLikeHostName(t string) bool {
	t = strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(t), "*."), ".")
	if t == "" || len(t) > 253 {
		return false
	}
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

var (
	nameInputs = []asset.TypeRef{tDomain, tSubdomain, tHost}
	addrInputs = []asset.TypeRef{tIP, tHost}
	webInputs  = []asset.TypeRef{tHTTPService, tDiscoveredURL, tWebsite, tAPI}
	// networkInputs are every stored pair a network kind stands for: a
	// stage that takes none of them is not gated by kind.
	networkInputs = []asset.TypeRef{tDomain, tSubdomain, tHost, tIP, tNetwork, tOpenPort,
		tHTTPService, tDiscoveredURL, tWebsite, tAPI}
)

func takesAny(s Stage, refs []asset.TypeRef) bool {
	for _, r := range refs {
		if slices.Contains(s.Inputs, r) {
			return true
		}
	}
	return false
}

// AcceptsKind reports whether the stage may be handed a target of kind k.
// A stage that takes no network kind (code, containers, cloud) accepts
// every kind: other gates decide for it. KindOther is always accepted.
//
// A range goes only to stages that take networks, and to the port scan,
// which expands it itself; never to HTTP probing, crawling or templates.
// A service goes to stages that take open ports, and to the port scan.
func (s Stage) AcceptsKind(k TargetKind) bool {
	if k == KindOther || !takesAny(s, networkInputs) {
		return true
	}
	switch k {
	case KindName:
		return takesAny(s, nameInputs)
	case KindAddr:
		return takesAny(s, addrInputs)
	case KindRange:
		return slices.Contains(s.Inputs, tNetwork) || s.Key == ScanPorts
	case KindURL:
		return takesAny(s, webInputs)
	case KindService:
		return slices.Contains(s.Inputs, tOpenPort) || s.Key == ScanPorts
	}
	return false
}

// FilterKinds keeps the targets the stage accepts, in order, and counts the
// rest by kind. A target with a stored inventory type (typed reports it) is
// left to the scanner type gate, which decides by that type; only a range
// is refused here whatever its type. Every other target is decided by its
// kind.
func (s Stage) FilterKinds(targets []string, typed func(string) bool) (kept []string, refused map[TargetKind]int) {
	kept = make([]string, 0, len(targets))
	for _, t := range targets {
		k := ClassifyTarget(t)
		if s.AcceptsKind(k) || (k != KindRange && typed != nil && typed(t)) {
			kept = append(kept, t)
			continue
		}
		if refused == nil {
			refused = map[TargetKind]int{}
		}
		refused[k]++
	}
	return kept, refused
}

// DescribeRefusedKinds names what FilterKinds left out: "2 range, 1 url
// target(s): Vulnerability templates does not take them".
func (s Stage) DescribeRefusedKinds(refused map[TargetKind]int) string {
	if len(refused) == 0 {
		return ""
	}
	parts := make([]string, 0, len(refused))
	for _, k := range []TargetKind{KindRange, KindAddr, KindName, KindURL, KindService} {
		if n := refused[k]; n > 0 {
			parts = append(parts, strconv.Itoa(n)+" "+string(k))
		}
	}
	msg := strings.Join(parts, ", ") + " target(s): " + s.Name + " does not take them"
	if refused[KindRange] > 0 {
		msg += " (a network range goes to port scans and network lookups only)"
	}
	return msg
}
