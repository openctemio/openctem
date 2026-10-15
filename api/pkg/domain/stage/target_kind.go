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
	// KindPath is a host and a path without a scheme: the form of a
	// repository ("github.com/acme/app", "git@github.com:acme/app") or an
	// image reference. It names no network endpoint of the organization:
	// a network tool given it would probe the host, which for a repository
	// is a code host many organizations share. No network stage takes it;
	// a web path is written as a URL with its scheme.
	KindPath TargetKind = "path"
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
	if isPathForm(t) {
		return KindPath
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

// isPathForm reports whether t is a host name with a dot followed by a
// non-empty path and no scheme ("github.com/acme/app"), or the SSH form of
// a repository ("git@github.com:acme/app"). A range ("a.b.c.d/n") was
// classified before.
func isPathForm(t string) bool {
	if strings.ContainsAny(t, " \t") {
		return false
	}
	if rest, ok := strings.CutPrefix(strings.ToLower(t), "git@"); ok {
		host, path, ok := strings.Cut(rest, ":")
		return ok && strings.Contains(host, ".") && looksLikeHostName(host) && strings.Trim(path, "/") != ""
	}
	host, path, ok := strings.Cut(t, "/")
	return ok && strings.Contains(host, ".") && looksLikeHostName(host) && strings.Trim(path, "/") != ""
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

// TakesNetworkKinds reports whether the stage takes any network kind (a
// name, an address, a range, a URL, a service): every stage whose tools
// send traffic to, or look up, the hosts they are given.
func (s Stage) TakesNetworkKinds() bool { return takesAny(s, networkInputs) }

// AcceptsKind reports whether the stage may be handed a target of kind k.
// A stage that takes no network kind (code, containers, cloud) accepts
// every kind: other gates decide for it. KindOther is always accepted.
//
// A range goes only to stages that take networks, and to the port scan,
// which expands it itself; never to HTTP probing, crawling or templates.
// A service goes to stages that take open ports, and to the port scan.
// A path (a repository) never goes to a stage that takes network kinds.
func (s Stage) AcceptsKind(k TargetKind) bool {
	if !s.TakesNetworkKinds() {
		return true
	}
	switch k {
	case KindOther:
		return true
	case KindPath:
		return false
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
// rest by kind. A target with a stored inventory type (typeOf reports it)
// is left to the scanner type gate, which decides by that type; only a
// range and a path are refused here whatever their type. A repository asset
// counts as a path whatever its name. Every other target is decided by its
// kind.
func (s Stage) FilterKinds(targets []string, typeOf func(string) (asset.TypeRef, bool)) (kept []string, refused map[TargetKind]int) {
	kept = make([]string, 0, len(targets))
	for _, t := range targets {
		k := ClassifyTarget(t)
		typed := false
		if typeOf != nil {
			var ref asset.TypeRef
			if ref, typed = typeOf(t); typed && IsRepositoryType(ref) {
				k = KindPath
			}
		}
		if s.AcceptsKind(k) || (typed && k != KindRange && k != KindPath) {
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
	for _, k := range []TargetKind{KindPath, KindRange, KindAddr, KindName, KindURL, KindService} {
		if n := refused[k]; n > 0 {
			parts = append(parts, strconv.Itoa(n)+" "+string(k))
		}
	}
	msg := strings.Join(parts, ", ") + " target(s): " + s.Name + " does not take them"
	if refused[KindRange] > 0 {
		msg += " (a network range goes to port scans and network lookups only)"
	}
	if refused[KindPath] > 0 {
		msg += " (" + ReasonPathTarget + ")"
	}
	return msg
}

// ReasonPathTarget explains why a network tool is never given a repository
// or a path without a scheme.
const ReasonPathTarget = "a repository, or a host with a path but no scheme, goes to code scanning only: " +
	"a network tool would probe the code host itself; write a web path as a URL with its scheme"

// IsRepositoryType reports whether a stored pair is a repository.
func IsRepositoryType(ref asset.TypeRef) bool {
	return asset.CanonicalPair(ref.Type, ref.SubType).Type == asset.AssetTypeRepository
}

// TakesPathTargets reports whether a job of the tool, asking for caps, may
// be handed a path target or a repository: only when the stage it runs
// takes no network kind (code and image scanning). A capability may carry a
// version ("scan.ports@1"). known is false when neither the tool nor the
// capabilities place the job in the catalog: the caller decides from what
// it knows of the tool, and refuses when it knows nothing.
func TakesPathTargets(tool string, caps []string) (ok, known bool) {
	bare := make([]string, 0, len(caps))
	for _, c := range caps {
		c, _, _ = strings.Cut(strings.TrimSpace(c), "@")
		if c != "" {
			bare = append(bare, c)
		}
	}
	if st, found := ForStep(tool, bare); found {
		return !st.TakesNetworkKinds(), true
	}
	if stages := ForTool(tool); len(stages) > 0 {
		// A tool of several stages the capabilities do not pick: a path
		// only when none of them takes network kinds.
		for _, st := range stages {
			if st.TakesNetworkKinds() {
				return false, true
			}
		}
		return true, true
	}
	if st, err := ForCapabilities(bare); err == nil {
		return !st.TakesNetworkKinds(), true
	}
	return false, false
}
