package scope

// Port, protocol and path limits of a scope entry (RFC-065 §16.8,
// docs/rfcs/RFC-065-bug-bounty-programs.md).
//
// A program often lists a service ("api.example.com:8443/tcp") or a part of
// a site ("https://example.com/api/") rather than a whole host. Such an
// entry must never authorize more than it names:
//
//   - a port-limited entry covers a target only when the target itself names
//     an allowed port (host:port, or a URL whose port, explicit or the
//     scheme's default, is allowed) over the allowed protocol. A bare host,
//     an address or a network is not covered, so a full port scan of the
//     host is refused by every gate that asks Target.Matches (dispatch,
//     claim, the signer's ledger);
//   - a URL entry with a path covers only URLs on the same scheme and host
//     whose path lies under the prefix segment by segment, with no dot
//     segments ("/api/../admin");
//   - a job on a target that only constrained entries cover runs only with a
//     tool that stays on the target it is given (ConstrainedJobRefusal); a
//     port list in the job must lie within the allowed ports.
//
// The constraint is part of the entry's identity, like its type and
// pattern: it is set at creation and never changed.

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Protocols a constraint may name.
const (
	ProtocolTCP = "tcp"
	ProtocolUDP = "udp"
)

// MaxConstraintPortRanges bounds a constraint's port list (the program feed
// schema allows 32 entries).
const MaxConstraintPortRanges = 32

// Constraint limits an entry to ports and a protocol. The zero value is no
// limit.
type Constraint struct {
	// Ports is the canonical port list ("443,8000-8100"); "" = every port.
	Ports string `json:"ports,omitempty"`
	// Protocol is "tcp", "udp" or "" (any).
	Protocol string `json:"protocol,omitempty"`
}

// IsZero reports whether the constraint limits nothing.
func (c Constraint) IsZero() bool { return c.Ports == "" && c.Protocol == "" }

// ErrInvalidConstraint refuses a malformed port list or protocol, or a
// constraint on a type that names no host.
var ErrInvalidConstraint = shared.NewDomainError("SCOPE_CONSTRAINT_INVALID",
	"ports must be a list of ports or ranges (1-65535), protocol tcp or udp, on a domain, address or network entry", shared.ErrValidation)

// constrainableTypes are the entry types that name hosts.
var constrainableTypes = map[TargetType]bool{
	TargetTypeDomain: true, TargetTypeSubdomain: true, TargetTypeIPAddress: true,
	TargetTypeIPRange: true, TargetTypeCIDR: true, TargetTypeHost: true,
}

// NormalizeConstraint validates ports and protocol for an entry of type t
// and returns the canonical constraint (ranges sorted and merged).
func NormalizeConstraint(t TargetType, ports []string, protocol string) (Constraint, error) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol != "" && protocol != ProtocolTCP && protocol != ProtocolUDP {
		return Constraint{}, ErrInvalidConstraint
	}
	var spec []string
	for _, p := range ports {
		for _, part := range strings.Split(p, ",") {
			if part = strings.TrimSpace(part); part != "" {
				spec = append(spec, part)
			}
		}
	}
	if len(spec) == 0 && protocol == "" {
		return Constraint{}, nil
	}
	if !constrainableTypes[t] || len(spec) > MaxConstraintPortRanges {
		return Constraint{}, ErrInvalidConstraint
	}
	var canonical string
	if len(spec) > 0 {
		rs, ok := parsePorts(strings.Join(spec, ","))
		if !ok {
			return Constraint{}, ErrInvalidConstraint
		}
		canonical = formatPorts(mergePorts(rs))
	}
	return Constraint{Ports: canonical, Protocol: protocol}, nil
}

type portSpan struct{ lo, hi int }

func parsePorts(spec string) ([]portSpan, bool) {
	parts := strings.Split(spec, ",")
	if len(parts) > 256 {
		return nil, false
	}
	out := make([]portSpan, 0, len(parts))
	for _, part := range parts {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(part), "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil || a < 1 || a > 65535 {
			return nil, false
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil || b < a || b > 65535 {
				return nil, false
			}
		}
		out = append(out, portSpan{a, b})
	}
	return out, true
}

func mergePorts(rs []portSpan) []portSpan {
	slices.SortFunc(rs, func(a, b portSpan) int { return a.lo - b.lo })
	out := make([]portSpan, 0, len(rs))
	for _, r := range rs {
		if n := len(out); n > 0 && r.lo <= out[n-1].hi+1 {
			out[n-1].hi = max(out[n-1].hi, r.hi)
			continue
		}
		out = append(out, r)
	}
	return out
}

func formatPorts(rs []portSpan) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		if r.lo == r.hi {
			parts = append(parts, strconv.Itoa(r.lo))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", r.lo, r.hi))
		}
	}
	return strings.Join(parts, ",")
}

// allowsPort reports whether port is in the constraint's list ("" = all).
func (c Constraint) allowsPort(port int) bool {
	if c.Ports == "" {
		return true
	}
	rs, ok := parsePorts(c.Ports)
	if !ok {
		return false
	}
	for _, r := range rs {
		if port >= r.lo && port <= r.hi {
			return true
		}
	}
	return false
}

// TargetPort returns the port and protocol a target names: host:port
// (protocol from a "/udp" or ":udp" suffix, else tcp), or a http(s) URL
// (its explicit port or the scheme's default, tcp). ok is false for a bare
// host, an address or a network.
func TargetPort(value string) (port int, protocol string, ok bool) {
	v := strings.TrimSpace(value)
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		if err != nil || u.Host == "" {
			return 0, "", false
		}
		if p := u.Port(); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return 0, "", false
			}
			return n, ProtocolTCP, true
		}
		switch strings.ToLower(u.Scheme) {
		case "http":
			return 80, ProtocolTCP, true
		case "https":
			return 443, ProtocolTCP, true
		}
		return 0, "", false
	}
	_, p, proto, ok := asset.SplitServiceName(v)
	if !ok {
		return 0, "", false
	}
	if proto == "" {
		proto = ProtocolTCP
	}
	return p, proto, true
}

// covers reports whether the constraint allows the port and protocol value
// names. A zero constraint allows anything.
func (c Constraint) covers(value string) bool {
	if c.IsZero() {
		return true
	}
	port, proto, ok := TargetPort(value)
	if !ok {
		return false
	}
	if c.Protocol != "" && proto != c.Protocol {
		return false
	}
	return c.allowsPort(port)
}

// PortsWithin reports whether every port of the job's port list (a list of
// ports and ranges) is allowed by one of the constraints. A list that
// cannot be read exactly ("top-100", "full") is not within.
func PortsWithin(jobPorts string, cs []Constraint) bool {
	job, ok := parsePorts(jobPorts)
	if !ok {
		return false
	}
	for _, j := range job {
		for p := j.lo; p <= j.hi; p++ {
			allowed := false
			for _, c := range cs {
				if c.allowsPort(p) {
					allowed = true
					break
				}
			}
			if !allowed {
				return false
			}
		}
	}
	return true
}

// URLPathLimited reports whether a URL entry is limited to a path: its
// pattern names a path below the root.
func URLPathLimited(t TargetType, pattern string) bool {
	if t != TargetTypeURL {
		return false
	}
	_, prefix, ok := urlPatternParts(pattern)
	return ok && strings.Trim(prefix, "/") != ""
}

// urlPatternParts splits a URL entry pattern ("https://host[:port]/path*")
// into "scheme://host[:port]" and the path prefix (without the trailing
// "*").
func urlPatternParts(pattern string) (origin, prefix string, ok bool) {
	p := strings.ToLower(strings.TrimSpace(pattern))
	scheme, rest, found := strings.Cut(p, "://")
	if !found || scheme == "" || rest == "" {
		return "", "", false
	}
	host, path, _ := strings.Cut(rest, "/")
	if host == "" {
		return "", "", false
	}
	return scheme + "://" + host, "/" + strings.TrimSuffix(path, "*"), true
}

// hasDotSegment reports whether a URL path has a "." or ".." segment, also
// percent-encoded: such a path can leave a prefix once a server normalizes
// it.
func hasDotSegment(path string) bool {
	p := strings.ToLower(path)
	p = strings.ReplaceAll(p, "%2e", ".")
	p = strings.ReplaceAll(p, "%2f", "/")
	p = strings.ReplaceAll(p, "%5c", "/")
	p = strings.ReplaceAll(p, `\`, "/")
	for _, s := range strings.Split(p, "/") {
		if s == "." || s == ".." {
			return true
		}
	}
	return false
}

// matchURLPrefix is the path-limited URL test: same scheme and host (and
// port), and the value's path at or under the prefix, segment by segment,
// without dot segments.
func matchURLPrefix(pattern, value string) bool {
	origin, prefix, ok := urlPatternParts(pattern)
	if !ok {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	if strings.ToLower(u.Scheme)+"://"+strings.ToLower(u.Host) != origin {
		return false
	}
	path := u.EscapedPath()
	if hasDotSegment(path) {
		return false
	}
	// A prefix ending in "/" or a pattern "…/api*" both mean the "api"
	// segment and what lies under it.
	return PathUnder(strings.ToLower(path), strings.TrimSuffix(prefix, "/"))
}

// EntryMatches is the coverage test of a scope entry: its pattern, its
// constraint, and for a path-limited URL entry the segment-safe prefix
// test. Every gate that asks whether an entry covers a target (the
// dispatch gate, the claim re-check, the signer's ledger) uses it, so the
// ledger is never wider than the entries in the database.
func EntryMatches(t TargetType, pattern string, c Constraint, value string) bool {
	if URLPathLimited(t, pattern) {
		return matchURLPrefix(pattern, value)
	}
	if c.IsZero() {
		return MatchesPattern(t, pattern, value)
	}
	if !c.covers(value) {
		return false
	}
	return MatchesPattern(t, pattern, asset.HostOf(value))
}

// constrainedTools are the tools that work only on the target they are
// given (one host:port or one URL), so a target covered only by a port- or
// path-limited entry may go to them. Crawlers, template scanners and DAST
// tools can reach other ports or paths and are refused there until they
// take an enforced scope from the platform.
var (
	portLimitedTools = map[string]bool{"naabu": true, "httpx": true}
	pathLimitedTools = map[string]bool{"httpx": true}
)

// Refusal reasons of a job on a constrained target.
const (
	ConstrainedToolRefused  = "constrained_tool"
	ConstrainedPortsOutside = "constrained_ports"
)

// ConstrainedJobRefusal decides whether a job may run on a target that only
// constrained entries cover: cs are the port constraints of those entries
// (empty when only path-limited URL entries cover it), pathLimited whether
// a path-limited URL entry is among them. jobPorts is the job's port list
// setting ("" = none) and topPorts whether it asks for a "top N" list. It
// returns "" when the job may run, otherwise a refusal reason.
func ConstrainedJobRefusal(tool string, cs []Constraint, pathLimited bool, jobPorts string, topPorts bool) string {
	tool = strings.ToLower(strings.TrimSpace(tool))
	if pathLimited && !pathLimitedTools[tool] {
		return ConstrainedToolRefused
	}
	if len(cs) > 0 && !portLimitedTools[tool] {
		return ConstrainedToolRefused
	}
	if topPorts {
		return ConstrainedPortsOutside
	}
	if tool == "naabu" && strings.TrimSpace(jobPorts) == "" {
		// A port scanner without a port list scans its default set.
		return ConstrainedPortsOutside
	}
	if strings.TrimSpace(jobPorts) != "" && (len(cs) == 0 || !PortsWithin(jobPorts, cs)) {
		return ConstrainedPortsOutside
	}
	return ""
}

// ConstrainedToolAllowed is the part of ConstrainedJobRefusal that needs
// only the tool (the signer sees the tool, not the job's settings).
func ConstrainedToolAllowed(tool string, portLimited, pathLimited bool) bool {
	tool = strings.ToLower(strings.TrimSpace(tool))
	if pathLimited && !pathLimitedTools[tool] {
		return false
	}
	return !portLimited || portLimitedTools[tool]
}

// JobShape is what the constraint check needs of a job: its tool, its port
// list setting ("" = none) and whether it asks for a "top N" port list.
type JobShape struct {
	Tool     string
	Ports    string
	TopPorts bool
}

// Overlaps reports whether two constraints allow a common port (a zero
// constraint allows every port; protocols are not compared).
func (c Constraint) Overlaps(o Constraint) bool {
	if c.Ports == "" || o.Ports == "" {
		return true
	}
	a, ok1 := parsePorts(c.Ports)
	b, ok2 := parsePorts(o.Ports)
	if !ok1 || !ok2 {
		return true // unreadable: assume they meet (the safe side for an exclusion)
	}
	for _, x := range a {
		for _, y := range b {
			if x.lo <= y.hi && y.lo <= x.hi {
				return true
			}
		}
	}
	return false
}
