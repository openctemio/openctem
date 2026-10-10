package jobsign

// Scope limits of a signed job (RFC-065 §16.8, docs/architecture/job-signing.md):
// for every target that only port- or path-limited scope entries cover, the
// ports, protocol and path prefix a sensor may reach on its host. The
// sensor (sdk-go pkg/scopelimit) enforces them in the task's egress
// forwarder; the signer signs them only when its ledger allows each one.

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// CapabilityScopeLimits is the sensor manifest capability of a sensor that
// enforces Statement.Limits.
const CapabilityScopeLimits = "scope.limits@1"

// MaxLimits caps the limits of one statement.
const MaxLimits = 1024

// Limit is one allowance on a limited host (the sdk-go scopelimit.Limit
// wire form).
type Limit struct {
	// Host is LimitHost of one of the statement's targets.
	Host string `json:"host"`
	// Ports is a canonical port list ("443,8000-8100"); "" = every port.
	Ports string `json:"ports,omitempty"`
	// Protocol is "tcp", "udp" or "" (any).
	Protocol string `json:"protocol,omitempty"`
	// PathPrefix is the URL path HTTP requests must stay under ("/api");
	// "" = every path.
	PathPrefix string `json:"path_prefix,omitempty"`
}

// LimitHost is the host a target names, as limits name it: lower case, no
// brackets or trailing dot, an IPv4-mapped address unmapped; "" for a
// network or a path. The same rule as the sensor's (sdk-go
// scopelimit.HostOf).
func LimitHost(target string) string {
	v := strings.TrimSpace(target)
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		if err != nil {
			return ""
		}
		return normLimitHost(u.Hostname())
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		return normLimitHost(h)
	}
	if v == "" || strings.ContainsAny(v, "/ ") {
		return ""
	}
	return normLimitHost(v)
}

func normLimitHost(h string) string {
	h = strings.TrimSuffix(strings.ToLower(strings.Trim(strings.TrimSpace(h), "[]")), ".")
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().String()
	}
	return h
}

// ValidateLimits checks the limits as a sensor reads them: each names the
// host of one of targets, has a canonical port list, a known protocol and
// a normalized path prefix. The sensor refuses a statement whose limits
// fail this, so neither the API nor the signer sends one.
func ValidateLimits(limits []Limit, targets []string) error {
	if len(limits) > MaxLimits {
		return fmt.Errorf("%d limits, at most %d", len(limits), MaxLimits)
	}
	hosts := map[string]bool{}
	for _, t := range targets {
		if h := LimitHost(t); h != "" {
			hosts[h] = true
		}
	}
	for i, l := range limits {
		switch {
		case !hosts[l.Host] || l.Host != normLimitHost(l.Host):
			return fmt.Errorf("limit %d: host %q is not one of the targets", i, l.Host)
		case l.Ports == "" && l.Protocol == "" && l.PathPrefix == "":
			return fmt.Errorf("limit %d: limits nothing", i)
		case l.Protocol != "" && l.Protocol != "tcp" && l.Protocol != "udp":
			return fmt.Errorf("limit %d: protocol %q", i, l.Protocol)
		case l.PathPrefix != "" && l.Protocol == "udp":
			return fmt.Errorf("limit %d: a path prefix needs tcp", i)
		}
		if l.Ports != "" && !canonicalPorts(l.Ports) {
			return fmt.Errorf("limit %d: port list %q is not canonical", i, l.Ports)
		}
		if l.PathPrefix != "" && !normalizedPrefix(l.PathPrefix) {
			return fmt.Errorf("limit %d: path prefix %q is not normalized", i, l.PathPrefix)
		}
	}
	return nil
}

// canonicalPorts: ascending, non-overlapping, non-adjacent "n" or "lo-hi"
// ranges, at most 32.
func canonicalPorts(spec string) bool {
	parts := strings.Split(spec, ",")
	if len(parts) > 32 {
		return false
	}
	prev := 0
	for _, part := range parts {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 1 || a > 65535 || strconv.Itoa(a) != lo || a <= prev+1 && prev > 0 {
			return false
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b <= a || b > 65535 || strconv.Itoa(b) != hi {
				return false
			}
		}
		prev = b
	}
	return true
}

// normalizedPrefix: absolute, decoded (no percent-escape), no query,
// fragment, control character, backslash or dot segment, and unchanged by
// path cleaning (a trailing slash aside). The sensor compares it with the
// decoded, cleaned request path.
func normalizedPrefix(p string) bool {
	if !strings.HasPrefix(p, "/") || len(p) > 1024 || strings.ContainsAny(p, "?#\\%") ||
		strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		base, _, _ := strings.Cut(seg, ";")
		if base == "." || base == ".." {
			return false
		}
	}
	c := path.Clean(p)
	return c == p || c+"/" == p
}
