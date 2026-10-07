package sensor

// Private targets in a command payload: the platform keeps jobs with
// private targets away from sensors without a local policy when the tenant
// asks (RFC-040 Q3 (a)), and away from sensors whose policy refuses private
// ranges (Accepts).

import (
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// HasPrivateTarget reports whether a command payload names a private,
// loopback, link-local or CGNAT address, a range that overlaps one, or a
// host name of a private namespace (localhost, .local, .internal, .lan,
// .corp, .home.arpa, .localdomain, .intranet). A payload it cannot read counts as
// private (fail closed). Names that resolve to private addresses in public
// DNS are not detected here; the sensor's own policy covers them.
func HasPrivateTarget(payload json.RawMessage) bool {
	targets, ok := payloadTargets(payload)
	if !ok {
		return true
	}
	for _, t := range targets {
		if isPrivateTarget(t) {
			return true
		}
	}
	return false
}

// HasPrivateAddress reports whether a command payload names a literal
// address or range inside the private ranges (RFC 1918, fc00::/7) that a
// sensor-local policy refuses unless it allows private ranges. Host names
// are not resolved: the sensor decides those. A payload it cannot read
// reports false (HasPrivateTarget fails closed for it).
func HasPrivateAddress(payload json.RawMessage) bool {
	targets, ok := payloadTargets(payload)
	if !ok {
		return false
	}
	for _, t := range targets {
		if isPrivateAddressLiteral(t) {
			return true
		}
	}
	return false
}

// payloadTargets returns the targets a payload names (target as a string
// or {address}, and targets); ok is false when they cannot be read.
func payloadTargets(payload json.RawMessage) ([]string, bool) {
	if len(payload) == 0 {
		return nil, true
	}
	var p struct {
		Target  json.RawMessage `json:"target"`
		Targets []string        `json:"targets"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, false
	}
	targets := p.Targets
	if len(p.Target) > 0 && string(p.Target) != "null" {
		var str string
		var obj struct {
			Address string `json:"address"`
		}
		switch {
		case json.Unmarshal(p.Target, &str) == nil:
			targets = append(targets, str)
		case json.Unmarshal(p.Target, &obj) == nil:
			targets = append(targets, obj.Address)
		default:
			return nil, false
		}
	}
	return targets, true
}

// policyPrivatePrefixes are the ranges a local policy treats as private
// (refused without allow_private). Loopback, link-local and CGNAT are in
// the sensor's built-in deny list instead.
var policyPrivatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7"),
}

// isPrivateAddressLiteral reports whether target is an address, a range,
// host:port or a URL whose host is an address, inside policyPrivatePrefixes.
func isPrivateAddressLiteral(target string) bool {
	host := strings.TrimSpace(target)
	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err != nil {
			return false
		}
		host = u.Hostname()
	}
	if p, err := netip.ParsePrefix(host); err == nil {
		p = p.Masked()
		for _, pp := range policyPrivatePrefixes {
			if pp.Bits() <= p.Bits() && pp.Contains(p.Addr()) {
				return true
			}
		}
		return false
	}
	if h, _, _, ok := asset.SplitServiceName(host); ok {
		host = h // a service in any name form: its host
	} else if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, pp := range policyPrivatePrefixes {
		if pp.Contains(a) {
			return true
		}
	}
	return false
}

var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("::1/128"),
}

var privateSuffixes = []string{".local", ".internal", ".lan", ".corp", ".home.arpa", ".localhost", ".localdomain", ".intranet"}

func isPrivateTarget(target string) bool {
	host := strings.TrimSpace(target)
	if host == "" || strings.HasPrefix(host, "/") || strings.HasPrefix(host, ".") {
		return false // a filesystem path (code scan), not a network target
	}
	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err != nil {
			return true
		}
		host = u.Hostname()
	}
	if p, err := netip.ParsePrefix(host); err == nil {
		for _, pp := range privatePrefixes {
			if pp.Overlaps(p) {
				return true
			}
		}
		return false
	}
	if h, _, _, ok := asset.SplitServiceName(host); ok {
		host = h // a service in any name form: its host
	} else if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i] // registry/path of an image reference
	}
	host = strings.Trim(host, "[]")
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		for _, pp := range privatePrefixes {
			if pp.Contains(a) {
				return true
			}
		}
		return a.IsUnspecified()
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	if name == "localhost" {
		return true
	}
	for _, sfx := range privateSuffixes {
		if strings.HasSuffix(name, sfx) {
			return true
		}
	}
	return false
}
