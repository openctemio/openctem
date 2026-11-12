package scope

// The sensor-side form of a port- or path-limited entry (RFC-065 §16.8):
// the limit a signed job carries for a target only such entries cover, so
// a sensor that enforces limits (sdk-go pkg/scopelimit) can run any tool
// on it and stay inside.

import (
	"net/url"
	"strconv"
	"strings"
)

// EntryLimit is the limit an entry puts on its host: ports, protocol and a
// URL path prefix ("" = none), in the form a signed job carries it.
type EntryLimit struct {
	Ports      string
	Protocol   string
	PathPrefix string
}

// LimitOfEntry is the limit a port- or path-limited entry gives a target it
// covers; ok is false for an entry without a limit (it covers the host on
// every port and path). A path-limited URL entry gives its origin's port
// over tcp and its path, percent-decoded, without the trailing "*" or "/";
// a path that cannot be decoded safely gives no limit and ok true with an
// empty limit, which allows nothing on the sensor's side.
func LimitOfEntry(t TargetType, pattern string, c Constraint) (EntryLimit, bool) {
	if URLPathLimited(t, pattern) {
		p := strings.TrimSpace(pattern)
		scheme, rest, _ := strings.Cut(p, "://")
		host, raw, _ := strings.Cut(rest, "/")
		port, _, ok := TargetPort(strings.ToLower(scheme) + "://" + strings.ToLower(host) + "/")
		raw = "/" + strings.TrimSuffix(raw, "*")
		dec, err := url.PathUnescape(raw)
		lower := strings.ToLower(raw)
		encodedSep := strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%00")
		if !ok || err != nil || encodedSep || hasDotSegment(raw) || strings.ContainsAny(dec, "?#\\%") {
			return EntryLimit{}, true
		}
		if dec != "/" {
			dec = strings.TrimSuffix(dec, "/")
		}
		return EntryLimit{Ports: strconv.Itoa(port), Protocol: ProtocolTCP, PathPrefix: dec}, true
	}
	if c.IsZero() {
		return EntryLimit{}, false
	}
	return EntryLimit{Ports: c.Ports, Protocol: c.Protocol}, true
}

// LimitWithin reports whether the limit l allows no more than the entry
// (type t, pattern, constraint c) does: an entry without a limit allows
// anything; otherwise l's protocol, ports and path prefix must lie within
// the entry's (path prefixes segment by segment, ignoring case, as entries
// match).
func LimitWithin(l EntryLimit, t TargetType, pattern string, c Constraint) bool {
	e, limited := LimitOfEntry(t, pattern, c)
	if !limited {
		return true
	}
	if e.Ports == "" && e.Protocol == "" && e.PathPrefix == "" {
		return false
	}
	if e.Protocol != "" && l.Protocol != e.Protocol {
		return false
	}
	if e.Ports != "" && (l.Ports == "" || !PortsWithin(l.Ports, []Constraint{{Ports: e.Ports}})) {
		return false
	}
	if e.PathPrefix != "" {
		if l.PathPrefix == "" || hasDotSegment(l.PathPrefix) ||
			!PathUnder(strings.ToLower(l.PathPrefix), strings.ToLower(strings.TrimSuffix(e.PathPrefix, "/"))) {
			return false
		}
	}
	return true
}
