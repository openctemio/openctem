package signer

// Shared-job rules (docs/rfcs/RFC-100-shared-sensors.md §8.1). A statement
// for a shared sensor (sensor_scope "instance") is signed only when it
// cannot reach internal space or carry an organization's own content,
// whatever the API asks: a compromised API cannot point a shared sensor,
// which probes from the operator's network, at an internal address.
//
//   - command_type is scan, validate or retest;
//   - no custom templates (no organization rulesets on a shared box);
//   - every target is public: an address or range is checked against the
//     list sensors use (ctis addrscope); a name must not carry an internal
//     suffix. Names are resolved by the API and again by the sensor, which
//     pins the address it checked;
//   - except inside an instance scan zone (RFC-100 §6.1): a statement that
//     names a zone may carry internal addresses and ranges that lie wholly
//     inside the zone's signed ranges (private ranges only), and nothing
//     else internal. Which zone, with which ranges, for which organization
//     and sensor is checked against the signer's own zone ledger
//     (zones.go), not taken from the API.

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/openctemio/ctis/addrscope"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// Refusal reasons of the shared-job rules.
const (
	ReasonBadSensorScope  = "bad_sensor_scope"
	ReasonSharedJobType   = "shared_job_type"
	ReasonSharedTemplates = "shared_templates"
	ReasonSharedInternal  = "shared_internal_target"
	ReasonBadZone         = "bad_zone"
)

// sharedJobTypes are the command types a shared sensor may be signed.
var sharedJobTypes = map[string]bool{"scan": true, "validate": true, "retest": true}

// checkShared applies the shared-job rules to a statement whose
// sensor_scope is set; nil for an organization's statement.
func checkShared(st *jobsign.Statement) *refusal {
	switch st.SensorScope {
	case "":
		if st.Zone != nil {
			return refuse(http.StatusBadRequest, ReasonBadZone, "zone is only for a shared sensor's job")
		}
		return nil
	case jobsign.SensorScopeInstance:
	default:
		return refuse(http.StatusBadRequest, ReasonBadSensorScope, "sensor_scope must be %q or absent", jobsign.SensorScopeInstance)
	}
	if !sharedJobTypes[st.CommandType] {
		return refuse(http.StatusForbidden, ReasonSharedJobType, "a shared sensor runs scan, validate and retest jobs only")
	}
	if len(st.Templates) > 0 {
		return refuse(http.StatusForbidden, ReasonSharedTemplates, "a shared sensor runs no custom templates")
	}
	var zoneRanges []string
	if st.Zone != nil {
		ranges, err := jobsign.CanonicalZoneRanges(st.Zone.Ranges)
		if err != nil || canonicalID(st.Zone.ID) == "" || !sameStrings(ranges, st.Zone.Ranges) {
			return refuse(http.StatusBadRequest, ReasonBadZone, "zone must name an id and its canonical private ranges")
		}
		zoneRanges = ranges
	}
	for i, t := range st.Targets {
		if !internalTarget(t) {
			continue
		}
		if p, ok := targetPrefix(t); ok && zoneRanges != nil && jobsign.ZoneContains(zoneRanges, p) {
			continue
		}
		if zoneRanges != nil {
			return refuse(http.StatusForbidden, ReasonSharedInternal, "target %d is internal and outside the job's zone ranges", i)
		}
		return refuse(http.StatusForbidden, ReasonSharedInternal, "target %d is internal; a shared sensor scans public targets only", i)
	}
	return nil
}

// targetPrefix reads an address or range target (a bare address, a CIDR,
// or a URL or host:port whose host is an address) as a prefix. Names are
// not prefixes: an internal name never passes inside a zone.
func targetPrefix(target string) (netip.Prefix, bool) {
	host := strings.TrimSpace(target)
	if p, err := netip.ParsePrefix(host); err == nil {
		return p, true
	}
	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err != nil {
			return netip.Prefix{}, false
		}
		host = u.Hostname()
	} else if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	a, err := netip.ParseAddr(host)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// internalTarget reports whether a target is an internal address or range,
// or a name with an internal suffix. A target that does not parse as a
// host is internal (fail closed).
func internalTarget(target string) bool {
	host := strings.TrimSpace(target)
	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err != nil {
			return true
		}
		host = u.Hostname()
	} else if i := strings.IndexAny(host, "?#"); i >= 0 {
		host = host[:i]
	}
	if p, err := netip.ParsePrefix(host); err == nil {
		return addrscope.IsInternalPrefix(p)
	}
	if i := strings.Index(host, "/"); i >= 0 { // host/path (a repository, a URL without scheme)
		host = host[:i]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSuffix(host, "]"), "["), ".")
	if host == "" {
		return true
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return addrscope.IsInternal(a)
	}
	lower := strings.ToLower(host)
	if jobsign.NumericHost(lower) {
		return true
	}
	return lower == "localhost" || strings.HasSuffix(lower, ".localhost") ||
		strings.HasSuffix(lower, ".local") || strings.HasSuffix(lower, ".internal") ||
		strings.HasSuffix(lower, ".home.arpa") || strings.HasSuffix(lower, ".in-addr.arpa") ||
		strings.HasSuffix(lower, ".ip6.arpa")
}
