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
//     pins the address it checked.

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
)

// sharedJobTypes are the command types a shared sensor may be signed.
var sharedJobTypes = map[string]bool{"scan": true, "validate": true, "retest": true}

// checkShared applies the shared-job rules to a statement whose
// sensor_scope is set; nil for an organization's statement.
func checkShared(st *jobsign.Statement) *refusal {
	switch st.SensorScope {
	case "":
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
	for i, t := range st.Targets {
		if internalTarget(t) {
			return refuse(http.StatusForbidden, ReasonSharedInternal, "target %d is internal; a shared sensor scans public targets only", i)
		}
	}
	return nil
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
