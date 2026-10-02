package legacyv1

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// The management API moved from /api/v1/agents to /api/v1/sensors. The old
// path answers 308 Permanent Redirect (method and body preserved, so a POST
// stays a POST) until the sunset date, then is removed (410 in the release
// that drops it).
const (
	// ManagementPathPrefix is the deprecated management mount.
	ManagementPathPrefix = "/api/v1/agents"
	// ManagementSuccessorPath is where it now lives.
	ManagementSuccessorPath = "/api/v1/sensors"
)

var (
	// DeprecatedSince is when /api/v1/agents was deprecated (RFC 9745).
	DeprecatedSince = time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)
	// SunsetAt is when /api/v1/agents stops answering (RFC 8594).
	SunsetAt = time.Date(2027, time.April, 1, 0, 0, 0, 0, time.UTC)
)

// DeprecationHeader is the RFC 9745 Deprecation value: "@" + unix seconds.
func DeprecationHeader() string { return "@" + strconv.FormatInt(DeprecatedSince.Unix(), 10) }

// SunsetHeader is the RFC 8594 Sunset value (an IMF-fixdate).
func SunsetHeader() string { return SunsetAt.UTC().Format(http.TimeFormat) }

// DeprecatedManagementRequests counts calls to the deprecated path so
// operators can see who still uses it before the sunset date.
var DeprecatedManagementRequests = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "deprecated_management_path_requests_total",
		Help: "Requests to the deprecated /api/v1/agents management path (redirected to /api/v1/sensors)",
	},
	[]string{"method"},
)

// ManagementTarget maps a deprecated management URL path onto its successor,
// or reports false when the path is not under ManagementPathPrefix.
func ManagementTarget(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, ManagementPathPrefix)
	if !ok || (rest != "" && !strings.HasPrefix(rest, "/")) {
		return "", false
	}
	return ManagementSuccessorPath + rest, true
}

// RedirectManagement answers a deprecated management request with 308 to the
// same resource under /api/v1/sensors, preserving the query string, and the
// Deprecation / Sunset / Link headers that tell the caller what to do.
func RedirectManagement(onUse func(r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// EscapedPath keeps percent-encoding, so nothing the client sent can
		// turn into a raw CR/LF in the Location header.
		target, ok := ManagementTarget(r.URL.EscapedPath())
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		DeprecatedManagementRequests.WithLabelValues(r.Method).Inc()
		if onUse != nil {
			onUse(r)
		}
		h := w.Header()
		h.Set("Deprecation", DeprecationHeader())
		h.Set("Sunset", SunsetHeader())
		h.Set("Link", "<"+ManagementSuccessorPath+">; rel=\"successor-version\"")
		h.Set("Location", target)
		w.WriteHeader(http.StatusPermanentRedirect)
	}
}
