package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Route deprecation (RFC-041 §6.1, docs/rfcs/RFC-041-api-path-design.md).
//
// A route that moved keeps answering at its old path, on the same handler and
// the same middleware chain as its successor, wrapped in Deprecated. Every
// response then says so. Mount it first in the chain (before the
// authenticator) so that errors such as a 401 carry the headers too; it reads
// no credential except to label the metric:
//
//	Deprecation: @<unix seconds>                (RFC 9745)
//	Sunset: <IMF-fixdate>                       (RFC 8594)
//	Link: <successor>; rel="successor-version"
//
// and deprecated_route_requests_total counts the call, so the old path is
// removed only once nobody uses it. Bodies and status codes do not change.

// DeprecatedRouteRequests counts calls to deprecated routes by plane, route
// and kind of caller.
var DeprecatedRouteRequests = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "deprecated_route_requests_total",
		Help: "Requests to deprecated API routes (RFC-041), by plane, route and kind of caller",
	},
	[]string{"plane", "route", "client"},
)

// Deprecation describes one deprecated route.
type Deprecation struct {
	// Plane is the route's plane (routes/plane), a metric label.
	Plane string
	// Route is a fixed name for the old route, a metric label. Never derive
	// it from the request path: that would make the label set unbounded.
	Route string
	// Successor is the path that replaces the route. SuccessorFunc, when set,
	// computes it from the request (for paths with parameters); its result
	// must already be escaped.
	Successor     string
	SuccessorFunc func(*http.Request) string
	// DeprecatedAt and SunsetAt are the RFC 9745 and RFC 8594 dates.
	DeprecatedAt time.Time
	SunsetAt     time.Time
}

func (d Deprecation) validate() error {
	switch {
	case d.Plane == "" || d.Route == "":
		return fmt.Errorf("deprecated route: plane and route name are required")
	case d.Successor == "" && d.SuccessorFunc == nil:
		return fmt.Errorf("deprecated route %s: a successor is required", d.Route)
	case d.DeprecatedAt.IsZero() || d.SunsetAt.IsZero():
		return fmt.Errorf("deprecated route %s: deprecation and sunset dates are required", d.Route)
	case d.SunsetAt.Before(d.DeprecatedAt):
		// RFC 9745 §3: Sunset MUST NOT be earlier than Deprecation.
		return fmt.Errorf("deprecated route %s: sunset %s is before deprecation %s",
			d.Route, d.SunsetAt.Format(time.DateOnly), d.DeprecatedAt.Format(time.DateOnly))
	}
	return nil
}

// Deprecated returns the middleware for a deprecated route. An invalid
// Deprecation is a programming error and panics at route registration, so it
// can never reach a running server.
func Deprecated(d Deprecation) func(http.Handler) http.Handler {
	if err := d.validate(); err != nil {
		panic(err)
	}
	deprecation := "@" + strconv.FormatInt(d.DeprecatedAt.Unix(), 10)
	sunset := d.SunsetAt.UTC().Format(http.TimeFormat)
	successor := d.SuccessorFunc
	if successor == nil {
		fixed := d.Successor
		successor = func(*http.Request) string { return fixed }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Deprecation", deprecation)
			h.Set("Sunset", sunset)
			h.Add("Link", "<"+successor(r)+">; rel=\"successor-version\"")
			DeprecatedRouteRequests.WithLabelValues(d.Plane, d.Route, DeprecatedRouteClient(r)).Inc()
			next.ServeHTTP(w, r)
		})
	}
}

// DeprecatedRouteClient names the kind of caller from the credential it
// presents: "admin", "oct_key", "sensor", "web" or "anonymous". It is a
// telemetry label only — it decides nothing, so it reads the credential's
// shape without verifying it, and never the User-Agent.
func DeprecatedRouteClient(r *http.Request) string {
	const admin = "admin"
	if r.Header.Get("X-Admin-API-Key") != "" {
		return admin
	}
	if _, err := r.Cookie(AdminSessionCookie); err == nil {
		return admin
	}
	tok := bearerToken(r)
	if tok == "" {
		tok = strings.TrimSpace(r.Header.Get("X-API-Key"))
	}
	switch {
	case strings.HasPrefix(tok, "oct_"):
		return "oct_key"
	case tok != "" && !strings.HasPrefix(tok, "eyJ"):
		// Not a user key and not a JWT: a sensor key (octs_, legacy keys) or
		// an enrollment token (octe_).
		return "sensor"
	case tok != "":
		return "web"
	}
	if _, err := r.Cookie(DefaultAccessTokenCookieName); err == nil {
		return "web"
	}
	return "anonymous"
}
