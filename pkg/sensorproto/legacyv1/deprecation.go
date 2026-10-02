package legacyv1

import "net/http"

// Protocol v1 is deprecated (RFC-029 §5.2,
// docs/rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md): every v1
// sensor route that has a protocol v2 successor answers with Deprecation,
// Sunset and Link headers. Bodies and status codes do not change (RFC-023
// C1). The dates are the management path's, so protocol v1 has one
// deprecation story.
var (
	// ProtocolDeprecatedAt is when protocol v1 was deprecated (RFC 9745).
	ProtocolDeprecatedAt = DeprecatedSince
	// ProtocolSunsetAt is the earliest date protocol v1 may stop answering
	// (RFC 8594). Removal also needs the telemetry criteria of RFC-029 §5.4.
	ProtocolSunsetAt = SunsetAt
)

// DeprecatedRoute adds the deprecation headers to a v1 route's responses,
// naming the request's protocol v2 successor (successor(r), a path that must
// already be escaped) in the Link header. The headers are set before the
// handler runs, so every answer carries them, errors included.
func DeprecatedRoute(successor func(r *http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Deprecation", DeprecationHeader())
			h.Set("Sunset", SunsetHeader())
			h.Set("Link", "<"+successor(r)+">; rel=\"successor-version\"")
			next.ServeHTTP(w, r)
		})
	}
}

// Successor returns a successor function for a fixed path.
func Successor(path string) func(*http.Request) string {
	return func(*http.Request) string { return path }
}
