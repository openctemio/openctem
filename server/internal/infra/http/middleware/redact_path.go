package middleware

import "strings"

// Secrets in URL paths (RFC-041 §3.2 P4, docs/rfcs/RFC-041-api-path-design.md).
//
// New routes carry tokens in the body or a header, and the route-style lint
// refuses a {token} parameter. Deprecated aliases that still take one in the
// path (/api/v1/invitations/{token}/...) stay until their sunset, so every
// place that records a request path (the access log, metric labels, trace
// span names and attributes, rate-limit and CSRF logs) passes it through
// RedactPath first.

// secretPathSegment is a prefix whose next path segment is a secret, unless it
// is one of the static route names below it.
type secretPathSegment struct {
	prefix string
	static map[string]bool
}

var secretPathSegments = []secretPathSegment{
	{
		prefix: "/api/v1/invitations/",
		static: map[string]bool{"lookup": true, "accept": true, "decline": true, "accept-with-refresh": true},
	},
}

// RedactedSegment replaces a secret path segment.
const RedactedSegment = "{redacted}"

// RedactPath returns path with any secret segment replaced by
// RedactedSegment. Paths without one are returned unchanged.
func RedactPath(path string) string {
	for _, s := range secretPathSegments {
		if !strings.HasPrefix(path, s.prefix) {
			continue
		}
		rest := path[len(s.prefix):]
		seg, tail, hasTail := strings.Cut(rest, "/")
		if seg == "" || s.static[seg] {
			return path
		}
		if hasTail {
			return s.prefix + RedactedSegment + "/" + tail
		}
		return s.prefix + RedactedSegment
	}
	return path
}
