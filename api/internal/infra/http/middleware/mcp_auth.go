package middleware

import (
	"net/http"
	"strings"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
)

// MCPBearerChallenge returns the WWW-Authenticate value of a 401 from the MCP
// endpoint (RFC 6750 §3, RFC 9728 §5.1): where the Protected Resource
// Metadata is and which scopes to ask for. Quotes and backslashes cannot
// occur in either value (both are built from a validated origin and the
// fixed scope table).
func MCPBearerChallenge(e mcpoauth.Endpoints) string {
	return `Bearer resource_metadata="` + e.ResourceMetadata + `", scope="` +
		mcpoauth.Join(mcpoauth.ReadScopes()) + `"`
}

// MCPChallenge adds the discovery challenge to every 401 the wrapped chain
// writes for the MCP endpoint, so an MCP client that is refused learns where
// to get a token (RFC-062 §4). Other statuses are untouched: a 200 never
// carries a challenge.
func MCPChallenge(e mcpoauth.Endpoints) func(http.Handler) http.Handler {
	challenge := MCPBearerChallenge(e)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(&challengeWriter{ResponseWriter: w, challenge: challenge}, r)
		})
	}
}

// challengeWriter sets WWW-Authenticate when the response status is 401.
// Only the status passes through it: a body written without an explicit
// status is a 200 and goes straight to the underlying writer.
type challengeWriter struct {
	http.ResponseWriter
	challenge string
	wrote     bool
}

func (c *challengeWriter) WriteHeader(code int) {
	if !c.wrote {
		c.wrote = true
		if code == http.StatusUnauthorized && c.Header().Get("WWW-Authenticate") == "" {
			c.Header().Set("WWW-Authenticate", c.challenge)
		}
	}
	c.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (c *challengeWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// MCPOriginGuard refuses a browser-originated request from an origin that is
// not allowed (MCP Streamable HTTP: servers MUST validate Origin; an invalid
// one is 403). A request without an Origin header (every non-browser MCP
// client) passes. allowed holds exact origins such as
// "https://openctem.example"; comparison ignores the case of scheme and host.
func MCPOriginGuard(allowed []string) func(http.Handler) http.Handler {
	set := make(map[string]bool, len(allowed))
	for _, o := range allowed {
		if o = normalizeOrigin(o); o != "" && o != "*" {
			set[o] = true
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && !set[normalizeOrigin(origin)] {
				apierror.Forbidden("Origin not allowed").WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// normalizeOrigin lower-cases an origin and drops a trailing slash. A
// serialized origin has no path, so anything else is left to fail the match.
func normalizeOrigin(o string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(o)), "/")
}
