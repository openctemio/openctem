// Package middleware provides HTTP middleware for the API server.
// This file implements bearer-token gating for the Prometheus /metrics endpoint.
package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/logger"
)

// MetricsAuth gates the Prometheus /metrics endpoint.
//
// Behavior:
//   - public == true: pass through (legacy open endpoint). Use only when the
//     endpoint is already firewalled to an internal scrape network.
//   - public == false && token != "": require an Authorization: Bearer <token>
//     header whose value matches token (constant-time). Missing/mismatched →
//     404 (the endpoint is not advertised to unauthenticated callers).
//   - public == false && token == "": fail closed — the endpoint is disabled
//     and always returns 404.
//
// It never touches /health or /ready — it is only wired onto /metrics.
func MetricsAuth(public bool, token string, log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if public {
				next.ServeHTTP(w, r)
				return
			}

			// Fail closed when no token is configured: metrics disabled.
			if token == "" {
				if log != nil {
					log.Debug("metrics endpoint disabled: METRICS_TOKEN unset and METRICS_PUBLIC=false")
				}
				apierror.NotFound("resource").WriteJSON(w)
				return
			}

			provided := extractBearerToken(r)
			// Constant-time compare to avoid leaking the token via timing.
			if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
				if log != nil {
					log.Debug("metrics auth: rejected unauthenticated scrape", "ip", extractIP(r))
				}
				// 404 rather than 401 so the endpoint is not advertised.
				apierror.NotFound("resource").WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractBearerToken returns the bearer token from the Authorization header,
// or "" if absent. Also accepts the raw token in X-Metrics-Token for scrapers
// that cannot set an Authorization header.
func extractBearerToken(r *http.Request) string {
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	return strings.TrimSpace(r.Header.Get("X-Metrics-Token"))
}
