package middleware

import (
	"net/http"

	"github.com/openctemio/api/pkg/apierror"
)

// DefaultMaxConcurrentRequests is the default maximum number of concurrent requests.
const DefaultMaxConcurrentRequests = 1000

// ConcurrencyLimit creates a middleware that limits the number of concurrent requests
// using a semaphore pattern. When the limit is reached, new requests receive a
// 503 Service Unavailable response.
//
// A maxConcurrent value of 0 or less disables the limit.
func ConcurrencyLimit(maxConcurrent int) func(http.Handler) http.Handler {
	if maxConcurrent <= 0 {
		// No limit - pass through
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	sem := make(chan struct{}, maxConcurrent)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try to acquire a slot without blocking
			select {
			case sem <- struct{}{}:
				// Acquired slot - ensure release on completion
				defer func() { <-sem }()
				next.ServeHTTP(w, r)
			default:
				// All slots taken - server is at capacity
				apierror.ServiceUnavailable("Server at capacity, please retry later").WriteJSON(w)
			}
		})
	}
}
