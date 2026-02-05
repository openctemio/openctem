package middleware

import (
	"net/http"

	"github.com/openctemio/api/pkg/apierror"
)

// DefaultMaxBodySize is the default maximum request body size (1MB).
const DefaultMaxBodySize = 1 << 20 // 1 MB

// BodyLimit limits the maximum size of request bodies.
// If maxBytes is 0, DefaultMaxBodySize is used.
func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBodySize
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip for methods without body
			if r.Method == http.MethodGet || r.Method == http.MethodHead ||
				r.Method == http.MethodOptions || r.Method == http.MethodTrace {
				next.ServeHTTP(w, r)
				return
			}

			// Wrap the body with a size limiter
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

			next.ServeHTTP(w, r)
		})
	}
}

// BodyLimitHandler is an error handler for body limit exceeded.
// Use this in your error handling middleware to catch http.MaxBytesError.
func HandleBodyLimitError(w http.ResponseWriter, _ *http.Request) {
	apierror.New(http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE",
		"Request body too large").WriteJSON(w)
}
