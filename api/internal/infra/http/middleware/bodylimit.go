package middleware

import (
	"io"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/apierror"
)

// DefaultMaxBodySize is the default maximum request body size (10MB).
const DefaultMaxBodySize = 10 << 20 // 10 MB

// IngestMaxBodySize is the maximum request body size for ingest endpoints (50MB).
const IngestMaxBodySize = 50 << 20 // 50 MB

// limitedBody is the body wrapper BodyLimit installs. It remembers the
// original (unlimited) body so a later, route-specific BodyLimit can REPLACE
// the limit instead of stacking a second MaxBytesReader on top of the first.
//
// Without this, the global 10 MB limit installed in server.go wrapped every
// body first, so the 50 MB limit the ingest routes declare could never take
// effect: a nested MaxBytesReader(50MB) over MaxBytesReader(10MB) still stops
// at 10 MB.
//
// The limit can only be replaced while nothing has been read yet, so a
// handler can never "reset" a limit on a partially consumed body.
type limitedBody struct {
	limited  io.ReadCloser // http.MaxBytesReader over orig
	orig     io.ReadCloser
	consumed bool
}

func (b *limitedBody) Read(p []byte) (int, error) {
	b.consumed = true
	return b.limited.Read(p)
}

func (b *limitedBody) Close() error { return b.limited.Close() }

// BodyLimit limits the maximum size of request bodies.
// If maxBytes is 0, DefaultMaxBodySize is used.
//
// When an outer BodyLimit already wrapped the (still unread) body, this one
// replaces that limit rather than nesting under it, so a route-level
// BodyLimit is authoritative for its route while the global limit still
// applies everywhere no route-level limit is declared.
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

			orig := r.Body
			if lb, ok := r.Body.(*limitedBody); ok && !lb.consumed {
				orig = lb.orig
			}
			if orig != nil {
				r.Body = &limitedBody{
					limited: http.MaxBytesReader(w, orig, maxBytes),
					orig:    orig,
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// HandleBodyLimitError is an error handler for body limit exceeded.
// Use this in your error handling middleware to catch http.MaxBytesError.
func HandleBodyLimitError(w http.ResponseWriter, _ *http.Request) {
	apierror.New(http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE",
		"Request body too large").WriteJSON(w)
}
