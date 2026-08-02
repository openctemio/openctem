package middleware

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/logger"
)

// Timeout adds a timeout to each request context.
// If the handler takes longer than the timeout, the request is canceled.
//
// Prefer TimeoutWithLogger — this variant cannot log a recovered panic.
func Timeout(timeout time.Duration) func(http.Handler) http.Handler {
	return TimeoutWithLogger(timeout, nil)
}

// TimeoutWithLogger is Timeout plus a logger for panics recovered inside the
// handler goroutine.
//
// This middleware runs the handler on its OWN goroutine, so the Recovery
// middleware — which sits further out, i.e. on the parent goroutine — cannot see
// a panic raised here. Go terminates the whole program on an unrecovered panic in
// ANY goroutine, and net/http's per-connection recover does not apply to a
// goroutine we started ourselves. Without the recover below, a single panic on
// any route killed the process and dropped every in-flight request. The recover
// must therefore live INSIDE the goroutine; it mirrors RecoveryWithConfig's
// behavior (log + 500) rather than re-panicking onto the parent.
func TimeoutWithLogger(timeout time.Duration, log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			// Create a channel to signal completion
			done := make(chan struct{})

			// Use a custom response writer to prevent writing after timeout
			tw := &timeoutWriter{
				ResponseWriter: w,
				done:           done,
			}

			go func() {
				// close(done) is its own defer so the recover below can `return`
				// after writing the 500 without skipping it (defers run LIFO).
				defer close(done)
				defer func() {
					if rec := recover(); rec != nil {
						if log != nil {
							log.Error("panic recovered in request handler",
								"error", rec,
								"stack", string(debug.Stack()),
								"request_id", GetRequestID(r.Context()),
								// Sanitized: the path is attacker-controlled and the text
								// handler emits plain lines, so a raw CR/LF here would let a
								// caller forge log entries (CodeQL go/log-injection).
								"path", logger.SanitizeValue(r.URL.Path),
							)
						}
						// Report a 500 unless something was already written, or
						// the timeout path has taken ownership of the response.
						tw.mu.Lock()
						handled := tw.written || tw.timedOut
						tw.written = true
						tw.mu.Unlock()
						if !handled {
							http.Error(tw.ResponseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
							return
						}
					}
				}()
				next.ServeHTTP(tw, r.WithContext(ctx))
			}()

			select {
			case <-done:
				// Request completed normally
				return
			case <-ctx.Done():
				// Timeout occurred
				tw.mu.Lock()
				defer tw.mu.Unlock()

				if !tw.written {
					tw.timedOut = true
					apierror.New(http.StatusGatewayTimeout, "TIMEOUT", "Request timeout").WriteJSON(w)
				}
			}
		})
	}
}

// timeoutWriter wraps http.ResponseWriter to handle timeout scenarios.
type timeoutWriter struct {
	http.ResponseWriter
	done     chan struct{}
	mu       sync.Mutex
	written  bool
	timedOut bool
}

// Write implements http.ResponseWriter. Same CodeQL
// go/reflected-xss false-positive note as the other middleware
// wrappers: transparent passthrough that only gates writes on the
// timeout state. Output escaping remains the handler's
// responsibility. Dismiss as wrapper-level false-positive.
func (tw *timeoutWriter) Write(b []byte) (int, error) {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	if tw.timedOut {
		return 0, context.DeadlineExceeded
	}

	tw.written = true
	return tw.ResponseWriter.Write(b)
}

func (tw *timeoutWriter) WriteHeader(code int) {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	if tw.timedOut {
		return
	}

	tw.written = true
	tw.ResponseWriter.WriteHeader(code)
}

// Hijack implements http.Hijacker interface to support WebSocket connections.
func (tw *timeoutWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := tw.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("timeoutWriter: underlying ResponseWriter does not implement http.Hijacker")
}
