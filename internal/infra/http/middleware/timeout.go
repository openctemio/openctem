package middleware

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/openctemio/api/pkg/apierror"
)

// Timeout adds a timeout to each request context.
// If the handler takes longer than the timeout, the request is canceled.
func Timeout(timeout time.Duration) func(http.Handler) http.Handler {
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
				next.ServeHTTP(tw, r.WithContext(ctx))
				close(done)
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
