package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// A handler still running when the timeout fires must not share the header
// map the timeout path writes its 504 into. Before the fix this was a
// concurrent map write (a fatal error that kills the process, reproduced
// with concurrent /dashboard/overview calls). Run with -race to see the
// data race on the old code.
func TestTimeout_LateHandlerHeadersDoNotRaceTheTimeout(t *testing.T) {
	released := make(chan struct{})
	finished := make(chan struct{})
	var ctxErr error
	h := TimeoutWithLogger(20*time.Millisecond, logger.NewNop())(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(finished)
			<-r.Context().Done() // the work is told to stop
			ctxErr = r.Context().Err()
			for i := 0; i < 2000; i++ {
				w.Header().Set("Cache-Control", "private, no-store")
				w.Header().Set("X-Late", "1")
			}
			close(released)
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("late body")); err == nil {
				t.Error("a write after the timeout succeeded")
			}
		}),
	)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/slow", nil))
	<-released
	<-finished

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", rec.Code)
	}
	if rec.Header().Get("X-Late") != "" {
		t.Fatal("a header set after the timeout reached the response")
	}
	if rec.Body.String() == "late body" {
		t.Fatal("the late body reached the response")
	}
	if ctxErr != context.DeadlineExceeded {
		t.Fatalf("handler context error = %v, want deadline exceeded", ctxErr)
	}
}

// Headers set before the handler (outer middlewares) and by the handler both
// reach a normal response; a header the handler deletes is gone.
func TestTimeout_HandlerHeadersReachTheResponse(t *testing.T) {
	h := TimeoutWithLogger(5*time.Second, logger.NewNop())(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if w.Header().Get("X-Request-ID") != "rid-1" {
				t.Error("handler does not see the outer middleware's header")
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Del("X-Drop")
			_, _ = w.Write([]byte("{}"))
		}),
	)
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "rid-1")
	rec.Header().Set("X-Drop", "x")
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ok", nil))
	if rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("X-Request-ID") != "rid-1" {
		t.Fatalf("headers = %v", rec.Header())
	}
	if rec.Header().Get("X-Drop") != "" {
		t.Fatal("a header the handler deleted was sent")
	}
}
