package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

// Timeout runs the handler on its own goroutine, so the Recovery middleware —
// which wraps it from the outside, on the parent goroutine — cannot see a panic
// raised there. Go kills the whole program on an unrecovered panic in ANY
// goroutine, so before the fix one panic on any route took the process down and
// dropped every in-flight request.
//
// Note how this test fails if the recover is removed: the panic escapes and the
// TEST BINARY dies, which is exactly the production failure mode.
func TestTimeoutWithLogger_RecoversHandlerPanic(t *testing.T) {
	h := TimeoutWithLogger(5*time.Second, logger.NewNop())(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("boom from handler")
		}),
	)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panics", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 after a recovered handler panic", rec.Code)
	}
}

// A nil logger must not itself panic inside the recover path (the Timeout
// back-compat shim passes nil).
func TestTimeout_NilLoggerStillRecovers(t *testing.T) {
	h := Timeout(5 * time.Second)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom with nil logger")
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panics", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// The normal path must be untouched: a handler that writes normally still wins.
func TestTimeoutWithLogger_HappyPathUnaffected(t *testing.T) {
	h := TimeoutWithLogger(5*time.Second, logger.NewNop())(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
			_, _ = w.Write([]byte("ok"))
		}),
	)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/fine", nil))

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418 (handler's own write)", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "ok")
	}
}
