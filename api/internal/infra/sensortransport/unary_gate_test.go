package sensortransport

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/v3/sensorv3connect"
)

// The HTTPS binding bounds the unary calls in flight before authentication
// runs (authentication costs a database lookup, and the binding is reachable
// without credentials). A control stream takes no unary slot.
func TestHTTPSBindingBoundsUnaryInFlight(t *testing.T) {
	s := NewServer(Config{MaxUnaryInFlight: 1}, nil, logger.NewNop())
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	var authCalls atomic.Int32
	auth := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCalls.Add(1)
			if strings.HasSuffix(r.URL.Path, sensorv3connect.SensorServiceHelloProcedure) {
				entered <- struct{}{}
				<-release
			}
			w.WriteHeader(http.StatusUnauthorized)
		})
	}
	h := s.HTTPSHandler(auth)
	post := func(proc string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, PathPrefix+proc, strings.NewReader("{}")))
		return rec
	}

	done := make(chan *httptest.ResponseRecorder)
	go func() { done <- post(sensorv3connect.SensorServiceHelloProcedure) }()
	<-entered // the first call holds the only slot

	if rec := post(sensorv3connect.SensorServiceHeartbeatProcedure); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("second unary call: %d, want 503", rec.Code)
	}
	if authCalls.Load() != 1 {
		t.Fatalf("authentication ran %d times, want 1 (the refused call must not reach it)", authCalls.Load())
	}
	if rec := post(sensorv3connect.SensorServiceSubscribeProcedure); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a control stream must not need a unary slot: %d", rec.Code)
	}

	close(release)
	if rec := <-done; rec.Code != http.StatusUnauthorized {
		t.Fatalf("first call: %d", rec.Code)
	}
	if rec := post(sensorv3connect.SensorServiceHeartbeatProcedure); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after release: %d, want the call admitted", rec.Code)
	}
}
