package routes

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The public error report is rate limited per client address: a flood from
// one address is refused (429) once its burst is spent, without credentials.
func TestClientErrorRouteIsRateLimitedPerAddress(t *testing.T) {
	log := logger.NewNop()
	router := infrahttp.NewChiRouter()
	registerClientErrorRoute(router, handler.NewClientErrorHandler(log), log)
	mux := router.(interface{ Handler() http.Handler }).Handler()

	codes := map[int]int{}
	for i := 0; i < clientErrorPerIPBurst+5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/client-errors", strings.NewReader(`{"kind":"render"}`))
		req.RemoteAddr = "198.51.100.7:1234"
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		codes[rec.Code]++
	}
	if codes[http.StatusNoContent] != clientErrorPerIPBurst || codes[http.StatusTooManyRequests] != 5 {
		t.Fatalf("answers = %v, want %d x 204 then 5 x 429", codes, clientErrorPerIPBurst)
	}

	// Another address still gets through.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/client-errors", strings.NewReader(`{"kind":"render"}`))
	req.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("other address: status = %d, want 204", rec.Code)
	}
}
