package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	infrahttp "github.com/openctemio/api/internal/infra/http"
)

// The build version is for signed-in users only: the route must sit behind the
// auth middleware it is given, not be reachable anonymously.
func TestVersionRoute_RequiresAuth(t *testing.T) {
	signedIn := false
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !signedIn {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	router := infrahttp.NewChiRouter()
	registerVersionRoute(router, auth)
	mux := router.(interface{ Handler() http.Handler }).Handler()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/version", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous GET /api/v1/version = %d, want 401", rec.Code)
	}

	signedIn = true
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/version", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("signed-in GET /api/v1/version = %d, want 200", rec.Code)
	}
}
