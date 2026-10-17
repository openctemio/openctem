package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Every console response is no-store: the sign-in and validate responses
// carry the session's CSRF token.
func TestConsoleNoStore(t *testing.T) {
	rec := httptest.NewRecorder()
	consoleNoStore(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/admin/auth/login", nil))
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control %q, want no-store", got)
	}
}
