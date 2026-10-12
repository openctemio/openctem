package routes

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
)

// The invitation token moved from the URL into the body (RFC-041 §3.2 P4).
// The body routes are mounted, and the old /{token} routes still answer, with
// the RFC 9745/8594 deprecation headers on every response, errors included.
func TestInvitationRoutes_BodyRoutesAndDeprecatedAliases(t *testing.T) {
	router := infrahttp.NewChiRouter()
	noAuth := func(next http.Handler) http.Handler { return next }
	registerTenantRoutes(router, &handler.TenantHandler{}, noAuth, nil, routeTenantRepo{}, routeMembers{}, &handler.LocalAuthHandler{}, nil)
	mux := router.(interface{ Handler() http.Handler }).Handler()

	// A malformed token is refused by the handler before any service call, so
	// a 400 proves the request reached the right handler.
	serve := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec
	}

	for _, path := range []string{
		"/api/v1/invitations/lookup",
		"/api/v1/invitations/accept",
		"/api/v1/invitations/decline",
		"/api/v1/invitations/accept-with-refresh",
	} {
		rec := serve(http.MethodPost, path, `{"token":"short"}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST %s = %d, want 400 from its handler", path, rec.Code)
		}
		if rec.Header().Get("Deprecation") != "" {
			t.Errorf("POST %s must not be deprecated", path)
		}
	}

	for _, tc := range []struct{ method, path, successor string }{
		{http.MethodGet, "/api/v1/invitations/short/preview", "/api/v1/invitations/lookup"},
		{http.MethodGet, "/api/v1/invitations/short", "/api/v1/invitations/lookup"},
		{http.MethodPost, "/api/v1/invitations/short/accept", "/api/v1/invitations/accept"},
		{http.MethodPost, "/api/v1/invitations/short/decline", "/api/v1/invitations/decline"},
		{http.MethodPost, "/api/v1/invitations/short/accept-with-refresh", "/api/v1/invitations/accept-with-refresh"},
	} {
		rec := serve(tc.method, tc.path, "")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s %s = %d, want 400 from its handler", tc.method, tc.path, rec.Code)
		}
		h := rec.Header()
		if !strings.HasPrefix(h.Get("Deprecation"), "@") || h.Get("Sunset") == "" {
			t.Errorf("%s %s: missing deprecation headers: %v", tc.method, tc.path, h)
		}
		if want := "<" + tc.successor + `>; rel="successor-version"`; h.Get("Link") != want {
			t.Errorf("%s %s: Link = %q, want %q", tc.method, tc.path, h.Get("Link"), want)
		}
	}
}
