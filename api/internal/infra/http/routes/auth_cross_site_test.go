package routes

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The routes that run before a session exists (and set session cookies)
// refuse a write a browser sends for another site: login CSRF when the API is
// reachable from browsers directly. The IdP's own cross-site posts (SAML ACS,
// back-channel logout) are not guarded.
var preSessionAuthRoutes = []string{
	"/api/v1/auth/register",
	"/api/v1/auth/login",
	"/api/v1/auth/mfa/verify",
	"/api/v1/auth/mfa/enroll/start",
	"/api/v1/auth/mfa/enroll/confirm",
	"/api/v1/auth/token",
	"/api/v1/auth/refresh",
	"/api/v1/auth/verify-email",
	"/api/v1/auth/forgot-password",
	"/api/v1/auth/reset-password",
	"/api/v1/auth/create-first-team",
}

func postWith(mux http.Handler, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "https://api.example.com"+path, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestPreSessionAuthRoutesRefuseCrossSite(t *testing.T) {
	mux := authMux(t, config.AuthProviderLocal)
	forged := map[string]map[string]string{
		"foreign Origin":            {"Origin": "https://evil.example"},
		"opaque Origin":             {"Origin": "null"},
		"cross-site without Origin": {"Sec-Fetch-Site": "cross-site"},
	}
	for _, path := range preSessionAuthRoutes {
		for name, headers := range forged {
			t.Run(path+" "+name, func(t *testing.T) {
				rec := postWith(mux, path, headers)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("POST %s with %s = %d %s, want 403", path, name, rec.Code, rec.Body.String())
				}
			})
		}
	}
}

// The web console calls these routes from its server (no Origin): they still
// reach the handler, which answers its own validation error for `{}`.
func TestPreSessionAuthRoutesServeServerSideCalls(t *testing.T) {
	mux := authMux(t, config.AuthProviderLocal)
	for _, path := range []string{"/api/v1/auth/login", "/api/v1/auth/token"} {
		for name, headers := range map[string]map[string]string{
			"no browser headers": nil,
			"same origin":        {"Origin": "https://api.example.com", "Sec-Fetch-Site": "same-origin"},
		} {
			rec := postWith(mux, path, headers)
			if rec.Code == http.StatusForbidden || rec.Code == http.StatusNotFound {
				t.Fatalf("POST %s (%s) = %d %s, want the handler's answer", path, name, rec.Code, rec.Body.String())
			}
		}
	}
}

func TestConsoleSignInStepsRefuseCrossSite(t *testing.T) {
	router := infrahttp.NewChiRouter()
	registerAdminRoutes(router, Handlers{
		AdminAuthMiddleware: middleware.NewAdminAuthMiddleware(nil, logger.NewNop()),
		AdminConsole:        &handler.AdminConsoleHandler{},
	}, middleware.RejectCrossSiteBrowser(nil, logger.NewNop()))
	mux := router.(interface{ Handler() http.Handler }).Handler()
	for _, path := range []string{
		"/api/v1/admin/auth/session",
		"/api/v1/admin/auth/mfa",
		"/api/v1/admin/auth/logout",
		"/api/v1/admin/auth/idp/start",
		"/api/v1/admin/auth/idp/callback",
	} {
		rec := postWith(mux, path, map[string]string{"Origin": "https://evil.example"})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("POST %s from another site = %d %s, want 403", path, rec.Code, rec.Body.String())
		}
	}
}
