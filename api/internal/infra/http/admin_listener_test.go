package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// With the console on its own listener, each listener serves only its own
// plane: the public one answers 404 for /api/v1/admin, the admin one answers
// 404 for every tenant, sensor or public route (the health probe excepted).
func TestAdminListenerPlaneSplit(t *testing.T) {
	routes := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	public, adminH := publicOnly(routes), adminOnly(routes)
	cases := []struct {
		path        string
		public, adm int
	}{
		{"/api/v1/admin", http.StatusNotFound, http.StatusNoContent},
		{"/api/v1/admin/auth/session", http.StatusNotFound, http.StatusNoContent},
		{"/api/v1/admin/tenants/x/users", http.StatusNotFound, http.StatusNoContent},
		{"/api/v1/findings", http.StatusNoContent, http.StatusNotFound},
		{"/api/v1/administrators", http.StatusNoContent, http.StatusNotFound},
		{"/api/v2/sensor/hello", http.StatusNoContent, http.StatusNotFound},
		{"/scim/v2/Users", http.StatusNoContent, http.StatusNotFound},
		{"/metrics", http.StatusNoContent, http.StatusNotFound},
		{"/health", http.StatusNoContent, http.StatusNoContent},
		// Readings of the path the router cleans: the console stays on its
		// listener, and nothing escapes it.
		{"/api/v1//admin/tenants", http.StatusNotFound, http.StatusNoContent},
		{"/api/v1/./admin/tenants", http.StatusNotFound, http.StatusNoContent},
		{"/api/v1/x/../admin/tenants", http.StatusNotFound, http.StatusNoContent},
		{"/api/v1/admin/", http.StatusNotFound, http.StatusNoContent},
		{"/api/v1/%61dmin/tenants", http.StatusNotFound, http.StatusNoContent},
		{"/api/v1%2Fadmin/tenants", http.StatusNotFound, http.StatusNotFound},
		{"/api/v1/admin/../findings", http.StatusNoContent, http.StatusNotFound},
		{"/api/v1/admin/x/../../findings", http.StatusNoContent, http.StatusNotFound},
		{"/api/v1/admin/..%2f..%2ffindings", http.StatusNotFound, http.StatusNotFound},
		{"/api/v1/admin/%2e%2e/findings", http.StatusNotFound, http.StatusNotFound},
	}
	for _, tc := range cases {
		for _, h := range []struct {
			name string
			h    http.Handler
			want int
		}{{"public", public, tc.public}, {"admin", adminH, tc.adm}} {
			rec := httptest.NewRecorder()
			h.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != h.want {
				t.Errorf("%s listener %s: %d, want %d", h.name, tc.path, rec.Code, h.want)
			}
		}
	}
}

// OPENCTEM_PLANE: the main listener of an admin-plane process serves only
// the console API and the health probe; a tenant-plane process never serves
// the console API; all serves both (the console listener aside).
func TestMainListenerPlane(t *testing.T) {
	for _, tc := range []struct {
		plane                   string
		console, tenant, health int
	}{
		{config.PlaneAll, http.StatusNoContent, http.StatusNoContent, http.StatusNoContent},
		{config.PlaneTenant, http.StatusNotFound, http.StatusNoContent, http.StatusNoContent},
		{config.PlaneAdmin, http.StatusNoContent, http.StatusNotFound, http.StatusNoContent},
	} {
		cfg := &config.Config{}
		cfg.AdminPlane.Plane = tc.plane
		s := NewServer(cfg, logger.NewNop())
		t.Cleanup(func() {
			for _, f := range s.cleanupFuncs {
				f()
			}
		})
		s.httpServer.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
		s.applyPlane()
		for path, want := range map[string]int{
			"/api/v1/admin/tenants":     tc.console,
			"/api/v1//admin/tenants":    tc.console,
			"/api/v1/findings":          tc.tenant,
			"/api/v1/admin/../findings": tc.tenant,
			"/api/v2/sensor/hello":      tc.tenant,
			"/scim/v2/Users":            tc.tenant,
			"/health":                   tc.health,
		} {
			rec := httptest.NewRecorder()
			s.httpServer.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != want {
				t.Errorf("plane %s %s: %d, want %d", tc.plane, path, rec.Code, want)
			}
		}
	}
}
