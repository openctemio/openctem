package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
