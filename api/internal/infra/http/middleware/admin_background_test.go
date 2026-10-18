package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// backgroundRecorder records whether each authentication saw a request marked
// as background (not activity for the idle timeout).
type backgroundRecorder struct {
	fakeSessions
	background []bool
}

func (b *backgroundRecorder) Authenticate(ctx context.Context, token string) (*admin.AdminUser, error) {
	b.background = append(b.background, admin.IsBackgroundRequest(ctx))
	return b.fakeSessions.Authenticate(ctx, token)
}

// A console page refresh marked X-Admin-Background: 1 is authenticated as
// usual but not counted as activity. The marker is accepted on reads only: a
// write is always the administrator's own action.
func TestAdminBackgroundHeaderMarksReadsOnly(t *testing.T) {
	rec := &backgroundRecorder{fakeSessions: *newFakeSessions()}
	rec.add("key-super", admin.AdminRoleSuperAdmin)
	m := middleware.NewAdminAuthMiddleware(rec, logger.NewNop())
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := m.Authenticate(ok)

	cases := []struct {
		method string
		header string
		want   bool
	}{
		{http.MethodGet, "1", true},
		{http.MethodGet, "", false},
		{http.MethodGet, "true", false},
		{http.MethodPost, "1", false},
		{http.MethodDelete, "1", false},
	}
	for _, c := range cases {
		rec.background = nil
		req := adminRequest(c.method, "/api/v1/admin/overview", "key-super")
		if c.header != "" {
			req.Header.Set(middleware.AdminBackgroundHeader, c.header)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s with header %q: status %d, want 200 (the marker never refuses)", c.method, c.header, w.Code)
		}
		if len(rec.background) != 1 || rec.background[0] != c.want {
			t.Errorf("%s with header %q: background = %v, want %v", c.method, c.header, rec.background, c.want)
		}
	}
}
