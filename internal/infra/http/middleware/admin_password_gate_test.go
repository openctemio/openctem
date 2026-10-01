package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// detailedSessions also returns the session, like the console service.
type detailedSessions struct {
	a      *admin.AdminUser
	method string
}

func (d detailedSessions) Authenticate(ctx context.Context, token string) (*admin.AdminUser, error) {
	a, _, err := d.AuthenticateSession(ctx, token)
	return a, err
}

func (d detailedSessions) AuthenticateSession(_ context.Context, token string) (*admin.AdminUser, *admin.Session, error) {
	if token != "tok" {
		return nil, nil, admin.ErrSessionNotFound
	}
	return d.a, &admin.Session{AuthMethod: d.method}, nil
}

func TestTemporaryPasswordGate(t *testing.T) {
	now := time.Now()
	a := admin.Reconstitute(shared.NewID(), "a@x.io", "A", admin.AdminRoleSuperAdmin, true,
		nil, nil, "", 0, nil, nil, "", now, nil, now).
		WithSignInState(admin.SignInState{PasswordChangeRequired: true})
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	cases := []struct {
		method, path, auth string
		want               int
	}{
		{http.MethodGet, "/api/v1/admin/tenants", admin.AuthMethodPassword, http.StatusForbidden},
		{http.MethodPost, "/api/v1/admin/administrators", admin.AuthMethodPassword, http.StatusForbidden},
		{http.MethodGet, "/api/v1/admin/auth/validate", admin.AuthMethodPassword, http.StatusOK},
		{http.MethodPost, "/api/v1/admin/auth/password", admin.AuthMethodPassword, http.StatusOK},
		// An IdP session did not use the temporary password.
		{http.MethodGet, "/api/v1/admin/tenants", admin.AuthMethodIdP, http.StatusOK},
	}
	for _, c := range cases {
		m := middleware.NewAdminAuthMiddleware(detailedSessions{a: a, method: c.auth}, logger.NewNop())
		rec := httptest.NewRecorder()
		m.Authenticate(ok).ServeHTTP(rec, adminRequest(c.method, c.path, "tok"))
		if rec.Code != c.want {
			t.Fatalf("%s %s (%s): got %d want %d (%s)", c.method, c.path, c.auth, rec.Code, c.want, rec.Body.String())
		}
	}
}
