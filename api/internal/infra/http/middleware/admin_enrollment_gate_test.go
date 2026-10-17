package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// enrollingSessions answers a session the console service marked "must enroll
// security keys" ("require WebAuthn" is on and the administrator lacks them).
type enrollingSessions struct {
	a      *admin.AdminUser
	enroll bool
}

func (e enrollingSessions) Authenticate(ctx context.Context, token string) (*admin.AdminUser, error) {
	a, _, err := e.AuthenticateSession(ctx, token)
	return a, err
}

func (e enrollingSessions) AuthenticateSession(_ context.Context, token string) (*admin.AdminUser, *admin.Session, error) {
	if token != "tok" {
		return nil, nil, admin.ErrSessionNotFound
	}
	return e.a, &admin.Session{AuthMethod: admin.AuthMethodPassword, MFAVerified: true, EnrollmentRequired: e.enroll}, nil
}

// A session held by "require WebAuthn" reaches only the enrollment routes;
// everything else answers FACTOR_ENROLLMENT_REQUIRED, including routes whose
// path differs only in an id.
func TestFactorEnrollmentGate(t *testing.T) {
	now := time.Now()
	a := admin.Reconstitute(shared.NewID(), "a@x.io", "A", admin.AdminRoleSuperAdmin, true,
		nil, nil, "", 0, nil, nil, "", now, nil, now)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	cases := []struct {
		method, path string
		enroll       bool
		want         int
	}{
		{http.MethodGet, "/api/v1/admin/tenants", true, http.StatusForbidden},
		{http.MethodPut, "/api/v1/admin/settings/console-mfa/", true, http.StatusForbidden},
		{http.MethodDelete, "/api/v1/admin/auth/webauthn/credentials/" + shared.NewID().String(), true, http.StatusForbidden},
		{http.MethodGet, "/api/v1/admin/auth/validate", true, http.StatusOK},
		{http.MethodGet, "/api/v1/admin/auth/factors", true, http.StatusOK},
		{http.MethodPost, "/api/v1/admin/auth/webauthn/credentials/options", true, http.StatusOK},
		{http.MethodPost, "/api/v1/admin/auth/webauthn/credentials", true, http.StatusOK},
		{http.MethodPost, "/api/v1/admin/auth/recovery-codes", true, http.StatusOK},
		{http.MethodPost, "/api/v1/admin/auth/step-up/webauthn", true, http.StatusOK},
		// Policy off or compliant: no gate.
		{http.MethodGet, "/api/v1/admin/tenants", false, http.StatusOK},
	}
	for _, c := range cases {
		m := middleware.NewAdminAuthMiddleware(enrollingSessions{a: a, enroll: c.enroll}, logger.NewNop())
		rec := httptest.NewRecorder()
		m.Authenticate(ok).ServeHTTP(rec, adminRequest(c.method, c.path, "tok"))
		if rec.Code != c.want {
			t.Fatalf("%s %s (enroll=%v): got %d want %d (%s)", c.method, c.path, c.enroll, rec.Code, c.want, rec.Body.String())
		}
		if c.want == http.StatusForbidden && !strings.Contains(rec.Body.String(), string(middleware.CodeFactorEnrollmentRequired)) {
			t.Fatalf("%s %s: want code %s, got %s", c.method, c.path, middleware.CodeFactorEnrollmentRequired, rec.Body.String())
		}
	}
}
