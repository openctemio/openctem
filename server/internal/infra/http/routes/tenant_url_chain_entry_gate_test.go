package routes

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The /api/v1/tenants/{tenant} routes take the organization from the URL and
// accept a token minted for another organization (or a tenantless sign-in
// token). Token issuance never evaluated the URL organization's requirements,
// so one entry check on the chain applies them on every request (research/310
// X-02).

type fakeEntry struct {
	err   error
	calls int
}

func (f *fakeEntry) CheckEntry(_ context.Context, _, _, _ string) error {
	f.calls++
	return f.err
}

func entryGateFixture(t *testing.T, claims *jwt.Claims, checker middleware.EntryChecker) http.Handler {
	t.Helper()
	tn, err := tenant.NewTenant("Acme", "acme", shared.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	u, err := userdom.NewProvisionedLocalUser("admin@acme.test", "Admin")
	if err != nil {
		t.Fatal(err)
	}
	m, err := tenant.NewMembership(u.ID(), tn.ID(), tenant.RoleAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	claims.UserID = u.ID().String()
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), middleware.LocalUserKey, u)
			ctx = context.WithValue(ctx, middleware.LocalClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	prev := entryGateMiddleware
	entryGateMiddleware = middleware.NewEntryGate(checker, time.Minute, logger.NewNop()).Enforce
	t.Cleanup(func() { entryGateMiddleware = prev })

	router := infrahttp.NewChiRouter()
	registerTenantRoutes(router, &handler.TenantHandler{}, auth, nil, routeTenantRepo{t: tn}, routeMembers{m: m}, nil, nil)
	return router.(interface{ Handler() http.Handler }).Handler()
}

func entryBody(mux http.Handler, method, path string) (code int, body string) {
	defer func() {
		if recover() != nil {
			code = reachedHandler
		}
	}()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec.Code, rec.Body.String()
}

var entryRoutes = []struct{ method, path string }{
	{http.MethodGet, "/api/v1/tenants/acme/members"},
	{http.MethodPost, "/api/v1/tenants/acme/invitations"},
	{http.MethodPatch, "/api/v1/tenants/acme/settings/security"},
	{http.MethodPost, "/api/v1/tenants/acme/users"},
}

func TestURLChain_AppliesURLOrgTwoFactorRequirement(t *testing.T) {
	refusal := &auth.EntryRefusal{Status: http.StatusForbidden, Code: apierror.CodeMFAEnrollmentRequired, Message: "two-factor required"}
	mux := entryGateFixture(t, &jwt.Claims{TenantID: shared.NewID().String(), SessionID: shared.NewID().String(), Role: "admin", AuthMethod: "password"}, &fakeEntry{err: refusal})
	for _, rt := range entryRoutes {
		code, body := entryBody(mux, rt.method, rt.path)
		if code != http.StatusForbidden || !strings.Contains(body, "MFA_ENROLLMENT_REQUIRED") {
			t.Errorf("%s %s: got %d %s, want 403 MFA_ENROLLMENT_REQUIRED", rt.method, rt.path, code, body)
		}
	}
}

func TestURLChain_RefusesTenantlessSocialToken(t *testing.T) {
	f := &fakeEntry{}
	mux := entryGateFixture(t, &jwt.Claims{SessionID: shared.NewID().String(), AuthMethod: "sso"}, f)
	for _, rt := range entryRoutes {
		code, body := entryBody(mux, rt.method, rt.path)
		if code != http.StatusForbidden || !strings.Contains(body, "ACCOUNT_TOKEN_NOT_ALLOWED") {
			t.Errorf("%s %s: got %d %s, want 403 ACCOUNT_TOKEN_NOT_ALLOWED", rt.method, rt.path, code, body)
		}
	}
}

func TestURLChain_UndecidableEntryFailsClosed(t *testing.T) {
	mux := entryGateFixture(t, &jwt.Claims{TenantID: shared.NewID().String(), SessionID: shared.NewID().String(), AuthMethod: "password"}, &fakeEntry{err: errors.New("db down")})
	if code, _ := entryBody(mux, http.MethodGet, "/api/v1/tenants/acme/members"); code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", code)
	}
}

func TestURLChain_EntrySatisfiedReachesHandlerAndIsCached(t *testing.T) {
	f := &fakeEntry{}
	mux := entryGateFixture(t, &jwt.Claims{TenantID: shared.NewID().String(), SessionID: shared.NewID().String(), AuthMethod: "password"}, f)
	for i := 0; i < 2; i++ {
		if code, _ := entryBody(mux, http.MethodGet, "/api/v1/tenants/acme/members"); code == http.StatusForbidden {
			t.Fatalf("request %d refused", i)
		}
	}
	if f.calls != 1 {
		t.Fatalf("entry check ran %d times for two requests of one session and organization, want 1", f.calls)
	}
}
