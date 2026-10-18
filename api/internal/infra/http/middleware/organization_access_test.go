package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scimtoken"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type mapGate map[shared.ID]error

func (g mapGate) CheckAccess(_ context.Context, id shared.ID) error {
	if err, ok := g[id]; ok {
		return err
	}
	return nil
}

func TestRequireActiveOrganization(t *testing.T) {
	active, suspended, gone, broken := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	gate := mapGate{suspended: tenantdom.ErrOrganizationSuspended, gone: shared.ErrNotFound, broken: errors.New("db down")}
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true; w.WriteHeader(http.StatusOK) })
	mw := RequireActiveOrganization(gate, nil)(next)

	for _, c := range []struct {
		name   string
		tenant string
		code   int
		reach  bool
	}{
		{"no organization passes", "", http.StatusOK, true},
		{"active passes", active.String(), http.StatusOK, true},
		{"suspended refused", suspended.String(), http.StatusForbidden, false},
		{"missing organization refused", gone.String(), http.StatusUnauthorized, false},
		{"unreadable status refused (fail closed)", broken.String(), http.StatusServiceUnavailable, false},
		{"malformed organization refused", "not-an-id", http.StatusUnauthorized, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			reached = false
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if c.tenant != "" {
				req = req.WithContext(context.WithValue(req.Context(), TenantIDKey, c.tenant))
			}
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, req)
			if rec.Code != c.code || reached != c.reach {
				t.Fatalf("code=%d reached=%v, want %d %v (%s)", rec.Code, reached, c.code, c.reach, rec.Body.String())
			}
			if c.code == http.StatusForbidden && (!strings.Contains(rec.Body.String(), tenantdom.CodeOrganizationSuspended) ||
				!strings.Contains(rec.Body.String(), "contact support")) {
				t.Fatalf("body = %s", rec.Body.String())
			}
		})
	}
}

func TestRequireActiveOrganizationParam(t *testing.T) {
	suspended := shared.NewID()
	mw := RequireActiveOrganizationParam(mapGate{suspended: tenantdom.ErrOrganizationSuspended},
		func(*http.Request) (shared.ID, bool) { return suspended, true }, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d", rec.Code)
	}
}

type scimAuthFunc func(string) (*scimtoken.ScimToken, error)

func (f scimAuthFunc) Authenticate(_ context.Context, p string) (*scimtoken.ScimToken, error) {
	return f(p)
}

// The SCIM client is told the organization is suspended (403), not that its
// token is bad.
func TestSCIMAuth_SuspendedOrganization(t *testing.T) {
	mw := SCIMAuth(scimAuthFunc(func(string) (*scimtoken.ScimToken, error) {
		return nil, tenantdom.ErrOrganizationSuspended
	}))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer oct_scim_x")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "suspended") {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}
