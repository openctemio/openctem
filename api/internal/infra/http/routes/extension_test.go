package routes

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/extensionhost"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	ext "github.com/openctemio/openctem/api/pkg/extension"
)

type fakeGrants struct {
	on  map[string]bool // tenant|key
	err error
}

func (f fakeGrants) RequireAddon(_ context.Context, tenantID shared.ID, key limits.GrantKey) error {
	if f.err != nil {
		return f.err
	}
	if f.on[tenantID.String()+"|"+string(key)] {
		return nil
	}
	return &limits.ErrGrantRequired{Key: key}
}

func serve(h http.Handler, tenant shared.ID) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/custom", nil)
	if !tenant.IsZero() {
		req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String()))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// The grant gate refuses an organization without the grant (and on a
// provider error), and the handler sees the caller of the credential only.
func TestExtensionRouteGrantAndCaller(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	var seen ext.Caller
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := ext.CallerFrom(r.Context())
		if !ok {
			t.Error("no caller in an extension handler")
		}
		seen = c
		w.WriteHeader(http.StatusNoContent)
	})
	g := fakeGrants{on: map[string]bool{a.String() + "|custom": true}}
	h := requireGrant(g, "custom")(withCaller(inner))

	if w := serve(h, a); w.Code != http.StatusNoContent || seen.TenantID != a {
		t.Fatalf("granted organization: %d, caller %v", w.Code, seen.TenantID)
	}
	w := serve(h, b)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), limits.CodeAddonNotLicensed) {
		t.Fatalf("organization without the grant: %d %s", w.Code, w.Body)
	}
	if w := serve(h, shared.ID{}); w.Code != http.StatusUnauthorized {
		t.Fatalf("no organization: %d", w.Code)
	}
	failing := requireGrant(fakeGrants{err: errors.New("provider down")}, "custom")(withCaller(inner))
	if w := serve(failing, a); w.Code != http.StatusForbidden {
		t.Fatalf("provider error must refuse: %d", w.Code)
	}
	expired := requireGrant(fakeGrants{err: &limits.ErrGrantRequired{Key: "custom", Expired: true}}, "custom")(withCaller(inner))
	if w := serve(expired, a); !strings.Contains(w.Body.String(), limits.CodeAddonLicenseExpired) {
		t.Fatalf("expired grant code: %s", w.Body)
	}
}

func TestExtensionRoutesNeverReplaceCoreRoutes(t *testing.T) {
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	r := infrahttp.NewChiRouter()
	r.GET("/api/v1/assets", h)
	defer func() {
		if p := recover(); p == nil || !strings.Contains(p.(string), "replaces a core route") {
			t.Fatalf("panic = %v", p)
		}
	}()
	registerExtensionRoutes(r, []extensionhost.Route{{Method: http.MethodGet, Path: "/assets", Permission: "assets:read", Grant: "x", Handler: h}}, fakeGrants{}, nil)
}

func TestExtensionRoutesNeedAGrantChecker(t *testing.T) {
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	defer func() {
		if recover() == nil {
			t.Fatal("mounted grant-gated routes without a grant checker")
		}
	}()
	registerExtensionRoutes(infrahttp.NewChiRouter(), []extensionhost.Route{{Method: http.MethodGet, Path: "/custom", Permission: "settings:read", Grant: "x", Handler: h}}, nil, nil)
}

// A mounted extension route sits behind the permission check: a member
// without the permission never reaches the grant check or the handler.
func TestExtensionRouteNeedsThePermission(t *testing.T) {
	reached := false
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })
	r := infrahttp.NewChiRouter()
	registerExtensionRoutes(r, []extensionhost.Route{{Method: http.MethodGet, Path: "/custom", Permission: "settings:write", Grant: "x", Handler: h}},
		fakeGrants{on: map[string]bool{}}, nil)
	tenant := shared.NewID()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/custom", nil)
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
	ctx = context.WithValue(ctx, middleware.FetchedPermissionsKey, []string{"settings:read"})
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, req.WithContext(ctx))
	if reached || w.Code != http.StatusForbidden {
		t.Fatalf("reached=%v code=%d", reached, w.Code)
	}
}
