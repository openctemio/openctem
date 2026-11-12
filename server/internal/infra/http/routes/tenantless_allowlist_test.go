package routes

// Account-only sessions: docs/architecture/tenantless-account-space.md.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/authzdoc"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/http/routes/plane"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// jwtPlanes are the planes whose routes a user's session token can reach.
var jwtPlanes = map[plane.Plane]bool{plane.User: true, plane.Self: true, plane.Auth: true}

// patternKey writes a route pattern with every parameter as {}, so the
// allow-list and the parsed routes compare whatever the parameter names.
func patternKey(method, p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		if strings.HasPrefix(s, "{") || s == "*" {
			segs[i] = "{}"
		}
	}
	return method + " /" + strings.Join(segs, "/")
}

// concretePath fills every parameter of a pattern with a value.
func concretePath(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		if strings.HasPrefix(s, "{") || s == "*" {
			segs[i] = "0b1e2c3d-0000-4000-8000-000000000001"
		}
	}
	return "/" + strings.Join(segs, "/")
}

func parsedJWTRoutes(t *testing.T) []authzdoc.Route {
	t.Helper()
	all, err := authzdoc.ParseRoutes("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	var out []authzdoc.Route
	for _, r := range all {
		if rule, ok := plane.Of(r.Path); ok && jwtPlanes[rule.Plane] {
			out = append(out, r)
		}
	}
	if len(out) < 500 {
		t.Fatalf("control: only %d user-plane routes parsed, the walk proves nothing", len(out))
	}
	return out
}

// The allow-list is exactly the routes it names: each entry is a registered
// route, and no other registered route matches it (a prefix or a parameter
// that swallows a tenant route would show up here).
func TestTenantlessAllowList_MatchesOnlyItsRoutes(t *testing.T) {
	routes := parsedJWTRoutes(t)
	want := map[string]bool{}
	for _, e := range middleware.TenantlessRoutes() {
		m, p, _ := strings.Cut(e, " ")
		want[patternKey(m, p)] = true
	}
	seen := map[string]bool{}
	var wrong []string
	for _, r := range routes {
		key := patternKey(r.Method, r.Path)
		allowed := middleware.TenantlessAllowed(r.Method, concretePath(r.Path))
		if allowed != want[key] {
			wrong = append(wrong, key)
		}
		if want[key] {
			seen[key] = true
		}
	}
	for k := range want {
		if !seen[k] {
			wrong = append(wrong, "not a registered route: "+k)
		}
	}
	sort.Strings(wrong)
	if len(wrong) > 0 {
		t.Fatalf("account-only allow-list disagrees with the routes:\n%s", strings.Join(wrong, "\n"))
	}
}

// Every user-plane route outside the allow-list refuses an access token with
// no tenant before its handler runs; the same request with an organization
// token passes the check. Covers every route the parser finds, so a route
// added later is refused until it is put on the list on purpose.
func TestTenantlessToken_RefusedOnEveryOtherRoute(t *testing.T) {
	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "tenantless-allowlist-test-secret-0123456789ab", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour})
	userID := uuid.NewString()
	accountOnly, _, err := gen.GenerateAccessToken(userID, uuid.NewString(), "user")
	if err != nil {
		t.Fatal(err)
	}
	inOrg, err := gen.GenerateTenantScopedAccessToken(userID, "u@it.test", "U", uuid.NewString(),
		jwt.TenantMembership{TenantID: uuid.NewString(), Role: "member"}, false, 0, "password")
	if err != nil {
		t.Fatal(err)
	}
	reached := false
	auth := middleware.UnifiedAuth(middleware.UnifiedAuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen, Logger: logger.NewNop()})
	srv := auth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusTeapot)
	}))
	call := func(method, path, token string) *httptest.ResponseRecorder {
		reached = false
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	refused, allowed := 0, 0
	for _, r := range parsedJWTRoutes(t) {
		path := concretePath(r.Path)
		rec := call(r.Method, path, accountOnly)
		if middleware.TenantlessAllowed(r.Method, path) {
			allowed++
			if !reached {
				t.Errorf("%s %s: allow-listed route refused an account-only token (%d)", r.Method, r.Path, rec.Code)
			}
			continue
		}
		refused++
		var body struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if reached || rec.Code != http.StatusUnauthorized || body.Code != "TENANT_REQUIRED" {
			t.Errorf("%s %s: account-only token got %d %q (handler reached: %v), want 401 TENANT_REQUIRED",
				r.Method, r.Path, rec.Code, body.Code, reached)
		}
		if call(r.Method, path, inOrg.AccessToken); !reached {
			t.Errorf("%s %s: an organization token was refused by the account-only check", r.Method, r.Path)
		}
	}
	if allowed == 0 || refused < 500 {
		t.Fatalf("control: %d allowed, %d refused", allowed, refused)
	}
}

// Paths that are not in canonical form never match an allow-listed route.
func TestTenantlessAllowed_RefusesNonCanonicalPaths(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{"GET", "/api/v1/users/me", true},
		{"GET", "/api/v1/users/me/", true},
		{"PUT", "/api/v1/users/me", true},
		{"DELETE", "/api/v1/users/me", false},
		{"GET", "/api/v1/users/me/../../findings", false},
		{"GET", "/api/v1/users//me", false},
		{"GET", "/api/v1/users/me/./preferences", false},
		{"DELETE", "/api/v1/users/me/sessions/", true},
		{"DELETE", "/api/v1/users/me/sessions/abc", true},
		{"DELETE", "/api/v1/users/me/sessions/abc/def", false},
		{"GET", "/api/v1/tenants/acme", false},
		{"GET", "/api/v1/findings", false},
		{"GET", "", false},
		{"GET", "/", false},
	} {
		if got := middleware.TenantlessAllowed(tc.method, tc.path); got != tc.want {
			t.Errorf("%s %q: got %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}
