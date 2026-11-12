package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	apikeydom "github.com/openctemio/openctem/api/pkg/domain/apikey"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// restHarness wires OrJWT in front of a stand-in JWT authenticator that only
// records whether it ran.
type restHarness struct {
	fa        *fakeAuthenticator
	jwtCalled bool
	next      bool
	handler   http.Handler
	seenPerms []string
	seenTen   string
	seenUser  string
	seenAdmin bool
	seenKey   string
	seenProv  string
	seenCook  bool
}

func newRESTHarness(fa *fakeAuthenticator) *restHarness {
	h := &restHarness{fa: fa}
	jwt := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.jwtCalled = true
			next.ServeHTTP(w, r)
		})
	}
	h.handler = NewAPIKeyAuth(fa, logger.NewNop()).OrJWT(jwt)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.next = true
		ctx := r.Context()
		h.seenPerms, h.seenTen, h.seenUser = GetPermissions(ctx), GetTenantID(ctx), GetUserID(ctx)
		h.seenAdmin, h.seenKey, h.seenProv, h.seenCook = IsAdmin(ctx), GetAPIKeyID(ctx), GetAuthProvider(ctx), IsCookieAuthenticated(ctx)
		w.WriteHeader(http.StatusOK)
	}))
	return h
}

func (h *restHarness) serve(method, path string, headers map[string]string, cookies ...*http.Cookie) int {
	h.jwtCalled, h.next = false, false
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec.Code
}

func userKey(scopes ...string) (*apikeydom.APIKey, shared.ID, shared.ID) {
	tenantID, userID := shared.NewID(), shared.NewID()
	k := newTestKey(tenantID, scopes)
	k.SetUserID(&userID)
	return k, tenantID, userID
}

func TestOrJWT_RequestWithoutKeyGoesToJWT(t *testing.T) {
	fa := &fakeAuthenticator{}
	h := newRESTHarness(fa)
	for _, headers := range []map[string]string{
		nil,
		{"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.jwt.sig"},
	} {
		if code := h.serve(http.MethodPost, "/api/v1/assets", headers); code != http.StatusOK || !h.jwtCalled {
			t.Errorf("headers %v: code %d jwtCalled %v, want the JWT path", headers, code, h.jwtCalled)
		}
	}
	if fa.calls != 0 {
		t.Errorf("a request without a key reached the key authenticator %d times", fa.calls)
	}
}

func TestOrJWT_KeyAuthenticatesAsItsTenantAndUser(t *testing.T) {
	key, tenantID, userID := userKey("assets:read", "findings:read")
	fa := &fakeAuthenticator{key: key, perms: []string{"assets:read"}} // narrowed by the service
	h := newRESTHarness(fa)

	for _, headers := range []map[string]string{
		{"Authorization": "Bearer oct_valid"},
		{"authorization": "bearer oct_valid"},
		{"X-API-Key": "oct_valid"},
		{"X-API-Key": "oct_valid", "Authorization": "Bearer oct_valid"},
	} {
		code := h.serve(http.MethodGet, "/api/v1/assets", headers)
		if code != http.StatusOK || h.jwtCalled {
			t.Fatalf("headers %v: code %d jwtCalled %v", headers, code, h.jwtCalled)
		}
		if fa.gotRaw != "oct_valid" {
			t.Errorf("authenticator got %q", fa.gotRaw)
		}
		if h.seenTen != tenantID.String() || h.seenUser != userID.String() || h.seenKey != key.ID().String() {
			t.Errorf("principal tenant=%s user=%s key=%s", h.seenTen, h.seenUser, h.seenKey)
		}
		if len(h.seenPerms) != 1 || h.seenPerms[0] != "assets:read" {
			t.Errorf("permissions = %v, want the effective set from the service", h.seenPerms)
		}
		if h.seenAdmin || h.seenCook || h.seenProv != AuthProviderAPIKey {
			t.Errorf("admin=%v cookie=%v provider=%q", h.seenAdmin, h.seenCook, h.seenProv)
		}
	}
}

func TestOrJWT_KeysAreReadOnly(t *testing.T) {
	key, _, _ := userKey("assets:read", "assets:write")
	h := newRESTHarness(&fakeAuthenticator{key: key})
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if code := h.serve(m, "/api/v1/assets", map[string]string{"Authorization": "Bearer oct_valid"}); code != http.StatusForbidden || h.next || h.jwtCalled {
			t.Errorf("%s with a key: code %d next %v jwt %v, want 403", m, code, h.next, h.jwtCalled)
		}
	}
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		if code := h.serve(m, "/api/v1/assets", map[string]string{"Authorization": "Bearer oct_valid"}); code != http.StatusOK {
			t.Errorf("%s with a key: %d", m, code)
		}
	}
}

// A request that presents a key is decided by the key: a bad key is a 401 and
// the session cookie it also carries is never consulted.
func TestOrJWT_BadKeyNeverFallsBackToSession(t *testing.T) {
	h := newRESTHarness(&fakeAuthenticator{err: apikeydom.ErrAPIKeyNotFound})
	session := &http.Cookie{Name: DefaultAccessTokenCookieName, Value: "a-valid-session"}
	for _, headers := range []map[string]string{
		{"Authorization": "Bearer oct_revoked"},
		{"X-API-Key": "oct_revoked"},
	} {
		if code := h.serve(http.MethodGet, "/api/v1/assets", headers, session); code != http.StatusUnauthorized || h.jwtCalled || h.next {
			t.Errorf("%v: code %d jwt %v next %v, want 401 without the session", headers, code, h.jwtCalled, h.next)
		}
	}
}

func TestOrJWT_AmbiguousCredentialsRejected(t *testing.T) {
	key, _, _ := userKey("assets:read")
	fa := &fakeAuthenticator{key: key}
	h := newRESTHarness(fa)
	for name, headers := range map[string]map[string]string{
		"non-oct X-API-Key":         {"X-API-Key": "sk_live_something"},
		"X-API-Key with a JWT":      {"X-API-Key": "oct_valid", "Authorization": "Bearer eyJ.jwt.sig"},
		"two different oct_ keys":   {"X-API-Key": "oct_one", "Authorization": "Bearer oct_two"},
		"X-API-Key with Basic auth": {"X-API-Key": "oct_valid", "Authorization": "Basic dXNlcjpwYXNz"},
	} {
		if code := h.serve(http.MethodGet, "/api/v1/assets", headers); code != http.StatusUnauthorized || h.jwtCalled || h.next {
			t.Errorf("%s: code %d jwt %v next %v, want 401", name, code, h.jwtCalled, h.next)
		}
	}
	if fa.calls != 0 {
		t.Errorf("ambiguous credentials reached the authenticator %d times", fa.calls)
	}
}

func TestOrJWT_DeniedRoutesRefuseKeysBeforeLookup(t *testing.T) {
	key, _, _ := userKey("api-keys:read", "api-keys:write")
	fa := &fakeAuthenticator{key: key}
	h := newRESTHarness(fa)
	for _, p := range []string{
		"/api/v1/api-keys",
		"/api/v1/api-keys/",
		"/api/v1/api-keys/0190/revoke",
		"/api/v1/scim-tokens",
		"/api/v1/me/permissions",
		"/api/v1/me",
		"/api/v1/notifications",
		"/api/v1/users/me/password",
		"/api/v1/users/0190/roles",
		"/api/v1/admin/tenants",
		"/api/v1/tenants/acme/members",
		"/api/v1/ws",
		"/api/v1//api-keys",
		"/api/v1/assets/../api-keys",
		"/api/v1/./me/bootstrap",
		"/api/v1/api%2Dkeys",
	} {
		if code := h.serve(http.MethodGet, p, map[string]string{"Authorization": "Bearer oct_valid"}); code != http.StatusForbidden || h.next {
			t.Errorf("GET %s with a key: code %d next %v, want 403", p, code, h.next)
		}
	}
	if fa.calls != 0 {
		t.Errorf("denied routes looked the key up %d times", fa.calls)
	}
	// The same routes still work for a session.
	if code := h.serve(http.MethodGet, "/api/v1/api-keys", nil); code != http.StatusOK || !h.jwtCalled {
		t.Errorf("session on /api-keys: %d", code)
	}
}

func TestAPIKeyRouteDenied(t *testing.T) {
	for p, want := range map[string]bool{
		"/api/v1/api-keys":         true,
		"/api/v1/api-keys/x":       true,
		"/api/v1/me":               true,
		"/api/v1/me/bootstrap":     true,
		"/api/v1/meetings":         false, // a prefix, not a path segment
		"/api/v1/api-keysx":        false,
		"/api/v1/assets":           false,
		"/api/v1/findings/x":       false,
		"/api/v1/users/me":         true,
		"/api/v1/x/../../v1/admin": true,
		"":                         false,
	} {
		if got := APIKeyRouteDenied(p); got != want {
			t.Errorf("APIKeyRouteDenied(%q) = %v, want %v", p, got, want)
		}
	}
}

// MCP and REST share one authenticator, so one key has one budget.
func TestAPIKeyAuth_RateLimitSharedAcrossMCPAndREST(t *testing.T) {
	key, _, _ := userKey("assets:read")
	key.SetRateLimit(2)
	m := NewAPIKeyAuth(&fakeAuthenticator{key: key}, logger.NewNop())
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mcp := m.Handler(ok)
	rest := m.OrJWT(func(next http.Handler) http.Handler { return next })(ok)

	codes := make([]int, 0, 3)
	for _, h := range []http.Handler{mcp, rest, rest} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
		req.Header.Set("Authorization", "Bearer oct_valid")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK || codes[2] != http.StatusTooManyRequests {
		t.Errorf("codes = %v, want [200 200 429]", codes)
	}
}

// The permission-sync middleware must leave a key request's permissions alone:
// reloading the user's permissions would replace the key's narrow set with
// everything the user can do. With nil services, any lookup would panic.
func TestEnrichPermissions_SkipsAPIKeyRequests(t *testing.T) {
	key, _, _ := userKey("assets:read")
	var perms []string
	sync := NewPermissionSyncMiddleware(nil, nil, logger.NewNop()).EnrichPermissions
	h := NewAPIKeyAuth(&fakeAuthenticator{key: key}, logger.NewNop()).Handler(sync(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		perms = GetPermissions(r.Context())
	})))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
	req.Header.Set("Authorization", "Bearer oct_valid")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if len(perms) != 1 || perms[0] != "assets:read" {
		t.Errorf("permissions after sync = %v, want the key's", perms)
	}
}
