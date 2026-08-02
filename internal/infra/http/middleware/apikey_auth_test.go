package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	apikeydom "github.com/openctemio/api/pkg/domain/apikey"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

type fakeAuthenticator struct {
	key    *apikeydom.APIKey
	err    error
	gotRaw string
	gotIP  string
}

func (f *fakeAuthenticator) Authenticate(_ context.Context, raw, ip string) (*apikeydom.APIKey, error) {
	f.gotRaw = raw
	f.gotIP = ip
	if f.err != nil {
		return nil, f.err
	}
	return f.key, nil
}

func newTestKey(tenantID shared.ID, scopes []string) *apikeydom.APIKey {
	k := apikeydom.NewAPIKey(shared.NewID(), tenantID, "test", "hash", "oct_abcd")
	k.SetScopes(scopes)
	return k
}

func TestAPIKeyAuth_ValidKeySetsTenantContext(t *testing.T) {
	tenantID := shared.NewID()
	fa := &fakeAuthenticator{key: newTestKey(tenantID, []string{"mcp:read"})}

	var gotTenant string
	var gotPerms []string
	var nextCalled bool
	h := APIKeyAuth(fa, logger.NewNop())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		gotTenant = GetTenantID(r.Context())
		gotPerms = GetPermissions(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil)
	req.Header.Set("Authorization", "Bearer oct_secret123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected next handler to run for a valid key")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if gotTenant != tenantID.String() {
		t.Errorf("tenant not set in context: got %q want %q", gotTenant, tenantID.String())
	}
	if len(gotPerms) != 1 || gotPerms[0] != "mcp:read" {
		t.Errorf("scopes not mapped to permissions: %v", gotPerms)
	}
	if fa.gotRaw != "oct_secret123" {
		t.Errorf("raw key not forwarded to authenticator: %q", fa.gotRaw)
	}
}

func TestAPIKeyAuth_MissingKeyIs401(t *testing.T) {
	fa := &fakeAuthenticator{}
	var nextCalled bool
	h := APIKeyAuth(fa, logger.NewNop())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil))

	if nextCalled {
		t.Fatal("next must not run without credentials")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAPIKeyAuth_JWTBearerIsNotTreatedAsKey(t *testing.T) {
	fa := &fakeAuthenticator{err: apikeydom.ErrAPIKeyNotFound}
	h := APIKeyAuth(fa, logger.NewNop())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJ.jwt.token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// A JWT (non-oct_) bearer must be rejected without even reaching the
	// authenticator — extraction returns "" so it can't be probed as a key.
	if fa.gotRaw != "" {
		t.Errorf("a JWT bearer must not be forwarded to the API-key authenticator, got %q", fa.gotRaw)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAPIKeyAuth_InvalidKeyIs401(t *testing.T) {
	fa := &fakeAuthenticator{err: apikeydom.ErrAPIKeyNotFound}
	h := APIKeyAuth(fa, logger.NewNop())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next must not run for an invalid key")
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil)
	req.Header.Set("X-API-Key", "oct_revoked")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
