package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// flakySessions answers the revoked-session lookup, or fails.
type flakySessions struct {
	err     error
	revoked bool
}

func (f *flakySessions) IsSessionRevoked(context.Context, string) (bool, error) {
	return f.revoked, f.err
}

func revocationTestSetup(t *testing.T, sessions RevokedSessionChecker) (http.Handler, string) {
	t.Helper()
	gen := jwt.NewGenerator(jwt.TokenConfig{
		Secret: "revocation-outage-test-secret-0123456789abcdef", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour,
	})
	scoped, err := gen.GenerateTenantScopedAccessToken("0a0e0c09-5e75-4556-8a26-c8de3ded5d73", "u@it.test", "U", "sid",
		jwt.TenantMembership{TenantID: "7d1c3b2a-0000-4000-8000-000000000001", Role: "member"}, false, 0, "password")
	tok := ""
	if scoped != nil {
		tok = scoped.AccessToken
	}
	if err != nil {
		t.Fatal(err)
	}
	mw := UnifiedAuth(UnifiedAuthConfig{
		Provider: config.AuthProviderLocal, LocalValidator: gen, RevokedSessions: sessions,
		Logger: logger.New(logger.Config{Level: "error"}),
	})
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })), tok
}

func doBearer(h http.Handler, method, tok string) int {
	r := httptest.NewRequest(method, "/api/v1/users/me", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code
}

// When the revoked-session lookup is down, writes are refused at once and
// reads continue for a bounded window; a working lookup restores both, and a
// revoked session stays refused.
func TestUnifiedAuth_RevocationLookupDown(t *testing.T) {
	s := &flakySessions{err: errors.New("redis down")}
	h, tok := revocationTestSetup(t, s)

	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if got := doBearer(h, m, tok); got != http.StatusServiceUnavailable {
			t.Errorf("%s during outage = %d, want 503", m, got)
		}
	}
	if got := doBearer(h, http.MethodGet, tok); got != http.StatusNoContent {
		t.Errorf("GET at the start of the outage = %d, want it served", got)
	}

	s.err = nil
	if got := doBearer(h, http.MethodPost, tok); got != http.StatusNoContent {
		t.Errorf("POST after recovery = %d, want served", got)
	}
	s.revoked = true
	if got := doBearer(h, http.MethodGet, tok); got != http.StatusUnauthorized {
		t.Errorf("GET of a revoked session = %d, want 401", got)
	}
}

func TestRevocationOutage_ReadWindowIsBounded(t *testing.T) {
	o := &revocationOutage{}
	start := time.Now()
	if !o.allowRead(start) {
		t.Fatal("first failure must still allow reads")
	}
	if !o.allowRead(start.Add(revocationReadWindow - time.Second)) {
		t.Fatal("reads inside the window must be allowed")
	}
	if o.allowRead(start.Add(revocationReadWindow + time.Second)) {
		t.Fatal("reads after the window must be refused")
	}
	o.clear()
	if !o.allowRead(start.Add(time.Hour)) {
		t.Fatal("a successful lookup must restart the window")
	}
}
