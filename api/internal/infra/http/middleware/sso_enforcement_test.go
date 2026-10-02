package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/jwt"
	"github.com/openctemio/api/pkg/logger"
)

// stubSSOEnforced implements SSOEnforcedProvider for tests.
type stubSSOEnforced struct {
	enforced map[string]bool
	err      error
	calls    int
}

func (s *stubSSOEnforced) IsSSOEnforced(_ context.Context, tenantID string) (bool, error) {
	s.calls++
	if s.err != nil {
		return false, s.err
	}
	return s.enforced[tenantID], nil
}

// runEnforce builds the middleware with the given provider and drives one request
// whose context carries the supplied local JWT claims. Returns the response code
// and whether next was reached.
func runEnforce(t *testing.T, provider SSOEnforcedProvider, claims *jwt.Claims) (int, bool) {
	t.Helper()
	gate := NewSSOEnforcementGate(provider, 60*time.Second, logger.NewNop())

	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
	if claims != nil {
		ctx := context.WithValue(req.Context(), LocalClaimsKey, claims)
		req = req.WithContext(ctx)
	}
	rr := httptest.NewRecorder()
	gate.Enforce(next).ServeHTTP(rr, req)
	return rr.Code, reached
}

func passwordClaims(tenantID, role string) *jwt.Claims {
	return &jwt.Claims{UserID: "u1", TenantID: tenantID, Role: role, AuthMethod: "password"}
}

func TestSSOEnforcement_PasswordNonOwner_EnforcedTenant_Denied(t *testing.T) {
	p := &stubSSOEnforced{enforced: map[string]bool{"t-enforced": true}}
	code, reached := runEnforce(t, p, passwordClaims("t-enforced", "member"))
	if code != http.StatusForbidden || reached {
		t.Fatalf("password/member on enforced tenant: code=%d reached=%v, want 403 & not reached", code, reached)
	}
}

func TestSSOEnforcement_Owner_EnforcedTenant_Allowed(t *testing.T) {
	p := &stubSSOEnforced{enforced: map[string]bool{"t-enforced": true}}
	code, reached := runEnforce(t, p, passwordClaims("t-enforced", "owner"))
	if code != http.StatusOK || !reached {
		t.Fatalf("owner break-glass: code=%d reached=%v, want 200 & reached", code, reached)
	}
	if p.calls != 0 {
		t.Fatalf("owner should short-circuit before the tenant lookup, got %d calls", p.calls)
	}
}

func TestSSOEnforcement_FederatedSession_EnforcedTenant_Allowed(t *testing.T) {
	p := &stubSSOEnforced{enforced: map[string]bool{"t-enforced": true}}
	for _, m := range []string{"sso", "saml"} {
		c := &jwt.Claims{UserID: "u1", TenantID: "t-enforced", Role: "member", AuthMethod: m}
		code, reached := runEnforce(t, p, c)
		if code != http.StatusOK || !reached {
			t.Fatalf("federated %q: code=%d reached=%v, want 200 & reached", m, code, reached)
		}
	}
	if p.calls != 0 {
		t.Fatalf("federated sessions should short-circuit before the tenant lookup, got %d calls", p.calls)
	}
}

func TestSSOEnforcement_PasswordNonOwner_NonEnforcedTenant_Allowed(t *testing.T) {
	p := &stubSSOEnforced{enforced: map[string]bool{"t-open": false}}
	code, reached := runEnforce(t, p, passwordClaims("t-open", "member"))
	if code != http.StatusOK || !reached {
		t.Fatalf("password/member on non-enforced tenant: code=%d reached=%v, want 200 & reached", code, reached)
	}
}

func TestSSOEnforcement_LookupError_FailsClosed(t *testing.T) {
	p := &stubSSOEnforced{err: errors.New("db down")}
	code, reached := runEnforce(t, p, passwordClaims("t-x", "member"))
	if code != http.StatusForbidden || reached {
		t.Fatalf("lookup error must fail closed: code=%d reached=%v, want 403 & not reached", code, reached)
	}
}

func TestSSOEnforcement_NoClaims_PassThrough(t *testing.T) {
	p := &stubSSOEnforced{enforced: map[string]bool{}}
	code, reached := runEnforce(t, p, nil)
	if code != http.StatusOK || !reached {
		t.Fatalf("no local claims (OIDC path): code=%d reached=%v, want 200 & reached", code, reached)
	}
}

func TestSSOEnforcement_EmptyTenant_PassThrough(t *testing.T) {
	p := &stubSSOEnforced{enforced: map[string]bool{}}
	code, reached := runEnforce(t, p, passwordClaims("", "member"))
	if code != http.StatusOK || !reached {
		t.Fatalf("global (no tenant) token: code=%d reached=%v, want 200 & reached", code, reached)
	}
}

func TestSSOEnforcement_EmptyAuthMethod_TreatedAsPassword(t *testing.T) {
	// A token minted before the auth_method claim existed carries "" — it must be
	// treated as password (fail-safe), so an enforced tenant denies it.
	p := &stubSSOEnforced{enforced: map[string]bool{"t-enforced": true}}
	c := &jwt.Claims{UserID: "u1", TenantID: "t-enforced", Role: "member", AuthMethod: ""}
	code, reached := runEnforce(t, p, c)
	if code != http.StatusForbidden || reached {
		t.Fatalf("empty auth_method must be treated as password: code=%d reached=%v, want 403", code, reached)
	}
}

func TestSSOEnforcement_CachesLookup(t *testing.T) {
	p := &stubSSOEnforced{enforced: map[string]bool{"t-enforced": true}}
	gate := NewSSOEnforcementGate(p, 60*time.Second, logger.NewNop())
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req = req.WithContext(context.WithValue(req.Context(), LocalClaimsKey, passwordClaims("t-enforced", "member")))
		gate.Enforce(next).ServeHTTP(httptest.NewRecorder(), req)
	}
	if p.calls != 1 {
		t.Fatalf("expected a single cached lookup across 3 requests, got %d", p.calls)
	}
}
