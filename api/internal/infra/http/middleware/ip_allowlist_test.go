package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/httpsec"
	"github.com/openctemio/api/pkg/jwt"
	"github.com/openctemio/api/pkg/logger"
)

type stubPolicy struct {
	byTenant map[string][]string
	err      error
	calls    int
}

func (s *stubPolicy) SecuritySettings(_ context.Context, tenantID string) (tenantdom.SecuritySettings, error) {
	s.calls++
	if s.err != nil {
		return tenantdom.SecuritySettings{}, s.err
	}
	return tenantdom.SecuritySettings{IPWhitelist: s.byTenant[tenantID]}, nil
}

type ipReq struct {
	remoteAddr string
	headers    map[string]string
	claims     *jwt.Claims
	urlTenant  shared.ID
}

func runIPGate(t *testing.T, gate *IPAllowlistGate, in ipReq) (int, bool, string) {
	t.Helper()
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
	req.RemoteAddr = in.remoteAddr
	for k, v := range in.headers {
		req.Header.Set(k, v)
	}
	ctx := req.Context()
	if in.claims != nil {
		ctx = context.WithValue(ctx, LocalClaimsKey, in.claims)
	}
	if !in.urlTenant.IsZero() {
		ctx = context.WithValue(ctx, TeamIDKey, in.urlTenant)
	}
	rr := httptest.NewRecorder()
	gate.Enforce(next).ServeHTTP(rr, req.WithContext(ctx))
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, reached, body.Code
}

func userClaims(tenantID string) *jwt.Claims {
	return &jwt.Claims{UserID: "u1", TenantID: tenantID, Role: "member", AuthMethod: "password"}
}

func TestIPAllowlist_NoListAllowsAll(t *testing.T) {
	gate := NewIPAllowlistGate(&stubPolicy{}, time.Minute, logger.NewNop())
	code, reached, _ := runIPGate(t, gate, ipReq{remoteAddr: "198.51.100.7:4000", claims: userClaims("t1")})
	if code != http.StatusOK || !reached {
		t.Fatalf("empty allowlist must allow, code=%d", code)
	}
}

func TestIPAllowlist_AllowedAndBlocked(t *testing.T) {
	gate := NewIPAllowlistGate(&stubPolicy{byTenant: map[string][]string{"t1": {"203.0.113.0/24"}}}, time.Minute, logger.NewNop())

	code, reached, _ := runIPGate(t, gate, ipReq{remoteAddr: "203.0.113.9:5555", claims: userClaims("t1")})
	if code != http.StatusOK || !reached {
		t.Fatalf("IP inside the allowlist must pass, code=%d", code)
	}
	code, reached, errCode := runIPGate(t, gate, ipReq{remoteAddr: "198.51.100.7:5555", claims: userClaims("t1")})
	if code != http.StatusForbidden || reached || errCode != string(CodeIPNotAllowed) {
		t.Fatalf("IP outside must be 403 IP_NOT_ALLOWED, code=%d reached=%v errCode=%s", code, reached, errCode)
	}
}

// Without a trusted proxy, a client cannot claim an allowed IP via headers.
func TestIPAllowlist_SpoofedForwardingHeadersIgnored(t *testing.T) {
	SetTrustedProxies(nil)
	gate := NewIPAllowlistGate(&stubPolicy{byTenant: map[string][]string{"t1": {"203.0.113.9"}}}, time.Minute, logger.NewNop())
	code, reached, _ := runIPGate(t, gate, ipReq{
		remoteAddr: "198.51.100.7:5555",
		headers:    map[string]string{"X-Forwarded-For": "203.0.113.9", "X-Real-IP": "203.0.113.9"},
		claims:     userClaims("t1"),
	})
	if code != http.StatusForbidden || reached {
		t.Fatalf("forwarding headers from an untrusted peer must be ignored, code=%d", code)
	}
}

// Behind a trusted proxy, the forwarded client IP is the one checked.
func TestIPAllowlist_TrustedProxyHeaderHonored(t *testing.T) {
	SetTrustedProxies(httpsec.NewTrustedProxySet([]string{"10.0.0.0/8"}))
	defer SetTrustedProxies(nil)
	gate := NewIPAllowlistGate(&stubPolicy{byTenant: map[string][]string{"t1": {"203.0.113.9"}}}, time.Minute, logger.NewNop())
	code, reached, _ := runIPGate(t, gate, ipReq{
		remoteAddr: "10.1.2.3:5555",
		headers:    map[string]string{"X-Real-IP": "203.0.113.9"},
		claims:     userClaims("t1"),
	})
	if code != http.StatusOK || !reached {
		t.Fatalf("trusted proxy's X-Real-IP must be used, code=%d", code)
	}
}

// The URL organization wins over the token's organization on /tenants/{t}.
func TestIPAllowlist_URLTenantTakesPrecedence(t *testing.T) {
	urlTenant := shared.NewID()
	gate := NewIPAllowlistGate(&stubPolicy{byTenant: map[string][]string{urlTenant.String(): {"203.0.113.0/24"}}}, time.Minute, logger.NewNop())
	code, _, _ := runIPGate(t, gate, ipReq{remoteAddr: "198.51.100.7:1", claims: userClaims("token-tenant"), urlTenant: urlTenant})
	if code != http.StatusForbidden {
		t.Fatalf("the URL organization's allowlist applies, code=%d", code)
	}
}

// Non-user requests (no access-token claims: API keys, agents, admin console)
// and tokens without an organization are not subject to the allowlist.
func TestIPAllowlist_NonUserAndTenantlessPassWithoutLookup(t *testing.T) {
	p := &stubPolicy{byTenant: map[string][]string{"t1": {"203.0.113.9"}}}
	gate := NewIPAllowlistGate(p, time.Minute, logger.NewNop())
	if code, reached, _ := runIPGate(t, gate, ipReq{remoteAddr: "198.51.100.7:1"}); code != http.StatusOK || !reached {
		t.Fatalf("no claims must pass, code=%d", code)
	}
	if code, reached, _ := runIPGate(t, gate, ipReq{remoteAddr: "198.51.100.7:1", claims: userClaims("")}); code != http.StatusOK || !reached {
		t.Fatalf("a tenant-less token must pass, code=%d", code)
	}
	if p.calls != 0 {
		t.Fatalf("no policy lookup expected, got %d", p.calls)
	}
}

func TestIPAllowlist_LookupErrorFailsClosed(t *testing.T) {
	gate := NewIPAllowlistGate(&stubPolicy{err: errors.New("db down")}, time.Minute, logger.NewNop())
	if code, reached, _ := runIPGate(t, gate, ipReq{remoteAddr: "203.0.113.9:1", claims: userClaims("t1")}); code != http.StatusForbidden || reached {
		t.Fatalf("lookup error must fail closed, code=%d", code)
	}
}

func TestIPAllowlist_CacheAndInvalidate(t *testing.T) {
	p := &stubPolicy{byTenant: map[string][]string{"t1": {"203.0.113.9"}}}
	gate := NewIPAllowlistGate(p, time.Hour, logger.NewNop())
	runIPGate(t, gate, ipReq{remoteAddr: "203.0.113.9:1", claims: userClaims("t1")})
	runIPGate(t, gate, ipReq{remoteAddr: "203.0.113.9:1", claims: userClaims("t1")})
	if p.calls != 1 {
		t.Fatalf("policy must be cached, got %d lookups", p.calls)
	}
	p.byTenant["t1"] = []string{"192.0.2.1"}
	gate.Invalidate("t1")
	if code, _, _ := runIPGate(t, gate, ipReq{remoteAddr: "203.0.113.9:1", claims: userClaims("t1")}); code != http.StatusForbidden {
		t.Fatalf("after Invalidate the new policy applies, code=%d", code)
	}
}
