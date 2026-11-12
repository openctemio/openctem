package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// runIPGateCtx runs the gate with a principal set the way a non-local-JWT
// authenticator sets it (tenant, user and provider in the context, no local
// claims).
func runIPGateCtx(t *testing.T, gate *IPAllowlistGate, remoteAddr string, kv map[any]any) (int, bool, string) {
	t.Helper()
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil)
	req.RemoteAddr = remoteAddr
	ctx := req.Context()
	for k, v := range kv {
		ctx = context.WithValue(ctx, k, v)
	}
	rr := httptest.NewRecorder()
	gate.Enforce(next).ServeHTTP(rr, req.WithContext(ctx))
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, reached, body.Code
}

// The allowlist binds the principal (an organization member acting in the
// organization), whatever credential carried it: an MCP OAuth access token and
// an OIDC token must be refused from outside the list exactly like a session.
func TestIPAllowlist_AppliesToEveryUserPrincipal(t *testing.T) {
	SetTrustedProxies(nil)
	gate := NewIPAllowlistGate(&stubPolicy{byTenant: map[string][]string{"t1": {"203.0.113.0/24"}}}, time.Minute, logger.NewNop())
	for _, provider := range []string{AuthProviderMCPOAuth, AuthProviderOIDC, AuthProviderAPIKey, "some_future_provider"} {
		t.Run(provider, func(t *testing.T) {
			kv := map[any]any{TenantIDKey: "t1", UserIDKey: "u1", AuthProviderKey: provider}
			code, reached, errCode := runIPGateCtx(t, gate, "198.51.100.7:4000", kv)
			if code != http.StatusForbidden || reached || errCode != string(CodeIPNotAllowed) {
				t.Fatalf("outside the allowlist must be 403 IP_NOT_ALLOWED, code=%d reached=%v errCode=%s", code, reached, errCode)
			}
			if code, reached, _ := runIPGateCtx(t, gate, "203.0.113.9:4000", kv); code != http.StatusOK || !reached {
				t.Fatalf("inside the allowlist must pass, code=%d", code)
			}
		})
	}
}

// Principals without a user (sensor keys, the platform admin acting in an
// organization with an empty actor) stay outside the gate: no lookup.
func TestIPAllowlist_UserlessPrincipalsUnaffected(t *testing.T) {
	SetTrustedProxies(nil)
	p := &stubPolicy{byTenant: map[string][]string{"t1": {"203.0.113.9"}}}
	gate := NewIPAllowlistGate(p, time.Minute, logger.NewNop())
	for name, kv := range map[string]map[any]any{
		"sensor":      {TenantIDKey: "t1"},
		"empty_actor": {TenantIDKey: "t1", UserIDKey: ""},
	} {
		if code, reached, _ := runIPGateCtx(t, gate, "198.51.100.7:1", kv); code != http.StatusOK || !reached {
			t.Fatalf("%s must pass, code=%d", name, code)
		}
	}
	if p.calls != 0 {
		t.Fatalf("no policy lookup expected, got %d", p.calls)
	}
}
