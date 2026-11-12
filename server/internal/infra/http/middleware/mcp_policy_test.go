package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type mcpStubPolicy struct {
	p   tenantdom.MCPSettings
	err error
}

func (s mcpStubPolicy) MCPPolicy(context.Context, shared.ID) (tenantdom.MCPSettings, error) {
	return s.p, s.err
}

func TestMCPKeyPolicyGate(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	tenant := "11111111-1111-1111-1111-111111111111"
	run := func(pol mcpStubPolicy, provider string) int {
		ctx := context.WithValue(context.Background(), AuthProviderKey, provider)
		ctx = context.WithValue(ctx, TenantIDKey, tenant)
		rec := httptest.NewRecorder()
		MCPKeyPolicyGate(pol, logger.NewNop())(ok).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil).WithContext(ctx))
		return rec.Code
	}
	for name, tc := range map[string]struct {
		pol      mcpStubPolicy
		provider string
		want     int
	}{
		"key, defaults":          {mcpStubPolicy{}, AuthProviderAPIKey, http.StatusOK},
		"key, keys off":          {mcpStubPolicy{p: tenantdom.MCPSettings{APIKeysDisabled: true}}, AuthProviderAPIKey, http.StatusForbidden},
		"key, mcp off":           {mcpStubPolicy{p: tenantdom.MCPSettings{Disabled: true}}, AuthProviderAPIKey, http.StatusForbidden},
		"key, policy unreadable": {mcpStubPolicy{err: errors.New("db down")}, AuthProviderAPIKey, http.StatusServiceUnavailable},
		// Access tokens are checked by the authorization server.
		"token, keys off": {mcpStubPolicy{p: tenantdom.MCPSettings{APIKeysDisabled: true}}, AuthProviderMCPOAuth, http.StatusOK},
	} {
		if got := run(tc.pol, tc.provider); got != tc.want {
			t.Errorf("%s: %d, want %d", name, got, tc.want)
		}
	}
}
