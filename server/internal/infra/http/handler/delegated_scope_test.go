package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
)

// An MCP OAuth access token acts for its user like an API key does: the
// findings list and the query endpoint must not give it the holder's
// full-data role. A session of the same user is the control.
func TestDelegatedCredentialsNeverGetFullDataOnReadPaths(t *testing.T) {
	const tenant, user = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	base := func() context.Context {
		ctx := context.WithValue(context.Background(), middleware.TenantIDKey, tenant)
		return context.WithValue(ctx, middleware.UserIDKey, user)
	}
	cases := map[string]struct {
		ctx  context.Context
		want bool
	}{
		"session":   {base(), false},
		"api key":   {context.WithValue(base(), middleware.APIKeyIDKey, "key-1"), true},
		"mcp oauth": {context.WithValue(base(), middleware.AuthProviderKey, middleware.AuthProviderMCPOAuth), true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(tc.ctx, http.MethodGet, "/api/v1/findings", nil)
			if got := filterCaller(r).APIKey; got != tc.want {
				t.Errorf("findings list caller APIKey = %v, want %v", got, tc.want)
			}
			if got := queryCaller(r).APIKey; got != tc.want {
				t.Errorf("query caller APIKey = %v, want %v", got, tc.want)
			}
		})
	}
}
