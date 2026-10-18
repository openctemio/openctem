package routes

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	mcpoauthapp "github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fixedIPPolicy struct{ allow []string }

func (f fixedIPPolicy) SecuritySettings(context.Context, string) (tenantdom.SecuritySettings, error) {
	return tenantdom.SecuritySettings{IPWhitelist: f.allow}, nil
}

// The organization IP allowlist binds an MCP OAuth access token on the MCP
// endpoint, not only an `oct_` key: a connection used from outside the
// organization's network is refused with IP_NOT_ALLOWED.
func TestMCPOAuthTokenBoundByIPAllowlist(t *testing.T) {
	middleware.SetTrustedProxies(nil)
	saved := ipAllowlistMiddleware
	t.Cleanup(func() { ipAllowlistMiddleware = saved })

	p := &mcpoauthapp.Principal{
		GrantID: "g1", TenantID: "11111111-1111-1111-1111-111111111111", UserID: "22222222-2222-2222-2222-222222222222",
		ClientID: "https://assistant.example/c.json", Scopes: []mcpoauth.Scope{mcpoauth.ScopeAssetsRead},
		Permissions: []string{"assets:read"}, Held: []string{"assets:read"},
	}

	// httptest requests come from 192.0.2.1.
	ipAllowlistMiddleware = middleware.NewIPAllowlistGate(fixedIPPolicy{allow: []string{"203.0.113.0/24"}}, time.Minute, logger.NewNop()).Enforce
	rec := mcpCall(newMCPOAuthMux(t, p), "Bearer octm_at_good", toolsList, nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), string(middleware.CodeIPNotAllowed)) {
		t.Fatalf("token from outside the allowlist: status %d body %s", rec.Code, rec.Body.String())
	}

	ipAllowlistMiddleware = middleware.NewIPAllowlistGate(fixedIPPolicy{allow: []string{"192.0.2.0/24"}}, time.Minute, logger.NewNop()).Enforce
	if rec := mcpCall(newMCPOAuthMux(t, p), "Bearer octm_at_good", toolsList, nil); rec.Code != http.StatusOK {
		t.Fatalf("token from inside the allowlist: status %d body %s", rec.Code, rec.Body.String())
	}
}
