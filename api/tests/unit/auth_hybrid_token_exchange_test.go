package unit

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The handler behind POST /auth/token in hybrid mode (routes test
// TestAuthTokenRoute_HybridServesLocalExchange): a local refresh token is
// exchanged for an access token of a tenant the user belongs to; a tenant the
// user is not a member of, and a token the platform did not issue (such as
// one from the identity provider), are refused.
func TestHybridTokenExchange_LocalTokens(t *testing.T) {
	cfg := defaultAuthTestConfig()
	cfg.Provider = config.AuthProviderHybrid
	svc, deps := newTestAuthServiceWithConfig(cfg)
	member := mustNewEnforcedTenant(t, deps.tenantRepo, "hybrid-member", false)
	other := mustNewEnforcedTenant(t, deps.tenantRepo, "hybrid-other", false)
	deps.tenantRepo.userMemberships = []tenant.UserMembership{
		{TenantID: member.ID().String(), TenantSlug: member.Slug(), TenantName: "Member", Role: "member"},
	}
	rt, _ := loginPassword(t, svc, deps, "hybrid@example.com")
	sess := auth.NewSessionService(deps.sessionRepo, deps.rtRepo, logger.NewNop())
	lh := handler.NewLocalAuthHandler(svc, sess, nil, nil, cfg, logger.NewNop())

	t.Run("member tenant", func(t *testing.T) {
		rec := postJSON(t, lh.ExchangeToken, map[string]string{"refresh_token": rt, "tenant_id": member.ID().String()})
		if rec.Code != http.StatusOK {
			t.Fatalf("exchange status %d: %s", rec.Code, rec.Body.String())
		}
		var resp handler.ExchangeTokenResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.AccessToken == "" || resp.TenantID != member.ID().String() {
			t.Fatalf("unexpected exchange response %+v", resp)
		}
		next := refreshCookie(t, rec, rt)
		if next == rt {
			t.Fatal("the exchange did not rotate the refresh token")
		}
		rt = next
	})

	t.Run("tenant the user is not a member of", func(t *testing.T) {
		rec := postJSON(t, lh.ExchangeToken, map[string]string{"refresh_token": rt, "tenant_id": other.ID().String()})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("cross-tenant exchange = %d %s, want 403", rec.Code, rec.Body.String())
		}
	})

	t.Run("token not issued by the platform", func(t *testing.T) {
		foreign, err := jwt.GenerateToken("hybrid-user", "user", "an-identity-provider-signing-key-0123456789", time.Hour)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		rec := postJSON(t, lh.ExchangeToken, map[string]string{"refresh_token": foreign, "tenant_id": member.ID().String()})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("foreign token exchange = %d %s, want 401", rec.Code, rec.Body.String())
		}
	})
}

// refreshCookie returns the rotated refresh token the exchange set, or prev.
func refreshCookie(t *testing.T, rec interface{ Result() *http.Response }, prev string) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Value != "" && strings.Contains(c.Name, "refresh") {
			return c.Value
		}
	}
	return prev
}
