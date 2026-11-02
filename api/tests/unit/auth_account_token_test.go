package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/jwt"
)

// An account with no organization gets an access token without a tenant
// (docs/architecture/tenantless-account-space.md); the refresh token rotates
// and the spent one cannot be presented again.
func TestAccountToken_NoOrganization(t *testing.T) {
	ctx := context.Background()
	h := newMFAHarness(t)
	h.seedUser(t, "solo@it.test")
	res := h.login(t, "solo@it.test")

	got, err := h.svc.AccountToken(ctx, res.RefreshToken)
	if err != nil {
		t.Fatalf("account token: %v", err)
	}
	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: defaultAuthTestConfig().JWTSecret, Issuer: defaultAuthTestConfig().JWTIssuer})
	claims, err := gen.ValidateAccessToken(got.AccessToken)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.TenantID != "" || claims.IsAdmin || len(claims.Permissions) != 0 {
		t.Fatalf("account token carries organization access: tenant=%q admin=%v perms=%v", claims.TenantID, claims.IsAdmin, claims.Permissions)
	}
	if got.RefreshToken == "" || got.RefreshToken == res.RefreshToken {
		t.Fatal("refresh token was not rotated")
	}
	// The spent token is refused (and ends the family); the rotated one is too.
	if _, err := h.svc.AccountToken(ctx, res.RefreshToken); err == nil {
		t.Fatal("spent refresh token minted a second account token")
	}
	if _, err := h.svc.AccountToken(ctx, got.RefreshToken); err == nil {
		t.Fatal("refresh family survived the replay of a spent token")
	}
}

// A member of an open organization never gets an account token: they use
// that organization's token, so its sign-in policies always apply. When every
// organization is suspended the account space is the way in.
func TestAccountToken_MemberRefusedUnlessEveryOrganizationIsClosed(t *testing.T) {
	ctx := context.Background()
	h := newMFAHarness(t)
	acme := newPolicyTenant(t, h.tenants, "acct-acme", false)
	h.tenants.userMemberships = []tenant.UserMembership{
		{TenantID: acme.ID().String(), TenantSlug: acme.Slug(), TenantName: "Acme", Role: "member"},
	}
	h.seedUser(t, "member@acme.test")
	res := h.login(t, "member@acme.test")

	if _, err := h.svc.AccountToken(ctx, res.RefreshToken); !errors.Is(err, auth.ErrAccountTokenHasOrganization) {
		t.Fatalf("member of an open organization: %v, want ErrAccountTokenHasOrganization", err)
	}
	// The refusal did not spend the token.
	h.svc.SetOrganizationGate(&toggleGate{suspended: map[string]bool{acme.ID().String(): true}})
	if _, err := h.svc.AccountToken(ctx, res.RefreshToken); err != nil {
		t.Fatalf("every organization suspended: %v", err)
	}
}
