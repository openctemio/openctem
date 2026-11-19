package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/auth"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/jwt"
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

// A member gets an account token too: it reaches only the account routes, so
// it skips none of the organization's rules. Those still decide the
// organization's own token: here the organization requires 2FA and the
// member has none, so the account token works while the exchange is refused.
func TestAccountToken_MemberGetsOneAndTheOrganizationRuleStillApplies(t *testing.T) {
	ctx := context.Background()
	h := newMFAHarness(t)
	acme := newPolicyTenant(t, h.tenants, "acct-acme", false)
	h.tenants.userMemberships = []tenant.UserMembership{
		{TenantID: acme.ID().String(), TenantSlug: acme.Slug(), TenantName: "Acme", Role: "member"},
	}
	h.seedUser(t, "member@acme.test")
	res := h.login(t, "member@acme.test") // policy off: a plain session
	// The organization then requires 2FA.
	st := acme.TypedSettings()
	st.Security.MFARequired = true
	_ = acme.UpdateSettings(st)

	got, err := h.svc.AccountToken(ctx, res.RefreshToken)
	if err != nil {
		t.Fatalf("member of an organization: %v, want an account token", err)
	}
	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: defaultAuthTestConfig().JWTSecret, Issuer: defaultAuthTestConfig().JWTIssuer})
	claims, err := gen.ValidateAccessToken(got.AccessToken)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.TenantID != "" || claims.IsAdmin || len(claims.Permissions) != 0 {
		t.Fatalf("account token carries organization access: tenant=%q admin=%v perms=%v", claims.TenantID, claims.IsAdmin, claims.Permissions)
	}
	if claims.SessionID == "" {
		t.Fatal("account token is not bound to the session")
	}
	_, err = h.svc.ExchangeToken(ctx, auth.ExchangeTokenInput{RefreshToken: got.RefreshToken, TenantID: acme.ID().String()})
	if !errors.Is(err, auth.ErrMFAEnrollmentRequired) {
		t.Fatalf("organization token for a member without 2FA: %v, want ErrMFAEnrollmentRequired", err)
	}
}
