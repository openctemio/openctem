package jwt

import (
	"testing"
	"time"
)

// The token's role claim is the team role the caller resolved from the system
// roles (owner/admin/member/viewer). It used to be replaced by the first RBAC
// role slug passed in, so a custom role named "owner" put role=owner in the
// token and IsOwner() trusted it (audit F1). The generator no longer takes the
// RBAC slugs at all.
func TestTenantScopedTokenRoleIsTheTeamRole(t *testing.T) {
	g := NewGenerator(TokenConfig{
		Secret:              "test-secret-32chars-minimum-len-ok",
		Issuer:              "openctem.api",
		AccessTokenDuration: time.Minute,
	})
	viewer := TenantMembership{TenantID: "t1", TenantSlug: "acme", Role: "viewer"}

	tok, err := g.GenerateTenantScopedAccessTokenWithPermissions(
		"u1", "u@x.com", "U", "sess1", viewer,
		[]string{"assets:read"}, false, 1, "password")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if tok.Role != "viewer" {
		t.Fatalf("token result role = %q, want viewer", tok.Role)
	}
	claims, err := g.ValidateAccessToken(tok.AccessToken)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.Role != "viewer" {
		t.Fatalf("role claim = %q, want viewer (custom slug must not become the role)", claims.Role)
	}
	if claims.IsAdmin {
		t.Fatal("admin flag set for a viewer")
	}
	if got := claims.GetTenantRole("t1"); got != "viewer" {
		t.Fatalf("tenant role = %q, want viewer", got)
	}
}
