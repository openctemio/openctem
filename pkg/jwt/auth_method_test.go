package jwt

import (
	"testing"
	"time"
)

// TestTenantScopedTokenCarriesAuthMethod proves the session's auth_method is
// embedded in the tenant-scoped access token and survives a validate round-trip,
// so the per-request SSO-enforcement gate can read it from the signed claim.
func TestTenantScopedTokenCarriesAuthMethod(t *testing.T) {
	g := NewGenerator(TokenConfig{
		Secret:              "test-secret-32chars-minimum-len-ok",
		Issuer:              "openctem.api",
		AccessTokenDuration: time.Minute,
	})
	member := TenantMembership{TenantID: "t1", TenantSlug: "acme", Role: "member"}

	for _, method := range []string{"password", "sso", "saml"} {
		tok, err := g.GenerateTenantScopedAccessToken("u1", "u@x.com", "U", "sess1", member, false, 0, method)
		if err != nil {
			t.Fatalf("generate (%s): %v", method, err)
		}
		claims, err := g.ValidateAccessToken(tok.AccessToken)
		if err != nil {
			t.Fatalf("validate (%s): %v", method, err)
		}
		if claims.AuthMethod != method {
			t.Errorf("auth_method = %q, want %q", claims.AuthMethod, method)
		}

		// Same for the DB-permissions path.
		tok2, err := g.GenerateTenantScopedAccessTokenWithPermissions(
			"u1", "u@x.com", "U", "sess1", member, []string{"assets:read"}, []string{"member"}, false, 0, method)
		if err != nil {
			t.Fatalf("generate w/perms (%s): %v", method, err)
		}
		claims2, err := g.ValidateAccessToken(tok2.AccessToken)
		if err != nil {
			t.Fatalf("validate w/perms (%s): %v", method, err)
		}
		if claims2.AuthMethod != method {
			t.Errorf("w/perms auth_method = %q, want %q", claims2.AuthMethod, method)
		}
	}
}
