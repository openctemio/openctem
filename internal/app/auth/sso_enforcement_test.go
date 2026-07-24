package auth

import (
	"testing"

	sessiondom "github.com/openctemio/api/pkg/domain/session"
)

// TestSSOEnforcementDecision exhaustively exercises the pure enforcement
// decision that both ExchangeToken and RefreshToken delegate to. This is the
// security-critical truth table: fail-closed for password non-owners, but
// break-glass-safe (owner + federated always pass).
func TestSSOEnforcementDecision(t *testing.T) {
	cases := []struct {
		name        string
		method      sessiondom.AuthMethod
		role        string
		ssoEnforced bool
		wantDenied  bool
	}{
		// --- tenant does NOT enforce SSO: nobody is ever denied ---
		{"not enforced / password member", sessiondom.AuthMethodPassword, "member", false, false},
		{"not enforced / password owner", sessiondom.AuthMethodPassword, "owner", false, false},
		{"not enforced / sso member", sessiondom.AuthMethodSSO, "member", false, false},

		// --- tenant enforces SSO ---
		// password + non-owner => DENIED (the whole point of the feature)
		{"enforced / password member", sessiondom.AuthMethodPassword, "member", true, true},
		{"enforced / password admin", sessiondom.AuthMethodPassword, "admin", true, true},
		{"enforced / password viewer", sessiondom.AuthMethodPassword, "viewer", true, true},
		// break-glass: password OWNER always passes
		{"enforced / password owner (break-glass)", sessiondom.AuthMethodPassword, "owner", true, false},
		// federated sessions always pass, regardless of role
		{"enforced / sso member", sessiondom.AuthMethodSSO, "member", true, false},
		{"enforced / sso admin", sessiondom.AuthMethodSSO, "admin", true, false},
		{"enforced / saml member", sessiondom.AuthMethodSAML, "member", true, false},
		{"enforced / saml owner", sessiondom.AuthMethodSAML, "owner", true, false},
		// fail-closed: an empty/unknown auth method is treated as password
		{"enforced / empty method member (fail-closed)", sessiondom.AuthMethod(""), "member", true, true},
		{"enforced / empty method owner", sessiondom.AuthMethod(""), "owner", true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ssoEnforcementDenied(tc.method, tc.role, tc.ssoEnforced)
			if got != tc.wantDenied {
				t.Fatalf("ssoEnforcementDenied(%q, %q, %v) = %v, want %v",
					tc.method, tc.role, tc.ssoEnforced, got, tc.wantDenied)
			}
		})
	}
}
