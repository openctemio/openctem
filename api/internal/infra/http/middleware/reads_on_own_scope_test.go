package middleware

import (
	"context"
	"testing"

	mcpoauthapp "github.com/openctemio/openctem/api/internal/app/mcpoauth"
)

// ReadsOnOwnScope is the data-scope flag of a delegated credential. Only an
// MCP connection whose principal is full-data (decided per request by the
// authorization server) escapes it; IsDelegatedCredential stays true for it,
// so a person-only decision (an approval) is never made by a connection.
func TestReadsOnOwnScope(t *testing.T) {
	mcp := func(p *mcpoauthapp.Principal) context.Context {
		ctx := context.WithValue(context.Background(), AuthProviderKey, AuthProviderMCPOAuth)
		if p != nil {
			ctx = context.WithValue(ctx, MCPPrincipalKey, p)
		}
		return ctx
	}
	cases := map[string]struct {
		ctx            context.Context
		ownScope       bool
		delegatedToken bool
	}{
		"scoped MCP connection":      {mcp(&mcpoauthapp.Principal{}), true, true},
		"full-data MCP connection":   {mcp(&mcpoauthapp.Principal{FullData: true}), false, true},
		"MCP without a principal":    {mcp(nil), true, true},
		"API key":                    {context.WithValue(context.Background(), AuthProviderKey, AuthProviderAPIKey), true, true},
		"API key with a stray flag":  {context.WithValue(context.WithValue(context.Background(), AuthProviderKey, AuthProviderAPIKey), MCPPrincipalKey, &mcpoauthapp.Principal{FullData: true}), true, true},
		"person's own session (jwt)": {context.WithValue(context.Background(), AuthProviderKey, "jwt"), false, false},
	}
	for name, tc := range cases {
		if got := ReadsOnOwnScope(tc.ctx); got != tc.ownScope {
			t.Errorf("%s: ReadsOnOwnScope = %v, want %v", name, got, tc.ownScope)
		}
		if got := IsDelegatedCredential(tc.ctx); got != tc.delegatedToken {
			t.Errorf("%s: IsDelegatedCredential = %v, want %v", name, got, tc.delegatedToken)
		}
	}
}
