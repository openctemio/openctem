package main

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
)

// The shared data-scope caller marks MCP OAuth and API key requests as
// delegated, so the enforcer never applies the holder's full-data role.
func TestHTTPDataScopeCallerMarksDelegatedCredentials(t *testing.T) {
	base := context.WithValue(context.Background(), middleware.UserIDKey, "22222222-2222-4222-8222-222222222222")
	if httpDataScopeCaller(base).APIKey {
		t.Fatal("a session must not be marked delegated")
	}
	if !httpDataScopeCaller(context.WithValue(base, middleware.AuthProviderKey, middleware.AuthProviderAPIKey)).APIKey {
		t.Fatal("an API key must be marked delegated")
	}
	if !httpDataScopeCaller(context.WithValue(base, middleware.AuthProviderKey, middleware.AuthProviderMCPOAuth)).APIKey {
		t.Fatal("an MCP OAuth token must be marked delegated")
	}
}
