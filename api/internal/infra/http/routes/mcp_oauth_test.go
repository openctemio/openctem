package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcpoauthapp "github.com/openctemio/openctem/api/internal/app/mcpoauth"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fakeTokens accepts one access token and returns a fixed principal.
type fakeTokens struct{ p *mcpoauthapp.Principal }

func (f fakeTokens) AuthenticateAccessToken(_ context.Context, raw, _ string) (*mcpoauthapp.Principal, error) {
	if raw != "octm_at_good" {
		return nil, mcpoauthapp.ErrInvalidToken
	}
	return f.p, nil
}

func newMCPOAuthMux(t *testing.T, p *mcpoauthapp.Principal) http.Handler {
	t.Helper()
	e, err := mcpoauth.NewEndpoints("https://openctem.example")
	if err != nil {
		t.Fatal(err)
	}
	log := logger.NewNop()
	router := infrahttp.NewChiRouter()
	d := &MCPDiscovery{Endpoints: e, Metadata: handler.NewMCPResourceMetadataHandler(e)}
	mcp := handler.NewMCPHandler(nil, nil, nil, nil, nil, nil, nil, log)
	mcp.SetResourceMetadataURL(e.ResourceMetadata)
	auth := middleware.MCPCredentialAuth(middleware.NewAPIKeyAuth(refuseEveryKey{}, log).Handler, fakeTokens{p}, log)
	registerMCPRoutes(router, mcp, nil, auth, d)
	return router.(interface{ Handler() http.Handler }).Handler()
}

func mcpCall(mux http.Handler, auth, body string, extra map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

const toolsList = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

// An access token reaches the tools with exactly its effective permissions:
// the tool list shows only what they allow.
func TestMCPAcceptsAccessTokens(t *testing.T) {
	p := &mcpoauthapp.Principal{
		GrantID: "g1", TenantID: "11111111-1111-1111-1111-111111111111", UserID: "22222222-2222-2222-2222-222222222222",
		ClientID: "https://assistant.example/c.json", Scopes: []mcpoauth.Scope{mcpoauth.ScopeAssetsRead},
		Permissions: []string{"assets:read"}, Held: []string{"assets:read", "findings:read"},
	}
	mux := newMCPOAuthMux(t, p)
	rec := mcpCall(mux, "Bearer octm_at_good", toolsList, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Result struct {
			Tools []struct{ Name string } `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tl := range resp.Result.Tools {
		names[tl.Name] = true
	}
	if !names["list_assets"] || names["list_findings"] || names["get_campaign"] {
		t.Fatalf("tools listed for an assets-only token: %v", names)
	}
}

// A call the user could make with another scope is a step-up challenge; a
// call no scope would allow is an ordinary tool error.
func TestMCPInsufficientScopeChallenge(t *testing.T) {
	p := &mcpoauthapp.Principal{
		GrantID: "g1", TenantID: "11111111-1111-1111-1111-111111111111", UserID: "22222222-2222-2222-2222-222222222222",
		Scopes: []mcpoauth.Scope{mcpoauth.ScopeAssetsRead}, Permissions: []string{"assets:read"},
		Held: []string{"assets:read", "findings:read"},
	}
	mux := newMCPOAuthMux(t, p)
	rec := mcpCall(mux, "Bearer octm_at_good", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_findings","arguments":{}}}`, nil)
	ch := rec.Header().Get("WWW-Authenticate")
	if rec.Code != http.StatusForbidden || !strings.Contains(ch, `error="insufficient_scope"`) ||
		!strings.Contains(ch, `scope="mcp:findings.read"`) || !strings.Contains(ch, `resource_metadata="https://openctem.example/.well-known/oauth-protected-resource/api/v1/mcp"`) {
		t.Fatalf("status %d, challenge %q", rec.Code, ch)
	}

	// The user does not hold pentest access: asking for the scope would not
	// help, so no challenge.
	rec = mcpCall(mux, "Bearer octm_at_good", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_campaign","arguments":{"campaign_id":"x"}}}`, nil)
	if rec.Code != http.StatusOK || rec.Header().Get("WWW-Authenticate") != "" || !strings.Contains(rec.Body.String(), `"isError":true`) {
		t.Fatalf("no-held-permission call: %d %q %s", rec.Code, rec.Header().Get("WWW-Authenticate"), rec.Body.String())
	}
}

func TestMCPRefusesBadAndAmbiguousTokens(t *testing.T) {
	mux := newMCPOAuthMux(t, &mcpoauthapp.Principal{GrantID: "g"})
	for name, tc := range map[string]struct {
		auth  string
		extra map[string]string
	}{
		"unknown access token":  {"Bearer octm_at_bad", nil},
		"refresh token":         {"Bearer octm_rt_good", nil},
		"token and api key":     {"Bearer octm_at_good", map[string]string{"X-API-Key": "oct_x"}},
		"lowercase bearer junk": {"bearer octm_at_", nil},
	} {
		rec := mcpCall(mux, tc.auth, toolsList, tc.extra)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "resource_metadata=") {
			t.Errorf("%s: status %d challenge %q", name, rec.Code, rec.Header().Get("WWW-Authenticate"))
		}
	}
}

// Answering a consent request is a person's decision: API keys never reach
// the consent API.
func TestConsentAPIRefusesAPIKeys(t *testing.T) {
	for _, p := range []string{"/api/v1/oauth/requests/x", "/api/v1/oauth/requests/x/approve", "//api/v1/oauth/./requests/x/deny"} {
		if !middleware.APIKeyRouteDenied(p) {
			t.Errorf("%s is reachable with an API key", p)
		}
	}
}
