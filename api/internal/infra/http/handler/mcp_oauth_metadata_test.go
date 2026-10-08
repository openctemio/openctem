package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
)

func TestMCPResourceMetadata(t *testing.T) {
	e, err := mcpoauth.NewEndpoints("https://openctem.example")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	NewMCPResourceMetadataHandler(e).Serve(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/api/v1/mcp", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want * (public document)", got)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["resource"] != "https://openctem.example/api/v1/mcp" {
		t.Errorf("resource = %v", doc["resource"])
	}
	if !reflect.DeepEqual(doc["authorization_servers"], []any{"https://openctem.example"}) {
		t.Errorf("authorization_servers = %v", doc["authorization_servers"])
	}
	if !reflect.DeepEqual(doc["bearer_methods_supported"], []any{"header"}) {
		t.Errorf("bearer_methods_supported = %v (tokens only in the header)", doc["bearer_methods_supported"])
	}
	want := []any{"mcp:assets.read", "mcp:compliance.read", "mcp:findings.read", "mcp:pentest.read"}
	if !reflect.DeepEqual(doc["scopes_supported"], want) {
		t.Errorf("scopes_supported = %v, want %v", doc["scopes_supported"], want)
	}
}

// Every tool and prompt must be reachable through some read scope: a tool
// whose permission no scope covers could never be called with an OAuth
// token, and the omission would only show as a silently missing tool.
func TestEveryMCPToolAndPromptIsCoveredByAScope(t *testing.T) {
	h := newTestMCP(&fakeFindingReader{})
	covered := map[string]bool{}
	for _, p := range mcpoauth.Permissions(mcpoauth.ReadScopes()) {
		covered[p] = true
	}
	for _, tool := range h.tools {
		if tool.RequiredPerm == "" || !covered[tool.RequiredPerm] {
			t.Errorf("tool %s: permission %q is covered by no MCP scope", tool.Name, tool.RequiredPerm)
		}
	}
	for _, p := range h.prompts {
		if p.RequiredPerm == "" || !covered[p.RequiredPerm] {
			t.Errorf("prompt %s: permission %q is covered by no MCP scope", p.Name, p.RequiredPerm)
		}
	}
}
