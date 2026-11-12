package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// GET /api/v1/tenants and GET /api/v1/tenants/{tenant} are open to every
// member, viewer included. They return the organization profile only: no
// secret, and none of the security policy, AI or risk configuration either
// (owner decision B20). Those sections are read through GET /settings.
func TestTenantResponse_IsProfileOnly(t *testing.T) {
	const aiKey = "sk-ant-encrypted-or-not-0123456789"

	tn, err := tenant.NewTenant("Acme", "acme", "u1")
	if err != nil {
		t.Fatal(err)
	}
	tn.SetSetting("ai", map[string]any{"mode": "byok", "provider": "claude", "api_key": aiKey, "monthly_token_limit": 1000})
	tn.SetSetting("security", map[string]any{"ip_whitelist": []any{"203.0.113.0/24"}, "allowed_domains": []any{"corp.example"}})
	tn.SetSetting("general", map[string]any{"timezone": "UTC"})

	raw, err := json.Marshal(toTenantResponse(tn))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, leak := range []string{aiKey, "203.0.113.0/24", "corp.example", `"settings"`, "monthly_token_limit"} {
		if strings.Contains(body, leak) {
			t.Errorf("tenant response carries %q: %s", leak, body)
		}
	}
	var resp map[string]any
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if resp["name"] != "Acme" || resp["slug"] != "acme" {
		t.Errorf("profile fields missing: %s", body)
	}

	// The entity itself is untouched: the server still needs its settings.
	if ai, _ := tn.GetSetting("ai"); ai.(map[string]any)["api_key"] != aiKey {
		t.Error("building the response must not modify the tenant's settings")
	}
}
