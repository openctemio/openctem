package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

type secSettings struct {
	MFARequired bool     `json:"mfa_required"`
	IPWhitelist []string `json:"ip_whitelist"`
	Webhook     struct {
		URL    string `json:"url"`
		Secret string `json:"webhook_secret"`
	} `json:"webhook"`
}

func TestDiffChanges_FieldLevelWithRedaction(t *testing.T) {
	var before, after secSettings
	before.MFARequired = true
	before.IPWhitelist = []string{"10.0.0.0/8"}
	before.Webhook.URL = "https://a.example"
	before.Webhook.Secret = "old-secret-value"
	after = before
	after.MFARequired = false
	after.Webhook.Secret = "new-secret-value"

	c := DiffChanges(before, after)
	if c == nil {
		t.Fatal("expected a diff")
	}
	if c.Before["mfa_required"] != true || c.After["mfa_required"] != false {
		t.Fatalf("mfa_required diff = %v -> %v", c.Before["mfa_required"], c.After["mfa_required"])
	}
	if _, ok := c.After["ip_whitelist"]; ok {
		t.Fatalf("unchanged field recorded: %v", c.After)
	}
	if c.Before["webhook.webhook_secret"] != RedactedChange || c.After["webhook.webhook_secret"] != RedactedChange {
		t.Fatalf("secret not redacted: %v / %v", c.Before, c.After)
	}
	raw, _ := json.Marshal(c)
	if strings.Contains(string(raw), "secret-value") {
		t.Fatalf("diff leaks a secret: %s", raw)
	}
	if got := ChangedFields(c); len(got) != 2 || got[0] != "mfa_required" || got[1] != "webhook.webhook_secret" {
		t.Fatalf("ChangedFields = %v", got)
	}
}

func TestDiffChanges_CreateDeleteAndNoChange(t *testing.T) {
	if DiffChanges(map[string]any{"a": 1}, map[string]any{"a": 1}) != nil {
		t.Fatal("no change must give nil")
	}
	c := DiffChanges(nil, map[string]any{"name": "x", "api_key": "k"})
	if c.After["name"] != "x" || c.After["api_key"] != RedactedChange || len(c.Before) != 0 {
		t.Fatalf("create diff = %+v", c)
	}
	c = DiffChanges(map[string]any{"name": "x"}, nil)
	if c.Before["name"] != "x" || len(c.After) != 0 {
		t.Fatalf("delete diff = %+v", c)
	}
}

func TestDiffChanges_Truncates(t *testing.T) {
	long := strings.Repeat("x", 1000)
	list := make([]string, 120)
	for i := range list {
		list[i] = "10.0.0.1"
	}
	c := DiffChanges(nil, map[string]any{"desc": long, "ips": list})
	if s, _ := c.After["desc"].(string); len(s) > maxDiffStringLen+3 {
		t.Fatalf("string not truncated: %d", len(s))
	}
	if l, _ := c.After["ips"].([]any); len(l) != maxDiffListLen+1 {
		t.Fatalf("list not truncated: %d", len(l))
	}
}

func TestIsSecretField(t *testing.T) {
	for _, k := range []string{"webhook_secret", "smtp_password", "api_key", "secret_key", "access_key", "bot_token", "credentials"} {
		if !IsSecretField(k) {
			t.Errorf("%s should be secret", k)
		}
	}
	for _, k := range []string{"api_key_enabled", "webhook_secret_configured", "has_secret", "name", "mfa_required"} {
		if IsSecretField(k) {
			t.Errorf("%s must not be secret", k)
		}
	}
}

func TestDiffChanges_HidesURLPassword(t *testing.T) {
	c := DiffChanges(nil, map[string]any{"url": "https://bot:" + "ghp_secret123" + "@git.example/repo.git"})
	s, _ := c.After["url"].(string)
	if strings.Contains(s, "ghp_secret123") || !strings.Contains(s, "git.example") {
		t.Fatalf("url password not hidden: %q", s)
	}
	c = DiffChanges(nil, map[string]any{"headers": map[string]any{"Authorization": "Bearer abc"}})
	raw, _ := json.Marshal(c)
	if strings.Contains(string(raw), "Bearer abc") {
		t.Fatalf("header value leaked: %s", raw)
	}
}
