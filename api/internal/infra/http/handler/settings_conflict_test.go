package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// A 409 SETTINGS_CONFLICT carries the current section so the UI can show
// what changed; secrets in that section must stay write-only.
func TestWriteSettingsConflict_RedactsSecretsAndCarriesETag(t *testing.T) {
	w := httptest.NewRecorder()
	writeSettingsConflict(w, &tenant.SettingsConflictError{
		Section: tenant.SectionAI,
		ETag:    `"abc123"`,
		Current: map[string]any{"api_key": "s3cr3t-value", "azure_endpoint": "https://ai.example"},
	})

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
	if got := w.Header().Get("ETag"); got != `"abc123"` {
		t.Fatalf("ETag header = %q", got)
	}
	body := w.Body.String()
	if strings.Contains(body, "s3cr3t-value") {
		t.Fatalf("conflict body leaks the secret: %s", body)
	}
	var resp struct {
		Code    string `json:"code"`
		Details struct {
			Section string         `json:"section"`
			ETag    string         `json:"etag"`
			Current map[string]any `json:"current"`
		} `json:"details"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if resp.Code != "SETTINGS_CONFLICT" || resp.Details.Section != tenant.SectionAI || resp.Details.ETag != `"abc123"` {
		t.Fatalf("unexpected conflict body: %s", body)
	}
	if resp.Details.Current["api_key_configured"] != true || resp.Details.Current["azure_endpoint"] != "https://ai.example" {
		t.Fatalf("current section not redacted as expected: %v", resp.Details.Current)
	}
}

// Members and viewers read the settings they need to render the app (general,
// branding, pentest pick-lists), not the security policy or the scoring
// formula (owner decision B20, 23b T-M3).
func TestSettingsResponse_ForRole(t *testing.T) {
	s := tenant.DefaultSettings()
	s.Security.IPWhitelist = []string{"10.0.0.0/8"}
	full := toSettingsResponse(&s)
	for _, role := range []tenant.Role{tenant.RoleMember, tenant.RoleViewer, ""} {
		got := full.forRole(role)
		if got.Security != nil || got.RiskScoring != nil {
			t.Fatalf("role %q sees admin-only sections", role)
		}
		raw, _ := json.Marshal(got)
		if strings.Contains(string(raw), "10.0.0.0/8") || strings.Contains(string(raw), "\"security\"") {
			t.Fatalf("role %q response leaks the security section: %s", role, raw)
		}
	}
	for _, role := range []tenant.Role{tenant.RoleOwner, tenant.RoleAdmin} {
		if got := full.forRole(role); got.Security == nil || got.RiskScoring == nil {
			t.Fatalf("role %q lost a section", role)
		}
	}
}
