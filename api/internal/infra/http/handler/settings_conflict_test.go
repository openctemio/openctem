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
		Section: tenant.SectionAPI,
		ETag:    `"abc123"`,
		Current: map[string]any{"webhook_secret": "s3cr3t-value", "webhook_url": "https://hooks.example"},
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
	if resp.Code != "SETTINGS_CONFLICT" || resp.Details.Section != tenant.SectionAPI || resp.Details.ETag != `"abc123"` {
		t.Fatalf("unexpected conflict body: %s", body)
	}
	if resp.Details.Current["webhook_secret_configured"] != true || resp.Details.Current["webhook_url"] != "https://hooks.example" {
		t.Fatalf("current section not redacted as expected: %v", resp.Details.Current)
	}
}
