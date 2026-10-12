package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// Custom templates are trusted code (owner decision 2026-10-02). A command
// that embeds one is refused for anyone but owners and administrators, even
// when the template itself passes validation.

const benignNucleiTemplate = `id: authz-benign
info:
  name: benign
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`

func TestPayloadEmbedsCustomTemplates(t *testing.T) {
	cases := map[string]struct {
		payload string
		want    bool
	}{
		"empty":                   {``, false},
		"no templates":            {`{"scanner":"nuclei","target":"example.test"}`, false},
		"empty list":              {`{"custom_templates":[]}`, false},
		"null":                    {`{"custom_templates":null}`, false},
		"one template":            {`{"custom_templates":[{"name":"x","content":"YWJj"}]}`, true},
		"unparseable carrier":     {`{"custom_templates":"YWJj"}`, true},
		"truncated with mention":  {`{"custom_templates":[{"name":"x"`, true},
		"nested mention only":     {`{"config":{"note":"custom_templates"}}`, false},
		"nested key, not the top": {`{"config":{"custom_templates":[{"name":"x"}]}}`, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := payloadEmbedsCustomTemplates(json.RawMessage(tc.payload)); got != tc.want {
				t.Fatalf("payloadEmbedsCustomTemplates(%s) = %v, want %v", tc.payload, got, tc.want)
			}
		})
	}
}

func TestCommandCreate_CustomTemplatesNeedAdmin(t *testing.T) {
	// The service is nil: a refused request must be answered before it is
	// reached, and the test fails with a panic if it is not.
	h := NewCommandHandler(nil, validator.New(), logger.NewNop())

	body, err := json.Marshal(map[string]any{
		"type": "scan",
		"payload": map[string]any{
			"scanner": "nuclei",
			"target":  "https://example.test",
			"custom_templates": []map[string]any{{
				"name":          "benign.yaml",
				"template_type": "nuclei",
				"content":       base64.StdEncoding.EncodeToString([]byte(benignNucleiTemplate)),
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateInlineScanTemplates(mustPayload(t, body)); err != nil {
		t.Fatalf("test template must pass validation so only the role decides: %v", err)
	}

	ctx := context.WithValue(context.Background(), middleware.IsAdminKey, false)
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/commands", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("member sending a custom template: status %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
}

func mustPayload(t *testing.T, body []byte) json.RawMessage {
	t.Helper()
	var req struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	return req.Payload
}
