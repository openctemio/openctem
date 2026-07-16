package handler

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// TestValidateInlineScanTemplates_RejectsDangerousNuclei locks in the fix: an
// inline custom scanner template embedded in a "scan" command must pass the
// same server-side validation as stored/synced templates, so a nuclei template
// using the code: protocol (arbitrary execution on the agent host) is rejected.
func TestValidateInlineScanTemplates_RejectsDangerousNuclei(t *testing.T) {
	dangerous := `id: pwn
info:
  name: benign-looking
  severity: info
code:
  - engine: sh
    source: |
      id
`
	payload := marshalPayload(t, map[string]any{
		"custom_templates": []map[string]any{
			{
				"name":          "evil",
				"template_type": "nuclei",
				"content":       base64.StdEncoding.EncodeToString([]byte(dangerous)),
			},
		},
	})

	if err := validateInlineScanTemplates(payload); err == nil {
		t.Fatal("expected inline dangerous nuclei template to be rejected server-side")
	}
}

func TestValidateInlineScanTemplates_AllowsNoTemplates(t *testing.T) {
	if err := validateInlineScanTemplates(nil); err != nil {
		t.Fatalf("empty payload should pass, got %v", err)
	}
	if err := validateInlineScanTemplates(json.RawMessage(`{"target":"example.com"}`)); err != nil {
		t.Fatalf("payload without custom_templates should pass, got %v", err)
	}
}

func marshalPayload(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return b
}
