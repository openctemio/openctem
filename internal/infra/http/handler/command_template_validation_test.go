package handler

import (
	"encoding/base64"
	"encoding/json"
	"strings"
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

// The gate parses the payload into a narrow struct and used to return nil when
// that parse failed. For an ordinary command — no custom_templates anywhere —
// that is correct, and TestValidateInlineScanTemplates_AllowsNoTemplates covers
// it.
//
// It was also doing that for a payload that NAMES custom_templates in a shape
// this struct cannot read. Passing there bets that the agent's decoder is
// exactly as strict as this one, and it is a bet with no upside: the payload is
// on its way to an executor that only checks name and size, and this function
// is the only thing looking at content.
func TestValidateInlineScanTemplates_RefusesUnparseableTemplateCarrier(t *testing.T) {
	cases := map[string]string{
		"list is a string":       `{"custom_templates":"YWJj"}`,
		"list is an object":      `{"custom_templates":{"name":"x","content":"YWJj"}}`,
		"entries are strings":    `{"custom_templates":["not-an-object"]}`,
		"content is a number":    `{"custom_templates":[{"name":"x","content":1234}]}`,
		"truncated json":         `{"custom_templates":[{"name":"x","content":"YWJj"`,
		"template_type is a map": `{"custom_templates":[{"name":"x","template_type":{"a":1}}]}`,
	}

	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateInlineScanTemplates(json.RawMessage(payload))
			if err == nil {
				t.Fatal("approved a payload carrying custom_templates that it could not parse; " +
					"the agent decodes and executes whatever it can read")
			}
			if !strings.Contains(err.Error(), "could not be parsed") {
				t.Errorf("rejected, but not for the expected reason: %v", err)
			}
		})
	}
}

// Malformed JSON that says nothing about templates is still not this function's
// problem — it must not start rejecting every unrelated command.
func TestValidateInlineScanTemplates_IgnoresUnrelatedMalformedPayloads(t *testing.T) {
	cases := map[string]string{
		"truncated, no templates": `{"target":"example.test"`,
		"not json at all":         `this is not json`,
		"wrong scalar type":       `{"target":123,"scanner":true}`,
	}

	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validateInlineScanTemplates(json.RawMessage(payload)); err != nil {
				t.Errorf("rejected a payload with no custom_templates in it: %v", err)
			}
		})
	}
}
